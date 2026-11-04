"""Validação implícita de telemetria: uma tecnologia só nasce com logs no Loki.

Regra de negócio:
    Antes de cadastrar uma tecnologia (``ss_groups``), o portal confirma que o
    recorte já produziu logs. A query usada é fixa, montada somente no backend e
    **nunca** devolvida ao usuário::

        sum(count_over_time({job="wazuh", ss_groups=~".*<tecnologia>.*"} | json [1m]))

Comportamento:
    * Loki disponível e contagem > 0  -> ``found=True`` (cadastro liberado).
    * Loki disponível e contagem == 0 -> ``found=False``; o front exige um
      pop-up de confirmação e o backend recusa a criação sem o aceite explícito
      (``confirm_without_logs``).
    * Loki não configurado/indisponível -> ``available=False``: não há como
      comprovar a ausência de logs, então a criação não é bloqueada (o portal
      continua operável em ambientes sem Loki), mas o resultado é informado na
      API com ``message`` própria.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from .grafana_client import GrafanaClient, GrafanaError
from .schemas import TechnologyLogCheckResult
from .technologies import (
    PRESENCE_WINDOW_SECONDS,
    build_log_presence_query,
)

logger = logging.getLogger("hunter_portal.loki_presence")

# Teto de espera da consulta: a checagem acontece durante o cadastro, então não
# pode travar a UI. Excedido o prazo, tratamos como indisponível.
PRESENCE_TIMEOUT_SECONDS = 6.0


def _extract_count(payload: dict[str, Any]) -> int:
    """Soma a contagem devolvida pelo Loki (resultado vetorial ou matricial)."""
    data = payload.get("data") or {}
    result = data.get("result") or []
    total = 0.0
    for series in result:
        if not isinstance(series, dict):
            continue
        values = series.get("values")
        if values:  # matrix
            raw = values[-1][1] if isinstance(values[-1], list) else 0
        else:  # vector
            value = series.get("value") or [0, 0]
            raw = value[1] if isinstance(value, list) and len(value) > 1 else 0
        try:
            total += float(raw)
        except (TypeError, ValueError):
            continue
    return int(total)


def _result(
    *,
    available: bool,
    found: bool,
    count: int,
    window_seconds: int,
    datasource: str | None,
    message: str,
) -> TechnologyLogCheckResult:
    return TechnologyLogCheckResult(
        available=available,
        found=found,
        count=count,
        window_seconds=window_seconds,
        datasource=datasource,
        checked_at=datetime.now(timezone.utc).isoformat(),
        message=message,
    )


async def check_technology_logs(
    grafana: GrafanaClient,
    rule_groups_regex: str | None = None,
    job: str = "wazuh",
    window_seconds: int = PRESENCE_WINDOW_SECONDS,
    datasource_uid: str | None = None,
    ss_groups_regex: str | None = None,
) -> TechnologyLogCheckResult:
    effective_regex = rule_groups_regex or ss_groups_regex or ""
    query = build_log_presence_query(job, effective_regex, window_seconds, label_name="rule_groups")
    """Consulta o Loki e informa se o recorte de ``ss_groups`` tem logs.

    Levanta ``TechnologyValidationError`` se o recorte/job forem inválidos --
    validação feita antes de qualquer chamada ao Grafana.

    ``datasource_uid`` força um data source específico (escaneamento por tenant,
    em que cada cliente tem o próprio Loki). Sem ele, a seleção segue a ordem de
    ``GrafanaClient.find_loki_datasource``.
    """
    # Valida recorte/job antes de qualquer chamada ao Grafana (a query é
    # interpolada com esses valores, então nunca chega ao Loki sem validação).
    

    ds_uid = ""
    ds_name = ""
    if datasource_uid and datasource_uid.strip():
        ds_uid = datasource_uid.strip()
        ds_name = ds_uid
    else:
        try:
            datasource = await grafana.find_loki_datasource()
        except GrafanaError as exc:
            logger.warning("Falha ao listar datasources do Grafana: %s", exc.message)
            return _result(
                available=False,
                found=False,
                count=0,
                window_seconds=window_seconds,
                datasource=None,
                message=(
                    "Não foi possível consultar os datasources do Grafana para validar a "
                    "presença de logs desta tecnologia."
                ),
            )

        if datasource is None:
            return _result(
                available=False,
                found=False,
                count=0,
                window_seconds=window_seconds,
                datasource=None,
                message=(
                    "Nenhum datasource Loki está configurado no Grafana, portanto não foi "
                    "possível validar a presença de logs desta tecnologia."
                ),
            )

        ds_uid = str(datasource.get("uid") or "")
        ds_name = str(datasource.get("name") or ds_uid)


    try:
        payload = await asyncio.wait_for(
            grafana.loki_instant_query(ds_uid, query),
            timeout=PRESENCE_TIMEOUT_SECONDS,
        )
    except (asyncio.TimeoutError, TimeoutError):
        logger.warning("Timeout na consulta implícita de logs (datasource %s)", ds_name)
        return _result(
            available=False,
            found=False,
            count=0,
            window_seconds=window_seconds,
            datasource=ds_name,
            message=(
                "A consulta de telemetria ao Loki excedeu o tempo limite; não foi "
                "possível validar a presença de logs desta tecnologia."
            ),
        )
    except GrafanaError as exc:
        logger.warning("Erro na consulta implícita de logs: %s", exc.message)
        return _result(
            available=False,
            found=False,
            count=0,
            window_seconds=window_seconds,
            datasource=ds_name,
            message=(
                "O Loki retornou erro ao verificar a telemetria desta tecnologia; "
                "não foi possível validar a presença de logs."
            ),
        )

    if str(payload.get("status") or "").lower() not in ("", "success"):
        return _result(
            available=False,
            found=False,
            count=0,
            window_seconds=window_seconds,
            datasource=ds_name,
            message=(
                "O Loki respondeu com erro ao verificar a telemetria desta tecnologia; "
                "não foi possível validar a presença de logs."
            ),
        )

    count = _extract_count(payload)
    # Se com rule_groups não achou logs, tenta fallback transparente com ss_groups
    if count == 0 and ds_uid:
        try:
            fallback_query = build_log_presence_query(job, effective_regex, window_seconds, label_name="ss_groups")
            fb_payload = await asyncio.wait_for(
                grafana.loki_instant_query(ds_uid, fallback_query),
                timeout=PRESENCE_TIMEOUT_SECONDS,
            )
            count = _extract_count(fb_payload)
        except Exception:
            pass

    if count > 0:
        return _result(
            available=True,
            found=True,
            count=count,
            window_seconds=window_seconds,
            datasource=ds_name,
            message=(
                f"Telemetria confirmada: {count} log(s) encontrados no Loki para este "
                "recorte de grupos de regras na janela analisada."
            ),
        )

    return _result(
        available=True,
        found=False,
        count=0,
        window_seconds=window_seconds,
        datasource=ds_name,
        message=(
            "Não foram encontrados logs no Loki para este grupo de regras na janela de "
            f"{window_seconds}s analisada."
        ),
    )
