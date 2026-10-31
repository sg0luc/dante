"""LaboratÃ³rio de logs sintÃ©ticos no Loki.

Objetivo: permitir testar regras de detecÃ§Ã£o LogQL com dados controlados, sem
depender do pipeline real (Vector -> Kafka -> Loki). O portal injeta linhas JSON
em um stream arbitrÃ¡rio e **verifica** a ingestÃ£o consultando o prÃ³prio Loki.

Rotas:
    GET  /api/loki/datasources lista datasources Loki (internos vs clientes)
    GET  /api/loki/status      disponibilidade do datasource + labels conhecidas
    POST /api/loki/logs        injeta linhas JSON e confirma a ingestÃ£o

SeguranÃ§a:
    * SessÃ£o obrigatÃ³ria; a injeÃ§Ã£o exige o cabeÃ§alho anti-CSRF.
    * Nenhuma URL/credencial do Loki Ã© devolvida ao navegador alÃ©m do nome do
      datasource e da URL interna jÃ¡ provisionada (nÃ£o secreta).
    * Data sources de clientes sÃ£o estritamente proibidos de receber injeÃ§Ã£o de
      logs sintÃ©ticos; apenas data sources internos sÃ£o aceitos.
    * A validaÃ§Ã£o de labels/volumes vive em ``app.loki_synthetic`` e Ã© a
      fronteira de confianÃ§a: o Loki interno nÃ£o tem autenticaÃ§Ã£o.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ..config import Settings
from ..grafana_client import GrafanaClient, GrafanaError
from ..loki_presence import _extract_count
from ..loki_synthetic import (
    SyntheticLogError,
    build_count_query,
    build_explore_url,
    build_push_payload,
    stream_selector,
    validate_stream,
)
from ..schemas import (
    LokiDatasourceItem,
    LokiStatusResponse,
    LokiSyntheticRequest,
    LokiSyntheticResponse,
)
from ..security import Session, get_current_user, require_csrf_header
from ..system_settings_store import SystemSettingsStore
from ..technology_insights import is_client_folder
from ..technology_store import get_system_settings_store
from ..tenants import (
    LOKI_DATASOURCE_TYPES,
    ensure_tenant_sandbox_datasource,
    find_tenant_datasource,
    find_tenant_sandbox_datasource,
    get_client_datasource_uids,
    get_client_sandbox_datasource_uids,
    is_sandbox_datasource,
    sandbox_datasource_name,
)
from .deps import get_app_settings, get_grafana

logger = logging.getLogger("hunter_portal.loki")

router = APIRouter(prefix="/loki", tags=["loki"])

# O laboratÃ³rio nÃ£o pode travar a UI: push e verificaÃ§Ã£o tÃªm prazo curto.
PUSH_TIMEOUT_SECONDS = 8.0
PROBE_TIMEOUT_SECONDS = 6.0
VERIFY_TIMEOUT_SECONDS = 5.0
# A ingestÃ£o do Loki Ã© assÃ­ncrona (poucas centenas de ms); confirmamos em retry.
VERIFY_ATTEMPTS = 3
VERIFY_INTERVAL_SECONDS = 0.6


def select_default_internal_datasource(
    datasources: list[dict[str, Any]],
    client_uids: set[str],
) -> dict[str, Any] | None:
    """Seleciona o data source Loki interno padrão para o laboratório de injeção.

    Garante que data sources pertencentes a clientes (tenants) nunca sejam
    selecionados por default.

    Critérios de preferência (estritamente restritos a datasources internos):
        1. Datasource interno com UID canônico 'loki' (case-insensitive);
        2. Datasource interno marcado como default no Grafana (`isDefault: True`);
        3. Datasource interno com nome canônico 'loki' (case-insensitive);
        4. Primeiro datasource interno ordenado alfabeticamente por nome.
    """
    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
    ]
    internal_lokis = [
        ds
        for ds in lokis
        if str(ds.get("uid") or "").strip().lower() == "loki"
        or (str(ds.get("uid") or "") not in client_uids)
    ]
    if not internal_lokis:
        return None

    # 1. UID 'loki'
    for ds in internal_lokis:
        if str(ds.get("uid") or "").strip().lower() == "loki":
            return ds

    # 2. isDefault no Grafana (apenas se for interno!)
    for ds in internal_lokis:
        if bool(ds.get("isDefault", False)):
            return ds

    # 3. Nome 'loki'
    for ds in internal_lokis:
        if str(ds.get("name") or "").strip().lower() == "loki":
            return ds

    # 4. Primeiro interno alfabético
    return sorted(internal_lokis, key=lambda d: str(d.get("name") or "").lower())[0]


async def _resolve_datasource(
    grafana: GrafanaClient,
    datasource_uid: str | None = None,
    datasources: list[dict[str, Any]] | None = None,
    client_uids: set[str] | None = None,
    baseline_uid: str = "global",
) -> dict[str, Any] | None:
    """Localiza o datasource Loki solicitado ou o padrão interno do laboratório."""
    if datasources is None:
        datasources = await grafana.list_datasources()

    if datasource_uid and datasource_uid.strip():
        target = datasource_uid.strip()
        for ds in datasources:
            if str(ds.get("uid") or "") == target:
                return ds
        return None

    if client_uids is None:
        try:
            client_uids = await _get_client_datasource_uids(grafana, datasources, baseline_uid)
        except GrafanaError as exc:
            logger.warning("Falha ao identificar pastas de clientes: %s", exc.message)
            client_uids = set()

    internal_ds = select_default_internal_datasource(datasources, client_uids)
    if internal_ds is not None:
        return internal_ds

    # Fallback apenas se não houver nenhum datasource interno identificado
    return await grafana.find_loki_datasource()


async def _get_client_datasource_uids(
    grafana: GrafanaClient,
    datasources: list[dict[str, Any]],
    baseline_uid: str = "global",
) -> set[str]:
    """Identifica os UIDs de datasources pertencentes a pastas de clientes (tenants)."""
    folders = await grafana.list_folders()
    return get_client_datasource_uids(folders, datasources, baseline_uid)


@router.get("/datasources", response_model=list[LokiDatasourceItem])
async def list_loki_datasources(
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> list[LokiDatasourceItem]:
    """Lista todos os data sources Loki do Grafana, discriminando internos, sandboxes e produção de clientes."""
    try:
        datasources = await grafana.list_datasources()
        folders = await grafana.list_folders()
    except GrafanaError as exc:
        logger.warning("Falha ao listar datasources do Grafana: %s", exc.message)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Não foi possível consultar os datasources do Grafana.",
        )

    baseline_uid = sys_settings.get_baseline_folder_uid()
    client_folders = [f for f in folders if is_client_folder(f, baseline_folder_uid=baseline_uid)]

    # Apenas reflete os datasources reais existentes no Grafana (sem auto-criação)

    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
    ]

    prod_client_uids = get_client_datasource_uids(client_folders, datasources, baseline_uid)
    sandbox_client_uids = get_client_sandbox_datasource_uids(client_folders, datasources, baseline_uid)

    # Mapeia título do cliente por UID para enriquecimento
    client_names_by_uid: dict[str, str] = {}
    for f in client_folders:
        f_title = str(f.get("title") or "").strip()
        f_uid = str(f.get("uid") or "")
        prod_ds = find_tenant_datasource(f_title, f_uid, datasources)
        if prod_ds and prod_ds.get("uid"):
            client_names_by_uid[str(prod_ds["uid"])] = f_title
        sb_ds = find_tenant_sandbox_datasource(f_title, f_uid, datasources)
        if sb_ds and sb_ds.get("uid"):
            client_names_by_uid[str(sb_ds["uid"])] = f_title
        if f_uid:
            client_names_by_uid[f_uid] = f_title
            client_names_by_uid[f"{f_uid}-loki"] = f_title
            client_names_by_uid[f"sandbox-{f_uid}"] = f_title
            client_names_by_uid[f"sandbox-{f_uid}-loki"] = f_title

    items: list[LokiDatasourceItem] = []
    for ds in lokis:
        uid = str(ds.get("uid") or "")
        name = str(ds.get("name") or uid)
        ds_type = str(ds.get("type") or "loki")
        url = str(ds.get("url") or "") or None
        is_default = bool(ds.get("isDefault", False))

        is_sb = (
            uid in sandbox_client_uids
            or is_sandbox_datasource(name=name, uid=uid)
        )
        is_prod = (
            not is_sb
            and (uid in prod_client_uids or uid in client_names_by_uid)
            and uid.lower() != "loki"
        )
        is_int = uid.lower() == "loki" or (not is_sb and not is_prod)

        client_name = client_names_by_uid.get(uid)
        if not client_name and is_sb:
            # Fallback para extrair nome do cliente retirando 'sandbox-'
            clean_name = name.strip()
            if clean_name.lower().startswith("sandbox-"):
                client_name = clean_name[8:]

        can_inj = is_int or is_sb

        items.append(
            LokiDatasourceItem(
                uid=uid,
                name=name,
                type=ds_type,
                url=url,
                is_internal=is_int,
                is_default=is_default,
                is_sandbox=is_sb,
                can_inject=can_inj,
                client_name=client_name,
            )
        )

    # Ordena: internos primeiro (default primeiro), depois sandboxes de clientes, depois produção
    items.sort(
        key=lambda item: (
            not item.is_internal,
            not item.is_sandbox,
            not item.is_default,
            item.name.lower(),
        )
    )
    return items


@router.get("/status", response_model=LokiStatusResponse)
async def loki_status(
    datasource_uid: str | None = Query(default=None, description="UID do data source Loki a consultar"),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> LokiStatusResponse:
    """Estado do datasource Loki: configurado, alcançável e labels existentes."""
    try:
        datasources = await grafana.list_datasources()
    except GrafanaError as exc:
        logger.warning("Falha ao listar datasources do Grafana: %s", exc.message)
        return LokiStatusResponse(
            available=False,
            ready=False,
            message="Não foi possível consultar os datasources do Grafana.",
        )

    baseline_uid = sys_settings.get_baseline_folder_uid()
    try:
        client_uids = await _get_client_datasource_uids(grafana, datasources, baseline_uid)
    except GrafanaError as exc:
        logger.warning("Falha ao identificar pastas de clientes: %s", exc.message)
        client_uids = set()

    try:
        datasource = await _resolve_datasource(
            grafana,
            datasource_uid=datasource_uid,
            datasources=datasources,
            client_uids=client_uids,
            baseline_uid=baseline_uid,
        )
    except GrafanaError as exc:
        logger.warning("Falha ao resolver datasource do Grafana: %s", exc.message)
        return LokiStatusResponse(
            available=False,
            ready=False,
            message="Não foi possível consultar os datasources do Grafana.",
        )

    if datasource is None:
        target_name = f" '{datasource_uid}'" if datasource_uid else ""
        return LokiStatusResponse(
            available=False,
            ready=False,
            message=(
                f"Nenhum datasource Loki{target_name} estÃ¡ configurado no Grafana. "
                "Suba o serviÃ§o 'loki' do compose para habilitar o laboratÃ³rio."
            ),
        )

    uid = str(datasource.get("uid") or "")
    name = str(datasource.get("name") or uid)
    url = str(datasource.get("url") or "") or None

    try:
        labels = await asyncio.wait_for(
            grafana.loki_labels(uid), timeout=PROBE_TIMEOUT_SECONDS
        )
    except (asyncio.TimeoutError, TimeoutError):
        return LokiStatusResponse(
            available=True,
            ready=False,
            datasource=name,
            datasource_uid=uid,
            url=url,
            message="O Loki nÃ£o respondeu Ã  consulta de labels (tempo esgotado).",
        )
    except GrafanaError as exc:
        logger.warning("Loki indisponÃ­vel via datasource %s: %s", name, exc.message)
        return LokiStatusResponse(
            available=True,
            ready=False,
            datasource=name,
            datasource_uid=uid,
            url=url,
            message="O datasource Loki existe, mas nÃ£o respondeu Ã  consulta de labels.",
        )

    return LokiStatusResponse(
        available=True,
        ready=True,
        datasource=name,
        datasource_uid=uid,
        url=url,
        labels=sorted(labels),
        message=(
            f"Loki disponÃ­vel via datasource '{name}'."
            if labels
            else f"Loki disponÃ­vel via datasource '{name}', ainda sem streams ingeridos."
        ),
    )


@router.post(
    "/logs",
    response_model=LokiSyntheticResponse,
    dependencies=[Depends(require_csrf_header)],
)
async def inject_synthetic_logs(
    payload: LokiSyntheticRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    user: Session = Depends(get_current_user),
) -> LokiSyntheticResponse:
    """Injeta linhas JSON fictÃ­cias no Loki e confirma que ficaram consultÃ¡veis."""
    try:
        stream = validate_stream(payload.stream, mark_synthetic=payload.mark_synthetic)
        body, total_bytes = build_push_payload(stream, payload.lines, payload.spread_seconds)
    except SyntheticLogError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    try:
        datasources = await grafana.list_datasources()
    except GrafanaError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.message)

    baseline_uid = sys_settings.get_baseline_folder_uid()
    try:
        client_uids = await _get_client_datasource_uids(grafana, datasources, baseline_uid)
    except GrafanaError as exc:
        logger.warning("Falha ao identificar pastas de clientes: %s", exc.message)
        client_uids = set()

    try:
        datasource = await _resolve_datasource(
            grafana,
            datasource_uid=payload.datasource_uid,
            datasources=datasources,
            client_uids=client_uids,
            baseline_uid=baseline_uid,
        )
    except GrafanaError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=exc.message)

    if datasource is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND if payload.datasource_uid else status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"Datasource Loki '{payload.datasource_uid}' nÃ£o foi encontrado no Grafana."
                if payload.datasource_uid
                else "Nenhum datasource Loki configurado no Grafana."
            ),
        )

    uid = str(datasource.get("uid") or "")
    name = str(datasource.get("name") or uid)

    # Bloqueio estrito de injeção em datasources de PRODUÇÃO de clientes (sandbox é permitido):
    folders = await grafana.list_folders()
    prod_client_uids = get_client_datasource_uids(folders, datasources, baseline_uid)

    if uid in prod_client_uids and not is_sandbox_datasource(name=name, uid=uid):
        logger.warning(
            "Tentativa de injeção de logs sintéticos em datasource de produção de cliente (%s, uid=%s) pelo usuário %s bloqueada.",
            name, uid, user.username,
        )
        sb_name = sandbox_datasource_name(name)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Data sources de produção de clientes não podem receber logs sintéticos. "
                f"Utilize o data source de sandbox correspondente ('{sb_name}')."
            ),
        )

    try:
        await asyncio.wait_for(
            grafana.loki_push(uid, body), timeout=PUSH_TIMEOUT_SECONDS
        )
    except (asyncio.TimeoutError, TimeoutError):
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="O Loki nÃ£o respondeu ao push dentro do tempo limite.",
        )
    except GrafanaError as exc:
        # A mensagem do GrafanaError Ã© genÃ©rica por design; o detalhe vai ao log.
        logger.warning(
            "Falha ao injetar logs sintÃ©ticos (datasource %s, usuÃ¡rio %s): %s",
            name, user.username, exc.message,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "O Loki rejeitou a injeÃ§Ã£o. Verifique se o serviÃ§o 'loki' estÃ¡ no ar "
                "e se as labels respeitam o formato esperado."
            ),
        )

    selector = stream_selector(stream)
    logql = f"{selector} | json"
    count_query = build_count_query(selector, payload.spread_seconds + 120)

    verified_count = 0
    for attempt in range(VERIFY_ATTEMPTS):
        try:
            result = await asyncio.wait_for(
                grafana.loki_instant_query(uid, count_query), timeout=VERIFY_TIMEOUT_SECONDS
            )
            verified_count = _extract_count(result)
        except (asyncio.TimeoutError, TimeoutError, GrafanaError):
            verified_count = 0
        if verified_count > 0:
            break
        if attempt < VERIFY_ATTEMPTS - 1:
            await asyncio.sleep(VERIFY_INTERVAL_SECONDS)

    verified = verified_count > 0
    logger.info(
        "Logs sintÃ©ticos injetados: %d linha(s), %d byte(s), datasource=%s, stream=%s, usuÃ¡rio=%s, verificado=%s",
        len(payload.lines), total_bytes, name, selector, user.username, verified,
    )

    message = (
        f"{len(payload.lines)} linha(s) injetada(s) no datasource '{name}'. O stream agora tem "
        f"{verified_count} entrada(s) consultÃ¡vel(is) na janela de verificaÃ§Ã£o."
        if verified
        else (
            f"{len(payload.lines)} linha(s) aceita(s) pelo Loki ({name}), mas a consulta de "
            "confirmaÃ§Ã£o ainda nÃ£o retornou entradas â€” aguarde alguns segundos e "
            "consulte novamente no Explore."
        )
    )

    return LokiSyntheticResponse(
        status="ok",
        datasource=name,
        datasource_uid=uid,
        stream=stream,
        lines_sent=len(payload.lines),
        bytes_sent=total_bytes,
        logql=logql,
        verified_count=verified_count,
        verified=verified,
        grafana_explore_url=build_explore_url(settings.grafana_public_url, logql, datasource=name),
        message=message,
    )
