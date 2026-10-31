"""Módulo de gerenciamento e geração de alertas fictícios/sintéticos do D.A.N.T.E.

Permite gerar uma sequência cronológica de alertas fictícios a partir de regras reais
para testes de visualização, validação de histogramas temporais e homologação.
"""

from __future__ import annotations

import json
import logging
import math
import os
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .schemas import AlertInstance

logger = logging.getLogger("dante.synthetic_alerts")

# Nomes de máquinas / ativos simulados para dar variedade realista aos alertas agrupados
_SAMPLE_HOSTS = [
    "srv-app-prod-01",
    "srv-db-cluster-02",
    "dc-primary-ad-01",
    "ws-finance-14",
    "gw-fortigate-edge",
    "srv-k8s-worker-03",
    "srv-vpn-gateway",
    "ws-dev-workstation-09",
    "srv-fileshare-corp",
    "ws-rh-workstation-02",
]


class SyntheticAlertsStore:
    """Armazena alertas fictícios em memória com persistência em arquivo JSON."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self._path = Path(store_path) if store_path else None
        self._alerts: list[AlertInstance] = []
        self._load()

    def _load(self) -> None:
        if not self._path or not self._path.exists():
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                raw_list = json.load(f)
            if isinstance(raw_list, list):
                self._alerts = [
                    AlertInstance(**item) for item in raw_list if isinstance(item, dict)
                ]
                logger.info(
                    "Carregados %d alertas fictícios de %s",
                    len(self._alerts),
                    self._path,
                )
        except Exception as exc:
            logger.warning(
                "Falha ao carregar alertas fictícios de %s: %s", self._path, exc
            )

    def _save(self) -> None:
        if not self._path:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(
                    [a.model_dump() for a in self._alerts],
                    f,
                    indent=2,
                    ensure_ascii=False,
                )
        except Exception as exc:
            logger.warning("Falha ao salvar alertas fictícios em %s: %s", self._path, exc)

    def list_alerts(self) -> list[AlertInstance]:
        return list(self._alerts)

    def clear(self) -> int:
        count = len(self._alerts)
        self._alerts = []
        self._save()
        return count

    def generate_chronological_sequence(
        self,
        rule: dict[str, Any],
        count: int = 15,
    ) -> list[AlertInstance]:
        """Gera uma sequência de alertas fictícios distribuídos cronologicamente nos últimos 7 dias.

        Garante distribuição homogênea cobrindo janelas comuns:
          - < 1 hora (ex: 15m, 40m)
          - 1h a 6h (ex: 2h, 4.5h)
          - 6h a 12h (ex: 8h, 10.5h)
          - 12h a 24h (ex: 16h, 21h)
          - 24h a 72h / 3 dias (ex: 32h, 48h, 60h)
          - 3 dias a 7 dias (ex: 85h, 115h, 145h)
        """
        rule_uid = str(rule.get("uid") or "ghp-det-fictitious")
        rule_title = str(rule.get("title") or "Alerta Fictício de Detecção")
        folder_uid = str(rule.get("folderUID") or "global")
        rule_labels = rule.get("labels") or {}
        rule_annotations = rule.get("annotations") or {}

        now_epoch = datetime.now(timezone.utc).timestamp()

        # Janelas de offset em segundos para espalhar uniformemente ao longo de 7 dias (604800s)
        # 1h: 900s (15m), 2400s (40m)
        # 6h: 7200s (2h), 16200s (4.5h)
        # 12h: 28800s (8h), 37800s (10.5h)
        # 24h: 57600s (16h), 75600s (21h)
        # 3d: 115200s (32h), 172800s (48h), 220000s (61h)
        # 7d: 300000s (~3.5d), 400000s (~4.6d), 500000s (~5.8d), 580000s (~6.7d)
        base_offsets_seconds = [
            900,      # ~15 min
            2400,     # ~40 min
            7200,     # ~2 horas
            16200,    # ~4.5 horas
            28800,    # ~8 horas
            37800,    # ~10.5 horas
            57600,    # ~16 horas
            75600,    # ~21 horas
            115200,   # ~32 horas (1.3 dias)
            172800,   # ~48 horas (2 dias)
            220000,   # ~61 horas (2.5 dias)
            300000,   # ~3.5 dias
            400000,   # ~4.6 dias
            500000,   # ~5.8 dias
            580000,   # ~6.7 dias
        ]

        if count != len(base_offsets_seconds):
            # Interpolação linear se contagem diferente de 15
            step = 580000.0 / max(count - 1, 1)
            base_offsets_seconds = [int(i * step) + 900 for i in range(count)]

        generated: list[AlertInstance] = []

        for i, offset in enumerate(base_offsets_seconds):
            alert_epoch = now_epoch - offset
            alert_dt = datetime.fromtimestamp(alert_epoch, tz=timezone.utc)
            alert_iso = alert_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

            # 75% ativos, 25% suprimidos para demonstrar histograma empilhado
            is_suppressed = (i % 4 == 3)
            state = "suppressed" if is_suppressed else "active"
            silenced_by = [f"silence-mock-{rule_uid[:8]}"] if is_suppressed else []

            host = _SAMPLE_HOSTS[i % len(_SAMPLE_HOSTS)]

            labels = {
                "alertname": rule_title,
                "rule_uid": rule_uid,
                "grafana_folder": folder_uid,
                "synthetic": "true",
                "synthetic_source": "portal_mock",
                "host": host,
            }
            # Herda metadados de tecnologia, severidade e mitre da regra base
            for k in ("technology", "technology_name", "severity", "mitre_tactic", "mitre_technique", "scope", "client", "ss_groups"):
                if k in rule_labels:
                    labels[k] = str(rule_labels[k])

            annotations = {
                "summary": f"{rule_title} disparado em {host}",
                "description": f"Instância fictícia #{i+1} gerada cronologicamente a partir da regra {rule_uid}.",
            }
            if "runbook_url" in rule_annotations:
                annotations["runbook_url"] = str(rule_annotations["runbook_url"])

            fingerprint = f"syn-{rule_uid[:10]}-{i+1}-{uuid.uuid4().hex[:6]}"

            instance = AlertInstance(
                fingerprint=fingerprint,
                alertname=rule_title,
                rule_uid=rule_uid,
                state=state,
                silenced_by=silenced_by,
                inhibited_by=[],
                labels=labels,
                annotations=annotations,
                starts_at=alert_iso,
                updated_at=alert_iso,
            )
            generated.append(instance)

        # Substitui a lista de alertas sintéticos atual pela nova sequência
        self._alerts = generated
        self._save()
        logger.info(
            "Gerada sequência de %d alertas fictícios para regra %s (%s)",
            len(generated),
            rule_uid,
            rule_title,
        )
        return list(self._alerts)

