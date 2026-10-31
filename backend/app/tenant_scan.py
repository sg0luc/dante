"""Escaneamento de tecnologias por tenant (evidência real de telemetria no Loki).

Regra de negócio:
    Um cliente "possui" uma tecnologia quando existe telemetria dela no data
    source Loki **daquele cliente** (uid do data source == uid da pasta). O
    escaneamento roda, para cada tecnologia do catálogo, a query canônica de
    presença::

        sum(count_over_time({job="wazuh", ss_groups=~".*<tecnologia>.*"} | json [1h]))

    A query é montada exclusivamente no backend (``loki_presence``) e nunca é
    devolvida ao usuário.

Persistência:
    O resultado de cada escaneamento é um snapshot por cliente em
    ``TENANT_TECHNOLOGY_SCAN_STORE_PATH`` (padrão
    ``/data/tenant-technology-scan.json``), com escrita atômica. É desse snapshot
    que a página Tenants deriva a coluna de contagem — sem ele, cada render da
    tabela dispararia N consultas ao Loki (caro e instável).

Diferença em relação ao footprint:
    O footprint (``tenant_technologies.py``) é o inventário **declarado** usado
    na conformidade. O snapshot de escaneamento é **evidência de logs** e não
    altera o inventário: são fontes independentes, exibidas separadamente.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .grafana_client import GrafanaClient
from .loki_presence import check_technology_logs
from .technologies import Technology, TechnologyValidationError

logger = logging.getLogger("hunter_portal.tenant_scan")

# Janela padrão do escaneamento: 1h é o menor intervalo que já cobre o ciclo
# típico de ingestão (Vector -> Kafka -> Loki) sem transformar a consulta em um
# range caro sobre dias de retenção.
SCAN_WINDOW_SECONDS = 3600

# Paralelismo das consultas: o data source é único por cliente, então rajadas
# grandes competem pelo mesmo Loki. 6 é suficiente para latência baixa e evita
# saturar o servidor com todas as tecnologias do catálogo simultaneamente.
SCAN_CONCURRENCY = 6


class TenantScanStoreError(RuntimeError):
    """Falha ao ler/gravar o snapshot de escaneamento por cliente."""


class TenantScanStore:
    """Snapshot do último escaneamento de tecnologias por cliente."""

    def __init__(self, store_path: str | Path) -> None:
        self._path = Path(store_path)
        self._lock = threading.Lock()
        self._tenants: dict[str, dict[str, Any]] = {}
        self._loaded = False

    # --- carga / persistência -------------------------------------------------
    def _read_records(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TenantScanStoreError(
                f"Não foi possível ler o snapshot de escaneamento em "
                f"'{self._path}': {exc}"
            ) from exc

        tenants = raw.get("tenants") if isinstance(raw, dict) else None
        if not isinstance(tenants, dict):
            raise TenantScanStoreError(
                f"Formato inválido em '{self._path}': esperado objeto com a chave 'tenants'."
            )

        records: dict[str, dict[str, Any]] = {}
        for client_uid, entry in tenants.items():
            if not isinstance(entry, dict):
                logger.error(
                    "Snapshot de escaneamento ignorado (cliente %s): formato inválido",
                    client_uid,
                )
                continue
            technologies = entry.get("technologies")
            if not isinstance(technologies, list):
                technologies = []
            records[str(client_uid).strip()] = {
                "client_name": str(entry.get("client_name") or ""),
                "datasource": entry.get("datasource"),
                "datasource_uid": entry.get("datasource_uid"),
                "window_seconds": int(entry.get("window_seconds") or SCAN_WINDOW_SECONDS),
                "scanned_at": str(entry.get("scanned_at") or ""),
                "available": bool(entry.get("available", True)),
                "technologies": [
                    {
                        "slug": str(item.get("slug") or "").strip().lower(),
                        "name": str(item.get("name") or ""),
                        "icon": str(item.get("icon") or ""),
                        "description": str(item.get("description") or ""),
                        "logs_count": int(item.get("logs_count") or 0),
                        "found": bool(item.get("found")),
                    }
                    for item in technologies
                    if isinstance(item, dict) and str(item.get("slug") or "").strip()
                ],
            }
        return records

    def _load(self) -> None:
        if self._loaded:
            return
        self._tenants = self._read_records()
        self._loaded = True

    def _persist(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {
                "version": 1,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "tenants": self._tenants,
            },
            ensure_ascii=False,
            indent=2,
        )
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".tenant-scan-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._path)
        except OSError as exc:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise TenantScanStoreError(
                f"Falha ao gravar o snapshot de escaneamento em '{self._path}': {exc}"
            ) from exc

    # --- operações ------------------------------------------------------------
    def record_for(self, client_uid: str) -> dict[str, Any] | None:
        """Último snapshot de um cliente (``None`` se nunca escaneado)."""
        with self._lock:
            self._load()
            record = self._tenants.get(client_uid.strip())
            return json.loads(json.dumps(record)) if record is not None else None

    def set_record(self, client_uid: str, record: dict[str, Any]) -> dict[str, Any]:
        """Grava o snapshot de um cliente (substituição total)."""
        uid = client_uid.strip()
        if not uid:
            raise TenantScanStoreError("Cliente inválido para registrar escaneamento.")
        with self._lock:
            self._load()
            self._tenants[uid] = record
            self._persist()
            return json.loads(json.dumps(record))

    def counts_map(self) -> dict[str, int]:
        """Quantidade de tecnologias detectadas por cliente (para a tabela)."""
        with self._lock:
            self._load()
            return {
                uid: sum(1 for item in record.get("technologies", []) if item.get("found"))
                for uid, record in self._tenants.items()
            }

    def forget(self, client_uid: str) -> None:
        """Remove o snapshot de um cliente excluído (idempotente)."""
        uid = client_uid.strip()
        with self._lock:
            self._load()
            if uid not in self._tenants:
                return
            self._tenants.pop(uid, None)
            self._persist()


async def scan_tenant_technologies(
    grafana: GrafanaClient,
    technologies: Iterable[Technology],
    datasource_uid: str,
    window_seconds: int = SCAN_WINDOW_SECONDS,
) -> tuple[bool, list[dict[str, Any]]]:
    """Consulta o Loki do tenant para cada tecnologia do catálogo.

    Devolve ``(available, items)``. ``available=False`` quando o Loki não pôde
    ser consultado (data source ausente/indisponível) — nesse caso nenhuma
    tecnologia é marcada como ausente, porque ausência de resposta não é prova de
    ausência de logs.
    """
    catalog = list(technologies)
    if not catalog:
        return True, []

    semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def probe(tech: Technology) -> dict[str, Any]:
        async with semaphore:
            try:
                presence = await check_technology_logs(
                    grafana,
                    ss_groups_regex=tech.ss_groups_regex,
                    job=tech.job,
                    window_seconds=window_seconds,
                    # Escaneia o data source Loki do próprio cliente; sem ele a
                    # contagem misturaria telemetria de outros tenants.
                    datasource_uid=datasource_uid,
                )
            except TechnologyValidationError as exc:
                logger.warning(
                    "Tecnologia %s ignorada no escaneamento (recorte inválido): %s",
                    tech.slug,
                    exc,
                )
                return {
                    "slug": tech.slug,
                    "name": tech.name,
                    "icon": tech.icon,
                    "description": tech.description,
                    "logs_count": 0,
                    "found": False,
                }
            return {
                "slug": tech.slug,
                "name": tech.name,
                "icon": tech.icon,
                "description": tech.description,
                "logs_count": presence.count if presence.available else 0,
                "found": bool(presence.available and presence.found),
                "available": presence.available,
            }

    items = list(await asyncio.gather(*(probe(tech) for tech in catalog)))

    # O escaneamento só é considerado válido quando ao menos uma consulta foi
    # respondida pelo Loki; se todas falharam, o snapshot não pode afirmar que o
    # cliente "não tem" nenhuma tecnologia.
    available = any(item.get("available", True) for item in items)
    for item in items:
        item.pop("available", None)
    return available, sorted(items, key=lambda item: item["name"].lower())


__all__ = [
    "SCAN_CONCURRENCY",
    "SCAN_WINDOW_SECONDS",
    "TenantScanStore",
    "TenantScanStoreError",
    "scan_tenant_technologies",
]
