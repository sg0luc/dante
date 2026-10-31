"""Escopo de tecnologias por cliente (footprint) — base persistente.

Regra de negócio:
    A conformidade ao baseline só faz sentido para as tecnologias que o cliente
    realmente possui no SIEM. Se o cliente não tem o ``ss_groups`` do Office365
    integrado ao Wazuh/Loki, ele não pode ser penalizado por não ter replicado as
    regras de Office365 da pasta ``global``.

O footprint de um cliente é a **união** de duas evidências:

    1. ``derived``  — tecnologias resolvidas a partir das regras de detecção que
       já existem na pasta do cliente (label ``technology`` ou recorte de
       ``ss_groups`` da query). Determinístico e sempre disponível.
    2. ``declared`` — inventário declarado pelo operador nesta base. Existe para
       cobrir o caso em que a tecnologia está integrada mas ainda não há regra
       na pasta: sem o inventário, a ausência de regra esconderia a lacuna (a
       tecnologia sairia do denominador em vez de puxar o percentual para baixo).

A base é um JSON com escrita atômica, no mesmo diretório persistente do catálogo
de tecnologias (``TENANT_TECHNOLOGIES_STORE_PATH``, por padrão
``/data/tenant-technologies.json``).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger("hunter_portal.tenant_technologies")

SLUG_RE = r"^[a-z0-9_]{2,32}$"


class TenantTechnologyStoreError(RuntimeError):
    """Falha ao ler/gravar o inventário de tecnologias por cliente."""


class TenantTechnologyStore:
    """Inventário declarado de tecnologias por cliente (pasta do Grafana)."""

    def __init__(self, store_path: str | Path) -> None:
        self._path = Path(store_path)
        self._lock = threading.Lock()
        self._tenants: dict[str, list[str]] = {}
        self._loaded = False

    # --- carga / persistência -------------------------------------------------
    def _read_records(self) -> dict[str, list[str]]:
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TenantTechnologyStoreError(
                f"Não foi possível ler o inventário de tecnologias por cliente em "
                f"'{self._path}': {exc}"
            ) from exc

        tenants = raw.get("tenants") if isinstance(raw, dict) else None
        if tenants is None:
            tenants = raw if isinstance(raw, dict) else {}
        if not isinstance(tenants, dict):
            raise TenantTechnologyStoreError(
                f"Formato inválido em '{self._path}': esperado objeto com a chave 'tenants'."
            )

        records: dict[str, list[str]] = {}
        for client_uid, entry in tenants.items():
            if isinstance(entry, dict):
                values = entry.get("technologies")
            else:
                values = entry
            if not isinstance(values, list):
                logger.error(
                    "Entrada de footprint ignorada (cliente %s): formato inválido", client_uid
                )
                continue
            slugs = sorted(
                {
                    str(value).strip().lower()
                    for value in values
                    if isinstance(value, str) and value.strip()
                }
            )
            records[str(client_uid).strip()] = slugs
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
                "tenants": {
                    client_uid: {
                        "technologies": slugs,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    }
                    for client_uid, slugs in self._tenants.items()
                },
            },
            ensure_ascii=False,
            indent=2,
        )
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent), prefix=".tenant-tech-", suffix=".tmp"
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
            raise TenantTechnologyStoreError(
                f"Falha ao gravar o inventário de tecnologias por cliente em "
                f"'{self._path}': {exc}"
            ) from exc

    # --- operações ------------------------------------------------------------
    def declared_map(self) -> dict[str, list[str]]:
        """Cópia do inventário declarado (``client_uid`` -> slugs)."""
        with self._lock:
            self._load()
            return {uid: list(slugs) for uid, slugs in self._tenants.items()}

    def declared_for(self, client_uid: str) -> list[str]:
        with self._lock:
            self._load()
            return list(self._tenants.get(client_uid.strip(), []))

    def set_declared(self, client_uid: str, slugs: Iterable[str]) -> list[str]:
        """Substitui o inventário declarado de um cliente."""
        uid = client_uid.strip()
        if not uid:
            raise TenantTechnologyStoreError("Cliente inválido para declarar tecnologias.")
        normalized = sorted(
            {
                str(slug).strip().lower()
                for slug in slugs
                if isinstance(slug, str) and str(slug).strip()
            }
        )
        with self._lock:
            self._load()
            if normalized:
                self._tenants[uid] = normalized
            else:
                self._tenants.pop(uid, None)
            self._persist()
            return list(normalized)

    def forget(self, client_uid: str) -> None:
        """Remove o inventário de um cliente excluído (idempotente)."""
        uid = client_uid.strip()
        with self._lock:
            self._load()
            if uid not in self._tenants:
                return
            self._tenants.pop(uid, None)
            self._persist()


__all__: list[str] = ["TenantTechnologyStore", "TenantTechnologyStoreError"]
