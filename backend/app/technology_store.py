"""Dependência compartilhada do catálogo de tecnologias.

O ``TechnologyStore`` é único por processo (lru_cache) e aponta para o arquivo
definido em ``TECHNOLOGIES_STORE_PATH`` (por padrão ``/data/technologies.json``,
montado como volume no Docker Compose). Quando o arquivo não existe, ele é
semeado a partir do catálogo embarcado ``app/data/technologies.seed.json``.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from .config import get_settings
from .curation import CurationStore
from .synthetic_alerts import SyntheticAlertsStore
from .system_settings_store import SystemSettingsStore
from .technologies import TechnologyStore
from .tenant_scan import TenantScanStore
from .tenant_technologies import TenantTechnologyStore

logger = logging.getLogger("hunter_portal.technologies")

SEED_PATH = Path(__file__).parent / "data" / "technologies.seed.json"


@lru_cache(maxsize=1)
def get_technology_store() -> TechnologyStore:
    """Retorna a instância única do catálogo de tecnologias."""
    settings = get_settings()
    store = TechnologyStore(settings.technologies_store_path, SEED_PATH)
    # Força a carga inicial para falhar cedo (e semear a base) no startup.
    count = len(store.list_all())
    logger.info(
        "Catálogo de tecnologias carregado (%d registros) de %s",
        count,
        settings.technologies_store_path,
    )
    return store


@lru_cache(maxsize=1)
def get_tenant_technology_store() -> TenantTechnologyStore:
    """Retorna a instância única do inventário de tecnologias por cliente."""
    settings = get_settings()
    store = TenantTechnologyStore(settings.tenant_technologies_store_path)
    logger.info(
        "Inventário de tecnologias por cliente em %s",
        settings.tenant_technologies_store_path,
    )
    return store


@lru_cache(maxsize=1)
def get_tenant_scan_store() -> TenantScanStore:
    """Retorna a instância única do snapshot de escaneamento por cliente."""
    settings = get_settings()
    store = TenantScanStore(settings.tenant_scan_store_path)
    logger.info(
        "Snapshot de escaneamento de tecnologias por cliente em %s",
        settings.tenant_scan_store_path,
    )
    return store


@lru_cache(maxsize=1)
def get_system_settings_store() -> SystemSettingsStore:
    """Retorna a instância única de configurações operacionais persistidas do portal."""
    settings = get_settings()
    store = SystemSettingsStore(settings.system_settings_store_path)
    logger.info(
        "Configurações do sistema gerenciadas em %s",
        settings.system_settings_store_path,
    )
    return store


@lru_cache(maxsize=1)
def get_synthetic_alerts_store() -> SyntheticAlertsStore:
    """Retorna a instância única de armazenamento de alertas fictícios."""
    settings = get_settings()
    store = SyntheticAlertsStore(settings.synthetic_alerts_store_path)
    logger.info(
        "Armazenamento de alertas fictícios gerenciado em %s",
        settings.synthetic_alerts_store_path,
    )
    return store


@lru_cache(maxsize=1)
def get_curation_store() -> CurationStore:
    """Retorna a instância única do armazenamento de curadoria de regras."""
    settings = get_settings()
    store = CurationStore(settings.curation_store_path)
    logger.info(
        "Armazenamento de curadoria de regras gerenciado em %s",
        settings.curation_store_path,
    )
    return store
