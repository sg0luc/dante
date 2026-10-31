"""Dependências compartilhadas entre os routers."""

from __future__ import annotations

from fastapi import Request

from ..config import Settings
from ..grafana_client import GrafanaClient
from ..upgrade_manager import UpgradeManager, get_upgrade_manager
from ..version_checker import VersionChecker, get_version_checker


def get_grafana(request: Request) -> GrafanaClient:
    """Cliente do Grafana criado no ciclo de vida da aplicação."""
    return request.app.state.grafana


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_version_checker_dep(request: Request) -> VersionChecker:
    """Instância do checador de versão e releases."""
    if not hasattr(request.app.state, "version_checker"):
        request.app.state.version_checker = get_version_checker(request.app.state.settings)
    return request.app.state.version_checker


def get_upgrade_manager_dep(request: Request) -> UpgradeManager:
    """Instância do gerenciador de upgrades in-app."""
    if not hasattr(request.app.state, "upgrade_manager"):
        request.app.state.upgrade_manager = get_upgrade_manager(request.app.state.settings)
    return request.app.state.upgrade_manager


