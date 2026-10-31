"""Saúde do serviço e configuração pública para o frontend."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..config import Settings
from ..grafana_client import GrafanaClient, GrafanaError
from ..schemas import (
    AppVersionInfo,
    BaselineFolderConfig,
    HealthStatus,
    PortalConfig,
    ReadinessStatus,
    SetBaselineFolderRequest,
    UpgradeStatusResponse,
    UpgradeTriggerRequest,
    UpgradeTriggerResponse,
)
from ..security import Session, get_current_user, require_csrf_header
from ..system_settings_store import SystemSettingsStore
from ..technology_store import get_system_settings_store
from ..upgrade_manager import UpgradeManager
from ..version_checker import VersionChecker
from .deps import (
    get_app_settings,
    get_grafana,
    get_upgrade_manager_dep,
    get_version_checker_dep,
)

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthStatus)
async def health(settings: Settings = Depends(get_app_settings)) -> HealthStatus:
    """Liveness: o processo está respondendo (usado pelo healthcheck do Docker e polling de upgrade)."""
    return HealthStatus(status="ok", version=settings.app_version)


@router.get("/health/ready", response_model=ReadinessStatus)
async def readiness(grafana: GrafanaClient = Depends(get_grafana)) -> ReadinessStatus:
    """Readiness: o Grafana está acessível e há token configurado.

    Expõe apenas booleanos (nenhum detalhe interno).
    """
    reachable = await grafana.is_healthy()
    has_token = grafana.has_token()
    return ReadinessStatus(
        status="ok" if reachable and has_token else "degraded",
        grafana_reachable=reachable,
        grafana_token_configured=has_token,
    )


@router.get("/config", response_model=PortalConfig)
async def portal_config(
    settings: Settings = Depends(get_app_settings),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    _user: Session = Depends(get_current_user),
) -> PortalConfig:
    """Configurações não sensíveis usadas pela interface."""
    return PortalConfig(
        grafana_public_url=settings.grafana_public_url,
        refresh_interval_seconds=settings.refresh_interval_seconds,
        is_external_grafana=settings.is_external_grafana,
        evaluation_group_optional=settings.is_external_grafana,
        baseline_folder_uid=sys_settings.get_baseline_folder_uid(),
        app_version=settings.app_version,
    )


@router.get("/system/version", response_model=AppVersionInfo)
@router.get("/version", response_model=AppVersionInfo)
async def get_version_status(
    force: bool = False,
    checker: VersionChecker = Depends(get_version_checker_dep),
    _user: Session = Depends(get_current_user),
) -> AppVersionInfo:
    """Retorna a versão atual do D.A.N.T.E. e checa se há nova release oficial no GitHub."""
    return await checker.check_version(force=force)


@router.post(
    "/system/version/check",
    response_model=AppVersionInfo,
    dependencies=[Depends(require_csrf_header)],
)
async def check_for_updates_now(
    checker: VersionChecker = Depends(get_version_checker_dep),
    _user: Session = Depends(get_current_user),
) -> AppVersionInfo:
    """Força verificação imediata de atualizações no GitHub (invalida cache)."""
    return await checker.check_version(force=True)


@router.post(
    "/system/upgrade",
    response_model=UpgradeTriggerResponse,
    dependencies=[Depends(require_csrf_header)],
)
async def trigger_system_upgrade(
    payload: UpgradeTriggerRequest | None = None,
    manager: UpgradeManager = Depends(get_upgrade_manager_dep),
    _user: Session = Depends(get_current_user),
) -> UpgradeTriggerResponse:
    """Dispara a atualização dos containers do portal via Watchtower."""
    target_ver = payload.target_version if payload else None
    return await manager.trigger_upgrade(target_version=target_ver)


@router.get("/system/upgrade/status", response_model=UpgradeStatusResponse)
async def get_system_upgrade_status(
    manager: UpgradeManager = Depends(get_upgrade_manager_dep),
    _user: Session = Depends(get_current_user),
) -> UpgradeStatusResponse:
    """Retorna o status persistido da atualização do sistema."""
    return await manager.get_upgrade_status()


@router.get("/baseline/folder", response_model=BaselineFolderConfig)
async def get_baseline_folder_config(
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    _user: Session = Depends(get_current_user),
) -> BaselineFolderConfig:
    """Retorna a pasta do Grafana arbitrada para atuar como baseline global."""
    folder_uid = sys_settings.get_baseline_folder_uid()
    folder_title = folder_uid
    try:
        folders = await grafana.list_folders()
        for f in folders:
            if str(f.get("uid") or "") == folder_uid:
                folder_title = str(f.get("title") or folder_uid)
                break
    except Exception:
        pass

    return BaselineFolderConfig(
        baseline_folder_uid=folder_uid,
        baseline_folder_title=folder_title,
    )


@router.put(
    "/baseline/folder",
    response_model=BaselineFolderConfig,
    dependencies=[Depends(require_csrf_header)],
)
async def set_baseline_folder_config(
    payload: SetBaselineFolderRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    _user: Session = Depends(get_current_user),
) -> BaselineFolderConfig:
    """Arbitra qual pasta do Grafana representará o baseline global."""
    target_uid = payload.baseline_folder_uid.strip()
    if not target_uid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="UID de pasta inválido.",
        )

    try:
        folders = await grafana.list_folders()
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    folder = next((f for f in folders if str(f.get("uid") or "") == target_uid), None)
    if not folder:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"A pasta com UID '{target_uid}' não foi encontrada no Grafana.",
        )

    folder_title = str(folder.get("title") or target_uid)
    sys_settings.set_baseline_folder_uid(target_uid)

    return BaselineFolderConfig(
        baseline_folder_uid=target_uid,
        baseline_folder_title=folder_title,
    )
