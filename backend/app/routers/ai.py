"""Rotas da API para gerenciamento das configurações de IA e testes de conectividade."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from ..ai import AIService
from ..config import Settings
from ..schemas import (
    AIClearCacheResponse,
    AISettingsPublicResponse,
    AISettingsUpdateRequest,
    AITestConnectionRequest,
    AITestConnectionResponse,
)
from ..security import Session, get_current_user, require_csrf_header
from ..system_settings_store import SystemSettingsStore
from ..technology_store import get_system_settings_store
from .deps import get_app_settings

router = APIRouter(prefix="/ai", tags=["ai"])


def get_ai_service_dep(
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    settings: Settings = Depends(get_app_settings),
) -> AIService:
    """Injeta a instância do AIService para as rotas."""
    return AIService(
        sys_settings=sys_settings,
        cache_path=settings.curation_ai_cache_path,
        settings=settings,
    )


@router.get("/settings", response_model=AISettingsPublicResponse)
async def get_ai_settings(
    ai_service: AIService = Depends(get_ai_service_dep),
    _user: Session = Depends(get_current_user),
) -> AISettingsPublicResponse:
    """Retorna as configurações atuais de IA com a chave de API mascarada."""
    return ai_service.get_public_settings()


@router.post(
    "/settings",
    response_model=AISettingsPublicResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_csrf_header)],
)
@router.put(
    "/settings",
    response_model=AISettingsPublicResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_csrf_header)],
)
async def update_ai_settings(
    req: AISettingsUpdateRequest,
    ai_service: AIService = Depends(get_ai_service_dep),
    _user: Session = Depends(get_current_user),
) -> AISettingsPublicResponse:
    """Atualiza as configurações do provedor de IA e salva em /data/system-settings.json."""
    return ai_service.update_settings(req)


@router.post(
    "/test-connection",
    response_model=AITestConnectionResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_csrf_header)],
)
async def test_ai_connection(
    req: AITestConnectionRequest,
    ai_service: AIService = Depends(get_ai_service_dep),
    _user: Session = Depends(get_current_user),
) -> AITestConnectionResponse:
    """Testa a conectividade com o modelo de IA especificado em tempo real."""
    return await ai_service.test_connection(req)


@router.post(
    "/clear-cache",
    response_model=AIClearCacheResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_csrf_header)],
)
async def clear_ai_cache(
    ai_service: AIService = Depends(get_ai_service_dep),
    _user: Session = Depends(get_current_user),
) -> AIClearCacheResponse:
    """Limpa o cache persistido de regras traduzidas por IA."""
    return ai_service.clear_cache()

