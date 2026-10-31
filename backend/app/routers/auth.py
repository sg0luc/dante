"""Login, logout e sessão atual."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..config import Settings
from ..schemas import LoginRequest, UserInfo
from ..security import (
    SESSION_COOKIE,
    Session,
    client_ip,
    get_current_user,
    require_csrf_header,
    verify_credentials,
)
from .deps import get_app_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=UserInfo, dependencies=[Depends(require_csrf_header)])
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    settings: Settings = Depends(get_app_settings),
) -> UserInfo:
    """Autentica o usuário e define o cookie de sessão."""
    ip = client_ip(request)
    limiter = request.app.state.login_limiter

    if limiter.is_blocked(ip):
        logger.warning("Login bloqueado por excesso de tentativas: ip=%s", ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Muitas tentativas de login. Aguarde alguns minutos e tente novamente.",
        )

    valid = verify_credentials(
        payload.username,
        payload.password,
        settings.portal_admin_user,
        settings.portal_admin_password.get_secret_value(),
    )
    if not valid:
        limiter.register_failure(ip)
        # %r escapa quebras de linha (evita log injection). Senha nunca é logada.
        logger.warning("Falha de login: usuario=%r ip=%s", payload.username[:64], ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário ou senha inválidos"
        )

    limiter.reset(ip)
    token = request.app.state.sessions.create(payload.username)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    logger.info("Login bem-sucedido: usuario=%r ip=%s", payload.username[:64], ip)
    return UserInfo(username=payload.username)


@router.post(
    "/logout", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_csrf_header)]
)
async def logout(request: Request) -> Response:
    """Revoga a sessão no servidor e remove o cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        request.app.state.sessions.revoke(token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="strict")
    return response


@router.get("/me", response_model=UserInfo)
async def me(user: Session = Depends(get_current_user)) -> UserInfo:
    """Retorna o usuário da sessão atual (401 se não autenticado)."""
    return UserInfo(username=user.username)
