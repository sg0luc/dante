"""Ponto de entrada da aplicação FastAPI.

Execução (dentro do contêiner):
    uvicorn app.main:app --host 0.0.0.0 --port 8000

Rotas (todas sob /api):
    GET  /api/health          liveness (sem autenticação)
    GET  /api/health/ready    readiness (sem autenticação; só booleanos)
    POST /api/auth/login      login (requer cabeçalho anti-CSRF)
    POST /api/auth/logout     logout (requer cabeçalho anti-CSRF)
    GET  /api/auth/me         usuário atual
    GET  /api/config          configurações para a UI
    GET  /api/rules           regras de detecção + estado
    GET  /api/rules/{uid}     detalhe de uma regra
    GET  /api/alerts          instâncias de alerta atuais
    GET  /api/silences        silences
    GET  /api/curation        curadoria de regras de detecção (fontes + candidatos)
    POST /api/curation/run    executa ciclo de curadoria
    GET  /api/loki/datasources datasources Loki (internos vs clientes)
    GET  /api/loki/status     estado do datasource Loki (laboratorio de logs)
    POST /api/loki/logs       injeta linhas JSON ficticias no Loki
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from . import __version__
from .config import get_settings
from .curation import curation_daily_scheduler_loop
from .grafana_client import GrafanaClient, GrafanaError
from .routers import ai, auth, curation, homologation, loki, monitoring, system, technologies
from .security import LoginRateLimiter, SessionStore
from .technology_store import (
    get_curation_store,
    get_system_settings_store,
    get_technology_store,
    get_tenant_scan_store,
    get_tenant_technology_store,
)

logger = logging.getLogger("hunter_portal")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    # Evita logar URLs/cabeçalhos de cada requisição do httpx em nível INFO.
    logging.getLogger("httpx").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Cria recursos compartilhados na inicialização e libera no desligamento."""
    settings = get_settings()
    app.state.settings = settings
    app.state.grafana = GrafanaClient(settings)
    app.state.sessions = SessionStore(ttl_seconds=settings.session_ttl_minutes * 60)
    app.state.login_limiter = LoginRateLimiter(
        max_attempts=settings.login_max_attempts,
        window_seconds=settings.login_window_seconds,
    )
    # Catálogo de tecnologias (ss_groups -> datasource): carrega/semeia no startup.
    app.state.technologies = get_technology_store()
    app.state.curation = get_curation_store()

    # Agendador periódico diário da Curadoria de Regras (todos os dias às 08h00).
    scheduler_task = asyncio.create_task(
        curation_daily_scheduler_loop(
            settings=settings,
            grafana=app.state.grafana,
            technology_store=app.state.technologies,
            footprint_store=get_tenant_technology_store(),
            scan_store=get_tenant_scan_store(),
            sys_settings=get_system_settings_store(),
            curation_store=app.state.curation,
        )
    )
    app.state.curation_scheduler_task = scheduler_task

    logger.info("Grafana Hunter Portal %s iniciado (Grafana: %s)", __version__, settings.grafana_url)
    if not settings.cookie_secure:
        logger.warning("COOKIE_SECURE=false: use apenas em desenvolvimento.")
    try:
        yield
    finally:
        scheduler_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await scheduler_task
        await app.state.grafana.aclose()


async def _grafana_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Converte GrafanaError em resposta JSON com mensagem segura."""
    assert isinstance(exc, GrafanaError)
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


def create_app() -> FastAPI:
    settings = get_settings()
    _configure_logging(settings.log_level)

    docs_enabled = settings.enable_api_docs
    app = FastAPI(
        title="Grafana Hunter Portal API",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs_enabled else None,
    )

    app.add_exception_handler(GrafanaError, _grafana_error_handler)

    @app.middleware("http")
    async def security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Cabeçalhos defensivos em todas as respostas da API."""
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app.include_router(system.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    app.include_router(monitoring.router, prefix="/api")
    app.include_router(technologies.router, prefix="/api")
    app.include_router(homologation.router, prefix="/api")
    app.include_router(curation.router, prefix="/api")
    app.include_router(ai.router, prefix="/api")
    app.include_router(loki.router, prefix="/api")
    return app


app = create_app()
