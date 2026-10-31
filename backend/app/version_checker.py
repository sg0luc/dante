"""Verificação de versão e releases oficiais no GitHub para o D.A.N.T.E.

Consulta a API do GitHub com cache inteligente e comparação semântica de versões.
Não expõe segredos nem trava a aplicação em caso de indisponibilidade externa.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import logging
import re
import time
from typing import Any

import httpx

from .config import Settings, get_settings
from .schemas import AppVersionInfo

logger = logging.getLogger("hunter_portal.version_checker")


def parse_semver(version_str: str) -> tuple[int, int, int]:
    """Converte string de versão (ex: 'v1.2.3' ou '0.1.0') em tupla (major, minor, patch)."""
    clean = version_str.strip().lstrip("vV")
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", clean)
    if not m:
        return (0, 0, 0)
    major = int(m.group(1) or 0)
    minor = int(m.group(2) or 0)
    patch = int(m.group(3) or 0)
    return (major, minor, patch)


def is_newer_version(current_ver: str, candidate_ver: str) -> bool:
    """Retorna True se candidate_ver for estritamente mais recente que current_ver."""
    c_tuple = parse_semver(current_ver)
    cand_tuple = parse_semver(candidate_ver)
    return cand_tuple > c_tuple


class VersionChecker:
    """Gerencia a verificação de versões e releases com cache temporal em memória."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()
        self._cache: AppVersionInfo | None = None
        self._last_checked: float = 0.0

    async def _check_ghcr_packages_scope(self, client: httpx.AsyncClient) -> tuple[str, str | None]:
        """Verifica se o GITHUB_TOKEN possui o escopo necessário para baixar containers do GHCR."""
        if not self._settings.github_token:
            return ("public", None)
        token = self._settings.github_token.get_secret_value()
        repo = self._settings.github_repo.strip()
        user = repo.split("/")[0] if "/" in repo else "sg0luc"
        auth_header = "Basic " + base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
        try:
            r = await client.get(
                f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}-backend:pull",
                headers={"Authorization": auth_header},
            )
            if r.status_code == 200:
                bearer = r.json().get("token")
                r2 = await client.get(
                    f"https://ghcr.io/v2/{repo}-backend/tags/list",
                    headers={"Authorization": f"Bearer {bearer}"},
                )
                if r2.status_code in {401, 403}:
                    return (
                        "missing_packages_scope",
                        "O GITHUB_TOKEN possui acesso às releases, mas não possui permissão para baixar containers do GHCR (read:packages). Para atualizar pela GUI, gere um token com o escopo 'read:packages'.",
                    )
            return ("ok", None)
        except Exception:
            return ("unknown", None)

    async def check_version(self, force: bool = False) -> AppVersionInfo:
        """Verifica a versão atual e consulta a última release oficial no GitHub."""
        now = time.time()
        ttl = self._settings.update_check_ttl_seconds

        async with self._lock:
            if not force and self._cache is not None and (now - self._last_checked) < ttl:
                return self._cache

            current = self._settings.app_version
            repo = self._settings.github_repo.strip()
            url = f"https://api.github.com/repos/{repo}/releases/latest"

            headers = {
                "Accept": "application/vnd.github+json",
                "User-Agent": f"dante-portal/{current}",
            }
            if self._settings.github_token:
                headers["Authorization"] = f"Bearer {self._settings.github_token.get_secret_value()}"

            checked_at = datetime.now(timezone.utc).isoformat()

            try:
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.get(url, headers=headers)

                    if resp.status_code == 200:
                        data: dict[str, Any] = resp.json()
                        tag_name = str(data.get("tag_name") or "")
                        update_available = is_newer_version(current, tag_name)

                        ghcr_status, ghcr_message = await self._check_ghcr_packages_scope(client)

                        info = AppVersionInfo(
                            current_version=current,
                            latest_version=tag_name or None,
                            update_available=update_available,
                            release_url=data.get("html_url"),
                            release_name=data.get("name"),
                            published_at=data.get("published_at"),
                            release_notes=data.get("body"),
                            checked_at=checked_at,
                            error=None,
                            ghcr_status=ghcr_status,
                            ghcr_message=ghcr_message,
                        )
                        self._cache = info
                        self._last_checked = now
                        return info

                    if resp.status_code == 404:
                        logger.info("Nenhuma release encontrada no repositório %s.", repo)
                        err_msg = (
                            f"Nenhuma release oficial encontrada no repositório '{repo}'. "
                            "O repositório é público e não requer autenticação para consultar releases."
                        )
                        info = AppVersionInfo(
                            current_version=current,
                            latest_version=None,
                            update_available=False,
                            checked_at=checked_at,
                            error=err_msg,
                        )
                        self._cache = info
                        self._last_checked = now
                        return info

                    if resp.status_code == 401:
                        logger.warning("Token do GitHub não autorizado (HTTP 401) para %s.", repo)
                        info = AppVersionInfo(
                            current_version=current,
                            latest_version=None,
                            update_available=False,
                            checked_at=checked_at,
                            error="GITHUB_TOKEN inválido ou expirado. Gere um novo Personal Access Token no GitHub.",
                        )
                        self._cache = info
                        self._last_checked = now
                        return info

                    if resp.status_code == 403:
                        logger.warning("Rate limit ou acesso negado (HTTP 403) no GitHub para %s.", repo)
                        if self._cache:
                            return self._cache
                        return AppVersionInfo(
                            current_version=current,
                            latest_version=None,
                            update_available=False,
                            checked_at=checked_at,
                            error="Acesso negado ou limite de requisições do GitHub atingido. Verifique permissões do GITHUB_TOKEN.",
                        )

                    logger.warning("Resposta inesperada do GitHub (%d) ao checar releases.", resp.status_code)
                    if self._cache:
                        return self._cache
                    return AppVersionInfo(
                        current_version=current,
                        latest_version=None,
                        update_available=False,
                        checked_at=checked_at,
                        error=f"Falha ao consultar releases no GitHub (HTTP {resp.status_code}).",
                    )

            except httpx.RequestError as exc:
                logger.warning("Falha de rede ao verificar versão no GitHub: %s", exc)
                if self._cache:
                    return self._cache
                return AppVersionInfo(
                    current_version=current,
                    latest_version=None,
                    update_available=False,
                    checked_at=checked_at,
                    error="Não foi possível conectar ao GitHub para verificar atualizações.",
                )


_checker_instance: VersionChecker | None = None


def get_version_checker(settings: Settings | None = None) -> VersionChecker:
    """Retorna instância singleton do checador de versões."""
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = VersionChecker(settings or get_settings())
    return _checker_instance
