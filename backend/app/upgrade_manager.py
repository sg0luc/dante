"""Gerenciador de atualização in-app da stack Docker do D.A.N.T.E.

Orquestra o disparo da atualização via API HTTP segura do Watchtower (sidecar)
e persiste o estado de progresso para a interface web. Não requer privilégios
de root nem montagem do docker.sock no processo do backend.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any

import httpx

from .config import Settings, get_settings
from .schemas import UpgradeStatusResponse, UpgradeTriggerResponse
from .version_checker import is_newer_version

logger = logging.getLogger("hunter_portal.upgrade_manager")


class UpgradeManager:
    """Orquestra atualização segura de containers e persistência de status."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()
        data_dir = Path("/data")
        if data_dir.exists() and data_dir.is_dir():
            self._state_file = data_dir / "system_upgrade.json"
        else:
            self._state_file = Path("/tmp/system_upgrade.json")
        self._sync_docker_config()

    def _sync_docker_config(self) -> None:
        """Gera ou atualiza /data/config.json com auth base64 para o GHCR se houver token."""
        if not self._settings.github_token:
            return
        token = self._settings.github_token.get_secret_value().strip()
        if not token:
            return
        repo = self._settings.github_repo.strip()
        user = repo.split("/")[0] if "/" in repo else "sg0luc"
        auth_str = base64.b64encode(f"{user}:{token}".encode("utf-8")).decode("utf-8")
        docker_config = {
            "auths": {
                "ghcr.io": {
                    "auth": auth_str
                }
            }
        }
        for target_dir in (Path("/data"), Path("/tmp")):
            if target_dir.exists() and target_dir.is_dir():
                try:
                    (target_dir / "config.json").write_text(
                        json.dumps(docker_config, indent=2), encoding="utf-8"
                    )
                    logger.info("Credenciais do GHCR sincronizadas em %s/config.json.", target_dir)
                    break
                except Exception as exc:
                    logger.warning("Falha ao gravar config.json em %s: %s", target_dir, exc)

    def _read_state(self) -> dict[str, Any]:
        if not self._state_file.exists():
            return {}
        try:
            return json.loads(self._state_file.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Falha ao ler %s: %s", self._state_file, exc)
            return {}

    def _write_state(self, state: dict[str, Any]) -> None:
        try:
            self._state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Falha ao salvar %s: %s", self._state_file, exc)

    async def trigger_upgrade(self, target_version: str | None = None) -> UpgradeTriggerResponse:
        """Dispara a atualização dos containers do portal via Watchtower."""
        now_iso = datetime.now(timezone.utc).isoformat()
        current_ver = self._settings.app_version
        self._sync_docker_config()

        async with self._lock:
            # Registra intenção de upgrade
            state = {
                "status": "upgrading",
                "started_at": now_iso,
                "target_version": target_version or "latest",
                "previous_version": current_ver,
                "message": "Atualização em andamento.",
            }
            self._write_state(state)

            updater_url = f"{self._settings.updater_url.rstrip('/')}/v1/update"
            token = self._settings.updater_token.get_secret_value() if self._settings.updater_token else ""
            headers = {"Authorization": f"Bearer {token}"} if token else {}

            try:
                # O Watchtower pode recriar os containers imediatamente, o que pode
                # derrubar o socket HTTP antes da resposta 200 completa.
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(updater_url, headers=headers)

                if resp.status_code in {200, 202, 204}:
                    logger.info("Comando de upgrade aceito pelo Watchtower (%s).", resp.status_code)
                    return UpgradeTriggerResponse(
                        status="upgrading",
                        message="Atualização iniciada com sucesso. Os containers estão sendo atualizados via Watchtower.",
                        target_version=target_version,
                        started_at=now_iso,
                    )

                logger.warning("Watchtower retornou HTTP %d ao solicitar update.", resp.status_code)
                state["status"] = "failed"
                state["message"] = f"Watchtower recusou atualização (HTTP {resp.status_code})."
                self._write_state(state)
                return UpgradeTriggerResponse(
                    status="error",
                    message=f"Falha ao acionar serviço de atualização (HTTP {resp.status_code}).",
                    target_version=target_version,
                    started_at=now_iso,
                )

            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                # Se o Watchtower já estava recriando o próprio backend ou indisponível
                logger.info("Comunicação com updater encerrou ou serviço inacessível: %s", exc)
                # Verifica se o Watchtower nem sequer subiu
                if isinstance(exc, httpx.ConnectError):
                    state["status"] = "manual_action_required"
                    state["message"] = "Serviço de atualização automática (Watchtower) não acessível."
                    self._write_state(state)
                    return UpgradeTriggerResponse(
                        status="manual_action_required",
                        message=(
                            "O serviço de atualização automática (Watchtower) não está ativo. "
                            "Execute a atualização no host: docker compose pull && docker compose up -d"
                        ),
                        target_version=target_version,
                        started_at=now_iso,
                    )

                # Timeout pode significar que os containers começaram a reiniciar
                return UpgradeTriggerResponse(
                    status="upgrading",
                    message="Atualização em andamento. Os containers estão sendo reiniciados.",
                    target_version=target_version,
                    started_at=now_iso,
                )

    async def get_upgrade_status(self) -> UpgradeStatusResponse:
        """Consulta o status persistido da atualização e detecta conclusão."""
        current_ver = self._settings.app_version
        async with self._lock:
            state = self._read_state()
            if not state:
                return UpgradeStatusResponse(
                    status="idle",
                    current_version=current_ver,
                    target_version=None,
                    last_upgraded_at=None,
                    message=None,
                )

            prev_status = state.get("status", "idle")
            target_ver = state.get("target_version")
            prev_ver = state.get("previous_version")

            # Se estava em 'upgrading' e a versão atual avançou em relação à anterior
            if prev_status == "upgrading":
                if prev_ver and is_newer_version(prev_ver, current_ver):
                    state["status"] = "completed"
                    state["completed_at"] = datetime.now(timezone.utc).isoformat()
                    state["message"] = f"Atualizado com sucesso para {current_ver}."
                    self._write_state(state)
                    return UpgradeStatusResponse(
                        status="completed",
                        current_version=current_ver,
                        target_version=target_ver,
                        last_upgraded_at=state.get("completed_at"),
                        message=state.get("message"),
                    )

            return UpgradeStatusResponse(
                status=state.get("status", "idle"),
                current_version=current_ver,
                target_version=target_ver,
                last_upgraded_at=state.get("completed_at") or state.get("started_at"),
                message=state.get("message"),
            )


_manager_instance: UpgradeManager | None = None


def get_upgrade_manager(settings: Settings | None = None) -> UpgradeManager:
    """Retorna instância singleton do gerenciador de upgrades."""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = UpgradeManager(settings or get_settings())
    return _manager_instance
