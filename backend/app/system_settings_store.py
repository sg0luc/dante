"""Armazenamento persistente de configurações operacionais do portal (JSON em /data).

Permite que operadores ajustem em runtime:
  - Mapeamento dos estágios de homologação (stg, dev, prod) para Contact Points
    reais existentes no Grafana;
  - Pasta arbitrária do Grafana que atua como baseline 'global' (UID e título);
  - Configurações e credenciais de Inteligência Artificial para a Curadoria;
  - Padrão de prefixo para títulos de regras no Baseline Global e clientes.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .schemas import AISettingsData, BaselinePrefixSettings

logger = logging.getLogger("hunter_portal.system_settings")

DEFAULT_STAGE_MAPPING: dict[str, str] = {
    "stg": "stg",
    "dev": "dev",
    "prod": "prod",
}

DEFAULT_BASELINE_FOLDER_UID = "global"


class SystemSettingsData(BaseModel):
    """Dados persistidos de configuração do sistema."""

    stage_contact_points: dict[str, str] = Field(
        default_factory=lambda: dict(DEFAULT_STAGE_MAPPING),
        description="Mapeamento do estágio ('stg', 'dev', 'prod') para o Contact Point real do Grafana.",
    )
    baseline_folder_uid: str = Field(
        default=DEFAULT_BASELINE_FOLDER_UID,
        description="UID da pasta do Grafana que representa o catálogo Baseline Global.",
    )
    ai_settings: AISettingsData = Field(
        default_factory=AISettingsData,
        description="Configurações e credenciais de Inteligência Artificial para Curadoria.",
    )
    baseline_prefix: BaselinePrefixSettings = Field(
        default_factory=BaselinePrefixSettings,
        description="Configurações de prefixo para títulos de regras no Baseline Global e clientes.",
    )


class SystemSettingsStore:
    """Gerenciador de leitura e escrita atômica do system-settings.json."""

    def __init__(self, store_path: str | Path) -> None:
        self._path = Path(store_path)
        self._lock = threading.Lock()
        self._data: SystemSettingsData = SystemSettingsData()
        self._loaded = False

    def _load_locked(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._data = SystemSettingsData()
            self._loaded = True
            return

        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                cps = raw.get("stage_contact_points")
                cleaned_cps = dict(DEFAULT_STAGE_MAPPING)
                if isinstance(cps, dict):
                    for stage in ("stg", "dev", "prod"):
                        val = cps.get(stage)
                        if isinstance(val, str) and val.strip():
                            cleaned_cps[stage] = val.strip()
                folder_uid = raw.get("baseline_folder_uid")
                if not isinstance(folder_uid, str) or not folder_uid.strip():
                    folder_uid = DEFAULT_BASELINE_FOLDER_UID
                else:
                    folder_uid = folder_uid.strip()

                ai_raw = raw.get("ai_settings")
                if isinstance(ai_raw, dict):
                    try:
                        ai_data = AISettingsData(**ai_raw)
                    except Exception:
                        ai_data = AISettingsData()
                else:
                    ai_data = AISettingsData()

                prefix_raw = raw.get("baseline_prefix")
                if isinstance(prefix_raw, dict):
                    try:
                        prefix_data = BaselinePrefixSettings(**prefix_raw)
                    except Exception:
                        prefix_data = BaselinePrefixSettings()
                else:
                    prefix_data = BaselinePrefixSettings()

                self._data = SystemSettingsData(
                    stage_contact_points=cleaned_cps,
                    baseline_folder_uid=folder_uid,
                    ai_settings=ai_data,
                    baseline_prefix=prefix_data,
                )
            else:
                self._data = SystemSettingsData()
        except Exception as exc:
            logger.warning("Falha ao ler %s (%s); usando valores padrão", self._path, exc)
            self._data = SystemSettingsData()

        self._loaded = True

    def _persist_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._data.model_dump()
        content = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

        # Escrita atômica via arquivo temporário no mesmo diretório
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix="sys-settings-",
            suffix=".tmp",
            dir=str(self._path.parent),
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp_path, self._path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def get_settings(self) -> SystemSettingsData:
        with self._lock:
            self._load_locked()
            return self._data.model_copy(deep=True)

    def get_stage_contact_points(self) -> dict[str, str]:
        with self._lock:
            self._load_locked()
            return dict(self._data.stage_contact_points)

    def resolve_stage_contact_point(self, stage: str) -> str:
        """Resolve o Contact Point real do Grafana configurado para o estágio (stg, dev, prod)."""
        key = (stage or "").strip().lower()
        cps = self.get_stage_contact_points()
        return cps.get(key, key)

    def update_stage_contact_points(self, mapping: dict[str, str]) -> dict[str, str]:
        with self._lock:
            self._load_locked()
            updated = dict(self._data.stage_contact_points)
            for stage in ("stg", "dev", "prod"):
                if stage in mapping and isinstance(mapping[stage], str) and mapping[stage].strip():
                    updated[stage] = mapping[stage].strip()
            self._data.stage_contact_points = updated
            self._persist_locked()
            return dict(self._data.stage_contact_points)

    def get_baseline_folder_uid(self) -> str:
        with self._lock:
            self._load_locked()
            return self._data.baseline_folder_uid

    def set_baseline_folder_uid(self, folder_uid: str) -> str:
        clean = (folder_uid or "").strip()
        if not clean:
            clean = DEFAULT_BASELINE_FOLDER_UID
        with self._lock:
            self._load_locked()
            self._data.baseline_folder_uid = clean
            self._persist_locked()
            return self._data.baseline_folder_uid

    def get_ai_settings(self) -> AISettingsData:
        with self._lock:
            self._load_locked()
            return self._data.ai_settings.model_copy(deep=True)

    def update_ai_settings(self, new_settings: AISettingsData) -> AISettingsData:
        with self._lock:
            self._load_locked()
            self._data.ai_settings = new_settings.model_copy(deep=True)
            self._persist_locked()
            return self._data.ai_settings.model_copy(deep=True)

    def get_baseline_prefix(self) -> BaselinePrefixSettings:
        with self._lock:
            self._load_locked()
            return self._data.baseline_prefix.model_copy(deep=True)

    def set_baseline_prefix(self, settings: BaselinePrefixSettings) -> BaselinePrefixSettings:
        with self._lock:
            self._load_locked()
            self._data.baseline_prefix = settings.model_copy(deep=True)
            self._persist_locked()
            return self._data.baseline_prefix.model_copy(deep=True)
