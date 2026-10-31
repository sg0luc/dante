"""Cache persistente em disco para respostas de IA (curadoria e avaliação técnica de regras).

Evita requisições repetidas a modelos de IA para regras cujas sintaxes e tecnologias
já foram traduzidas e validadas ou avaliadas tecnicamente, economizando tokens e tempo de processamento.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("hunter_portal.ai.cache")


class AICurationCache:
    """Armazenamento atômico em JSON do cache de regras curadas por IA."""

    def __init__(self, cache_path: str | Path) -> None:
        self._path = Path(cache_path)
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _load_locked(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._loaded = True
            return

        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._cache = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        except Exception as exc:
            logger.warning("Falha ao ler cache de IA em %s (%s); iniciando vazio.", self._path, exc)
            self._cache = {}

        self._loaded = True

    def _persist_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self._cache, indent=2, ensure_ascii=False) + "\n"

        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix="ai-cache-",
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

    @staticmethod
    def compute_rule_key(raw_syntax: str, original_title: str, tech_slug: str) -> str:
        """Gera chave SHA-256 única baseada na assinatura da regra e tecnologia."""
        data = f"{raw_syntax.strip()}::{original_title.strip().lower()}::{tech_slug.strip().lower()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        """Retorna o resultado em cache se existir."""
        with self._lock:
            self._load_locked()
            item = self._cache.get(key)
            return dict(item) if isinstance(item, dict) else None

    def set(self, key: str, payload: dict[str, Any]) -> None:
        """Armazena um resultado no cache de forma persistente."""
        with self._lock:
            self._load_locked()
            self._cache[key] = payload
            try:
                self._persist_locked()
            except Exception as exc:
                logger.warning("Falha ao persistir cache de IA: %s", exc)

    def count(self) -> int:
        """Retorna o total de regras cacheadas."""
        with self._lock:
            self._load_locked()
            return len(self._cache)

    def clear(self) -> int:
        """Limpa o cache persistido de IA."""
        with self._lock:
            self._load_locked()
            total = len(self._cache)
            self._cache.clear()
            try:
                self._persist_locked()
            except Exception as exc:
                logger.warning("Falha ao persistir limpeza do cache de IA: %s", exc)
            return total


class AIRuleEvaluationCache:
    """Armazenamento atômico em JSON do cache de avaliações técnicas de regras por IA.

    Persiste em /data/rules-ai-evaluation-cache.json para manter o parecer técnico,
    métricas de telemetria e sugestões de cada regra entre consultas, economizando tokens
    e tempo de processamento até que uma nova análise explícita seja solicitada.
    """

    def __init__(self, cache_path: str | Path = "/data/rules-ai-evaluation-cache.json") -> None:
        self._path = Path(cache_path)
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._loaded = False

    def _load_locked(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._loaded = True
            return

        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._cache = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        except Exception as exc:
            logger.warning("Falha ao ler cache de avaliações de regras em %s (%s); iniciando vazio.", self._path, exc)
            self._cache = {}

        self._loaded = True

    def _persist_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self._cache, indent=2, ensure_ascii=False) + "\n"

        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix="rules-ai-cache-",
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

    def get(self, rule_uid: str) -> dict[str, Any] | None:
        """Retorna a última avaliação técnica em cache para a regra."""
        with self._lock:
            self._load_locked()
            item = self._cache.get(rule_uid)
            return dict(item) if isinstance(item, dict) else None

    def set(self, rule_uid: str, evaluation_data: dict[str, Any]) -> None:
        """Armazena a avaliação técnica da regra no cache persistente."""
        with self._lock:
            self._load_locked()
            self._cache[rule_uid] = evaluation_data
            try:
                self._persist_locked()
            except Exception as exc:
                logger.warning("Falha ao persistir cache de avaliação da regra %s: %s", rule_uid, exc)

    def delete(self, rule_uid: str) -> bool:
        """Remove a avaliação em cache para a regra."""
        with self._lock:
            self._load_locked()
            if rule_uid in self._cache:
                del self._cache[rule_uid]
                try:
                    self._persist_locked()
                except Exception as exc:
                    logger.warning("Falha ao atualizar cache após remoção da regra %s: %s", rule_uid, exc)
                return True
            return False

    def count(self) -> int:
        """Retorna a quantidade de regras com avaliação em cache."""
        with self._lock:
            self._load_locked()
            return len(self._cache)

    def clear(self) -> int:
        """Limpa todo o cache de avaliações de regras."""
        with self._lock:
            self._load_locked()
            total = len(self._cache)
            self._cache.clear()
            try:
                self._persist_locked()
            except Exception as exc:
                logger.warning("Falha ao limpar cache de avaliações: %s", exc)
            return total
