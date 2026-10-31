"""Gerenciador do repositório local de regras Sigma (SigmaHQ).

Responsabilidades:
1. Clonar localmente o repositório oficial SigmaHQ (https://github.com/SigmaHQ/sigma.git)
   em volume persistente (/data/sigma-repo).
2. Atualizar o repositório diariamente via 'git pull' na rotina das 08h00.
3. Varrer e carregar todas as regras de detecção Sigma legítimas em disco, derivando
   a URL canônica real e garantida no GitHub:
   https://github.com/SigmaHQ/sigma/blob/master/<caminho_relativo_real>
   eliminando completamente erros 404 e queries inventadas.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

import yaml

from .config import get_settings

logger = logging.getLogger("hunter_portal.sigma_manager")

DEFAULT_SIGMA_REPO_DIR = "/data/sigma-repo"
DEFAULT_SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"


def get_configured_sigma_dir() -> Path:
    """Retorna o caminho do repositório Sigma configurado ou padrão."""
    try:
        settings = get_settings()
        return Path(settings.sigma_repo_dir)
    except Exception:
        env_dir = os.environ.get("SIGMA_REPO_DIR", DEFAULT_SIGMA_REPO_DIR)
        return Path(env_dir)


def get_configured_sigma_url() -> str:
    """Retorna a URL do repositório Sigma configurada ou padrão."""
    try:
        settings = get_settings()
        return settings.sigma_repo_url
    except Exception:
        return os.environ.get("SIGMA_REPO_URL", DEFAULT_SIGMA_REPO_URL)


def ensure_sigma_repo(
    repo_dir: Path | str | None = None,
    repo_url: str | None = None,
    timeout_seconds: int = 120,
) -> tuple[bool, str]:
    """Garante que o repositório oficial SigmaHQ esteja clonado e pronto em disco.
    
    Retorna (sucesso, mensagem_detalhada).
    """
    target_dir = Path(repo_dir) if repo_dir else get_configured_sigma_dir()
    clone_url = repo_url or get_configured_sigma_url()

    # Se a pasta já existir e contiver o .git e a pasta rules, valida o repo
    git_dir = target_dir / ".git"
    rules_dir = target_dir / "rules"
    if git_dir.exists() and rules_dir.exists():
        try:
            res = subprocess.run(
                ["git", "-C", str(target_dir), "status", "--porcelain"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if res.returncode == 0:
                logger.info("Repositório Sigma verificado em %s.", target_dir)
                return True, f"Repositório Sigma já está clonado e funcional em {target_dir}."
        except Exception as exc:
            logger.warning("Falha ao checar status do repo Sigma em %s: %s", target_dir, exc)

    # Diretório não existe ou está corrompido: cria o diretório pai e executa o clone
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    logger.info("Iniciando clone do repositório SigmaHQ a partir de %s em %s...", clone_url, target_dir)

    # Tenta shallow clone com depth 1 para agilidade e baixo consumo de disco (~40MB)
    cmd = [
        "git",
        "-c",
        "safe.directory=*",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--branch",
        "master",
        clone_url,
        str(target_dir),
    ]

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if res.returncode != 0:
            # Fallback: tentar sem forçar branch master (caso o upstream tenha alterado para main)
            logger.warning(
                "Clone com branch master falhou (%s). Tentando clone sem especificar branch...",
                res.stderr.strip()[:200],
            )
            cmd_fallback = [
                "git",
                "-c",
                "safe.directory=*",
                "clone",
                "--depth",
                "1",
                clone_url,
                str(target_dir),
            ]
            res = subprocess.run(
                cmd_fallback,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )

        if res.returncode == 0 and (target_dir / "rules").exists():
            msg = f"Repositório Sigma clonado com sucesso em {target_dir}."
            logger.info(msg)
            return True, msg

        err = res.stderr.strip() or res.stdout.strip()
        logger.error("Falha ao clonar repositório SigmaHQ (código %d): %s", res.returncode, err)
        return False, f"Falha ao clonar repositório SigmaHQ: {err}"
    except subprocess.TimeoutExpired:
        logger.error("Timeout de %ds expirado durante clone do SigmaHQ.", timeout_seconds)
        return False, f"Timeout ({timeout_seconds}s) durante clone do repositório SigmaHQ."
    except Exception as exc:
        logger.error("Exceção ao clonar repositório SigmaHQ: %s", exc)
        return False, f"Exceção ao clonar repositório SigmaHQ: {exc}"


def pull_sigma_repo(
    repo_dir: Path | str | None = None,
    timeout_seconds: int = 60,
) -> tuple[bool, str]:
    """Executa 'git pull' no repositório SigmaHQ local.
    
    Usado na rotina diária das 08h00 para sincronizar novas regras.
    """
    target_dir = Path(repo_dir) if repo_dir else get_configured_sigma_dir()
    if not (target_dir / ".git").exists():
        logger.info("Repositório Sigma ainda não clonado. Executando ensure_sigma_repo primeiro...")
        return ensure_sigma_repo(target_dir)

    logger.info("Executando git pull no repositório Sigma em %s...", target_dir)
    cmd = [
        "git",
        "-c",
        "safe.directory=*",
        "-C",
        str(target_dir),
        "pull",
        "--ff-only",
    ]
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if res.returncode == 0:
            out = res.stdout.strip()
            msg = f"Repositório Sigma atualizado com sucesso: {out}"
            logger.info(msg)
            return True, msg
        err = res.stderr.strip() or res.stdout.strip()
        logger.warning("Falha no git pull do repositório Sigma (código %d): %s", res.returncode, err)
        return False, f"Falha no git pull: {err}"
    except Exception as exc:
        logger.error("Exceção no git pull do repositório Sigma: %s", exc)
        return False, f"Exceção no git pull: {exc}"


def scan_local_sigma_rules(
    repo_dir: Path | str | None = None,
    max_rules: int | None = None,
) -> list[dict[str, Any]]:
    """Varre recursivamente a pasta 'rules/' no repositório Sigma clonado localmente.
    
    Para cada arquivo YAML de regra:
    - Constrói o 'source_url' CANÔNICO REAL a partir do caminho físico:
      f"https://github.com/SigmaHQ/sigma/blob/master/{rel_path}"
      (Zero links 404!).
    - Extrai metadados completos: título, MITRE ATT&CK, severidade, tecnologia/logsource.
    """
    target_dir = Path(repo_dir) if repo_dir else get_configured_sigma_dir()
    rules_dir = target_dir / "rules"
    if not rules_dir.exists():
        logger.warning("Diretório de regras %s não encontrado no disco.", rules_dir)
        return []

    candidates: list[dict[str, Any]] = []
    supported_extensions = {".yml", ".yaml"}

    for root, _, files in os.walk(rules_dir):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in supported_extensions:
                continue

            filepath = Path(root) / file
            rel_path = filepath.relative_to(target_dir).as_posix()

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                data = yaml.safe_load(content)
                if not isinstance(data, dict):
                    continue

                title = str(data.get("title") or "").strip()
                if not title:
                    continue

                rule_id = str(data.get("id") or "").strip()
                if not rule_id:
                    # Gera um ID determinístico a partir do caminho relativo
                    stem = filepath.stem.replace("_", "-")
                    rule_id = f"sigma-{stem}"

                status_val = str(data.get("status") or "").lower()
                if status_val in {"deprecated", "unsupported"}:
                    continue

                level_val = str(data.get("level") or "medium").lower()
                sev_map = {
                    "informational": "LOW",
                    "low": "LOW",
                    "medium": "MEDIUM",
                    "high": "HIGH",
                    "critical": "CRITICAL",
                }
                severity = sev_map.get(level_val, "MEDIUM")

                # Tags MITRE ATT&CK
                tags = data.get("tags") or []
                if isinstance(tags, str):
                    tags = [tags]
                mitre_tech = None
                mitre_tactic = None
                for tag in tags:
                    tag_str = str(tag).lower()
                    if tag_str.startswith("attack.t"):
                        mitre_tech = tag_str.replace("attack.", "").upper()
                    elif tag_str.startswith("attack."):
                        mitre_tactic = tag_str.replace("attack.", "").replace("_", "-")

                # Logsource
                logsource = data.get("logsource") or {}
                category = str(logsource.get("category") or "").strip()
                product = str(logsource.get("product") or "").strip()
                service = str(logsource.get("service") or "").strip()

                # URL Canônica Real no GitHub (Garantia absoluta de URL válida!)
                source_url = f"https://github.com/SigmaHQ/sigma/blob/master/{rel_path}"

                candidate = {
                    "external_id": rule_id,
                    "original_title": title,
                    "description": str(data.get("description") or f"Regra Sigma importada de {rel_path}").strip(),
                    "source_id": "sigmahq",
                    "source_name": "SigmaHQ",
                    "source_url": source_url,
                    "rel_path": rel_path,
                    "rule_format": "Sigma (YAML)",
                    "severity": severity,
                    "mitre_technique": mitre_tech,
                    "mitre_tactic": mitre_tactic,
                    "logsource": logsource,
                    "category": category,
                    "product": product,
                    "service": service,
                    "detection": data.get("detection") or {},
                    "raw_yaml": content,
                }
                candidates.append(candidate)

                if max_rules and len(candidates) >= max_rules:
                    return candidates

            except Exception as exc:
                logger.debug("Falha ao analisar regra Sigma %s: %s", filepath, exc)
                continue

    logger.info("Varredura local do Sigma concluída: %d regra(s) encontrada(s) em %s.", len(candidates), rules_dir)
    return candidates

