"""Módulo de padronização e formatação de prefixos de regras de detecção.

Permite configurar prefixos para o Baseline Global e regras replicadas em clientes,
suportando variáveis dinâmicas:
  - {{technology}}: Tecnologia associada à regra (ex: 'Ad_windows', 'Fortigate').
  - {{tenant}}: Nome do tenant onde a regra está implementada.
    No Baseline Global, o valor é SEMPRE 'Baseline'.
  - {{tactic}}: Tática MITRE ATT&CK (ex: 'Persistence', 'Initial_access').
  - {{severity}}: Severidade do alerta (ex: 'Critical', 'High', 'Medium', 'Low').

Sempre garante o padrão de primeira letra maiúscula (capitalizada).
"""

from __future__ import annotations

import re
from typing import Any

from .schemas import BaselinePrefixSettings
from .technology_insights import strip_scope_prefix

# Regex para casar {{variavel}} ou {variavel} ignorando espaços internos
_PLACEHOLDER_RE = re.compile(r"\{\{\s*(\w+)\s*\}\}|\{\s*(\w+)\s*\}")


def capitalize_first(val: Any, default: str = "") -> str:
    """Retorna o valor com a primeira letra maiúscula mantendo o restante.

    Exemplos:
      'ad_windows' -> 'Ad_windows'
      'persistence' -> 'Persistence'
      'critical' -> 'Critical'
      'global' -> 'Baseline'
    """
    s = str(val or default).strip()
    if not s:
        return ""
    if s.lower() in ("global", "baseline"):
        return "Baseline"
    return s[:1].upper() + s[1:]


def evaluate_prefix_template(
    template: str,
    *,
    tenant_name: str | None = None,
    is_baseline: bool = False,
    technology: str | None = None,
    technology_name: str | None = None,
    tactic: str | None = None,
    severity: str | None = None,
) -> str:
    """Avalia o template de prefixo substituindo as variáveis dinâmicas."""
    if not template or not template.strip():
        return ""

    # Determina o valor de {{tenant}}
    if is_baseline or not tenant_name or tenant_name.strip().lower() in ("global", "baseline"):
        tenant_val = "Baseline"
    else:
        tenant_val = capitalize_first(tenant_name)

    # Determina o valor de {{technology}}
    tech_val = capitalize_first(technology_name or technology or "Geral")

    # Determina o valor de {{tactic}}
    tactic_val = capitalize_first(tactic or "Detecção")

    # Determina o valor de {{severity}}
    severity_val = capitalize_first(severity or "Média")

    var_map = {
        "tenant": tenant_val,
        "technology": tech_val,
        "tech": tech_val,
        "tactic": tactic_val,
        "mitre_tactic": tactic_val,
        "severity": severity_val,
    }

    def _repl(match: re.Match[str]) -> str:
        key = (match.group(1) or match.group(2) or "").strip().lower()
        return var_map.get(key, match.group(0))

    return _PLACEHOLDER_RE.sub(_repl, template)


def format_rule_title(
    title: str,
    settings: BaselinePrefixSettings | None,
    *,
    tenant_name: str | None = None,
    is_baseline: bool = False,
    technology: str | None = None,
    technology_name: str | None = None,
    tactic: str | None = None,
    severity: str | None = None,
) -> str:
    """Aplica o prefixo configurado ao título da regra, evitando duplicidade.

    Se as configurações estiverem desabilitadas ou o template for vazio,
    retorna o título original (removendo prefixos legados no formato '[Cliente]').
    """
    clean_title = strip_scope_prefix(title).strip()
    if not clean_title:
        clean_title = str(title or "").strip()

    if not settings or not settings.enabled:
        return clean_title

    template = (settings.template or "").strip()
    if not template:
        return clean_title

    # Avalia as variáveis dinâmicas
    prefix = evaluate_prefix_template(
        settings.template,
        tenant_name=tenant_name,
        is_baseline=is_baseline,
        technology=technology,
        technology_name=technology_name,
        tactic=tactic,
        severity=severity,
    )

    if not prefix:
        return clean_title

    # Idempotência: não duplica se clean_title já iniciar com o prefixo
    prefix_clean = prefix.strip()
    if clean_title.startswith(prefix) or (prefix_clean and clean_title.startswith(prefix_clean)):
        return clean_title

    return f"{prefix}{clean_title}"
