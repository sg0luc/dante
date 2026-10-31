"""Contact Point como estágio de deploy de uma regra de detecção.

No D.A.N.T.E. o Contact Point amarrado à regra diz **onde** a regra está
publicada, e é isso que define o estado de deploy exibido nas telas:

===========  =====================================================  ================
Status       Condição                                               Contact Point
===========  =====================================================  ================
Ativa        regra avaliando (``isPaused = false``)                  ``prod`` (ou CP mapeado como prod)
Homologação  regra avaliando (``isPaused = false``)                  ``dev``/``stg`` (ou CPs mapeados)
Pausada      regra pausada (``isPaused = true``)                     qualquer (ou nenhum)
Sem Contato  regra avaliando, porém sem ``notification_settings``     nenhum/desconhecido
===========  =====================================================  ================

REGRA DE NEGÓCIO: toda regra nova e toda replicação de
baseline entre clientes nascem com o Contact Point correspondente ao estágio ``dev``.
Promover para ``stg``/``prod`` é decisão explícita do operador na página Homologação.
"""

from __future__ import annotations

from typing import Any, Literal

# Contact Points canônicos padrão provisionados na stack (grafana/provisioning/alerting).
DEV_CONTACT_POINT = "dev"
STAGING_CONTACT_POINT = "stg"
PROD_CONTACT_POINT = "prod"
STANDARD_CONTACT_POINTS: tuple[str, ...] = (
    DEV_CONTACT_POINT,
    STAGING_CONTACT_POINT,
    PROD_CONTACT_POINT,
)

# Toda regra nasce em Homologação.
DEFAULT_CONTACT_POINT = DEV_CONTACT_POINT

# Status de deploy exibidos para o operador.
DeployStatus = Literal["active", "homolog", "paused", "unassigned"]

_DEPLOY_STATUS_LABELS: dict[str, str] = {
    "active": "Ativa",
    "homolog": "Homologação",
    "paused": "Pausada",
    "unassigned": "Sem Contact Point",
}

# Nomes aceitos como equivalentes de cada estágio por padrão.
_PROD_ALIASES = frozenset({"prod", "production", "producao"})
_HOMOLOG_ALIASES = frozenset(
    {"dev", "development", "desenvolvimento", "homolog", "homologacao", "hml", "stg", "staging"}
)


def normalize_contact_point(value: Any) -> str | None:
    """Devolve o nome do Contact Point normalizado (sem espaços, minúsculo)."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized or None


def contact_point_tier(
    value: Any, stage_mapping: dict[str, str] | None = None
) -> str | None:
    """Classifica o Contact Point em ``prod`` ou ``homolog`` (``None`` se não mapeado).

    Leva em conta o mapeamento dinâmico configurado pelo operador se fornecido.
    """
    normalized = normalize_contact_point(value)
    if normalized is None:
        return None

    if stage_mapping:
        mapped_prod = normalize_contact_point(stage_mapping.get("prod"))
        mapped_stg = normalize_contact_point(stage_mapping.get("stg"))
        mapped_dev = normalize_contact_point(stage_mapping.get("dev"))

        if mapped_prod and normalized == mapped_prod:
            return PROD_CONTACT_POINT
        if (mapped_stg and normalized == mapped_stg) or (mapped_dev and normalized == mapped_dev):
            return "homolog"

    if normalized in _PROD_ALIASES:
        return PROD_CONTACT_POINT
    if normalized in _HOMOLOG_ALIASES:
        return "homolog"
    return None


def extract_contact_point(rule: Any) -> str | None:
    """Extrai o Contact Point de um objeto de regra do Grafana.

    A API de Provisioning expõe a rota de notificação da regra em
    ``notification_settings.receiver``. Alguns payloads legados/replicados usam
    ``contactPoint`` na raiz; ambos são aceitos.
    """
    if not isinstance(rule, dict):
        return None
    settings = rule.get("notification_settings") or rule.get("notificationSettings")
    if isinstance(settings, dict):
        receiver = normalize_contact_point(settings.get("receiver"))
        if receiver:
            return receiver
    return normalize_contact_point(rule.get("contactPoint"))


def notification_settings(contact_point: str) -> dict[str, Any]:
    """Monta o ``notification_settings`` de uma regra apontando para o Contact Point."""
    return {"receiver": contact_point}


def resolve_stage_receiver(
    stage: str,
    stage_mapping: dict[str, str] | None = None,
    available_contact_points: list[dict[str, Any] | str] | None = None,
) -> str:
    """Resolve o Contact Point real do Grafana atribuído ao estágio ('stg', 'dev', 'prod').

    Leva em conta:
    1. O mapeamento dinâmico configurado pelo operador (stage_mapping, vindo de SystemSettingsStore);
    2. A verificação contra os Contact Points reais existentes no Grafana (available_contact_points);
    3. Fallbacks seguros para aliases conhecidos caso o Contact Point configurado não exista.
    """
    target_stage = (stage or "stg").strip().lower()
    configured = ""
    if stage_mapping:
        configured = str(stage_mapping.get(target_stage) or "").strip()
    if not configured:
        configured = target_stage

    names: list[str] = []
    if available_contact_points:
        for cp in available_contact_points:
            if isinstance(cp, str):
                name = cp.strip()
            elif isinstance(cp, dict):
                name = str(cp.get("name") or "").strip()
            else:
                name = ""
            if name:
                names.append(name)

    # Sem lista de contact points disponíveis do Grafana, devolve o configurado
    if not names:
        return configured or target_stage

    # 1. Correspondência exata (case-insensitive) com o configurado
    for name in names:
        if name.lower() == configured.lower():
            return name

    # 2. Aliases correspondentes ao estágio
    stage_alias_map: dict[str, tuple[str, ...]] = {
        "stg": ("stg", "staging", "homolog", "homologacao"),
        "dev": ("dev", "development", "desenvolvimento"),
        "prod": ("prod", "production", "producao"),
    }
    aliases = stage_alias_map.get(target_stage, (target_stage,))
    for alias in aliases:
        for name in names:
            if name.lower() == alias:
                return name

    # 3. Se for 'stg' e não achou, tenta o 'dev' configurado ou aliases de dev
    if target_stage == "stg":
        dev_configured = str(stage_mapping.get("dev") or "").strip() if stage_mapping else ""
        if dev_configured:
            for name in names:
                if name.lower() == dev_configured.lower():
                    return name
        for alias in ("dev", "development", "desenvolvimento"):
            for name in names:
                if name.lower() == alias:
                    return name

    # 4. Fallback para o primeiro contact point disponível no Grafana
    if names:
        return names[0]

    return configured or target_stage


def apply_contact_point(
    rule_payload: dict[str, Any], contact_point: str = DEFAULT_CONTACT_POINT
) -> dict[str, Any]:
    """Aplica (mutando e devolvendo) o Contact Point no payload de uma regra."""
    rule_payload["notification_settings"] = notification_settings(contact_point)
    return rule_payload


def derive_deploy_status(
    is_paused: bool,
    contact_point: Any,
    stage_mapping: dict[str, str] | None = None,
) -> DeployStatus:
    """Deriva o estado de deploy a partir da pausa e do Contact Point."""
    if is_paused:
        return "paused"
    tier = contact_point_tier(contact_point, stage_mapping=stage_mapping)
    if tier == PROD_CONTACT_POINT:
        return "active"
    if tier == "homolog":
        return "homolog"
    # Regra ativa sem Contact Point conhecido NÃO é Ativa: ninguém recebe o alerta.
    return "unassigned"


def deploy_status_label(status: str) -> str:
    return _DEPLOY_STATUS_LABELS.get(str(status), str(status))
