"""Conversão das respostas do Grafana para os modelos do portal.

Funções puras (sem I/O), fáceis de testar isoladamente.

Combinação de fontes para as regras:
  * ``/api/v1/provisioning/alert-rules``  -> configuração (título, labels, pausa...)
  * ``/api/prometheus/grafana/api/v1/rules`` -> estado de execução (firing, health...)
  * ``/api/search?type=dash-folder``       -> título das pastas
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .contact_points import derive_deploy_status, extract_contact_point
from .schemas import (
    AlertInstance,
    RuleDetail,
    RuleQuery,
    RuleState,
    RuleSummary,
    Silence,
    SilenceKind,
    SilenceMatcher,
    SilencedAlertSummary,
)

_TIMESTAMP_RE = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d+))?(?P<tz>Z|[+-]\d{2}:\d{2})$"
)

# Ordem de exibição: o que exige atenção aparece primeiro.
_STATE_PRIORITY: dict[str, int] = {
    "firing": 0, "error": 1, "pending": 2, "recovering": 3,
    "nodata": 4, "normal": 5, "unknown": 6, "paused": 7,
}


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------
def normalize_timestamp(value: Any) -> str | None:
    """Normaliza timestamps do Grafana.

    * ``0001-01-01T00:00:00Z`` (valor zero do Go) -> ``None``
    * Frações de nanossegundos -> milissegundos (compatível com ``Date`` do JS)
    """
    if not isinstance(value, str) or not value or value.startswith("0001-01-01"):
        return None
    match = _TIMESTAMP_RE.match(value)
    if not match:
        return value
    frac = (match.group("frac") or "")[:3]
    return f"{match.group('base')}{'.' + frac if frac else ''}{match.group('tz')}"


def public_labels(labels: Any) -> dict[str, str]:
    """Remove labels internos do Grafana (prefixo ``__``) e força strings."""
    if not isinstance(labels, dict):
        return {}
    return {str(k): str(v) for k, v in labels.items() if not str(k).startswith("__")}


def string_map(values: Any) -> dict[str, str]:
    if not isinstance(values, dict):
        return {}
    return {str(k): str(v) for k, v in values.items()}


def folder_titles(folders: list[dict[str, Any]]) -> dict[str, str]:
    """Mapa ``folder_uid -> título``."""
    return {
        str(f["uid"]): str(f.get("title") or f["uid"])
        for f in folders
        if isinstance(f, dict) and f.get("uid")
    }


# ---------------------------------------------------------------------------
# Regras
# ---------------------------------------------------------------------------
RuntimeLookup = Callable[[dict[str, Any]], "dict[str, Any] | None"]


def runtime_index(groups: list[dict[str, Any]]) -> RuntimeLookup:
    """Indexa o estado de execução das regras.

    Usa o ``uid`` da regra quando disponível; caso contrário, cai para a chave
    (pasta, grupo, título) para compatibilidade com versões antigas.
    """
    by_uid: dict[str, dict[str, Any]] = {}
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for group in groups:
        folder_uid = str(group.get("folderUid") or "")
        group_name = str(group.get("name") or "")
        for rule in group.get("rules") or []:
            if rule.get("uid"):
                by_uid[str(rule["uid"])] = rule
            by_key[(folder_uid, group_name, str(rule.get("name") or ""))] = rule

    def lookup(config: dict[str, Any]) -> dict[str, Any] | None:
        uid = str(config.get("uid") or "")
        if uid in by_uid:
            return by_uid[uid]
        key = (
            str(config.get("folderUID") or ""),
            str(config.get("ruleGroup") or ""),
            str(config.get("title") or ""),
        )
        return by_key.get(key)

    return lookup


def derive_rule_state(is_paused: bool, runtime: dict[str, Any] | None) -> RuleState:
    """Consolida configuração + execução em um único estado para a UI."""
    if is_paused:
        return "paused"
    if runtime is None:
        return "unknown"
    health = str(runtime.get("health") or "").lower()
    state = str(runtime.get("state") or "").lower()
    if health == "error":
        return "error"
    if health == "nodata":
        return "nodata"
    if state == "firing":
        return "firing"
    if state == "pending":
        return "pending"
    if state == "recovering":
        return "recovering"
    if state in ("inactive", "normal", "ok"):
        return "normal"
    return "unknown"


def _active_instances(runtime: dict[str, Any] | None) -> int:
    """Conta instâncias em estado Alerting (inclui 'Alerting (NoData)' etc.)."""
    if not runtime:
        return 0
    return sum(
        1
        for alert in runtime.get("alerts") or []
        if str(alert.get("state") or "").lower().startswith(("alerting", "firing"))
    )


def _summary_fields(
    config: dict[str, Any],
    lookup: RuntimeLookup,
    folders: dict[str, str],
    stage_mapping: dict[str, str] | None = None,
    silenced_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    runtime = lookup(config)
    is_paused = bool(config.get("isPaused"))
    folder_uid = str(config.get("folderUID") or "")
    uid = str(config.get("uid") or "")
    title = str(config.get("title") or "")
    # O Contact Point amarrado à regra define o estágio de deploy exibido na UI
    # (Ativa/Homologação/Pausada/Sem Contact Point) — ver contact_points.py.
    contact_point = extract_contact_point(config)
    silenced = 0
    if silenced_counts:
        silenced = silenced_counts.get(uid, silenced_counts.get(title, 0))
    return {
        "uid": uid,
        "title": title,
        "folder_uid": folder_uid,
        "folder_title": folders.get(folder_uid, folder_uid),
        "rule_group": str(config.get("ruleGroup") or ""),
        "rule_type": "recording" if config.get("record") else "alerting",
        "labels": public_labels(config.get("labels")),
        "annotations": string_map(config.get("annotations")),
        "is_paused": is_paused,
        "for_duration": str(config["for"]) if config.get("for") is not None else None,
        "state": derive_rule_state(is_paused, runtime),
        "health": (str(runtime.get("health")) if runtime and runtime.get("health") else None),
        "last_evaluation": normalize_timestamp(runtime.get("lastEvaluation")) if runtime else None,
        "last_error": (str(runtime.get("lastError")) if runtime and runtime.get("lastError") else None),
        "active_instances": _active_instances(runtime),
        "updated": normalize_timestamp(config.get("updated")),
        "contact_point": contact_point,
        "deploy_status": derive_deploy_status(is_paused, contact_point, stage_mapping),
        "silenced_instances": silenced,
    }


def build_rule_summaries(
    rules: list[dict[str, Any]],
    groups: list[dict[str, Any]],
    folders: dict[str, str],
    stage_mapping: dict[str, str] | None = None,
    silenced_counts: dict[str, int] | None = None,
) -> list[RuleSummary]:
    lookup = runtime_index(groups)
    summaries = [
        RuleSummary(**_summary_fields(r, lookup, folders, stage_mapping, silenced_counts))
        for r in rules
    ]
    summaries.sort(key=lambda s: (_STATE_PRIORITY.get(s.state, 99), s.title.lower()))
    return summaries


def build_rule_detail(
    rule: dict[str, Any],
    groups: list[dict[str, Any]],
    folders: dict[str, str],
    stage_mapping: dict[str, str] | None = None,
) -> RuleDetail:
    lookup = runtime_index(groups)
    queries = [
        RuleQuery(
            ref_id=str(q.get("refId") or ""),
            datasource_uid=q.get("datasourceUid"),
            relative_time_range=q.get("relativeTimeRange"),
            model=q.get("model") or {},
        )
        for q in rule.get("data") or []
        if isinstance(q, dict)
    ]
    return RuleDetail(
        **_summary_fields(rule, lookup, folders, stage_mapping),
        condition=rule.get("condition"),
        no_data_state=rule.get("noDataState"),
        exec_err_state=rule.get("execErrState"),
        provenance=rule.get("provenance") or None,
        queries=queries,
    )


# ---------------------------------------------------------------------------
# Alertas
# ---------------------------------------------------------------------------
def build_alert(raw: dict[str, Any]) -> AlertInstance:
    labels = raw.get("labels") or {}
    status = raw.get("status") or {}
    state = str(status.get("state") or "unprocessed")
    if state not in ("active", "suppressed", "unprocessed"):
        state = "unprocessed"
    return AlertInstance(
        fingerprint=str(raw.get("fingerprint") or ""),
        alertname=str(labels.get("alertname") or "(sem nome)"),
        rule_uid=labels.get("__alert_rule_uid__"),
        state=state,  # type: ignore[arg-type]
        silenced_by=[str(s) for s in status.get("silencedBy") or []],
        inhibited_by=[str(s) for s in status.get("inhibitedBy") or []],
        labels=public_labels(labels),
        annotations=string_map(raw.get("annotations")),
        starts_at=normalize_timestamp(raw.get("startsAt")),
        updated_at=normalize_timestamp(raw.get("updatedAt")),
    )


def build_alerts(raw_alerts: list[dict[str, Any]]) -> list[AlertInstance]:
    alerts = [build_alert(a) for a in raw_alerts if isinstance(a, dict)]
    # Ativos primeiro; dentro do grupo, os mais recentes primeiro.
    alerts.sort(key=lambda a: a.starts_at or "", reverse=True)
    alerts.sort(key=lambda a: 0 if a.state == "active" else 1)
    return alerts


# ---------------------------------------------------------------------------
# Silences
# ---------------------------------------------------------------------------
# Vigência mínima (em dias) para um silence ser tratado como EXCEÇÃO PERMANENTE
# a uma regra de detecção em vez de janela temporária de supressão.
PERMANENT_MIN_SPAN_DAYS = 365

# Tags canônicas que o portal grava no comentário para tornar a origem explícita
# (o Alertmanager não possui campo próprio de metadados livres).
_PERMANENT_TAG_RE = re.compile(r"\[(?:excecao|excecoes|permanente|permanentes|whitelist|allowlist)\]")
_ANTIFLOOD_TAG_RE = re.compile(r"\[(?:antiflood|anti-flood|flood)\]")
_MAINTENANCE_TAG_RE = re.compile(r"\[(?:manutencao|maintenance|janela|mudanca|change|deploy)\]")

_ACCENT_MAP = str.maketrans("áàâãéêíóôõúç", "aaaaeeiooouc")


def _normalize_text(value: str) -> str:
    """Minúsculas e sem acentos, para casar heurísticas com textos em pt-BR."""
    return value.lower().translate(_ACCENT_MAP)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def classify_silence(
    raw: dict[str, Any], starts_at: str | None, ends_at: str | None
) -> SilenceKind:
    """Deriva a natureza do silence para a visão segregada da tela de Silences.

    Prioridade de decisão:
      1. Tag explícita ``[excecao]``/``[permanente]`` no comentário.
      2. Vigência efetiva >= ``PERMANENT_MIN_SPAN_DAYS`` (ou sem término válido)
         -> exceção permanente: o objetivo é impedir que a regra volte a disparar.
      3. Tags/heurísticas de origem: antiflood, janela de manutenção.
      4. Fallback: supressão temporária ad hoc criada pelo operador (``manual``).
    """
    comment = _normalize_text(str(raw.get("comment") or ""))
    creator = _normalize_text(str(raw.get("createdBy") or ""))

    if _PERMANENT_TAG_RE.search(comment):
        return "permanent"

    start_dt = _parse_timestamp(starts_at)
    end_dt = _parse_timestamp(ends_at)
    now = datetime.now(timezone.utc)

    # Alertmanager representa "sem término" com a data zero (ano 0001).
    if end_dt is None or end_dt.year <= 1:
        return "permanent"

    remaining = end_dt - now
    span = (end_dt - start_dt) if start_dt else remaining
    threshold = timedelta(days=PERMANENT_MIN_SPAN_DAYS)
    if remaining >= threshold or span >= threshold:
        return "permanent"

    if (
        _ANTIFLOOD_TAG_RE.search(comment)
        or "antiflood" in creator
        or "anti-flood" in creator
    ):
        return "antiflood"

    if (
        _MAINTENANCE_TAG_RE.search(comment)
        or "manutencao" in creator
        or "maintenance" in creator
    ):
        return "maintenance"

    return "manual"


def alert_matches_matchers(labels: dict[str, str], matchers: list[SilenceMatcher]) -> bool:
    """Verifica se um conjunto de labels satisfaz todos os critérios do silence."""
    if not matchers:
        return False
    for m in matchers:
        val = str(labels.get(m.name) or "")
        if m.is_regex:
            try:
                matched = bool(re.search(m.value, val))
            except re.error:
                matched = False
        else:
            matched = (val == m.value)

        if m.is_equal and not matched:
            return False
        if not m.is_equal and matched:
            return False
    return True


def build_silence(
    raw: dict[str, Any],
    alerts_count: int = 0,
    silenced_alerts: list[SilencedAlertSummary] | None = None,
) -> Silence:
    state = str((raw.get("status") or {}).get("state") or "expired")
    if state not in ("active", "pending", "expired"):
        state = "expired"
    matchers = [
        SilenceMatcher(
            name=str(m.get("name") or ""),
            value=str(m.get("value") or ""),
            is_regex=bool(m.get("isRegex")),
            # Ausência de isEqual significa igualdade (compatibilidade Alertmanager).
            is_equal=bool(m.get("isEqual", True)),
        )
        for m in raw.get("matchers") or []
        if isinstance(m, dict)
    ]
    alerts_list = silenced_alerts if silenced_alerts is not None else []
    return Silence(
        id=str(raw.get("id") or ""),
        state=state,  # type: ignore[arg-type]
        kind=classify_silence(
            raw,
            normalize_timestamp(raw.get("startsAt")),
            normalize_timestamp(raw.get("endsAt")),
        ),
        matchers=matchers,
        starts_at=normalize_timestamp(raw.get("startsAt")),
        ends_at=normalize_timestamp(raw.get("endsAt")),
        updated_at=normalize_timestamp(raw.get("updatedAt")),
        created_by=str(raw.get("createdBy") or ""),
        comment=str(raw.get("comment") or ""),
        silenced_alerts_count=len(alerts_list) if silenced_alerts is not None else alerts_count,
        silenced_alerts=alerts_list,
    )


def build_silences(
    raw_silences: list[dict[str, Any]],
    raw_alerts: list[dict[str, Any]] | None = None,
    synthetic_alerts: list[Any] | None = None,
) -> list[Silence]:
    order = {"active": 0, "pending": 1, "expired": 2}

    # Pré-constroi os matchers de cada silence para testar alertas
    silences_data: list[tuple[dict[str, Any], str, str, list[SilenceMatcher]]] = []
    for s in raw_silences:
        if not isinstance(s, dict):
            continue
        s_id = str(s.get("id") or "")
        state = str((s.get("status") or {}).get("state") or "expired")
        matchers = [
            SilenceMatcher(
                name=str(m.get("name") or ""),
                value=str(m.get("value") or ""),
                is_regex=bool(m.get("isRegex")),
                is_equal=bool(m.get("isEqual", True)),
            )
            for m in s.get("matchers") or []
            if isinstance(m, dict)
        ]
        silences_data.append((s, s_id, state, matchers))

    # Mapeamento s_id -> lista de SilencedAlertSummary
    silenced_map: dict[str, list[SilencedAlertSummary]] = {s_id: [] for _, s_id, _, _ in silences_data}
    seen_by_silence: dict[str, set[str]] = {s_id: set() for _, s_id, _, _ in silences_data}

    # 1. Alertas reais do Grafana Alertmanager
    if raw_alerts:
        for alert in raw_alerts:
            if not isinstance(alert, dict):
                continue
            labels = {str(k): str(v) for k, v in (alert.get("labels") or {}).items()}
            annotations = {str(k): str(v) for k, v in (alert.get("annotations") or {}).items()}
            fp = str(alert.get("fingerprint") or f"fp-{hash(frozenset(labels.items()))}")
            alertname = labels.get("alertname") or annotations.get("summary") or "Alerta sem nome"
            folder = labels.get("grafana_folder") or labels.get("tenant") or labels.get("client")
            severity = labels.get("severity", "medium")
            starts_at = normalize_timestamp(alert.get("startsAt"))
            status_dict = alert.get("status") or {}
            silenced_by_ids = [str(x) for x in (status_dict.get("silencedBy") or [])]

            alert_summary = SilencedAlertSummary(
                fingerprint=fp,
                alertname=alertname,
                grafana_folder=folder,
                severity=severity,
                starts_at=starts_at,
                state=str(status_dict.get("state") or "suppressed"),
                labels=labels,
                annotations=annotations,
            )

            # Verifica cada silence
            for _, s_id, state, matchers in silences_data:
                is_matched = False
                if s_id in silenced_by_ids:
                    is_matched = True
                elif state == "active" and alert_matches_matchers(labels, matchers):
                    is_matched = True

                if is_matched and fp not in seen_by_silence[s_id]:
                    seen_by_silence[s_id].add(fp)
                    silenced_map[s_id].append(alert_summary)

    # 2. Alertas sintéticos / fictícios do SyntheticAlertsStore
    if synthetic_alerts:
        for syn in synthetic_alerts:
            if isinstance(syn, dict):
                labels = {str(k): str(v) for k, v in (syn.get("labels") or {}).items()}
                annotations = {str(k): str(v) for k, v in (syn.get("annotations") or {}).items()}
                fp = str(syn.get("fingerprint") or f"syn-{hash(frozenset(labels.items()))}")
                alertname = str(syn.get("alertname") or labels.get("alertname") or "Alerta Sintético")
                folder = str(labels.get("grafana_folder") or labels.get("tenant") or labels.get("client") or "global")
                severity = str(labels.get("severity", "medium"))
                starts_at = normalize_timestamp(syn.get("starts_at"))
                syn_silenced_by = [str(x) for x in (syn.get("silenced_by") or [])]
                syn_state = str(syn.get("state") or "suppressed")
            else:
                labels = dict(syn.labels)
                annotations = dict(syn.annotations)
                fp = str(syn.fingerprint)
                alertname = str(syn.alertname)
                folder = str(labels.get("grafana_folder") or labels.get("tenant") or labels.get("client") or "global")
                severity = str(labels.get("severity", "medium"))
                starts_at = normalize_timestamp(syn.starts_at)
                syn_silenced_by = [str(x) for x in (syn.silenced_by or [])]
                syn_state = str(syn.state or "suppressed")

            alert_summary = SilencedAlertSummary(
                fingerprint=fp,
                alertname=alertname,
                grafana_folder=folder,
                severity=severity,
                starts_at=starts_at,
                state=syn_state,
                labels=labels,
                annotations=annotations,
            )

            for _, s_id, state, matchers in silences_data:
                is_matched = False
                if s_id in syn_silenced_by:
                    is_matched = True
                elif state == "active" and alert_matches_matchers(labels, matchers):
                    is_matched = True

                if is_matched and fp not in seen_by_silence[s_id]:
                    seen_by_silence[s_id].add(fp)
                    silenced_map[s_id].append(alert_summary)

    silences = [
        build_silence(s, len(silenced_map.get(s_id, [])), silenced_map.get(s_id, []))
        for s, s_id, _, _ in silences_data
    ]
    silences.sort(key=lambda s: s.ends_at or "", reverse=True)
    silences.sort(key=lambda s: order.get(s.state, 99))
    return silences


