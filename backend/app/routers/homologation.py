"""Página Homologação: estado de deploy das regras por Contact Point.

O Contact Point amarrado à regra (``notification_settings.receiver``) define onde
a detecção está publicada. Este router expõe a avaliação consolidada e a única
ação de promoção/rebaixamento do estágio de deploy:

    GET  /api/homologation                          -> visão consolidada
    POST /api/homologation/rules/{uid}/contact-point -> promove/rebaixa a regra

Regra de negócio: nada aqui cria regra. A criação e a replicação de baseline
sempre nascem em ``dev`` (Homologação); promover para ``stg``/``prod`` é uma
decisão explícita do operador registrada nesta tela.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from ..ai import AIService
from ..config import Settings
from ..contact_points import (
    STANDARD_CONTACT_POINTS,
    contact_point_tier,
    deploy_status_label,
    derive_deploy_status,
    extract_contact_point,
    normalize_contact_point,
    notification_settings,
)
from ..grafana_client import GrafanaClient, GrafanaError
from ..mappers import build_alerts, build_rule_summaries, folder_titles
from ..schemas import (
    ContactPointInfo,
    HomologationClientBreakdown,
    HomologationMetrics,
    HomologationOverview,
    RuleAlertEventKind,
    RuleAlertHistogramBucket,
    RuleAlertHistoryEvent,
    RuleHomologationAIEvaluation,
    RuleHomologationHistoryResponse,
    SetRuleContactPointRequest,
    SetRuleContactPointResponse,
    UpdateStageContactPointsRequest,
)
from ..security import get_current_user, require_csrf_header
from ..system_settings_store import SystemSettingsStore
from ..technology_store import get_system_settings_store
from ..technology_insights import exclude_hidden_rules
from ..tenants import detection_rules, is_internal_rule
from .deps import get_app_settings, get_grafana

# UIDs do Grafana: até 40 caracteres alfanuméricos, "-" ou "_" (mesmo padrão dos
# outros routers; valida antes de montar a URL repassada ao Grafana).
UID_PATTERN = r"^[A-Za-z0-9_-]{1,40}$"

_INLINE_LABELS_RE = re.compile(r"\{([^{}]*)\}")

router = APIRouter(dependencies=[Depends(get_current_user)])


def _classify_event_kind(new_state: str, prev_state: str) -> RuleAlertEventKind:
    """Classifica a transição de estado do Grafana para o histograma e histórico."""
    ns = new_state.strip().lower()
    ps = prev_state.strip().lower()
    if ns.startswith(("alerting", "firing")):
        return "firing"
    if ns.startswith("pending"):
        return "pending"
    if ns.startswith("error") or "error" in ns:
        return "error"
    if "nodata" in ns:
        return "nodata"
    if ns.startswith(("normal", "ok")) and ps.startswith(("alerting", "firing")):
        return "resolved"
    return "other"


def _extract_event_labels(raw: dict[str, Any]) -> dict[str, str]:
    """Extrai labels da anotação do Grafana (tags + bloco `{k=v}` do texto)."""
    labels: dict[str, str] = {}
    for tag in raw.get("tags") or []:
        if not isinstance(tag, str) or ":" not in tag:
            continue
        k, v = tag.split(":", 1)
        k_clean = k.strip()
        if k_clean and not k_clean.startswith("__"):
            labels[k_clean] = v.strip()

    text = str(raw.get("text") or "")
    match = _INLINE_LABELS_RE.search(text)
    if match:
        for pair in match.group(1).split(","):
            if "=" not in pair:
                continue
            k, v = pair.split("=", 1)
            k_clean = k.strip()
            if k_clean and not k_clean.startswith("__"):
                labels[k_clean] = v.strip()
    return labels


def _extract_event_values(raw: dict[str, Any]) -> dict[str, float]:
    """Extrai os valores numéricos das expressões da regra (ex.: B, C) na transição."""
    data = raw.get("data")
    if not isinstance(data, dict):
        return {}
    raw_vals = data.get("values")
    if not isinstance(raw_vals, dict):
        return {}
    values: dict[str, float] = {}
    for k, v in raw_vals.items():
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            values[str(k)] = round(float(v), 4)
    return values


def _extract_rule_logql(rule: dict[str, Any]) -> str | None:
    """Obtém a expressão LogQL configurada na regra (anotação ou modelo da query A)."""
    annotations = rule.get("annotations") or {}
    if isinstance(annotations, dict):
        annotated = str(annotations.get("logql_query") or "").strip()
        if annotated:
            return annotated
    for q in rule.get("data") or []:
        if not isinstance(q, dict):
            continue
        model = q.get("model") or {}
        if isinstance(model, dict):
            expr = str(model.get("expr") or "").strip()
            if expr and str(q.get("datasourceUid") or "") != "__expr__":
                return expr
    return None


async def _contact_point_inventory(
    grafana: GrafanaClient,
    stage_mapping: dict[str, str] | None = None,
) -> list[ContactPointInfo]:
    """Contact Points do Grafana classificados por estágio (tolerante a falha).

    Se a API de provisionamento não responder, a tela continua funcional: as
    regras mostram o Contact Point que têm e o operador vê a lista vazia.
    """
    try:
        raw = await grafana.list_contact_points()
    except GrafanaError:
        return []

    inventory: list[ContactPointInfo] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        tier = contact_point_tier(name, stage_mapping=stage_mapping)
        inventory.append(
            ContactPointInfo(
                name=name,
                uid=str(item.get("uid") or "") or None,
                type=str(item.get("type") or "") or None,
                tier="other" if tier is None else ("homolog" if tier == "homolog" else "prod"),
                standard=name.lower() in STANDARD_CONTACT_POINTS,
            )
        )
    inventory.sort(key=lambda cp: (0 if cp.standard else 1, cp.name.lower()))
    return inventory


@router.get("/homologation", response_model=HomologationOverview, tags=["homologation"])
async def get_homologation_overview(
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> HomologationOverview:
    """Consolida o estágio de deploy de todas as regras de detecção."""
    try:
        raw_rules, folders, groups = await asyncio.gather(
            grafana.list_alert_rules(),
            grafana.list_folders(),
            grafana.list_rule_groups(),
        )
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    stage_mapping = sys_settings.get_stage_contact_points()

    # Regras-âncora dos grupos de avaliação são internas do portal: nunca entram
    # nas contagens (mesmo filtro usado por /api/rules, matriz e tenants).
    rules = build_rule_summaries(
        exclude_hidden_rules(detection_rules(raw_rules)), groups, folder_titles(folders), stage_mapping=stage_mapping
    )

    metrics = HomologationMetrics(
        total_rules=len(rules),
        active=sum(1 for r in rules if r.deploy_status == "active"),
        homolog=sum(1 for r in rules if r.deploy_status == "homolog"),
        paused=sum(1 for r in rules if r.deploy_status == "paused"),
        unassigned=sum(1 for r in rules if r.deploy_status == "unassigned"),
    )

    clients: dict[str, HomologationClientBreakdown] = {}
    for rule in rules:
        entry = clients.get(rule.folder_uid)
        if entry is None:
            entry = HomologationClientBreakdown(
                folder_uid=rule.folder_uid,
                folder_title=rule.folder_title,
                total=0,
                active=0,
                homolog=0,
                paused=0,
                unassigned=0,
            )
            clients[rule.folder_uid] = entry
        entry.total += 1
        setattr(entry, rule.deploy_status, getattr(entry, rule.deploy_status) + 1)

    inventory = await _contact_point_inventory(grafana, stage_mapping=stage_mapping)
    present = {cp.name.lower() for cp in inventory}

    return HomologationOverview(
        generated_at=datetime.now(timezone.utc).isoformat(),
        contact_points=inventory,
        missing_contact_points=[cp for cp in STANDARD_CONTACT_POINTS if cp not in present],
        stage_contact_points=stage_mapping,
        metrics=metrics,
        clients=sorted(clients.values(), key=lambda c: c.folder_title.lower()),
        rules=rules,
    )


@router.put(
    "/homologation/stage-contact-points",
    response_model=dict[str, str],
    dependencies=[Depends(require_csrf_header)],
    tags=["homologation"],
)
async def update_stage_contact_points(
    payload: UpdateStageContactPointsRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> dict[str, str]:
    """Configura o Contact Point real do Grafana atribuído a cada estágio (stg, dev, prod)."""
    inventory = await _contact_point_inventory(grafana)
    available_cps = {cp.name for cp in inventory}

    mapping = payload.stage_contact_points
    if available_cps:
        for stage in ("stg", "dev", "prod"):
            target_cp = mapping.get(stage)
            if target_cp and target_cp not in available_cps:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Contact Point '{target_cp}' para o estágio '{stage}' não foi encontrado no Grafana.",
                )

    return sys_settings.update_stage_contact_points(mapping)


@router.get(
    "/homologation/rules/{uid}/alert-history",
    response_model=RuleHomologationHistoryResponse,
    tags=["homologation"],
)
async def get_rule_alert_history(
    uid: str = Path(pattern=UID_PATTERN),
    window_hours: int = Query(default=24, ge=1, le=168),
    bucket_count: int = Query(default=12, ge=4, le=48),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> RuleHomologationHistoryResponse:
    """Retorna volume, histograma temporal e histórico de alertas de uma regra.

    Usado pelo pop-up de avaliação na página Homologação (tanto ao clicar no badge
    ``🧪 Homologação`` quanto antes de confirmar a promoção para ``prod``), dando ao
    analista visibilidade volumétrica e qualitativa da regra.
    """
    now_dt = datetime.now(timezone.utc)
    start_dt = now_dt - timedelta(hours=window_hours)
    now_ms = int(now_dt.timestamp() * 1000)
    from_ms = int(start_dt.timestamp() * 1000)

    try:
        rule, folders, groups, raw_alerts = await asyncio.gather(
            grafana.get_alert_rule(uid),
            grafana.list_folders(),
            grafana.list_rule_groups(),
            grafana.list_alerts(),
        )
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    if is_internal_rule(rule):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Regra interna do portal (âncora de grupo) não possui histórico de homologação.",
        )

    try:
        raw_annotations = await grafana.list_rule_annotations(
            uid, time_from_ms=from_ms, time_to_ms=now_ms, limit=1000
        )
    except GrafanaError:
        raw_annotations = []

    stage_mapping = sys_settings.get_stage_contact_points()
    summaries = build_rule_summaries(
        [rule], groups, folder_titles(folders), stage_mapping=stage_mapping
    )
    summary = summaries[0]

    # Filtra instâncias ativas/suprimidas desta regra no Alertmanager
    all_alerts = build_alerts(raw_alerts)
    rule_alerts = [
        a
        for a in all_alerts
        if a.rule_uid == uid
        or (
            not a.rule_uid
            and a.alertname == summary.title
            and a.labels.get("grafana_folder", "").lower()
            in ("", summary.folder_title.lower(), summary.folder_uid.lower())
        )
    ]

    # Constrói a lista de eventos históricos a partir das anotações de estado do Grafana
    events_with_dt: list[tuple[datetime, RuleAlertHistoryEvent]] = []
    for item in raw_annotations:
        if not isinstance(item, dict):
            continue
        ts_raw = item.get("time") or item.get("created") or item.get("updated")
        if not isinstance(ts_raw, (int, float)) or ts_raw <= 0:
            continue
        ev_dt = datetime.fromtimestamp(float(ts_raw) / 1000.0, tz=timezone.utc)
        if ev_dt < start_dt:
            continue
        new_state = str(item.get("newState") or "Unknown").strip()
        prev_state = str(item.get("prevState") or "").strip()
        kind = _classify_event_kind(new_state, prev_state)
        ev = RuleAlertHistoryEvent(
            id=str(item.get("id") or f"{int(ts_raw)}"),
            timestamp=ev_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            new_state=new_state,
            prev_state=prev_state,
            kind=kind,
            text=str(item.get("text") or ""),
            labels=_extract_event_labels(item),
            values=_extract_event_values(item),
        )
        events_with_dt.append((ev_dt, ev))

    # Garante que instâncias ativas neste momento no Alertmanager constem no histórico
    # caso ainda não tenham anotação correspondente na janela
    firing_timestamps = [dt for dt, ev in events_with_dt if ev.kind == "firing"]
    for active_inst in rule_alerts:
        if not active_inst.starts_at:
            continue
        try:
            inst_dt = datetime.fromisoformat(active_inst.starts_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if inst_dt.tzinfo is None:
            inst_dt = inst_dt.replace(tzinfo=timezone.utc)
        if inst_dt < start_dt:
            continue
        if not any(abs((inst_dt - f_dt).total_seconds()) <= 120 for f_dt in firing_timestamps):
            synth_ev = RuleAlertHistoryEvent(
                id=f"alert-{active_inst.fingerprint}",
                timestamp=inst_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                new_state="Alerting",
                prev_state="Normal",
                kind="firing",
                text=(
                    active_inst.annotations.get("summary")
                    or active_inst.annotations.get("description")
                    or active_inst.alertname
                ),
                labels=dict(active_inst.labels),
                values={},
            )
            events_with_dt.append((inst_dt, synth_ev))
            firing_timestamps.append(inst_dt)

    # Ordena do evento mais recente para o mais antigo
    events_with_dt.sort(key=lambda pair: pair[0], reverse=True)
    events = [ev for _dt, ev in events_with_dt]

    # Monta os buckets do histograma cobrindo [start_dt, now_dt]
    total_window_seconds = float(window_hours * 3600)
    bucket_span_seconds = total_window_seconds / float(bucket_count)
    buckets: list[RuleAlertHistogramBucket] = []

    for idx in range(bucket_count):
        b_start = start_dt + timedelta(seconds=idx * bucket_span_seconds)
        b_end = start_dt + timedelta(seconds=(idx + 1) * bucket_span_seconds)
        if window_hours <= 48:
            label = b_start.strftime("%H:%M")
        else:
            label = b_start.strftime("%d/%m %Hh")

        buckets.append(
            RuleAlertHistogramBucket(
                bucket_start=b_start.isoformat(timespec="seconds").replace("+00:00", "Z"),
                bucket_end=b_end.isoformat(timespec="seconds").replace("+00:00", "Z"),
                label=label,
            )
        )

    for ev_dt, ev in events_with_dt:
        offset_sec = (ev_dt - start_dt).total_seconds()
        b_idx = int(offset_sec // bucket_span_seconds)
        if b_idx < 0:
            b_idx = 0
        elif b_idx >= bucket_count:
            b_idx = bucket_count - 1
        target_bucket = buckets[b_idx]
        target_bucket.total_events += 1
        if ev.kind == "firing":
            target_bucket.firing_count += 1
        elif ev.kind == "resolved":
            target_bucket.resolved_count += 1
        else:
            target_bucket.other_count += 1

    firing_count = sum(1 for ev in events if ev.kind == "firing")
    resolved_count = sum(1 for ev in events if ev.kind == "resolved")
    pending_count = sum(1 for ev in events if ev.kind == "pending")
    error_count = sum(1 for ev in events if ev.kind == "error")
    active_now = max(
        sum(1 for a in rule_alerts if a.state == "active"),
        summary.active_instances if summary.state == "firing" else 0,
    )
    suppressed_now = sum(1 for a in rule_alerts if a.state == "suppressed")
    peak_firing = max((b.firing_count for b in buckets), default=0)
    avg_firing = round(firing_count / max(float(window_hours), 1.0), 2)
    last_firing_at = next((ev.timestamp for ev in events if ev.kind == "firing"), None)

    labels = summary.labels
    return RuleHomologationHistoryResponse(
        uid=summary.uid,
        title=summary.title,
        folder_uid=summary.folder_uid,
        folder_title=summary.folder_title,
        contact_point=summary.contact_point,
        deploy_status=summary.deploy_status,
        state=summary.state,
        is_paused=summary.is_paused,
        severity=labels.get("severity"),
        technology_name=labels.get("technology_name") or labels.get("technology"),
        mitre_tactic=labels.get("mitre_tactic"),
        mitre_technique=labels.get("mitre_technique"),
        logql_query=_extract_rule_logql(rule),
        window_hours=window_hours,
        generated_at=now_dt.isoformat(),
        total_events=len(events),
        firing_events_count=firing_count,
        resolved_events_count=resolved_count,
        pending_events_count=pending_count,
        error_events_count=error_count,
        active_alerts_count=active_now,
        suppressed_alerts_count=suppressed_now,
        peak_bucket_firing=peak_firing,
        avg_firing_per_hour=avg_firing,
        last_firing_at=last_firing_at,
        last_evaluation=summary.last_evaluation,
        active_alerts=rule_alerts,
        histogram=buckets,
        events=events,
    )


def get_ai_service(
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    settings: Settings = Depends(get_app_settings),
) -> AIService:
    return AIService(
        sys_settings=sys_settings,
        cache_path=settings.curation_ai_cache_path,
        settings=settings,
    )


@router.get(
    "/homologation/rules/{uid}/ai-evaluation",
    response_model=RuleHomologationAIEvaluation,
    tags=["homologation"],
)
async def evaluate_rule_with_ai(
    uid: str = Path(pattern=UID_PATTERN),
    window_hours: int = Query(default=24, ge=1, le=168),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    ai_service: AIService = Depends(get_ai_service),
) -> RuleHomologationAIEvaluation:
    """Emite parecer técnico da IA sobre o histórico de alertas e volumetria de uma regra.

    Avalia pontos de melhoria, ações para redução de falso positivo e floods, análise de
    incidentes reais e calibração necessária para produção (ou calibração contínua se já em prod).
    """
    history = await get_rule_alert_history(
        uid=uid,
        window_hours=window_hours,
        bucket_count=12,
        grafana=grafana,
        sys_settings=sys_settings,
    )
    return await ai_service.evaluate_rule_homologation(history)


@router.post(
    "/homologation/rules/{uid}/contact-point",
    response_model=SetRuleContactPointResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["homologation"],
)
async def set_rule_contact_point(
    payload: SetRuleContactPointRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> SetRuleContactPointResponse:
    """Move a regra entre os estágios de deploy (dev/stg/prod).

    Se o operador passar o alias canônico (stg, dev, prod), resolve
    para o Contact Point configurado nas preferências de homologação.
    """
    raw_target = normalize_contact_point(payload.contact_point)
    if not raw_target:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Contact Point inválido para deploy.",
        )

    stage_mapping = sys_settings.get_stage_contact_points()
    mapped_target_names = {v.lower() for v in stage_mapping.values()}

    # O endpoint aceita os aliases canônicos ('stg', 'dev', 'prod') ou os contact points configurados neles
    if raw_target in STANDARD_CONTACT_POINTS:
        resolved_target = sys_settings.resolve_stage_contact_point(raw_target)
    elif raw_target in mapped_target_names:
        resolved_target = raw_target
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Contact Point inválido para deploy: use um dos estágios "
                f"padrão do portal ({', '.join(STANDARD_CONTACT_POINTS)}) ou um Contact Point mapeado."
            ),
        )

    try:
        rule = await grafana.get_alert_rule(uid)
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    if is_internal_rule(rule):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Regra interna do portal (grupo de avaliação do tenant): o estágio "
                "de deploy não se aplica e não pode ser alterado por aqui."
            ),
        )
    if rule.get("record"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Regra de gravação (recording rule) não dispara alertas: não possui estágio de deploy.",
        )

    inventory = await _contact_point_inventory(grafana, stage_mapping=stage_mapping)
    present_names = {cp.name.lower() for cp in inventory}
    if resolved_target.lower() not in present_names:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"O Contact Point '{resolved_target}' não está provisionado no Grafana. "
                "Verifique os Contact Points cadastrados no Grafana."
            ),
        )

    matched_cp = next(cp for cp in inventory if cp.name.lower() == resolved_target.lower())
    exact_target = matched_cp.name

    previous_contact_point = extract_contact_point(rule)
    previous_status = derive_deploy_status(
        bool(rule.get("isPaused")), previous_contact_point, stage_mapping=stage_mapping
    )

    # O PUT do provisioning recebe o objeto completo da regra (mesmo padrão do
    # toggle de pausa): só a rota de notificação é alterada.
    rule["notification_settings"] = notification_settings(exact_target)
    try:
        await grafana.update_alert_rule(uid, rule)
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    new_status = derive_deploy_status(
        bool(rule.get("isPaused")), exact_target, stage_mapping=stage_mapping
    )
    return SetRuleContactPointResponse(
        message=(
            f"Regra '{rule.get('title') or uid}' movida para o estágio "
            f"{deploy_status_label(new_status)} (Contact Point '{exact_target}')."
        ),
        uid=uid,
        title=str(rule.get("title") or ""),
        contact_point=exact_target,
        deploy_status=new_status,
        previous_contact_point=previous_contact_point,
        previous_deploy_status=previous_status,
    )

