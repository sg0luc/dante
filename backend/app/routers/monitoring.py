"""Consulta de regras de detecÃ§Ã£o, alertas e silences (somente leitura nesta etapa)."""

from __future__ import annotations

import asyncio
import copy
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status

from ..config import Settings
from ..contact_points import DEFAULT_CONTACT_POINT, apply_contact_point, resolve_stage_receiver
from ..grafana_client import GrafanaClient, GrafanaError
from ..logql_validator import (
    LogQLLintResult,
    LogQLValidationReport,
    evaluate_logql,
    lint_logql,
)
from ..mappers import (
    build_alerts,
    build_rule_detail,
    build_rule_summaries,
    build_silences,
    folder_titles,
)
from ..schemas import (
    AlertHistoryEvent,
    AlertHistoryResponse,
    AlertInstance,
    BatchToggleRulesPauseRequest,
    BatchToggleRulesPauseResponse,
    PausedRuleMatchItem,
    PausedRulesMatchesResponse,
    ClearSyntheticAlertsResponse,
    ClientRuleCoverage,
    ClientRuleStatusType,
    CreateFolderRequest,
    CreateRuleRequest,
    CreateRuleResponse,
    CreateSilenceRequest,
    CreateSilenceResponse,
    CreateTenantDatasourceRequest,
    CreateTenantRequest,
    TenantSandboxResponse,
    DuplicateRuleRequest,
    ExecuteQueryRequest,
    EnvironmentQueryResult,
    ExecuteQueryResult,
    ExtendSilenceRequest,
    FolderItem,
    GenerateSyntheticAlertsRequest,
    GlobalRuleMatrixItem,
    ImplementedRuleResult,
    LogLineResult,
    ApplyRuleAISuggestionsRequest,
    ApplyRuleAISuggestionsResponse,
    RuleDetail,
    RuleImprovementEvaluation,
    RuleImportExecuteRequest,
    RuleImportExecuteResponse,
    RuleImportPreviewRequest,
    RuleImportPreviewResponse,
    RuleSummary,
    Silence,
    TenantDatasourceResponse,
    TenantEvaluationGroupResponse,
    RepairEvaluationGroupRequest,
    TenantSummary,
    TenantTechnologiesResponse,
    TenantTechnologyBaselineState,
    TenantTechnologyScanItem,
    TenantTechnologyScanRequest,
    TenantTechnologyScanResponse,
    TestLogQLRequest,
    ToggleRulePauseRequest,
    ToggleTenantPauseRequest,
)
from ..rule_importer import (
    preview_rules_curated,
    build_baseline_grafana_payload,
    preview_rules_json,
    preview_rules_multiple,
)
from ..security import Session, get_current_user, require_csrf_header
from ..technologies import (
    Technology,
    TechnologyNotFound,
    TechnologyStore,
    extract_ss_groups_values,
    selector_matches_technology,
)
from ..technology_insights import (
    baseline_rules_for_technology,
    client_has_technology,
    find_implemented_rule,
    is_client_folder,
)
from ..synthetic_alerts import SyntheticAlertsStore
from ..technology_store import (
    get_synthetic_alerts_store,
    get_system_settings_store,
    get_tenant_scan_store,
    get_tenant_technology_store,
    get_technology_store,
)
from ..tenant_scan import (
    SCAN_WINDOW_SECONDS,
    TenantScanStore,
    TenantScanStoreError,
    scan_tenant_technologies,
)
from ..tenant_technologies import TenantTechnologyStoreError
from ..tenants import (
    BASELINE_RULE_GROUP,
    LOKI_DATASOURCE_TYPES,
    RULE_GROUP_INTERVAL,
    RULE_GROUP_INTERVAL_SECONDS,
    DEFAULT_TENANT_RULE_GROUP,
    anchor_rule,
    build_tenant_sandbox_datasource_payload,
    ensure_tenant_sandbox_datasource,
    find_tenant_datasource,
    find_tenant_sandbox_datasource,
    sandbox_datasource_uid,
    bind_rule_datasource,
    build_anchor_rule_payload,
    detection_rules,
    format_interval,
    get_client_datasource_uids,
    resolve_baseline_loki_datasource,
    rules_in_other_groups,
    tenant_rule_group,
)
from ..curation import (
    CURATION_QUERY_WINDOWS,
    _extract_stream_expression,
    _flatten_json_keys,
    _query_loki_lines,
)
from .deps import get_app_settings, get_grafana

logger = logging.getLogger(__name__)

# UIDs do Grafana: atÃ© 40 caracteres alfanumÃ©ricos, "-" ou "_".
# Validar aqui impede path traversal/injeÃ§Ã£o na URL repassada ao Grafana.
UID_PATTERN = r"^[A-Za-z0-9_-]{1,40}$"

router = APIRouter(dependencies=[Depends(get_current_user)])


@router.get("/rules", response_model=list[RuleSummary], tags=["rules"])
async def list_rules(
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    synthetic_store: SyntheticAlertsStore = Depends(get_synthetic_alerts_store),
) -> list[RuleSummary]:
    """Todas as regras com estado atual, ordenadas por criticidade do estado."""
    rules, groups, folders, raw_alerts = await asyncio.gather(
        grafana.list_alert_rules(),
        grafana.list_rule_groups(),
        grafana.list_folders(),
        grafana.list_alerts(),
    )
    silenced_counts: dict[str, int] = {}
    for a in raw_alerts or []:
        if not isinstance(a, dict):
            continue
        status_dict = a.get("status") or {}
        is_silenced = (
            str(status_dict.get("state") or "").lower() == "suppressed"
            or bool(status_dict.get("silencedBy"))
        )
        if is_silenced:
            labels = a.get("labels") or {}
            r_uid = str(labels.get("__alert_rule_uid__") or labels.get("rule_uid") or "").strip()
            alertname = str(labels.get("alertname") or "").strip()
            if r_uid:
                silenced_counts[r_uid] = silenced_counts.get(r_uid, 0) + 1
            if alertname:
                silenced_counts[alertname] = silenced_counts.get(alertname, 0) + 1

    for syn in synthetic_store.list_alerts():
        if syn.state == "suppressed" or syn.silenced_by:
            r_uid = str(syn.rule_uid or syn.labels.get("__alert_rule_uid__") or syn.labels.get("rule_uid") or "").strip()
            alertname = str(syn.alertname or "").strip()
            if r_uid:
                silenced_counts[r_uid] = silenced_counts.get(r_uid, 0) + 1
            if alertname:
                silenced_counts[alertname] = silenced_counts.get(alertname, 0) + 1

    stage_mapping = sys_settings.get_stage_contact_points()
    return build_rule_summaries(
        detection_rules(rules),
        groups,
        folder_titles(folders),
        stage_mapping=stage_mapping,
        silenced_counts=silenced_counts,
    )


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

@router.get(
    "/rules/paused-matches",
    response_model=PausedRulesMatchesResponse,
    tags=["rules"],
)
async def get_paused_rules_matches(
    window: str = Query("15m", pattern=r"^(15m|1h|6h|24h)$"),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> PausedRulesMatchesResponse:
    """Verifica em background via queries no Loki se regras atualmente pausadas possuem matches (eventos) nos ultimos 15 minutos."""
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_rules, raw_folders, raw_datasources = await asyncio.gather(
        grafana.list_alert_rules(),
        grafana.list_folders(),
        grafana.list_datasources(),
    )
    real_rules = detection_rules(raw_rules)
    folder_map = {str(f.get("uid") or ""): str(f.get("title") or "") for f in raw_folders}
    baseline_uid = sys_settings.get_baseline_folder_uid()

    # Detecta regras pausadas pelo campo isPaused ou por deploy_status / labels de pausa
    stage_mapping = sys_settings.get_stage_contact_points()
    paused_rules: list[dict[str, Any]] = []
    for r in real_rules:
        is_p = bool(r.get("isPaused", False))
        if not is_p:
            labels = r.get("labels") or {}
            if str(labels.get("alertstate") or "").lower() == "paused":
                is_p = True
        if not is_p and stage_mapping:
            cp = extract_contact_point(r)
            if cp and derive_deploy_status(False, cp, stage_mapping) == "paused":
                is_p = True
        if is_p:
            paused_rules.append(r)

    if not paused_rules:
        return PausedRulesMatchesResponse(
            total_paused=0,
            matching_rules_count=0,
            total_events=0,
            evaluated_at=now_iso,
            window=window,
            rules=[],
        )

    time_from = f"now-{window}"

    async def _check_rule(r: dict[str, Any]) -> PausedRuleMatchItem | None:
        r_uid = str(r.get("uid") or "")
        r_title = str(r.get("title") or "")
        f_uid = str(r.get("folderUID") or "")
        f_title = folder_map.get(f_uid, "")

        logql = _extract_rule_logql(r)
        if not logql:
            return None

        # Resolve o datasource adequado do cliente ou o Loki padrão
        target_ds = None
        if f_uid and f_uid not in (baseline_uid, "global"):
            target_ds = find_tenant_datasource(f_title, f_uid, raw_datasources)
        if not target_ds:
            lokis = [ds for ds in raw_datasources if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES]
            target_ds = resolve_baseline_loki_datasource(raw_datasources) or (lokis[0] if lokis else None)

        ds_uid = str((target_ds or {}).get("uid") or "loki")
        stream_query = _extract_stream_expression(logql)
        if not stream_query:
            return None

        try:
            ok, lines, _, _ = await _query_loki_lines(
                grafana,
                ds_uid,
                stream_query,
                limit=15,
                time_from=time_from,
                timeout=3.0,
            )
            if ok and len(lines) > 0:
                return PausedRuleMatchItem(
                    rule_uid=r_uid,
                    rule_title=r_title,
                    folder_uid=f_uid,
                    folder_title=f_title,
                    matched_events_count=len(lines),
                    matched_window=window,
                    sample_logs=lines[:3],
                )
        except Exception as exc:
            logger.debug("Erro ao consultar telemetria para regra pausada %s: %s", r_uid, exc)
        return None

    results = await asyncio.gather(*[_check_rule(r) for r in paused_rules], return_exceptions=True)
    matched_items: list[PausedRuleMatchItem] = [
        item for item in results if isinstance(item, PausedRuleMatchItem)
    ]
    total_ev = sum(item.matched_events_count for item in matched_items)

    return PausedRulesMatchesResponse(
        total_paused=len(paused_rules),
        matching_rules_count=len(matched_items),
        total_events=total_ev,
        evaluated_at=now_iso,
        window=window,
        rules=matched_items,
    )

@router.get("/rules/global-matrix", response_model=list[GlobalRuleMatrixItem], tags=["rules"])
async def get_global_rules_matrix(
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> list[GlobalRuleMatrixItem]:
    """Retorna exclusivamente todas as regras de detecÃ§Ã£o da pasta baseline ('global' ou arbitrada),
    apresentando em quais clientes (pastas) ela estÃ¡ presente com seus respectivos status.
    """
    baseline_uid = sys_settings.get_baseline_folder_uid()
    raw_rules, raw_folders = await asyncio.gather(
        grafana.list_alert_rules(),
        grafana.list_folders(),
    )

    # Identificar todas as pastas de clientes (excluindo a pasta de baseline e 'global')
    client_folders = [
        f
        for f in raw_folders
        if str(f.get("uid", "")).lower() != baseline_uid.lower()
        and str(f.get("uid", "")).lower() != "global"
        and str(f.get("title", "")).lower() != baseline_uid.lower()
        and str(f.get("title", "")).lower() != "global"
    ]

    # Identificar todas as regras que pertencem Ã  pasta baseline
    global_rules = [
        r
        for r in detection_rules(raw_rules)
        if str(r.get("folderUID", "")).lower() == baseline_uid.lower()
        or str(r.get("folderUID", "")).lower() == "global"
    ]

    # Regras nÃ£o-globais (regras dos clientes)
    client_rules = [
        r
        for r in raw_rules
        if str(r.get("folderUID", "")).lower() != baseline_uid.lower()
        and str(r.get("folderUID", "")).lower() != "global"
    ]

    matrix: list[GlobalRuleMatrixItem] = []

    for g_rule in global_rules:
        g_uid = str(g_rule.get("uid", ""))
        g_title = str(g_rule.get("title", ""))
        g_base_title = re.sub(r"^\[.*?\]\s*", "", g_title).strip().lower()

        client_coverages: list[ClientRuleCoverage] = []
        active_count = 0
        paused_count = 0

        for cf in client_folders:
            c_uid = str(cf.get("uid", ""))
            c_name = str(cf.get("title", ""))

            # Procurar regra correspondente neste cliente
            matched_c_rule = None
            for cr in client_rules:
                if str(cr.get("folderUID", "")) != c_uid:
                    continue

                annotations = cr.get("annotations") or {}
                if annotations.get("cloned_from") == g_uid:
                    matched_c_rule = cr
                    break

                cr_title = str(cr.get("title", "")).lower()
                cr_base_title = re.sub(r"^\[.*?\]\s*", "", cr_title).strip().lower()
                if g_base_title and (g_base_title == cr_base_title or g_base_title in cr_title):
                    matched_c_rule = cr
                    break

            if matched_c_rule:
                is_paused = bool(matched_c_rule.get("isPaused", False))
                rule_status: ClientRuleStatusType = "paused" if is_paused else "active"
                if is_paused:
                    paused_count += 1
                else:
                    active_count += 1

                client_coverages.append(
                    ClientRuleCoverage(
                        client_uid=c_uid,
                        client_name=c_name,
                        status=rule_status,
                        rule_uid=str(matched_c_rule.get("uid", "")),
                        rule_title=str(matched_c_rule.get("title", "")),
                    )
                )
            else:
                client_coverages.append(
                    ClientRuleCoverage(
                        client_uid=c_uid,
                        client_name=c_name,
                        status="not_implemented",
                        rule_uid=None,
                        rule_title=None,
                    )
                )

        total_c = len(client_folders)
        implemented_c = active_count + paused_count
        not_imp_c = total_c - implemented_c

        matrix.append(
            GlobalRuleMatrixItem(
                global_uid=g_uid,
                global_title=g_title,
                labels=dict(g_rule.get("labels") or {}),
                annotations=dict(g_rule.get("annotations") or {}),
                total_clients=total_c,
                implemented_clients_count=implemented_c,
                active_clients_count=active_count,
                paused_clients_count=paused_count,
                not_implemented_clients_count=not_imp_c,
                clients=client_coverages,
            )
        )

    return matrix


def get_rules_ai_service(
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    settings: Settings = Depends(get_app_settings),
):
    from ..ai.service import AIService
    return AIService(
        sys_settings=sys_settings,
        cache_path=settings.curation_ai_cache_path,
        settings=settings,
        rules_cache_path=getattr(settings, "rule_evaluation_ai_cache_path", "/data/rules-ai-evaluation-cache.json"),
    )


@router.post(
    "/rules/import/preview",
    response_model=RuleImportPreviewResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def preview_rules_import(
    payload: RuleImportPreviewRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    ai_service = Depends(get_rules_ai_service),
) -> RuleImportPreviewResponse:
    """Valida um arquivo ou bloco YAML ou JSON de regras de deteccao (Loki Ruler).

    Analisa a estrutura, executa linting LogQL, valida o seletor 'ss_groups' contra o
    catalogo de tecnologias, avalia compatibilidade de campos e telemetria no Loki dos clientes,
    e gera parecer tecnico de IA e curadoria completa.
    Nao altera o estado do sistema.
    """
    tech_store = get_technology_store()
    existing_rules = detection_rules(await grafana.list_alert_rules())
    baseline_uid = sys_settings.get_baseline_folder_uid()
    existing_titles = {
        str(r.get("title") or "").strip().lower()
        for r in existing_rules
        if str(r.get("folderUID") or "").lower() == baseline_uid.lower()
    }
    return await preview_rules_curated(
        content=payload.content,
        files=payload.files if payload.files else None,
        technology_store=tech_store,
        existing_baseline_titles=existing_titles,
        grafana=grafana,
        sys_settings=sys_settings,
        ai_service=ai_service,
    )


@router.post(
    "/rules/import",
    response_model=RuleImportExecuteResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def execute_rules_import(
    payload: RuleImportExecuteRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> RuleImportExecuteResponse:
    """Importa regras validadas no Baseline Global do Grafana.

    REGRAS DE NEGÓCIO E INVARIANTES:
    1. Regras inválidas ou com erro NÃO são importadas sob hipótese alguma.
    2. Todas as regras importadas vão SEMPRE para a pasta global (Baseline), NUNCA pasta de cliente.
    3. Data source é SEMPRE interno (Loki padrão ou selecionado).
    4. Contact Point é dinamicamente amarrado ao Contact Point real correspondente ao estágio 'stg' (Homologação).
    5. Grupo de avaliação é SEMPRE 'global-detections'.
    """
    raw_datasources, folders, raw_contact_points = await asyncio.gather(
        grafana.list_datasources(),
        grafana.list_folders(),
        grafana.list_contact_points(),
    )
    baseline_folder_uid = sys_settings.get_baseline_folder_uid()
    client_uids = get_client_datasource_uids(folders, raw_datasources, baseline_folder_uid)

    if payload.datasource_uid and payload.datasource_uid.strip():
        target_uid = payload.datasource_uid.strip()
        matched_ds = next(
            (ds for ds in raw_datasources if str(ds.get("uid") or "") == target_uid),
            None,
        )
        if not matched_ds:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Datasource Loki '{target_uid}' não foi encontrado no Grafana.",
            )
        ds_type = str(matched_ds.get("type") or "")
        if ds_type not in LOKI_DATASOURCE_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Datasource '{target_uid}' não é do tipo Loki.",
            )
        if target_uid in client_uids:
            logger.warning(
                "Tentativa de importar regras para datasource de cliente (uid=%s) bloqueada.",
                target_uid,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Data sources de clientes não podem ser selecionados para importação de regras. Selecione apenas data sources internos.",
            )
        loki_ds_uid = target_uid
    else:
        baseline_ds = resolve_baseline_loki_datasource(raw_datasources)
        loki_ds_uid = str(baseline_ds.get("uid") or "loki")

    # Resolução dinâmica do Contact Point real correspondente ao 'stg' (Homologação)
    stg_contact_point = resolve_stage_receiver(
        "stg",
        stage_mapping=sys_settings.get_stage_contact_points(),
        available_contact_points=raw_contact_points,
    )

    # Filtra estritamente as regras válidas, sem erros e que possuam tecnologia cadastrada
    valid_items = [
        item for item in payload.rules
        if item.valid and not item.errors and not getattr(item, "technology_missing", False)
    ]
    if not valid_items:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhuma regra válida fornecida para importação. Regras com erros ou sem tecnologia cadastrada não podem ser importadas.",
        )

    imported_uids: list[str] = []
    imported_titles: list[str] = []
    failed: list[dict[str, str]] = []

    target_evaluation_group = (
        payload.evaluation_group.strip()
        if payload.evaluation_group and payload.evaluation_group.strip()
        else None
    )

    for item in valid_items:
        rule_payload = build_baseline_grafana_payload(
            item=item,
            baseline_folder_uid=baseline_folder_uid,
            loki_ds_uid=loki_ds_uid,
            contact_point=stg_contact_point,
            evaluation_group=target_evaluation_group,
        )
        try:
            res = await grafana.create_alert_rule(rule_payload)
            rule_uid = str(res.get("uid") or rule_payload.get("uid") or "")
            imported_uids.append(rule_uid)
            imported_titles.append(item.title)
        except Exception as exc:
            logger.error("Falha ao persistir regra importada '%s': %s", item.title, exc)
            failed.append({"title": item.title, "error": str(exc)})

    if imported_uids:
        target_group = target_evaluation_group or BASELINE_RULE_GROUP
        await grafana.set_rule_group_interval(
            baseline_folder_uid,
            target_group,
            RULE_GROUP_INTERVAL_SECONDS,
        )

    msg = f"{len(imported_uids)} regra(s) importada(s) com sucesso na pasta Global (Baseline)."
    if failed:
        msg += f" {len(failed)} regra(s) falharam na criação no Grafana."

    return RuleImportExecuteResponse(
        message=msg,
        total=len(payload.rules),
        imported_count=len(imported_uids),
        failed_count=len(failed),
        imported_uids=imported_uids,
        imported_titles=imported_titles,
        failed=failed,
    )


@router.get(
    "/rules/evaluation-groups",
    response_model=list[str],
    tags=["rules"],
)
async def list_evaluation_groups(
    grafana: GrafanaClient = Depends(get_grafana),
) -> list[str]:
    """Lista grupos de avaliação (Evaluation Groups / ruleGroups) existentes no Grafana."""
    raw_groups, raw_rules = await asyncio.gather(
        grafana.list_rule_groups(),
        grafana.list_alert_rules(),
    )
    names: set[str] = {BASELINE_RULE_GROUP}
    for g in raw_groups:
        name = str(g.get("name") or "").strip()
        if name:
            names.add(name)
    for r in raw_rules:
        rg = str(r.get("ruleGroup") or "").strip()
        if rg:
            names.add(rg)
    sorted_others = sorted(n for n in names if n != BASELINE_RULE_GROUP)
    return [BASELINE_RULE_GROUP] + sorted_others


@router.get("/rules/{uid}", response_model=RuleDetail, tags=["rules"])
async def get_rule(
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> RuleDetail:
    """Detalhes de uma regra, incluindo queries e expressÃµes."""
    rule, groups, folders = await asyncio.gather(
        grafana.get_alert_rule(uid), grafana.list_rule_groups(), grafana.list_folders()
    )
    stage_mapping = sys_settings.get_stage_contact_points()
    return build_rule_detail(rule, groups, folder_titles(folders), stage_mapping=stage_mapping)




@router.get("/rules/{uid}/ai-evaluation", response_model=RuleImprovementEvaluation, tags=["rules"])
async def get_rule_ai_evaluation(
    uid: str = Path(pattern=UID_PATTERN),
    refresh: bool = Query(False, description="Força reavaliação completa da regra desconsiderando o cache"),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    ai_service = Depends(get_rules_ai_service),
) -> RuleImprovementEvaluation:
    """Retorna o parecer técnico da IA sobre oportunidades de melhoria na regra de detecção.

    REGRA DE NEGÓCIO: Se a regra já possui uma avaliação prévia em cache e refresh=False,
    retorna a avaliação em cache imediatamente, preservando tokens de IA e eliminando latência.
    Se a regra nunca foi analisada (cache miss) ou se refresh=True (clique explícito em 'Analisar'),
    executa a análise completa, persiste no cache e retorna o parecer atualizado.
    """
    if not refresh:
        cached = ai_service.get_cached_rule_evaluation(uid)
        if cached:
            return cached
    try:
        rule, groups, folders, datasources = await asyncio.gather(
            grafana.get_alert_rule(uid),
            grafana.list_rule_groups(),
            grafana.list_folders(),
            grafana.list_datasources(),
        )
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    stage_mapping = sys_settings.get_stage_contact_points()
    folder_map = folder_titles(folders)
    rule_detail = build_rule_detail(rule, groups, folder_map, stage_mapping=stage_mapping)

    is_paused = bool(
        rule.get("isPaused")
        or rule_detail.is_paused
        or rule_detail.deploy_status == "paused"
        or (rule.get("labels") or {}).get("alertstate") == "paused"
    )

    client_telemetry: dict[str, Any] | None = None

    # Extrai a query LogQL principal da regra
    current_query = ""
    for q in rule_detail.queries:
        if isinstance(q.model, dict) and q.model.get("expr"):
            current_query = str(q.model.get("expr") or "").strip()
            break

    # Roda telemetria nas 5 etapas progressivas no Loki do cliente
    if current_query:
        folder_uid = rule_detail.folder_uid
        folder_title = rule_detail.folder_title
        baseline_uid = sys_settings.get_baseline_folder_uid()

        target_ds = None
        client_name = folder_title or "Cliente"
        client_uid = folder_uid

        if folder_uid and folder_uid not in (baseline_uid, "global"):
            target_ds = find_tenant_datasource(folder_title, folder_uid, datasources)

        if not target_ds:
            lokis = [ds for ds in datasources if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES]
            target_ds = resolve_baseline_loki_datasource(datasources) or (lokis[0] if lokis else None)
            if folder_uid in (baseline_uid, "global"):
                client_name = "Baseline Global"

        ds_uid = str((target_ds or {}).get("uid") or "loki")
        stream_query = _extract_stream_expression(current_query)

        windows_evaluated: list[str] = []
        matched_window: str | None = None
        matched_lines: list[str] = []
        observed_fields: set[str] = set()

        for step_idx, (win_expr, win_label) in enumerate(CURATION_QUERY_WINDOWS, start=1):
            ok, lines, is_to, _ = await _query_loki_lines(
                grafana,
                ds_uid,
                stream_query,
                limit=25,
                time_from=win_expr,
                timeout=3.5,
            )
            windows_evaluated.append(win_label)

            if ok and len(lines) > 0:
                matched_window = win_label
                matched_lines = lines
                for line in lines[:15]:
                    try:
                        import json
                        data = json.loads(line)
                        if isinstance(data, dict):
                            observed_fields.update(_flatten_json_keys(data))
                    except Exception:
                        pass
                break

            # Otimização progressiva idêntica à curadoria: se janela 15m der 0 eventos, checa 3d
            if ok and step_idx == 1 and len(lines) == 0:
                last_expr, _ = CURATION_QUERY_WINDOWS[-1]
                ok_3d, lines_3d, is_to_3d, _ = await _query_loki_lines(
                    grafana,
                    ds_uid,
                    stream_query,
                    limit=25,
                    time_from=last_expr,
                    timeout=3.5,
                )
                if ok_3d and not is_to_3d and len(lines_3d) == 0:
                    windows_evaluated = [w[1] for w in CURATION_QUERY_WINDOWS]
                    break

        # Aferição de conformidade de campos
        filtered_fields = set(re.findall(r"\b(data_[a-zA-Z0-9_]+)\b", stream_query))
        if filtered_fields and observed_fields:
            matching_fields = filtered_fields.intersection(observed_fields)
            field_compat_pct = round((len(matching_fields) / len(filtered_fields)) * 100.0, 1)
        elif observed_fields:
            field_compat_pct = 100.0
        elif filtered_fields:
            field_compat_pct = 75.0 if all(f.startswith("data_") for f in filtered_fields) else 50.0
        else:
            field_compat_pct = 90.0

        client_telemetry = {
            "telemetry_evaluated": True,
            "client_name": client_name,
            "client_uid": client_uid,
            "windows_evaluated": windows_evaluated,
            "matched_window": matched_window,
            "matched_events_count": len(matched_lines),
            "sample_logs": matched_lines[:3],
            "observed_fields": sorted(list(observed_fields))[:25],
            "field_compatibility_pct": field_compat_pct,
            "is_paused_rule": is_paused,
        }

    evaluation = await ai_service.evaluate_rule_improvements(rule_detail, client_telemetry=client_telemetry)
    ai_service.set_cached_rule_evaluation(uid, evaluation)
    return evaluation


@router.post(
    "/rules/{uid}/apply-ai-suggestions",
    response_model=ApplyRuleAISuggestionsResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def apply_rule_ai_suggestions(
    payload: ApplyRuleAISuggestionsRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    settings: Settings = Depends(get_app_settings),
) -> ApplyRuleAISuggestionsResponse:
    """Aplica as melhorias recomendadas pela IA na regra de detecção no Grafana Alerting."""
    try:
        raw_rule = await grafana.get_alert_rule(uid)
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=f"Regra não encontrada: {exc.message}") from exc

    sug_query = payload.suggested_logql_query
    if sug_query:
        from ..curation import ensure_data_prefix_in_logql
        sug_query = ensure_data_prefix_in_logql(sug_query.strip())
        lint_res = lint_logql(sug_query)
        if not lint_res.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Expressão LogQL sugerida inválida no linter: {lint_res.message}",
            )

        data_queries = raw_rule.get("data") or []
        updated_query = False
        for q in data_queries:
            if isinstance(q, dict) and isinstance(q.get("model"), dict) and "expr" in q["model"]:
                q["model"]["expr"] = sug_query
                updated_query = True
                break
        if not updated_query and data_queries:
            if isinstance(data_queries[0], dict):
                data_queries[0].setdefault("model", {})["expr"] = sug_query

    if payload.suggested_labels:
        existing_labels = raw_rule.get("labels") or {}
        raw_rule["labels"] = {**existing_labels, **payload.suggested_labels}

    if payload.suggested_annotations:
        existing_annotations = raw_rule.get("annotations") or {}
        raw_rule["annotations"] = {**existing_annotations, **payload.suggested_annotations}

    if payload.suggested_for_duration:
        raw_rule["for"] = payload.suggested_for_duration

    try:
        await grafana.update_alert_rule(uid, raw_rule)
    except GrafanaError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=f"Falha ao atualizar regra no Grafana: {exc.message}",
        ) from exc

    updated_raw, groups, folders = await asyncio.gather(
        grafana.get_alert_rule(uid), grafana.list_rule_groups(), grafana.list_folders()
    )
    stage_mapping = sys_settings.get_stage_contact_points()
    updated_detail = build_rule_detail(updated_raw, groups, folder_titles(folders), stage_mapping=stage_mapping)

    # Invalida cache de IA para que a próxima análise reflita o estado atualizado
    ai_service_inst = get_rules_ai_service(sys_settings, settings)
    ai_service_inst.invalidate_rule_evaluation_cache(uid)

    return ApplyRuleAISuggestionsResponse(
        message=f"Melhorias da IA aplicadas com sucesso na regra '{updated_detail.title}'.",
        rule_uid=uid,
        rule=updated_detail,
    )


@router.post("/rules/{uid}/toggle-pause", dependencies=[Depends(require_csrf_header)], tags=["rules"])
async def toggle_rule_pause(
    payload: ToggleRulePauseRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
) -> dict[str, str]:
    """Ativa ou desativa a avaliaÃ§Ã£o de uma regra de detecÃ§Ã£o."""
    await grafana.toggle_rule_pause(uid, payload.paused)
    return {
        "message": "Status de pausa atualizado com sucesso",
        "uid": uid,
        "paused": str(payload.paused),
    }


@router.post(
    "/rules/batch-pause",
    response_model=BatchToggleRulesPauseResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def batch_toggle_rules_pause(
    payload: BatchToggleRulesPauseRequest,
    grafana: GrafanaClient = Depends(get_grafana),
) -> BatchToggleRulesPauseResponse:
    """Altera o status de pausa (isPaused) de mÃºltiplas regras de detecÃ§Ã£o de forma concorrente e segura."""
    valid_uids: list[str] = []
    failed: list[dict[str, str]] = []

    # ValidaÃ§Ã£o de seguranÃ§a: cada UID deve seguir o padrÃ£o UID_PATTERN para evitar injeÃ§Ã£o
    for uid in payload.uids:
        if re.match(UID_PATTERN, uid):
            valid_uids.append(uid)
        else:
            failed.append({"uid": uid, "error": "UID com formato invÃ¡lido"})

    async def _toggle(target_uid: str) -> tuple[str, bool, str | None]:
        try:
            await grafana.toggle_rule_pause(target_uid, payload.paused)
            return (target_uid, True, None)
        except Exception as exc:
            return (target_uid, False, str(exc))

    results = await asyncio.gather(*[_toggle(u) for u in valid_uids], return_exceptions=True)
    succeeded: list[str] = []

    for res in results:
        if isinstance(res, tuple):
            u_id, ok, err_msg = res
            if ok:
                succeeded.append(u_id)
            else:
                failed.append({"uid": u_id, "error": err_msg or "Erro ao atualizar status"})
        elif isinstance(res, Exception):
            failed.append({"uid": "desconhecido", "error": str(res)})

    action_label = "pausada(s)" if payload.paused else "reativada(s)"
    msg = f"{len(succeeded)} regra(s) {action_label} com sucesso."
    if failed:
        msg += f" {len(failed)} falha(s)."

    return BatchToggleRulesPauseResponse(
        message=msg,
        total=len(payload.uids),
        succeeded=succeeded,
        failed=failed,
    )



# --- Silences ---------------------------------------------------------------
# Tag canÃ´nica gravada no comentÃ¡rio: o Alertmanager nÃ£o expÃµe campo de
# metadados, entÃ£o a origem do silence precisa ser explÃ­cita no texto.
_SILENCE_KIND_TAGS: dict[str, str] = {
    "permanent": "[excecao]",
    "antiflood": "[antiflood]",
    "maintenance": "[manutencao]",
}

_EXISTING_TAG_RE = re.compile(r"^\s*\[[a-z0-9 _-]{2,32}\]\s*", re.IGNORECASE)


def _compose_silence_comment(kind: str, comment: str) -> str:
    """Normaliza o comentÃ¡rio: remove tag anterior e prefixa a tag da natureza."""
    body = _EXISTING_TAG_RE.sub("", comment.strip())
    tag = _SILENCE_KIND_TAGS.get(kind)
    return f"{tag} {body}" if tag else body


_INLINE_LABELS_RE = re.compile(r"\{([^}]+)\}")


def _extract_annotation_labels(raw: dict[str, Any]) -> dict[str, str]:
    """Extrai labels da anotação do Grafana (tags + bloco {k=v} do texto)."""
    labels: dict[str, str] = {}
    for tag in raw.get("tags") or []:
        if isinstance(tag, str) and ":" in tag:
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


@router.get("/alerts/history", response_model=AlertHistoryResponse, tags=["alerts"])
async def get_alerts_history(
    hours: float = Query(default=168.0, ge=0.5, le=720.0),
    grafana: GrafanaClient = Depends(get_grafana),
    synthetic_store: SyntheticAlertsStore = Depends(get_synthetic_alerts_store),
) -> AlertHistoryResponse:
    """Histórico consolidado de alertas disparados e suprimidos (Grafana annotations + Alertmanager + sintéticos)."""
    now_dt = datetime.now(timezone.utc)
    start_dt = now_dt - timedelta(hours=hours)
    now_ms = int(now_dt.timestamp() * 1000)
    from_ms = int(start_dt.timestamp() * 1000)

    try:
        raw_annotations, raw_alerts = await asyncio.gather(
            grafana.list_annotations(
                type="alert", time_from_ms=from_ms, time_to_ms=now_ms, limit=5000
            ),
            grafana.list_alerts(),
        )
    except Exception as exc:
        logger.warning("Falha ao consultar anotações/alertas do Grafana: %s", exc)
        raw_annotations = []
        raw_alerts = []

    events_by_id: dict[str, AlertHistoryEvent] = {}
    firing_timestamps: list[datetime] = []

    # 1. Anotações reais de transições de alertas registradas no Grafana Unified Alerting
    for ann in (raw_annotations if isinstance(raw_annotations, list) else []):
        if not isinstance(ann, dict):
            continue
        new_state = str(ann.get("newState") or "").strip().lower()
        if not (new_state.startswith("alerting") or new_state.startswith("firing")):
            continue

        ts_raw = ann.get("time") or ann.get("created") or ann.get("updated")
        if not isinstance(ts_raw, (int, float)) or ts_raw <= 0:
            continue
        ev_dt = datetime.fromtimestamp(float(ts_raw) / 1000.0, tz=timezone.utc)
        if ev_dt < start_dt or ev_dt > now_dt:
            continue

        firing_timestamps.append(ev_dt)
        ann_id = str(ann.get("id") or f"{int(ts_raw)}")
        alert_name = str(ann.get("alertName") or "Alerta").strip()
        labels = _extract_annotation_labels(ann)

        events_by_id[ann_id] = AlertHistoryEvent(
            id=ann_id,
            alertname=alert_name,
            rule_uid=str(ann.get("alertUID") or "") or None,
            timestamp=ev_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            state="firing",
            labels=labels,
            text=str(ann.get("text") or ""),
        )

    # 2. Instâncias do Alertmanager atualmente ativas ou suprimidas
    alerts = build_alerts(raw_alerts if isinstance(raw_alerts, list) else [])
    for inst in alerts:
        if not inst.starts_at:
            continue
        try:
            inst_dt = datetime.fromisoformat(inst.starts_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if inst_dt.tzinfo is None:
            inst_dt = inst_dt.replace(tzinfo=timezone.utc)
        if inst_dt < start_dt or inst_dt > now_dt:
            continue

        state_key = "silenced" if inst.state == "suppressed" else "firing"
        already_tracked = any(
            abs((inst_dt - f_dt).total_seconds()) <= 120 for f_dt in firing_timestamps
        )
        if state_key == "firing" and already_tracked:
            continue

        inst_id = f"am-{inst.fingerprint}"
        events_by_id[inst_id] = AlertHistoryEvent(
            id=inst_id,
            alertname=inst.alertname,
            rule_uid=inst.rule_uid,
            timestamp=inst_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            state=state_key,
            labels=dict(inst.labels),
            text=(
                inst.annotations.get("summary")
                or inst.annotations.get("description")
                or inst.alertname
            ),
        )

    # 3. Alertas sintéticos para testes e laboratório
    synthetic = synthetic_store.list_alerts()
    for syn in synthetic:
        if not syn.starts_at:
            continue
        try:
            syn_dt = datetime.fromisoformat(syn.starts_at.replace("Z", "+00:00"))
        except ValueError:
            continue
        if syn_dt.tzinfo is None:
            syn_dt = syn_dt.replace(tzinfo=timezone.utc)
        if syn_dt < start_dt or syn_dt > now_dt:
            continue

        syn_id = f"syn-{syn.fingerprint}"
        state_key = "silenced" if syn.state == "suppressed" else "firing"
        events_by_id[syn_id] = AlertHistoryEvent(
            id=syn_id,
            alertname=syn.alertname,
            rule_uid=syn.rule_uid,
            timestamp=syn_dt.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            state=state_key,
            labels=dict(syn.labels),
            text=(
                syn.annotations.get("summary")
                or syn.annotations.get("description")
                or syn.alertname
            ),
        )

    events_list = sorted(events_by_id.values(), key=lambda e: e.timestamp, reverse=True)
    firing_cnt = sum(1 for e in events_list if e.state == "firing")
    silenced_cnt = sum(1 for e in events_list if e.state == "silenced")

    return AlertHistoryResponse(
        window_hours=hours,
        total_events=len(events_list),
        firing_count=firing_cnt,
        silenced_count=silenced_cnt,
        events=events_list,
    )


@router.get("/alerts", response_model=list[AlertInstance], tags=["alerts"])
async def list_alerts(
    grafana: GrafanaClient = Depends(get_grafana),
    synthetic_store: SyntheticAlertsStore = Depends(get_synthetic_alerts_store),
) -> list[AlertInstance]:
    """Instâncias de alerta atuais (reais do Alertmanager + fictícias/sintéticas)."""
    raw_alerts = await grafana.list_alerts()
    alerts = build_alerts(raw_alerts)
    synthetic = synthetic_store.list_alerts()
    if synthetic:
        seen = {a.fingerprint for a in alerts if a.fingerprint}
        for syn in synthetic:
            if syn.fingerprint not in seen:
                alerts.append(syn)
                seen.add(syn.fingerprint)
        alerts.sort(key=lambda a: a.starts_at or "", reverse=True)
        alerts.sort(key=lambda a: 0 if a.state == "active" else 1)
    return alerts


@router.post(
    "/alerts/synthetic/generate",
    response_model=list[AlertInstance],
    dependencies=[Depends(require_csrf_header)],
    tags=["alerts"],
)
async def generate_synthetic_alerts(
    payload: GenerateSyntheticAlertsRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    synthetic_store: SyntheticAlertsStore = Depends(get_synthetic_alerts_store),
) -> list[AlertInstance]:
    """Gera uma sequência cronológica de alertas fictícios a partir de uma regra para validar histogramas."""
    target_rule: dict[str, Any] | None = None
    if payload.rule_uid:
        try:
            target_rule = await grafana.get_alert_rule(payload.rule_uid)
        except GrafanaError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail=f"Regra {payload.rule_uid} não encontrada: {exc.message}",
            ) from exc
    else:
        # Busca automaticamente uma regra de baseline não interna e não pausada
        rules = await grafana.list_alert_rules()
        for r in rules:
            if r.get("isPaused"):
                continue
            labels = r.get("labels") or {}
            if labels.get("portal_internal") == "rule_group_anchor":
                continue
            target_rule = r
            break

    if not target_rule:
        target_rule = {
            "uid": "ghp-det-demo",
            "title": "Linux - SSH Força Bruta Detectada",
            "folderUID": "global",
            "labels": {
                "technology": "linux",
                "technology_name": "Linux",
                "severity": "high",
                "mitre_tactic": "credential-access",
                "mitre_technique": "T1110",
                "scope": "baseline",
                "client": "global",
            },
        }

    return synthetic_store.generate_chronological_sequence(
        target_rule, count=payload.count or 15
    )


@router.delete(
    "/alerts/synthetic",
    response_model=ClearSyntheticAlertsResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["alerts"],
)
async def clear_synthetic_alerts(
    synthetic_store: SyntheticAlertsStore = Depends(get_synthetic_alerts_store),
    user: Session = Depends(get_current_user),
) -> ClearSyntheticAlertsResponse:
    """Limpa todos os alertas fictícios/sintéticos."""
    cleared = synthetic_store.clear()
    return ClearSyntheticAlertsResponse(status="ok", cleared=cleared)


@router.get("/silences", response_model=list[Silence], tags=["silences"])
async def list_silences(
    grafana: GrafanaClient = Depends(get_grafana),
    synthetic_store: SyntheticAlertsStore = Depends(get_synthetic_alerts_store),
) -> list[Silence]:
    """Silences com contagem exata e lista de alertas atualmente suprimidos em tempo real."""
    silences_raw, alerts_raw = await asyncio.gather(
        grafana.list_silences(), grafana.list_alerts()
    )
    synthetic_alerts = synthetic_store.list_alerts()
    return build_silences(silences_raw, alerts_raw, synthetic_alerts)


@router.post(
    "/silences",
    response_model=CreateSilenceResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["silences"],
)
async def create_silence(
    payload: CreateSilenceRequest,
    user: Session = Depends(get_current_user),
    grafana: GrafanaClient = Depends(get_grafana),
) -> CreateSilenceResponse:
    """Cria um novo silence no Grafana Alertmanager."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    matchers = [
        {
            "name": m.name,
            "value": m.value,
            "isRegex": m.is_regex,
            "isEqual": m.is_equal,
        }
        for m in payload.matchers
    ]

    # ExceÃ§Ã£o permanente: vigÃªncia fixa de 10 anos (mesma semÃ¢ntica do portal),
    # garantindo que o silence nunca volte a expirar por decurso de prazo.
    ends_at = payload.ends_at
    if payload.kind == "permanent":
        ends_at = (datetime.now(timezone.utc) + timedelta(days=3652)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    grafana_payload = {
        "matchers": matchers,
        "startsAt": payload.starts_at or now_iso,
        "endsAt": ends_at,
        "createdBy": user.username,
        "comment": _compose_silence_comment(payload.kind, payload.comment),
    }
    silence_id = await grafana.create_silence(grafana_payload)
    return CreateSilenceResponse(silence_id=silence_id)


@router.post(
    "/silences/{silence_id}/extend",
    response_model=CreateSilenceResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["silences"],
)
async def extend_silence(
    payload: ExtendSilenceRequest,
    silence_id: str = Path(pattern=r"^[A-Za-z0-9_-]{1,64}$"),
    user: Session = Depends(get_current_user),
    grafana: GrafanaClient = Depends(get_grafana),
) -> CreateSilenceResponse:
    """Prolonga a duraÃ§Ã£o de um silence (opÃ§Ãµes: +2h, +4h, +8h, +24h, +3d, permanente (10y))."""
    current_silence = await grafana.get_silence(silence_id)
    ends_at_str = current_silence.get("endsAt")
    now_dt = datetime.now(timezone.utc)

    base_dt = now_dt
    if ends_at_str:
        try:
            parsed_dt = datetime.fromisoformat(ends_at_str.replace("Z", "+00:00"))
            if parsed_dt > now_dt:
                base_dt = parsed_dt
        except Exception:
            pass

    deltas = {
        "2h": timedelta(hours=2),
        "4h": timedelta(hours=4),
        "8h": timedelta(hours=8),
        "24h": timedelta(hours=24),
        "3d": timedelta(days=3),
        "10y": timedelta(days=3652),  # 10 anos
    }
    delta = deltas.get(payload.duration, timedelta(hours=2))
    new_ends_dt = base_dt + delta
    new_ends_at = new_ends_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    res_id = await grafana.extend_silence(silence_id, new_ends_at, user.username)
    return CreateSilenceResponse(silence_id=res_id)



@router.delete(
    "/silences/{silence_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf_header)],
    tags=["silences"],
)
async def delete_silence(
    silence_id: str = Path(pattern=r"^[A-Za-z0-9_-]{1,64}$"),
    grafana: GrafanaClient = Depends(get_grafana),
) -> Response:
    """Expira um silence existente no Grafana Alertmanager."""
    await grafana.delete_silence(silence_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Pastas / Clientes SIEM -------------------------------------------------
@router.get("/folders", response_model=list[FolderItem], tags=["folders"])
async def list_folders(grafana: GrafanaClient = Depends(get_grafana)) -> list[FolderItem]:
    """Lista todas as pastas do Grafana (representando os clientes integrados)."""
    raw_folders = await grafana.list_folders()
    return [
        FolderItem(id=f.get("id"), uid=str(f.get("uid", "")), title=str(f.get("title", "")))
        for f in raw_folders
    ]


@router.post(
    "/folders",
    response_model=FolderItem,
    dependencies=[Depends(require_csrf_header)],
    tags=["folders"],
)
async def create_folder(
    payload: CreateFolderRequest,
    grafana: GrafanaClient = Depends(get_grafana),
) -> FolderItem:
    """Cria uma nova pasta/cliente no Grafana."""
    res = await grafana.create_folder(payload.title, payload.uid)
    return FolderItem(
        id=res.get("id"),
        uid=str(res.get("uid", payload.uid or "")),
        title=str(res.get("title", payload.title)),
    )


# --- Tenants (Pastas de Clientes Grafana) ------------------------------------
# Cada tenant Ã© um par de recursos no Grafana: uma pasta (`grafana_folder`) para
# regras/dashboards e um data source Loki com o mesmo nome do tenant, que Ã© a
# fronteira lÃ³gica de telemetria daquele cliente.
LOKI_DATASOURCE_TYPES = {"loki", "grafana-loki-datasource"}

# UIDs de data source de sistema/stack que nÃ£o podem ser reaproveitados por tenant.
RESERVED_DATASOURCE_UIDS = {"loki", "testdata", "grafana", "global", "portal"}


def _validate_loki_url(raw: str | None, default_url: str) -> str:
    """Valida e normaliza a URL do Loki do tenant.

    Vazio = usa a URL padrÃ£o configurada (`LOKI_TENANT_DATASOURCE_URL`). SÃ³
    http(s) Ã© aceito; a URL Ã© repassada ao Grafana, entÃ£o nÃ£o pode virar vetor
    de esquema arbitrÃ¡rio (file://, gopher:// etc.).
    """
    value = (raw or "").strip()
    if not value:
        return default_url
    if not value.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A URL do Loki deve comeÃ§ar com http:// ou https://.",
        )
    if len(value) > 200:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A URL do Loki excede o tamanho mÃ¡ximo de 200 caracteres.",
        )
    return value.rstrip("/")


def _build_tenant_datasource_payload(title: str, uid: str, url: str) -> dict[str, Any]:
    """Payload de criaÃ§Ã£o do data source Loki do tenant (nome = nome do tenant)."""
    return {
        "name": title,
        "uid": uid,
        "type": "loki",
        "access": "proxy",
        "url": url,
        "isDefault": False,
        "editable": True,
        "jsonData": {
            "maxLines": 1000,
            "timeout": 30,
        },
    }


async def _rollback_tenant_creation(
    grafana: GrafanaClient, folder_uid: str, datasource_uid: str
) -> None:
    """Desfaz a criaÃ§Ã£o de um tenant que falhou no meio (data source + pasta).

    A ordem Ã© inversa Ã  criaÃ§Ã£o: data source primeiro, pasta depois. A pasta pode
    conter a Ã¢ncora do grupo de avaliaÃ§Ã£o, entÃ£o a exclusÃ£o usa
    ``force_delete_rules`` â€” a criaÃ§Ã£o nunca chega aqui com regras de cliente.
    """
    try:
        await grafana.delete_datasource(datasource_uid)
    except GrafanaError:
        logger.warning(
            "Rollback de tenant: data source %s jÃ¡ ausente ou nÃ£o removÃ­vel", datasource_uid
        )
    try:
        await grafana.delete_datasource(sandbox_datasource_uid(datasource_uid))
    except GrafanaError:
        pass
    try:
        await grafana.delete_folder(folder_uid, force_delete_rules=True)
    except GrafanaError:
        logger.error("Rollback de tenant: falha ao remover a pasta %s", folder_uid)


def _find_tenant_datasource(
    title: str, uid: str, datasources: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Localiza o data source Loki do tenant (por UID; fallback por nome)."""
    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
    ]
    for datasource in lokis:
        if str(datasource.get("uid") or "") in (uid, f"{uid}-loki"):
            return datasource
    normalized = title.strip().casefold()
    for datasource in lokis:
        if str(datasource.get("name") or "").strip().casefold() == normalized:
            return datasource
    return None


def _tenant_summary(
    folder: dict[str, Any],
    folder_rules: list[dict[str, Any]],
    datasource: dict[str, Any] | None,
    default_loki_url: str,
    evaluation_groups: list[dict[str, Any]] | None = None,
    scan_record: dict[str, Any] | None = None,
    settings: Settings | None = None,
    sandbox_datasource: dict[str, Any] | None = None,
) -> TenantSummary:
    """Monta o resumo do tenant: data source Loki + grupo de avaliaÃ§Ã£o.

    ``folder_rules`` deve conter as regras **incluindo** a Ã¢ncora interna (para
    derivar a presenÃ§a do grupo), mas as contagens usam apenas regras reais.

    ``scan_record`` Ã© o snapshot do Ãºltimo escaneamento de tecnologias (Loki do
    prÃ³prio cliente); a contagem exibida na tabela vem dele, nunca de uma
    reconsulta ao Loki a cada render.
    """
    rules = detection_rules(folder_rules)
    active_count = sum(1 for r in rules if not r.get("isPaused", False))
    paused_count = sum(1 for r in rules if r.get("isPaused", False))
    datasource_url = str((datasource or {}).get("url") or "") or None
    title = str(folder.get("title") or "")
    uid = str(folder.get("uid") or "")

    # Grupo de avaliaÃ§Ã£o: nome canÃ´nico + intervalo real lido do Grafana.
    group_name = tenant_rule_group(title)
    group = next(
        (
            g
            for g in (evaluation_groups or [])
            if str(g.get("folderUid") or "") == uid and str(g.get("name") or "") == group_name
        ),
        None,
    )
    group_interval = format_interval((group or {}).get("interval"))

    # PresenÃ§a do grupo: derivada das regras provisionadas da pasta (a Ã¢ncora
    # interna conta), sem depender sÃ³ do endpoint Prometheus â€” ele Ã© uma projeÃ§Ã£o
    # do ruler e pode nÃ£o refletir grupos recÃ©m-criados/parcialmente materializados.
    # O intervalo continua vindo do ruler quando disponÃ­vel.
    group_present = group is not None or any(
        str(rule.get("ruleGroup") or "") == group_name
        for rule in (folder_rules or [])
    )

    # Coleta todos os evaluation groups desta pasta (para o seletor drop-down do tenant)
    # Inclui grupos reportados pela API de regras e/ou derivados das regras existentes na pasta
    folder_groups_map: dict[str, dict[str, Any]] = {}
    for g in (evaluation_groups or []):
        if str(g.get("folderUid") or "") == uid:
            g_name = str(g.get("name") or "")
            if g_name:
                folder_groups_map[g_name] = {
                    "name": g_name,
                    "interval": format_interval(g.get("interval")),
                    "rules_count": len(detection_rules(g.get("rules"))),
                }

    for r in (folder_rules or []):
        rg_name = str(r.get("ruleGroup") or "")
        if rg_name and rg_name not in folder_groups_map:
            folder_groups_map[rg_name] = {
                "name": rg_name,
                "interval": None,
                "rules_count": sum(1 for rule in detection_rules(folder_rules) if str(rule.get("ruleGroup") or "") == rg_name),
            }

    # Se o grupo canÃ´nico foi materializado ou existe, garante seu rules_count real
    if group_name in folder_groups_map:
        folder_groups_map[group_name]["rules_count"] = sum(
            1 for rule in rules if str(rule.get("ruleGroup") or "") == group_name
        )

    all_folder_groups = sorted(folder_groups_map.values(), key=lambda x: str(x.get("name") or "").lower())

    return TenantSummary(
        id=folder.get("id"),
        uid=uid,
        title=title,
        rules_count=len(rules),
        active_rules_count=active_count,
        paused_rules_count=paused_count,
        rules_uids=[str(r.get("uid")) for r in rules if r.get("uid")],
        loki_datasource_name=str((datasource or {}).get("name") or "") or None,
        loki_datasource_uid=str((datasource or {}).get("uid") or "") or None,
        loki_datasource_url=datasource_url,
        loki_datasource_present=datasource is not None,
        loki_datasource_url_matches=(
            datasource is None
            or datasource_url is None
            or datasource_url.rstrip("/") == default_loki_url.rstrip("/")
        ),
        evaluation_group=group_name,
        evaluation_group_interval=group_interval or RULE_GROUP_INTERVAL,
        evaluation_group_present=group_present,
        evaluation_groups=all_folder_groups,
        evaluation_group_optional=getattr(settings, "is_external_grafana", False) if hasattr(settings, "is_external_grafana") else False,
        technologies_count=sum(
            1
            for item in (scan_record or {}).get("technologies", [])
            if item.get("found")
        ),
        technologies_scanned_at=((scan_record or {}).get("scanned_at") or None),
        sandbox_datasource_present=sandbox_datasource is not None,
        sandbox_datasource_name=str((sandbox_datasource or {}).get("name") or "") or None,
        sandbox_datasource_uid=str((sandbox_datasource or {}).get("uid") or "") or None,
    )


@router.get("/tenants", response_model=list[TenantSummary], tags=["tenants"])
async def list_tenants(
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
    scan_store: TenantScanStore = Depends(get_tenant_scan_store),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> list[TenantSummary]:
    """Lista os tenants (pastas do Grafana, exceto global/baseline) com data source Loki e grupo.

    As regras internas do portal (Ã¢ncora do grupo de avaliaÃ§Ã£o) nunca entram nas
    contagens de detecÃ§Ã£o. A coluna de tecnologias vem do snapshot do Ãºltimo
    escaneamento (``POST /tenants/{uid}/technologies/scan``).
    """
    baseline_uid = sys_settings.get_baseline_folder_uid()
    raw_folders, raw_rules, raw_datasources, raw_groups = await asyncio.gather(
        grafana.list_folders(),
        grafana.list_alert_rules(),
        grafana.list_datasources(),
        grafana.list_rule_groups(),
    )

    try:
        scan_records = {
            uid: scan_store.record_for(uid)
            for uid in (str(f.get("uid") or "") for f in raw_folders)
            if uid
        }
    except TenantScanStoreError as exc:
        # O snapshot Ã© complementar: sem ele a pÃ¡gina continua operÃ¡vel, sÃ³ sem
        # a contagem de tecnologias.
        logger.warning("Falha ao ler o snapshot de escaneamento: %s", exc)
        scan_records = {}

    # Agrupa regras por folderUID â€” incluindo a Ã¢ncora interna, necessÃ¡ria para
    # provar a existÃªncia do grupo de avaliaÃ§Ã£o (as contagens filtram em
    # detection_rules, entÃ£o ela continua fora dos nÃºmeros de detecÃ§Ã£o).
    rules_by_folder: dict[str, list[dict[str, Any]]] = {}
    for r in raw_rules:
        f_uid = str(r.get("folderUID") or "")
        if f_uid:
            rules_by_folder.setdefault(f_uid, []).append(r)

    tenants: list[TenantSummary] = []
    for f in raw_folders:
        uid = str(f.get("uid") or "")
        title = str(f.get("title") or "")
        # Filtra a pasta Global / Baseline
        if (
            uid.lower() == baseline_uid.lower()
            or uid.lower() == "global"
            or title.strip().lower() == baseline_uid.lower()
            or title.strip().lower() == "global"
        ):
            continue

        tenants.append(
            _tenant_summary(
                f,
                rules_by_folder.get(uid, []),
                _find_tenant_datasource(title, uid, raw_datasources),
                settings.loki_tenant_datasource_url,
                raw_groups,
                scan_records.get(uid),
                settings=settings,
                sandbox_datasource=find_tenant_sandbox_datasource(title, uid, raw_datasources),
            )
        )

    tenants.sort(key=lambda t: t.title.lower())
    return tenants


@router.post(
    "/tenants",
    response_model=TenantSummary,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def create_tenant(
    payload: CreateTenantRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
) -> TenantSummary:
    """Cria um tenant: pasta no Grafana + data source Loki com o mesmo nome.

    A operaÃ§Ã£o Ã© transacional do ponto de vista do portal: se o data source
    falhar, a pasta recÃ©m-criada Ã© removida para nÃ£o deixar cliente pela metade
    (sem fronteira de telemetria).
    """
    clean_title = payload.title.strip()
    if not clean_title:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O nome do tenant Ã© obrigatÃ³rio.",
        )
    if clean_title.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NÃ£o Ã© permitido criar um tenant com o nome reservado 'Global'.",
        )
    requested_uid = (payload.uid or "").strip() or None
    if requested_uid and requested_uid.lower() in RESERVED_DATASOURCE_UIDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"O UID '{requested_uid}' Ã© reservado por um data source de sistema.",
        )

    loki_url = _validate_loki_url(payload.loki_url, settings.loki_tenant_datasource_url)

    # Nome do data source Ã© o nome do tenant: precisa ser Ãºnico no Grafana.
    raw_datasources = await grafana.list_datasources()
    for datasource in raw_datasources:
        if str(datasource.get("name") or "").strip().casefold() == clean_title.casefold():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"JÃ¡ existe um data source chamado '{clean_title}' no Grafana. "
                    "Um tenant exige um data source Loki exclusivo com o prÃ³prio nome."
                ),
            )

    folder = await grafana.create_folder(clean_title, requested_uid)
    folder_uid = str(folder.get("uid") or requested_uid or "")

    # UID do data source acompanha o UID da pasta (1:1), salvo colisÃ£o.
    datasource_uid = folder_uid
    if any(str(ds.get("uid") or "") == datasource_uid for ds in raw_datasources):
        datasource_uid = f"{folder_uid}-loki"

    datasource_info = {
        "name": clean_title,
        "uid": datasource_uid,
        "url": loki_url,
    }

    try:
        created = await grafana.create_datasource(
            _build_tenant_datasource_payload(clean_title, datasource_uid, loki_url)
        )
        # Data source sandbox é ativado sob demanda via switch na tela de Tenants
        datasource_info.update(
            {
                "name": str(created.get("name") or clean_title),
                "uid": str(created.get("uid") or datasource_uid),
                "url": str(created.get("url") or loki_url),
            }
        )
        # Grupo de avaliação: o Grafana não guarda grupo vazio, então a âncora
        # (regra interna pausada) materializa o grupo canônico '5m' com intervalo 5m.
        # Em modo Grafana externo, a criação do grupo canônico é opcional:
        # falha ao criar âncora não aborta a criação do tenant.
        if not settings.is_external_grafana:
            await grafana.create_alert_rule(build_anchor_rule_payload(folder_uid, clean_title))
            await grafana.set_rule_group_interval(
                folder_uid, DEFAULT_TENANT_RULE_GROUP, RULE_GROUP_INTERVAL_SECONDS
            )
        else:
            try:
                await grafana.create_alert_rule(build_anchor_rule_payload(folder_uid, clean_title))
                await grafana.set_rule_group_interval(
                    folder_uid, DEFAULT_TENANT_RULE_GROUP, RULE_GROUP_INTERVAL_SECONDS
                )
            except GrafanaError as exc:
                logger.info(
                    "Modo Grafana externo: criação da âncora para '%s' falhou ou ignorada (%s). Prosseguindo.",
                    clean_title,
                    exc,
                )
    except GrafanaError as exc:
        # Rollback: sem data source e sem grupo o tenant nÃ£o estÃ¡ segregado.
        await _rollback_tenant_creation(grafana, folder_uid, datasource_uid)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"A pasta foi criada, mas os recursos do tenant '{clean_title}' nÃ£o puderam "
                f"ser criados ({exc}); a criaÃ§Ã£o foi revertida. Verifique o Grafana e tente novamente."
            ),
        ) from exc

    try:
        groups = await grafana.list_rule_groups()
    except GrafanaError:
        groups = []

    raw_ds_after = await grafana.list_datasources()
    sb_after = find_tenant_sandbox_datasource(clean_title, folder_uid, raw_ds_after)
    return _tenant_summary(
        folder,
        [],
        datasource_info,
        settings.loki_tenant_datasource_url,
        groups,
        settings=settings,
        sandbox_datasource=sb_after,
    )


@router.post(
    "/tenants/{uid}/datasource",
    response_model=TenantDatasourceResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def create_tenant_datasource(
    payload: CreateTenantDatasourceRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
) -> TenantDatasourceResponse:
    """Cria o data source Loki de um tenant existente (backfill ou correÃ§Ã£o).

    Ãštil para tenants cadastrados antes desta regra ou cujo data source foi
    removido manualmente no Grafana. Idempotente por nome: se jÃ¡ existir, recusa
    com 409 em vez de duplicar.
    """
    if uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O tenant 'Global' Ã© o baseline institucional e nÃ£o possui data source prÃ³prio.",
        )

    folders = await grafana.list_folders()
    folder = next((f for f in folders if str(f.get("uid") or "") == uid), None)
    if folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant nÃ£o encontrado no Grafana.",
        )
    title = str(folder.get("title") or "").strip()

    loki_url = _validate_loki_url(payload.loki_url, settings.loki_tenant_datasource_url)
    raw_datasources = await grafana.list_datasources()
    existing = _find_tenant_datasource(title, uid, raw_datasources)
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"O tenant '{title}' jÃ¡ possui o data source Loki "
                f"'{existing.get('name')}' (uid: {existing.get('uid')})."
            ),
        )

    datasource_uid = uid
    if any(str(ds.get("uid") or "") == datasource_uid for ds in raw_datasources):
        datasource_uid = f"{uid}-loki"

    created = await grafana.create_datasource(
        _build_tenant_datasource_payload(title, datasource_uid, loki_url)
    )
    return TenantDatasourceResponse(
        message=f"Data source Loki '{title}' criado para o tenant.",
        uid=uid,
        datasource_name=str(created.get("name") or title),
        datasource_uid=str(created.get("uid") or datasource_uid),
        datasource_url=str(created.get("url") or loki_url),
    )



@router.post(
    "/tenants/{uid}/sandbox",
    response_model=TenantSandboxResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def enable_tenant_sandbox(
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
) -> TenantSandboxResponse:
    """Ativa e cria o data source de SANDBOX de um cliente no Grafana."""
    if uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O tenant 'Global' é o baseline institucional e não possui sandbox de cliente.",
        )

    folders = await grafana.list_folders()
    folder = next((f for f in folders if str(f.get("uid") or "") == uid), None)
    if folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant não encontrado no Grafana.",
        )
    title = str(folder.get("title") or "").strip()

    raw_datasources = await grafana.list_datasources()
    existing_sb = find_tenant_sandbox_datasource(title, uid, raw_datasources)
    if existing_sb is not None:
        sb_name = str(existing_sb.get("name") or sandbox_datasource_name(title))
        sb_uid = str(existing_sb.get("uid") or sandbox_datasource_uid(uid))
        return TenantSandboxResponse(
            message=f"Data source de sandbox '{sb_name}' já está ativo para o tenant.",
            uid=uid,
            sandbox_datasource_name=sb_name,
            sandbox_datasource_uid=sb_uid,
            present=True,
        )

    prod_ds = _find_tenant_datasource(title, uid, raw_datasources)
    prod_uid = str((prod_ds or {}).get("uid") or uid)
    loki_url = str((prod_ds or {}).get("url") or settings.loki_tenant_datasource_url)

    payload = build_tenant_sandbox_datasource_payload(title, prod_uid, loki_url)
    try:
        created = await grafana.create_datasource(payload)
    except GrafanaError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha ao criar data source de sandbox no Grafana: {exc.message}",
        )

    sb_name = str(created.get("name") or payload["name"])
    sb_uid = str(created.get("uid") or payload["uid"])
    return TenantSandboxResponse(
        message=f"Data source de sandbox '{sb_name}' criado e ativado com sucesso.",
        uid=uid,
        sandbox_datasource_name=sb_name,
        sandbox_datasource_uid=sb_uid,
        present=True,
    )


@router.delete(
    "/tenants/{uid}/sandbox",
    response_model=TenantSandboxResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def disable_tenant_sandbox(
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
) -> TenantSandboxResponse:
    """Desativa e exclui o data source de SANDBOX de um cliente no Grafana."""
    if uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O tenant 'Global' é o baseline institucional e não possui sandbox de cliente.",
        )

    folders = await grafana.list_folders()
    folder = next((f for f in folders if str(f.get("uid") or "") == uid), None)
    if folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant não encontrado no Grafana.",
        )
    title = str(folder.get("title") or "").strip()

    raw_datasources = await grafana.list_datasources()
    existing_sb = find_tenant_sandbox_datasource(title, uid, raw_datasources)
    if existing_sb is None:
        return TenantSandboxResponse(
            message=f"O tenant '{title}' já não possui data source de sandbox ativo.",
            uid=uid,
            sandbox_datasource_name=sandbox_datasource_name(title),
            sandbox_datasource_uid=sandbox_datasource_uid(uid),
            present=False,
        )

    sb_uid = str(existing_sb.get("uid") or sandbox_datasource_uid(uid))
    sb_name = str(existing_sb.get("name") or sandbox_datasource_name(title))

    try:
        await grafana.delete_datasource(sb_uid)
    except GrafanaError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha ao remover data source de sandbox no Grafana: {exc.message}",
        )

    return TenantSandboxResponse(
        message=f"Data source de sandbox '{sb_name}' excluído com sucesso do Grafana.",
        uid=uid,
        sandbox_datasource_name=sb_name,
        sandbox_datasource_uid=sb_uid,
        present=False,
    )

@router.post(
    "/tenants/{uid}/evaluation-group",
    response_model=TenantEvaluationGroupResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def repair_tenant_evaluation_group(
    payload: RepairEvaluationGroupRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
) -> TenantEvaluationGroupResponse:
    """Garante o grupo de avaliaÃ§Ã£o canÃ´nico de um tenant (backfill/correÃ§Ã£o).

    O padrÃ£o de tenant exige **trÃªs** recursos: pasta, data source Loki homÃ´nimo
    e grupo ``5m`` (intervalo ``5m``). Tenants cadastrados antes
    dessa regra â€” ou com regras em grupo divergente â€” ficam visivelmente fora do
    padrÃ£o (badge *grupo padrÃ£o ausente*). Esta rota corrige o desvio de forma
    idempotente:

    1. materializa o grupo com a regra-Ã¢ncora pausada, se ele nÃ£o existir;
    2. realinha a Ã¢ncora caso ela esteja em grupo divergente;
    3. com ``migrate_rules``, move as regras de detecÃ§Ã£o da pasta para o grupo
       canÃ´nico (sem tocar no conteÃºdo da query/regra).
    """
    if uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="O tenant 'Global' Ã© o baseline institucional e usa o grupo 'global-detections'.",
        )

    folders = await grafana.list_folders()
    folder = next((f for f in folders if str(f.get("uid") or "") == uid), None)
    if folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant nÃ£o encontrado no Grafana.",
        )
    title = str(folder.get("title") or "").strip()
    group_name = tenant_rule_group(title)

    raw_rules = await grafana.list_alert_rules()
    anchor = anchor_rule(raw_rules, uid)
    anchor_created = False
    anchor_uid = str((anchor or {}).get("uid") or "") or None

    if anchor is None:
        anchor_payload = build_anchor_rule_payload(uid, title)
        try:
            created = await grafana.create_alert_rule(anchor_payload)
        except GrafanaError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"O grupo de avaliaÃ§Ã£o '{group_name}' do tenant '{title}' nÃ£o pÃ´de ser "
                    f"materializado no Grafana ({exc}). O tenant segue fora do padrÃ£o."
                ),
            ) from exc
        anchor_created = True
        anchor_uid = str(created.get("uid") or anchor_payload["uid"])
    elif str(anchor.get("ruleGroup") or "") != group_name:
        # Ã‚ncora apontando para um grupo divergente (renomeaÃ§Ã£o manual no Grafana).
        if not anchor_uid:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"A regra-Ã¢ncora do tenant '{title}' nÃ£o possui UID legÃ­vel no Grafana.",
            )
        try:
            anchor_detail = await grafana.get_alert_rule(anchor_uid)
            anchor_detail["ruleGroup"] = group_name
            await grafana.update_alert_rule(anchor_uid, anchor_detail)
        except GrafanaError as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=(
                    f"A regra-Ã¢ncora do tenant '{title}' estÃ¡ no grupo "
                    f"'{anchor.get('ruleGroup')}' e nÃ£o pÃ´de ser realinhada para "
                    f"'{group_name}' ({exc})."
                ),
            ) from exc

    migrated: list[str] = []
    migration_failures: list[dict[str, str]] = []
    outside_group = rules_in_other_groups(raw_rules, uid, group_name)
    if payload.migrate_rules:
        for rule in outside_group:
            rule_uid = str(rule.get("uid") or "")
            if not rule_uid:
                continue
            try:
                rule_detail = await grafana.get_alert_rule(rule_uid)
                rule_detail["ruleGroup"] = group_name
                await grafana.update_alert_rule(rule_uid, rule_detail)
                migrated.append(rule_uid)
            except Exception as exc:  # noqa: BLE001 - falha isolada por regra
                migration_failures.append({"uid": rule_uid, "error": str(exc)})

    await grafana.set_rule_group_interval(uid, group_name, RULE_GROUP_INTERVAL_SECONDS, force=True)
    # Estado final (fonte de verdade: Grafana, não o payload de entrada).
    try:
        raw_groups = await grafana.list_rule_groups()
    except GrafanaError:
        raw_groups = []
    final_rules = await grafana.list_alert_rules()
    raw_datasources = await grafana.list_datasources()
    summary = _tenant_summary(
        folder,
        [r for r in final_rules if str(r.get("folderUID") or "") == uid],
        _find_tenant_datasource(title, uid, raw_datasources),
        settings.loki_tenant_datasource_url,
        raw_groups,
    )

    parts: list[str] = []
    if anchor_created:
        parts.append(f"Grupo de avaliação '{group_name}' criado com intervalo {RULE_GROUP_INTERVAL}")
    elif not outside_group:
        parts.append(f"Grupo de avaliaÃ§Ã£o '{group_name}' jÃ¡ estava conforme")
    else:
        parts.append(f"Grupo de avaliaÃ§Ã£o '{group_name}' confirmado")
    if migrated:
        parts.append(f"{len(migrated)} regra(s) migrada(s) para o grupo canÃ´nico")
    if migration_failures:
        parts.append(f"{len(migration_failures)} regra(s) nÃ£o puderam ser migradas")
    if outside_group and not payload.migrate_rules:
        parts.append(
            f"{len(outside_group)} regra(s) continuam em outro grupo (migraÃ§Ã£o desativada)"
        )

    return TenantEvaluationGroupResponse(
        message=". ".join(parts) + ".",
        uid=uid,
        evaluation_group=group_name,
        evaluation_group_interval=summary.evaluation_group_interval,
        evaluation_group_present=summary.evaluation_group_present,
        anchor_created=anchor_created,
        anchor_rule_uid=anchor_uid,
        migrated_rules=migrated,
        migration_failures=migration_failures,
    )


@router.delete(
    "/tenants/{uid}",
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def delete_tenant(
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
) -> dict[str, str]:
    """Exclui um tenant vazio: a pasta e o data source Loki correspondente.

    Proibido excluir tenants que possuem regras de detecÃ§Ã£o.
    """
    if uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="NÃ£o Ã© permitido excluir o tenant de sistema 'Global'.",
        )

    # Consulta regras existentes para garantir a regra de negÃ³cio fundamental
    # (a Ã¢ncora interna do grupo de avaliaÃ§Ã£o nÃ£o conta como detecÃ§Ã£o).
    raw_rules = await grafana.list_alert_rules()
    tenant_rules = [
        r
        for r in detection_rules(raw_rules)
        if str(r.get("folderUID") or "") == uid
    ]
    if len(tenant_rules) > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Proibido excluir este tenant: existem {len(tenant_rules)} regra(s) de detecÃ§Ã£o implementada(s) nele. Remova ou transfira as regras antes de excluir o tenant.",
        )

    folders = await grafana.list_folders()
    folder = next((f for f in folders if str(f.get("uid") or "") == uid), None)
    title = str((folder or {}).get("title") or "").strip()

    await grafana.delete_folder(uid, force_delete_rules=True)

    # Remove o data source Loki do cliente; a pasta jÃ¡ saiu, entÃ£o uma falha
    # aqui nÃ£o deve mascarar a exclusÃ£o â€” apenas reportar no campo `datasource`.
    datasource_status = "inexistente"
    if title:
        raw_datasources = await grafana.list_datasources()
        datasource = _find_tenant_datasource(title, uid, raw_datasources)
        if datasource is not None:
            try:
                await grafana.delete_datasource(str(datasource.get("uid") or uid))
                datasource_status = "removido"
            except GrafanaError:
                logger.warning(
                    "Pasta %s removida, mas o data source Loki do tenant nÃ£o pÃ´de ser excluÃ­do",
                    uid,
                )
                datasource_status = "falha ao remover"
        sandbox_ds = find_tenant_sandbox_datasource(title, uid, raw_datasources)
        if sandbox_ds is not None:
            try:
                await grafana.delete_datasource(str(sandbox_ds.get("uid") or sandbox_datasource_uid(uid)))
            except GrafanaError:
                logger.warning(
                    "Pasta %s removida, mas o data source Loki de sandbox do tenant não pôde ser excluído",
                    uid,
                )

    # O inventÃ¡rio declarado de tecnologias do cliente nÃ£o faz sentido sem a
    # pasta: limpa para nÃ£o vazar footprint Ã³rfÃ£o caso o uid seja reaproveitado.
    try:
        get_tenant_technology_store().forget(uid)
    except TenantTechnologyStoreError:
        logger.warning("Pasta %s removida, mas o footprint de tecnologias nÃ£o pÃ´de ser limpo", uid)

    # O snapshot de escaneamento tambÃ©m Ã© especÃ­fico do cliente.
    try:
        get_tenant_scan_store().forget(uid)
    except TenantScanStoreError:
        logger.warning("Pasta %s removida, mas o snapshot de escaneamento nÃ£o pÃ´de ser limpo", uid)

    return {
        "message": f"Tenant excluÃ­do com sucesso (data source Loki: {datasource_status}).",
        "uid": uid,
    }


@router.post(
    "/tenants/{uid}/toggle-pause",
    response_model=BatchToggleRulesPauseResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def toggle_tenant_pause(
    payload: ToggleTenantPauseRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
) -> BatchToggleRulesPauseResponse:
    """Pausa ou reativa todas as regras de detecÃ§Ã£o pertencentes ao tenant."""
    raw_rules = await grafana.list_alert_rules()
    tenant_rules = [
        r
        for r in detection_rules(raw_rules)
        if str(r.get("folderUID") or "") == uid
    ]
    uids = [str(r.get("uid")) for r in tenant_rules if r.get("uid")]

    if not uids:
        action_verb = "pausar" if payload.paused else "reativar"
        return BatchToggleRulesPauseResponse(
            message=f"O tenant nÃ£o possui regras de detecÃ§Ã£o para {action_verb}.",
            total=0,
            succeeded=[],
            failed=[],
        )

    async def _toggle(r_uid: str) -> tuple[str, bool, str | None]:
        try:
            await grafana.toggle_rule_pause(r_uid, payload.paused)
            return (r_uid, True, None)
        except Exception as exc:
            return (r_uid, False, str(exc))

    results = await asyncio.gather(*[_toggle(u) for u in uids], return_exceptions=True)
    succeeded: list[str] = []
    failed: list[dict[str, str]] = []

    for res in results:
        if isinstance(res, tuple):
            r_uid, ok, err_msg = res
            if ok:
                succeeded.append(r_uid)
            else:
                failed.append({"uid": r_uid, "error": err_msg or "Erro ao atualizar regra"})
        elif isinstance(res, Exception):
            failed.append({"uid": "desconhecido", "error": str(res)})

    action_label = "pausada(s)" if payload.paused else "reativada(s)"
    msg = f"{len(succeeded)} regra(s) do tenant {action_label} com sucesso."
    if failed:
        msg += f" {len(failed)} falha(s)."

    return BatchToggleRulesPauseResponse(
        message=msg,
        total=len(uids),
        succeeded=succeeded,
        failed=failed,
    )


# --- Escaneamento de tecnologias de um tenant (evidÃªncia de logs no Loki) ----
def _tenant_loki_datasource(
    datasources: list[dict[str, Any]], uid: str, title: str
) -> dict[str, Any] | None:
    """Data source Loki do tenant; cai para o Loki da stack quando ausente.

    O tenant ideal tem um data source cujo uid acompanha o uid da pasta. Sem ele
    (tenant legado), o escaneamento usa o Loki padrÃ£o para nÃ£o devolver "zero
    tecnologias" por falta de data source.
    """
    tenant_ds = _find_tenant_datasource(title, uid, datasources)
    if tenant_ds is not None:
        return tenant_ds
    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
        and str(ds.get("url") or "").strip()
    ]
    for datasource in lokis:
        if str(datasource.get("uid") or "") == "loki":
            return datasource
    return lokis[0] if lokis else None


async def _require_client_folder(
    grafana: GrafanaClient, uid: str
) -> dict[str, Any]:
    """Valida que ``uid`` Ã© a pasta de um cliente (existe e nÃ£o Ã© ``global``)."""
    if uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "A pasta 'global' Ã© o baseline institucional, nÃ£o um cliente: "
                "escaneie tecnologias na pasta de um tenant."
            ),
        )
    folders = await grafana.list_folders()
    folder = next((f for f in folders if str(f.get("uid") or "") == uid), None)
    if folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant nÃ£o encontrado: a pasta '{uid}' nÃ£o existe no Grafana.",
        )
    if not is_client_folder(folder):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A pasta informada nÃ£o representa um cliente.",
        )
    return folder


@router.post(
    "/tenants/{uid}/technologies/scan",
    response_model=TenantTechnologyScanResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["tenants"],
)
async def scan_tenant_technology_presence(
    payload: TenantTechnologyScanRequest | None = None,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    catalog: TechnologyStore = Depends(get_technology_store),
    scan_store: TenantScanStore = Depends(get_tenant_scan_store),
) -> TenantTechnologyScanResponse:
    """Roda a query de presenÃ§a de logs de cada tecnologia no Loki do tenant.

    Para cada tecnologia do catÃ¡logo Ã© executada a query canÃ´nica
    (``sum(count_over_time({job="wazuh", ss_groups=~".*<tech>.*"} | json [1h]))``)
    contra o data source Loki do prÃ³prio cliente. O resultado Ã© persistido como
    snapshot e alimenta a coluna de tecnologias da pÃ¡gina Tenants.

    ``available=False`` significa que o Loki nÃ£o pÃ´de ser consultado: nesse caso
    nada Ã© marcado como ausente e nenhum snapshot Ã© gravado.
    """
    folder = await _require_client_folder(grafana, uid)
    client_name = str(folder.get("title") or uid)
    window_seconds = (payload or TenantTechnologyScanRequest()).window_seconds

    technologies = catalog.list_all()
    if not technologies:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Nenhuma tecnologia estÃ¡ cadastrada no catÃ¡logo. Cadastre as "
                "tecnologias antes de escanear a presenÃ§a de logs do tenant."
            ),
        )

    datasources = await grafana.list_datasources()
    datasource = _tenant_loki_datasource(datasources, uid, client_name)
    if datasource is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Nenhum data source Loki disponÃ­vel no Grafana (nem dedicado ao "
                "tenant, nem o Loki padrÃ£o da stack): nÃ£o Ã© possÃ­vel escanear a "
                "presenÃ§a de logs."
            ),
        )

    ds_uid = str(datasource.get("uid") or "")
    ds_name = str(datasource.get("name") or ds_uid)

    available, items = await scan_tenant_technologies(
        grafana,
        technologies,
        datasource_uid=ds_uid,
        window_seconds=window_seconds,
    )

    detected = sum(1 for item in items if item.get("found"))
    scan_items = [TenantTechnologyScanItem(**item) for item in items]
    scanned_at = datetime.now(timezone.utc).isoformat()

    if not available:
        return TenantTechnologyScanResponse(
            message=(
                "O Loki do tenant nÃ£o respondeu ao escaneamento; nenhuma tecnologia "
                "foi marcada como ausente e o resultado anterior foi preservado."
            ),
            tenant_uid=uid,
            client_name=client_name,
            datasource=ds_name,
            datasource_uid=ds_uid,
            window_seconds=window_seconds,
            scanned_at=scanned_at,
            available=False,
            technologies_detected=detected,
            technologies_total=len(items),
            technologies=scan_items,
        )

    record = {
        "client_name": client_name,
        "datasource": ds_name,
        "datasource_uid": ds_uid,
        "window_seconds": window_seconds,
        "scanned_at": scanned_at,
        "available": True,
        "technologies": items,
    }
    try:
        scan_store.set_record(uid, record)
    except TenantScanStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return TenantTechnologyScanResponse(
        message=(
            f"Escaneamento concluÃ­do em '{client_name}': {detected} de {len(items)} "
            f"tecnologia(s) do catÃ¡logo possuem logs no Loki (janela de "
            f"{window_seconds}s)."
        ),
        tenant_uid=uid,
        client_name=client_name,
        datasource=ds_name,
        datasource_uid=ds_uid,
        window_seconds=window_seconds,
        scanned_at=scanned_at,
        available=True,
        technologies_detected=detected,
        technologies_total=len(items),
        technologies=scan_items,
    )


@router.get(
    "/tenants/{uid}/technologies",
    response_model=TenantTechnologiesResponse,
    tags=["tenants"],
)
async def get_tenant_technologies(
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    catalog: TechnologyStore = Depends(get_technology_store),
    scan_store: TenantScanStore = Depends(get_tenant_scan_store),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> TenantTechnologiesResponse:
    """Tecnologias do cliente com o estado do baseline de cada uma.

    A lista Ã© a uniÃ£o de: tecnologias com logs no Ãºltimo escaneamento, com
    regras jÃ¡ implementadas na pasta do cliente e as declaradas no footprint.
    Para cada tecnologia devolve quantas regras do baseline jÃ¡ foram
    replicadas, quantas estÃ£o pausadas e o status de conformidade.
    """
    baseline_uid = sys_settings.get_baseline_folder_uid()
    folder = await _require_client_folder(grafana, uid)
    client_name = str(folder.get("title") or uid)

    try:
        record = scan_store.record_for(uid)
    except TenantScanStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    technologies = catalog.list_all()
    by_slug = {tech.slug: tech for tech in technologies}

    rules = detection_rules(await grafana.list_alert_rules())
    client_rules = [
        rule for rule in rules if str(rule.get("folderUID") or "") == uid
    ]
    global_rules = [
        rule
        for rule in rules
        if str(rule.get("folderUID") or "").strip().lower() == baseline_uid.lower()
        or str(rule.get("folderUID") or "").strip().lower() == "global"
    ]

    rules_by_tech: dict[str, int] = {}
    for rule in client_rules:
        tech = next(
            (
                candidate
                for candidate in technologies
                if str((rule.get("labels") or {}).get("technology") or "").strip().lower()
                in (candidate.slug, candidate.name.strip().lower())
            ),
            None,
        )
        if tech is not None:
            rules_by_tech[tech.slug] = rules_by_tech.get(tech.slug, 0) + 1

    scanned = {
        str(item.get("slug") or ""): item
        for item in (record or {}).get("technologies", [])
        if item.get("slug")
    }

    try:
        declared = set(get_tenant_technology_store().declared_for(uid))
    except TenantTechnologyStoreError:
        declared = set()

    selected = sorted(
        {
            slug
            for slug in (
                set(scanned) | set(rules_by_tech) | (declared & set(by_slug))
            )
            if slug in by_slug
        }
    )

    items: list[TenantTechnologyBaselineState] = []
    for slug in selected:
        tech = by_slug[slug]
        scan_item = scanned.get(slug) or {}
        baseline = baseline_rules_for_technology(tech, global_rules)
        implemented = 0
        paused = 0
        for baseline_rule in baseline:
            replica = find_implemented_rule(baseline_rule, client_rules)
            if replica is not None:
                implemented += 1
                if replica.get("isPaused"):
                    paused += 1
        total_baseline = len(baseline)
        if total_baseline > 0 and implemented >= total_baseline:
            status_value = "complete"
        elif implemented > 0:
            status_value = "partial"
        else:
            status_value = "none"
        items.append(
            TenantTechnologyBaselineState(
                slug=slug,
                name=tech.name,
                icon=tech.icon,
                description=tech.description,
                detected=bool(scan_item.get("found")),
                logs_count=int(scan_item.get("logs_count") or 0),
                baseline_rules=total_baseline,
                implemented_rules=implemented,
                paused_rules=paused,
                existing_rules=rules_by_tech.get(slug, 0),
                compliance_pct=(
                    round(implemented * 100.0 / total_baseline, 1)
                    if total_baseline
                    else 0.0
                ),
                status=status_value,
            )
        )

    return TenantTechnologiesResponse(
        tenant_uid=uid,
        client_name=client_name,
        scanned_at=(record or {}).get("scanned_at") or None,
        window_seconds=(record or {}).get("window_seconds"),
        datasource=(record or {}).get("datasource"),
        available=bool((record or {}).get("available", False)),
        technologies_detected=sum(1 for item in items if item.detected),
        technologies_total=len(technologies),
        technologies=items,
    )


# --- ValidaÃ§Ã£o e InjeÃ§Ã£o de Log FictÃ­cio (LogQL) ----------------------------
@router.post(
    "/rules/test-logql",
    response_model=LogQLValidationReport,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def test_logql_rule(
    payload: TestLogQLRequest,
) -> LogQLValidationReport:
    """Injeta um log fictÃ­cio e valida a compatibilidade/parsing com a regra LogQL."""
    return evaluate_logql(
        logql=payload.logql_query,
        log_line=payload.log_line,
        initial_labels=payload.stream_labels,
    )


# --- DuplicaÃ§Ã£o de Regra para Clientes ---------------------------------------
@router.post(
    "/rules/{uid}/duplicate",
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def duplicate_rule(
    payload: DuplicateRuleRequest,
    uid: str = Path(pattern=UID_PATTERN),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> dict[str, Any]:
    """Duplica uma regra de detecÃ§Ã£o para a pasta de um cliente SIEM.

    REGRA DE NEGÃ“CIO: Somente regras pertencentes Ã  pasta baseline ('global' ou arbitrada) podem ser duplicadas.
    """
    baseline_uid = sys_settings.get_baseline_folder_uid()
    source_rule = await grafana.get_alert_rule(uid)
    source_folder_uid = (source_rule.get("folderUID") or "").strip().lower()

    # Mapear tÃ­tulos de pastas para verificar se Ã© global / baseline
    folders = await grafana.list_folders()
    folder_map = {f.get("uid"): f.get("title", "") for f in folders}
    source_folder_title = str(folder_map.get(source_rule.get("folderUID"), "")).strip().lower()

    if (
        source_folder_uid != baseline_uid.lower()
        and source_folder_uid != "global"
        and source_folder_title != baseline_uid.lower()
        and source_folder_title != "global"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas regras de detecÃ§Ã£o pertencentes Ã  pasta baseline podem ser duplicadas.",
        )

    # Query que serÃ¡ efetivamente aplicada na regra do cliente (custom ou herdada da global)
    store = get_technology_store()
    final_query = payload.custom_logql or ""
    if not final_query:
        for q in source_rule.get("data") or []:
            expr = (q.get("model") or {}).get("expr")
            if isinstance(expr, str) and "ss_groups" in expr:
                final_query = expr
                break

    # REGRA DE NEGÃ“CIO: nenhuma regra Ã© persistida (nem replicada) sem passar pelo
    # linting de LogQL. O front-end valida antes do submit; esta checagem garante a
    # regra no servidor mesmo em chamadas diretas Ã  API. Executada antes de qualquer
    # efeito colateral (criaÃ§Ã£o de pasta / de regra no Grafana).
    if final_query:
        lint_result = lint_logql(
            final_query,
            known_ss_groups_patterns=[tech.ss_groups_regex for tech in store.list_all()],
        )
        if not lint_result.is_valid:
            error_msgs = [issue.message for issue in lint_result.issues if issue.level == "error"]
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "A regra nÃ£o pode ser implementada no cliente: a query LogQL possui erros "
                    f"que impedem sua execuÃ§Ã£o: {'; '.join(error_msgs) or lint_result.message}"
                ),
            )

    # Verifica se a pasta do cliente de destino existe; se nÃ£o, cria
    target_folder_uid = payload.target_folder_uid
    folder_title = str(
        folder_map.get(target_folder_uid)
        or payload.target_folder_title
        or payload.client_name
    )
    if target_folder_uid not in folder_map:
        new_folder = await grafana.create_folder(folder_title, target_folder_uid)
        target_folder_uid = str(new_folder.get("uid", target_folder_uid))
        folder_title = str(new_folder.get("title") or folder_title)

    # Cria o novo payload com base na regra global (deepcopy para nÃ£o mutar data aninhado)
    new_uid = f"ghp-{uuid.uuid4().hex[:10]}"
    rule_copy = copy.deepcopy(source_rule)
    rule_copy.pop("id", None)
    rule_copy.pop("updated", None)
    # Nunca herdar identidade/proveniência da regra de origem: provenance 'api'
    # faz o clone nascer "Provisioned" (read-only) no Grafana.
    rule_copy.pop("provenance", None)
    rule_copy.pop("readOnly", None)
    rule_copy.pop("orgID", None)
    rule_copy["uid"] = new_uid
    rule_copy["folderUID"] = target_folder_uid
    target_rule_group = payload.new_rule_group or tenant_rule_group(payload.client_name)
    rule_copy["title"] = payload.new_title
    rule_copy["ruleGroup"] = target_rule_group
    rule_copy["isPaused"] = False

    # Labels adicionando o cliente
    labels = dict(rule_copy.get("labels") or {})
    labels["client"] = payload.client_name
    labels["siem_tier"] = "client"
    rule_copy["labels"] = labels

    # AnotaÃ§Ãµes adicionando rastreabilidade da origem
    annotations = dict(rule_copy.get("annotations") or {})
    annotations["cloned_from"] = uid
    annotations["client_name"] = payload.client_name
    if payload.custom_logql:
        annotations["logql_query"] = payload.custom_logql.strip()
    rule_copy["annotations"] = annotations

    # Atualiza LogQL caso tenha sido modificado no payload
    if payload.custom_logql and rule_copy.get("data"):
        for q in rule_copy["data"]:
            model = q.get("model") or {}
            if "expr" in model:
                model["expr"] = payload.custom_logql

    # Direciona a query da regra replicada para o data source Loki do cliente correspondente
    raw_datasources = await grafana.list_datasources()
    client_ds = _find_tenant_datasource(folder_title, target_folder_uid, raw_datasources)
    if not client_ds:
        client_ds = _find_tenant_datasource(payload.client_name, target_folder_uid, raw_datasources)
    if not client_ds:
        client_ds = resolve_baseline_loki_datasource(raw_datasources)
    bind_rule_datasource(rule_copy, client_ds)

    # SegregaÃ§Ã£o de tecnologia preservada/atualizada na duplicaÃ§Ã£o:
    # o recorte de ss_groups da query final define a tecnologia da regra clonada.
    if final_query:
        matched = store.match_query(final_query)
        if len(matched) == 1:
            labels["technology"] = matched[0].slug
            labels["technology_name"] = matched[0].name
            rule_copy["labels"] = labels

    # REGRA DE NEGÃ“CIO: toda replicaÃ§Ã£o nasce com o Contact Point 'dev'
    # (HomologaÃ§Ã£o), jamais herdando 'prod' da regra de origem.
    apply_contact_point(rule_copy)

    await grafana.create_alert_rule(rule_copy)
    await grafana.set_rule_group_interval(
        target_folder_uid,
        target_rule_group,
        RULE_GROUP_INTERVAL_SECONDS,
    )

    return {
        "message": f"Regra duplicada com sucesso para o cliente '{payload.client_name}'",
        "uid": new_uid,
        "title": payload.new_title,
        "folder_uid": target_folder_uid,
        "client": payload.client_name,
        "contact_point": DEFAULT_CONTACT_POINT,
        "datasource_uid": str(client_ds.get("uid") or ""),
        "datasource_name": str(client_ds.get("name") or ""),
    }


# --- Linting SintÃ¡tico e SemÃ¢ntico de LogQL -----------------------------------
@router.post(
    "/rules/lint-logql",
    response_model=LogQLLintResult,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def lint_logql_query(
    payload: dict[str, str],
    store: TechnologyStore = Depends(get_technology_store),
) -> LogQLLintResult:
    """Valida sintÃ¡tica e semanticamente uma expressÃ£o LogQL informada.

    AlÃ©m da sintaxe, aplica a segregaÃ§Ã£o de tecnologia: o recorte de ``ss_groups``
    Ã© comparado com o catÃ¡logo para avisar quando a query aponta para uma fonte
    desconhecida (e o ``job`` Ã© conferido contra o pipeline padrÃ£o do SIEM).
    """
    query = payload.get("query", "").strip()
    catalog = store.list_all()
    result = lint_logql(
        query,
        known_ss_groups_patterns=[tech.ss_groups_regex for tech in catalog],
    )
    result.technologies = [tech.slug for tech in store.match_query(query)]
    return result


# --- ExecuÃ§Ã£o e Consulta de Query LogQL (com tratamento de Timeout) -----------
# Teto de linhas pedidas ao Grafana por consulta (limite do plugin Loki).
MAX_FETCH_LINES = 1000


def _fetch_margin(limit: int) -> int:
    """Quantidade de linhas a pedir ao datasource para devolver as N mais novas.

    O Loki aplica ``maxLines`` por consulta e entrega os streams em ordem
    arbitrÃ¡ria; pedir apenas ``limit`` faz as linhas mais recentes de um stream
    sumirem atrÃ¡s de outro. Pedimos uma margem e ordenamos no servidor.
    """
    return min(max(limit * 5, 100), MAX_FETCH_LINES)


def _timestamp_sort_key(item: LogLineResult) -> float:
    """Chave de ordenaÃ§Ã£o por timestamp ISO-8601 (0.0 quando nÃ£o parseÃ¡vel)."""
    try:
        return datetime.fromisoformat(item.timestamp).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _extract_stream_logql(query: str) -> str:
    """Extrai a expressÃ£o de stream e pipeline de logs subjacente de uma query LogQL.

    Regras de detecÃ§Ã£o no Grafana Alerting frequentemente utilizam funÃ§Ãµes mÃ©tricas de
    agregaÃ§Ã£o temporal, tais como:
        count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json [5m])
        sum(count_over_time({job="wazuh"} | json | eventID="4625" [5m]))

    Quando executadas no modo logs ("queryType": "range"), funÃ§Ãµes mÃ©tricas retornam apenas
    amostras numÃ©ricas (por exemplo, "1", "2") em vez dos streams contendo o corpo JSON
    real dos eventos. Esta funÃ§Ã£o localiza o seletor {...} e os estÃ¡gios subsequentes do
    pipeline (como | json ou |= "termo"), descartando as funÃ§Ãµes mÃ©tricas externas e
    o range vector [...], permitindo que o Loki devolva as linhas reais de log.
    """
    raw = query.strip()
    start_brace = raw.find("{")
    if start_brace == -1:
        return raw

    range_match = re.search(r"\[\s*\d+[smhdwy]\s*\]", raw[start_brace:])
    if range_match:
        extracted = raw[start_brace : start_brace + range_match.start()].strip()
        if extracted:
            return extracted

    return raw


async def _execute_single_datasource_query(
    grafana: GrafanaClient,
    target_ds: dict[str, Any],
    effective_query: str,
    time_range_from: str,
    time_range_to: str,
    limit: int,
) -> tuple[bool, list[LogLineResult], float, str | None, bool]:
    """Executa a query contra um único datasource Loki e devolve (success, lines, duration_ms, error, is_timeout)."""
    start_time = asyncio.get_event_loop().time()
    ds_uid = str(target_ds.get("uid") or "loki")
    ds_name = str(target_ds.get("name") or ds_uid)
    ds_type = str(target_ds.get("type") or "loki")

    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"uid": ds_uid, "type": ds_type},
                "expr": effective_query,
                "queryType": "range",
                "lines": _fetch_margin(limit),
                "maxLines": _fetch_margin(limit),
            }
        ],
        "from": time_range_from,
        "to": time_range_to,
    }

    try:
        res = await asyncio.wait_for(
            grafana._request("POST", "/api/ds/query", json=body),
            timeout=8.0,
        )
    except (asyncio.TimeoutError, TimeoutError):
        duration_ms = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        return False, [], duration_ms, "A consulta atingiu o tempo limite no Grafana.", True
    except GrafanaError as exc:
        duration_ms = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        is_timeout = exc.status_code == 504
        err_msg = "Tempo limite esgotado (Timeout) ao consultar o Grafana." if is_timeout else f"Falha ao consultar data source '{ds_name}': {exc.message}"
        return False, [], duration_ms, err_msg, is_timeout

    duration_ms = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
    lines: list[LogLineResult] = []

    results = (res or {}).get("results", {})
    query_res = results.get("A", {})
    frames = query_res.get("frames", [])

    for frame in frames:
        schema = frame.get("schema", {})
        fields = schema.get("fields", [])
        data_values = (frame.get("data") or {}).get("values", [])

        time_idx = next(
            (i for i, f in enumerate(fields) if f.get("type") == "time" or f.get("name") in ("timestamp", "Time", "time")),
            -1,
        )
        line_idx = next(
            (
                i
                for i, f in enumerate(fields)
                if str(f.get("name", "")).lower() in ("body", "line", "message", "value")
            ),
            -1,
        )
        labels_idx = next((i for i, f in enumerate(fields) if f.get("name") == "labels"), -1)

        if line_idx != -1 and len(data_values) > line_idx:
            raw_lines = data_values[line_idx]
            times = data_values[time_idx] if time_idx != -1 and len(data_values) > time_idx else []
            labels_list = data_values[labels_idx] if labels_idx != -1 and len(data_values) > labels_idx else []

            for idx, log_val in enumerate(raw_lines):
                t_val = times[idx] if idx < len(times) else ""
                if isinstance(t_val, (int, float)):
                    t_str = datetime.fromtimestamp(t_val / 1000, tz=timezone.utc).isoformat()
                else:
                    t_str = str(t_val) or datetime.now(timezone.utc).isoformat()

                lbls = labels_list[idx] if idx < len(labels_list) and isinstance(labels_list[idx], dict) else {}
                lines.append(
                    LogLineResult(
                        timestamp=t_str,
                        line=str(log_val),
                        labels=lbls,
                    )
                )

    lines.sort(key=_timestamp_sort_key, reverse=True)
    if len(lines) > limit:
        lines = lines[:limit]

    return True, lines, duration_ms, None, False


@router.post(
    "/rules/execute-query",
    response_model=ExecuteQueryResult,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def execute_query_logs(
    payload: ExecuteQueryRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    settings: Settings = Depends(get_app_settings),
) -> ExecuteQueryResult:
    """Executa a consulta LogQL diretamente no datasource do Grafana.

    Se a abrangência (scope) for 'baseline' (ou padrão), consulta o data source
    'Loki' institucional.
    Se a abrangência for 'client', consulta tanto o data source de produção <cliente>
    quanto o data source de SANDBOX sandbox-<cliente>, segregando os resultados entre
    Ambiente Sandbox (logs sintéticos) e Ambiente de Produção.
    """
    start_time = asyncio.get_event_loop().time()
    try:
        raw_datasources = await grafana.list_datasources()
        scope = (payload.scope or "").strip().lower()

        effective_query = _extract_stream_logql(payload.query)

        if scope == "client" or (payload.client_uid and scope != "baseline"):
            if not payload.client_uid:
                return ExecuteQueryResult(
                    success=False,
                    query=payload.query,
                    total_lines=0,
                    lines=[],
                    duration_ms=0.0,
                    error="Selecione um cliente para consultar os logs no data source do cliente.",
                )

            # Resolução da pasta do cliente
            folders = await grafana.list_folders()
            folder = next((f for f in folders if str(f.get("uid") or "") == payload.client_uid), None)
            folder_title = str(folder.get("title") or payload.client_uid) if folder else payload.client_uid

            # Consulta se o data source de sandbox está ativo para o cliente
            sandbox_ds = find_tenant_sandbox_datasource(folder_title, payload.client_uid, raw_datasources)

            target_ds = _find_tenant_datasource(folder_title, payload.client_uid, raw_datasources)
            if not target_ds:
                target_ds = next(
                    (d for d in raw_datasources if str(d.get("uid") or "") == payload.client_uid),
                    None,
                )

            if not target_ds:
                return ExecuteQueryResult(
                    success=False,
                    query=payload.query,
                    total_lines=0,
                    lines=[],
                    duration_ms=0.0,
                    error=(
                        f"Data source Loki de produção do cliente '{folder_title}' não foi encontrado no Grafana. "
                        "Certifique-se de que o data source do tenant foi provisionado na página 'Clientes SIEM'."
                    ),
                )

            # Consulta concorrente nos ambientes de Produção e Sandbox (se ativo)
            prod_task = _execute_single_datasource_query(
                grafana, target_ds, effective_query, payload.time_range_from, payload.time_range_to, payload.limit
            )

            if sandbox_ds is not None:
                sandbox_task = _execute_single_datasource_query(
                    grafana, sandbox_ds, effective_query, payload.time_range_from, payload.time_range_to, payload.limit
                )
                (
                    (prod_success, prod_lines, prod_dur, prod_err, prod_timeout),
                    (sb_success, sb_lines, sb_dur, sb_err, sb_timeout),
                ) = await asyncio.gather(prod_task, sandbox_task)
            else:
                (prod_success, prod_lines, prod_dur, prod_err, prod_timeout) = await prod_task
                sb_success = False
                sb_lines = []
                sb_dur = 0.0
                sb_err = "Data source de sandbox desativado para este cliente. Ative o switch na página 'Clientes SIEM' para habilitar a validação em sandbox."
                sb_timeout = False

            # Segregação de telemetria: no ambiente de produção, desconsidera eventos de teste sintéticos
            # para evitar contaminação quando a stack local usa a mesma instância do Loki.
            clean_prod_lines = [l for l in prod_lines if (l.labels or {}).get("synthetic") != "true"]

            prod_env = EnvironmentQueryResult(
                environment="production",
                environment_label="Ambiente de Produção",
                datasource_name=str(target_ds.get("name") or folder_title),
                datasource_uid=str(target_ds.get("uid") or ""),
                success=prod_success,
                total_lines=len(clean_prod_lines),
                lines=clean_prod_lines,
                duration_ms=prod_dur,
                error=prod_err,
                is_timeout=prod_timeout,
            )

            sandbox_env = EnvironmentQueryResult(
                environment="sandbox",
                environment_label="Ambiente Sandbox",
                datasource_name=str(sandbox_ds.get("name") or f"sandbox-{folder_title}") if sandbox_ds else f"sandbox-{folder_title} (desativado)",
                datasource_uid=str(sandbox_ds.get("uid") or "") if sandbox_ds else "",
                success=sb_success,
                total_lines=len(sb_lines),
                lines=sb_lines,
                duration_ms=sb_dur,
                error=sb_err,
                is_timeout=sb_timeout,
            )

            total_duration_ms = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
            combined_lines = clean_prod_lines + sb_lines
            combined_lines.sort(key=_timestamp_sort_key, reverse=True)
            if len(combined_lines) > payload.limit:
                combined_lines = combined_lines[: payload.limit]

            overall_success = prod_success or sb_success
            overall_error = None if overall_success else (prod_err or sb_err or "Falha ao consultar datasources.")

            return ExecuteQueryResult(
                success=overall_success,
                query=payload.query,
                total_lines=len(clean_prod_lines) + len(sb_lines),
                lines=combined_lines,
                duration_ms=total_duration_ms,
                is_timeout=prod_timeout and sb_timeout,
                error=overall_error,
                datasource_name=f"{prod_env.datasource_name} & {sandbox_env.datasource_name}",
                environments=[sandbox_env, prod_env],
            )

        else:
            # Abrangência Baseline: busca explicitamente o data source 'Loki'
            lokis = [
                d for d in raw_datasources
                if str(d.get("type") or "") in LOKI_DATASOURCE_TYPES
            ]
            target_ds = next(
                (
                    d for d in lokis
                    if str(d.get("name") or "").strip().casefold() == "loki"
                    or str(d.get("uid") or "").strip().casefold() == "loki"
                ),
                None,
            )
            if not target_ds:
                target_ds = await grafana.find_loki_datasource()
            if not target_ds:
                target_ds = {"uid": "loki", "name": "Loki", "type": "loki"}

            success, lines, duration_ms, err, is_timeout = await _execute_single_datasource_query(
                grafana, target_ds, effective_query, payload.time_range_from, payload.time_range_to, payload.limit
            )
            return ExecuteQueryResult(
                success=success,
                query=payload.query,
                total_lines=len(lines),
                lines=lines,
                duration_ms=duration_ms,
                is_timeout=is_timeout,
                error=err,
                datasource_name=str(target_ds.get("name") or "Loki"),
                environments=None,
            )

    except Exception as exc:
        duration_ms = round((asyncio.get_event_loop().time() - start_time) * 1000, 2)
        return ExecuteQueryResult(
            success=False,
            query=payload.query,
            total_lines=0,
            lines=[],
            duration_ms=duration_ms,
            is_timeout=False,
            error=f"Falha ao consultar logs: {exc}",
            datasource_name=None,
            environments=None,
        )


# --- CriaÃ§Ã£o de Regra de DetecÃ§Ã£o com ValidaÃ§Ã£o ObrigatÃ³ria ------------------
@router.post(
    "/rules",
    response_model=CreateRuleResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["rules"],
)
async def create_detection_rule(
    payload: CreateRuleRequest,
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> CreateRuleResponse:
    """Cria uma nova regra de detecÃ§Ã£o no Grafana com validaÃ§Ã£o sintÃ¡tica obrigatÃ³ria.

    REGRAS DE NEGÃ“CIO:
    1. Uma regra de detecÃ§Ã£o NUNCA poderÃ¡ ser criada sem que a query seja devidamente validada (Linting).
    2. Se AbrangÃªncia for 'baseline', folderUID Ã© 'global'.
    3. Se AbrangÃªncia for 'client', target_client_uid Ã© obrigatÃ³rio.
    4. Todos os metadados (Severidade, TÃ¡tica/TÃ©cnica MITRE, AbrangÃªncia, Cliente) sÃ£o inseridos como labels.
    5. SegregaÃ§Ã£o de tecnologia: grafana_folder = cliente (tenant); ss_groups = tecnologia.
       A regra sÃ³ pode ser criada se o matcher 'ss_groups' da query pertencer Ã  tecnologia
       selecionada no catÃ¡logo (labels 'technology'/'technology_name' registram a escolha).
    6. Deploy: TODA regra nova nasce com o Contact Point 'dev' (estÃ¡gio HomologaÃ§Ã£o).
       Promover para 'stg'/'prod' Ã© aÃ§Ã£o explÃ­cita na pÃ¡gina HomologaÃ§Ã£o â€” nunca no create.
    """
    store = get_technology_store()

    # 1. ValidaÃ§Ã£o obrigatÃ³ria da query LogQL (com cross-check contra o catÃ¡logo)
    lint = lint_logql(
        payload.logql_query,
        known_ss_groups_patterns=[tech.ss_groups_regex for tech in store.list_all()],
    )
    if not lint.is_valid:
        error_msgs = [i.message for i in lint.issues if i.level == "error"]
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"A regra nÃ£o pode ser criada pois a query LogQL possui erros de sintaxe/semÃ¢ntica: {'; '.join(error_msgs)}",
        )

    # 1.1. ResoluÃ§Ã£o e validaÃ§Ã£o da tecnologia (data source) observada pela regra
    technology: Technology | None = None
    if payload.technology:
        try:
            technology = store.get(payload.technology)
        except TechnologyNotFound as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Tecnologia invÃ¡lida para a regra: {exc}",
            ) from exc
    else:
        candidates = store.match_query(payload.logql_query)
        if len(candidates) == 1:
            technology = candidates[0]
        elif not candidates:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Selecione a tecnologia (data source) da regra: o matcher 'ss_groups' da "
                    "query nÃ£o corresponde a nenhuma tecnologia cadastrada no catÃ¡logo."
                ),
            )
        else:
            names = ", ".join(f"{tech.name} ({tech.slug})" for tech in candidates)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "A query referencia mais de uma tecnologia cadastrada "
                    f"({names}). Selecione explicitamente a tecnologia da regra."
                ),
            )

    # 1.2. Garantia de segregaÃ§Ã£o: a query precisa olhar exatamente para essa tecnologia
    ss_groups_in_query = [value for _op, value in extract_ss_groups_values(payload.logql_query)]
    if not ss_groups_in_query:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A query precisa conter um matcher 'ss_groups' para delimitar a tecnologia.",
        )
    if not any(
        selector_matches_technology(value, technology) for value in ss_groups_in_query
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"SegregaÃ§Ã£o invÃ¡lida: a tecnologia selecionada Ã© '{technology.name}' "
                f"(ss_groups=~\"{technology.ss_groups_regex}\"), mas a query restringe "
                f"ss_groups a {ss_groups_in_query}. Ajuste o seletor da query."
            ),
        )

    # 2. DefiniÃ§Ã£o da pasta e resoluÃ§Ã£o do data source Loki correspondente (AbrangÃªncia)
    folders, raw_datasources = await asyncio.gather(
        grafana.list_folders(),
        grafana.list_datasources(),
    )
    folder_map = {str(f.get("uid")): str(f.get("title", "")) for f in folders}

    if payload.scope == "baseline":
        folder_uid = sys_settings.get_baseline_folder_uid()
        folder_title = folder_map.get(folder_uid, "Global Baseline")
        rule_title = payload.name.strip()
        rule_group = payload.evaluation_group.strip() if payload.evaluation_group and payload.evaluation_group.strip() else BASELINE_RULE_GROUP
        client_label_val = "global"
        siem_tier = "global"
        target_ds = resolve_baseline_loki_datasource(raw_datasources)
    else:
        if not payload.target_client_uid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Para abrangÃªncia de Cliente, o cliente (grafana_folder) de destino Ã© obrigatÃ³rio.",
            )
        folder_uid = payload.target_client_uid.strip()
        baseline_uid = sys_settings.get_baseline_folder_uid()
        if folder_uid.lower() == baseline_uid.lower() or folder_uid.lower() == "global":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A pasta de baseline Ã© reservada ao Baseline: selecione a pasta de um cliente.",
            )
        if folder_uid not in folder_map:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Cliente nÃ£o encontrado: a pasta '{folder_uid}' nÃ£o existe no Grafana.",
            )
        folder_title = folder_map[folder_uid] or folder_uid
        rule_title = payload.name.strip()
        rule_group = payload.evaluation_group.strip() if payload.evaluation_group and payload.evaluation_group.strip() else tenant_rule_group(folder_title)
        client_label_val = folder_title
        siem_tier = "client"

        target_ds = _find_tenant_datasource(folder_title, folder_uid, raw_datasources)
        if not target_ds:
            target_ds = next(
                (d for d in raw_datasources if str(d.get("uid") or "") == folder_uid),
                None,
            )
        if not target_ds:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Data source Loki do cliente '{folder_title}' nÃ£o foi encontrado no Grafana. "
                    "Certifique-se de que o data source do tenant foi provisionado na pÃ¡gina 'Clientes SIEM'."
                ),
            )

    ds_uid = str(target_ds.get("uid") or "loki")
    ds_name = str(target_ds.get("name") or ds_uid)
    ds_type = str(target_ds.get("type") or "loki")
    if ds_type not in LOKI_DATASOURCE_TYPES:
        ds_type = "loki"

    # 3. Metadados inseridos no formato de labels
    labels = {
        "severity": payload.severity,
        "mitre_tactic": payload.mitre_tactic.strip().lower(),
        "mitre_technique": payload.mitre_technique.strip().upper(),
        "scope": payload.scope,
        "client": client_label_val,
        "siem_tier": siem_tier,
        # SegregaÃ§Ã£o de tecnologia: permite filtrar/segmentar regras por data source.
        "technology": technology.slug,
        "technology_name": technology.name,
        "source": "dante",
    }

    # 4. AnotaÃ§Ãµes com descriÃ§Ã£o e query
    annotations = {
        "summary": payload.name.strip(),
        "description": payload.description.strip() if payload.description else f"Regra de detecÃ§Ã£o {payload.name.strip()}",
        "logql_query": payload.logql_query.strip(),
    }

    # 5. Montagem do payload Grafana Provisioning apontando para o Loki (Baseline) ou Data Source do Cliente
    new_uid = f"ghp-{uuid.uuid4().hex[:10]}"
    rule_payload = {
        "uid": new_uid,
        "title": rule_title,
        "folderUID": folder_uid,
        "ruleGroup": rule_group,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "Error",
        "for": "0s",
        "isPaused": False,
        "labels": labels,
        "annotations": annotations,
        "data": [
            {
                "refId": "A",
                "queryType": "range",
                "relativeTimeRange": {"from": 300, "to": 0},
                "datasourceUid": ds_uid,
                "model": {
                    "refId": "A",
                    "editorMode": "code",
                    "expr": payload.logql_query.strip(),
                    "queryType": "range",
                    "legendFormat": "__auto",
                    "datasource": {"type": ds_type, "uid": ds_uid},
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                },
            },
            {
                "refId": "B",
                "queryType": "",
                "relativeTimeRange": {"from": 0, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "reducer": "last",
                    "refId": "B",
                    "type": "reduce",
                },
            },
            {
                "refId": "C",
                "queryType": "",
                "relativeTimeRange": {"from": 0, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "conditions": [{"evaluator": {"params": [0], "type": "gt"}}],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "B",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "refId": "C",
                    "type": "threshold",
                },
            },
        ],
    }

    await grafana.create_alert_rule(apply_contact_point(rule_payload))
    if payload.scope != "baseline":
        await grafana.set_rule_group_interval(
            folder_uid,
            rule_group,
            RULE_GROUP_INTERVAL_SECONDS,
        )

    replicated_rules: list[ImplementedRuleResult] = []
    replicated_to_clients = bool(payload.scope == "baseline" and payload.replicate_to_clients)

    if replicated_to_clients:
        raw_rules, raw_cps = await asyncio.gather(
            grafana.list_alert_rules(),
            grafana.list_contact_points(),
        )
        all_rules = detection_rules(raw_rules)
        stg_contact_point = resolve_stage_receiver(
            "stg",
            stage_mapping=sys_settings.get_stage_contact_points(),
            available_contact_points=raw_cps,
        )
        footprint_store = get_tenant_technology_store()
        scan_store = get_tenant_scan_store()
        client_folders = sorted(
            [f for f in folders if is_client_folder(f, baseline_folder_uid=sys_settings.get_baseline_folder_uid())],
            key=lambda f: str(f.get("title") or "").lower(),
        )

        for cf in client_folders:
            c_uid = str(cf.get("uid") or "").strip()
            c_name = str(cf.get("title") or c_uid).strip()
            if not c_uid:
                continue

            c_rules = [r for r in all_rules if str(r.get("folderUID") or "") == c_uid]
            try:
                declared_slugs = footprint_store.declared_for(c_uid)
            except TenantTechnologyStoreError:
                declared_slugs = []
            try:
                scan_rec = scan_store.record_for(c_uid)
            except TenantScanStoreError:
                scan_rec = None

            scanned_found = any(
                str(item.get("slug") or "").strip().lower() == technology.slug
                and bool(item.get("found"))
                for item in (scan_rec or {}).get("technologies", [])
            )
            has_tech = (
                client_has_technology(c_rules, technology, declared_slugs) or scanned_found
            )
            if not has_tech:
                continue

            existing = find_implemented_rule(rule_payload, c_rules)
            if existing is not None:
                replicated_rules.append(
                    ImplementedRuleResult(
                        uid=str(existing.get("uid") or new_uid),
                        title=str(existing.get("title") or rule_title),
                        status="skipped",
                        detail=f"Regra jÃ¡ implementada no cliente '{c_name}'.",
                    )
                )
                continue

            clone_uid = f"ghp-{uuid.uuid4().hex[:10]}"
            clone_title = f"[{c_name}] {rule_title}"
            rule_copy = copy.deepcopy(rule_payload)
            for k in ("id", "updated", "provenance", "readOnly", "orgID"):
                rule_copy.pop(k, None)
            rule_copy["uid"] = clone_uid
            rule_copy["folderUID"] = c_uid
            rule_copy["title"] = clone_title
            rule_copy["ruleGroup"] = tenant_rule_group(c_name)
            rule_copy["isPaused"] = False

            c_labels = dict(rule_copy.get("labels") or {})
            c_labels.update(
                {
                    "scope": "client",
                    "client": c_name,
                    "siem_tier": "client",
                    "technology": technology.slug,
                    "technology_name": technology.name,
                    "source": "dante",
                }
            )
            rule_copy["labels"] = c_labels

            c_annotations = dict(rule_copy.get("annotations") or {})
            c_annotations.update(
                {
                    "cloned_from": new_uid,
                    "client_name": c_name,
                    "baseline_technology": technology.slug,
                }
            )
            rule_copy["annotations"] = c_annotations

            client_ds = _find_tenant_datasource(c_name, c_uid, raw_datasources) or target_ds
            bind_rule_datasource(rule_copy, client_ds)
            apply_contact_point(rule_copy, contact_point=stg_contact_point)

            try:
                await grafana.create_alert_rule(rule_copy)
                await grafana.set_rule_group_interval(
                    c_uid,
                    tenant_rule_group(c_name),
                    RULE_GROUP_INTERVAL_SECONDS,
                )
                replicated_rules.append(
                    ImplementedRuleResult(
                        uid=clone_uid,
                        title=clone_title,
                        status="created",
                        detail=c_name,
                    )
                )
            except GrafanaError as exc:
                replicated_rules.append(
                    ImplementedRuleResult(
                        uid=clone_uid,
                        title=clone_title,
                        status="failed",
                        detail=f"{c_name}: {exc.message}",
                    )
                )

    replicated_count = sum(1 for item in replicated_rules if item.status == "created")

    if replicated_to_clients:
        if replicated_count > 0:
            msg = (
                f"Regra de detecÃ§Ã£o criada no Baseline (data source '{ds_name}') e replicada "
                f"automaticamente para {replicated_count} cliente(s) que possuem a tecnologia '{technology.name}'!"
            )
        elif replicated_rules:
            msg = (
                f"Regra de detecÃ§Ã£o criada no Baseline (data source '{ds_name}'). "
                f"Os clientes que possuem a tecnologia '{technology.name}' jÃ¡ contavam com esta regra."
            )
        else:
            msg = (
                f"Regra de detecÃ§Ã£o criada no Baseline (data source '{ds_name}'). "
                f"Nenhum cliente possui atualmente a tecnologia '{technology.name}' para replicaÃ§Ã£o."
            )
    else:
        msg = (
            f"Regra de detecÃ§Ã£o criada com sucesso para a tecnologia '{technology.name}' "
            f"(data source '{ds_name}')!"
        )

    return CreateRuleResponse(
        message=msg,
        uid=new_uid,
        title=rule_title,
        folder_uid=folder_uid,
        folder_title=folder_title,
        scope=payload.scope,
        severity=payload.severity,
        technology=technology.slug,
        technology_name=technology.name,
        labels=labels,
        contact_point=DEFAULT_CONTACT_POINT,
        datasource_uid=ds_uid,
        datasource_name=ds_name,
        replicated_to_clients=replicated_to_clients,
        replicated_count=replicated_count,
        replicated_rules=replicated_rules,
    )




