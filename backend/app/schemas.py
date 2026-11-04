"""Modelos (Pydantic) de entrada e saÃ­da da API do portal.

O frontend depende APENAS destes modelos, nunca do formato bruto do Grafana.
Isso isola o portal de mudanÃ§as entre versÃµes da API do Grafana.
Timestamps sÃ£o strings ISO-8601 (UTC) com no mÃ¡ximo milissegundos.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

RuleState = Literal[
    "firing", "pending", "recovering", "normal", "paused", "error", "nodata", "unknown"
]
AlertState = Literal["active", "suppressed", "unprocessed"]
SilenceState = Literal["active", "pending", "expired"]
# Natureza operacional do silence (segregaÃ§Ã£o da tela de Silences):
#   permanent   -> exceÃ§Ã£o permanente a uma regra de detecÃ§Ã£o (whitelist operacional)
#   antiflood   -> supressÃ£o temporÃ¡ria criada pelo mecanismo de antiflood
#   maintenance -> janela de manutenÃ§Ã£o planejada (deploy, upgrade, mudanÃ§a)
#   manual      -> supressÃ£o temporÃ¡ria ad hoc criada pelo operador
SilenceKind = Literal["permanent", "antiflood", "maintenance", "manual"]

# Conformidade de um cliente frente ao baseline de uma tecnologia:
#   complete       -> todas as regras do baseline replicadas
#   partial        -> parte do baseline replicada
#   none           -> cliente possui a tecnologia, mas nenhuma regra do baseline
#   not_applicable -> cliente fora do footprint da tecnologia
TechnologyComplianceStatus = Literal["complete", "partial", "none", "not_applicable"]

# Origem da evidÃªncia do footprint de tecnologia de um cliente.
TechnologyFootprintSource = Literal["derived", "declared", "both", "none"]


# EstÃ¡gio de deploy da regra, derivado do Contact Point amarrado a ela:
#   active     -> regra avaliando com Contact Point 'prod'
#   homolog    -> regra avaliando com Contact Point 'dev'/'stg'
#   paused     -> regra pausada (independente do Contact Point)
#   unassigned -> regra avaliando sem Contact Point conhecido (ninguÃ©m recebe o alerta)
DeployStatus = Literal["active", "homolog", "paused", "unassigned"]


# --- AutenticaÃ§Ã£o / sistema -------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class UserInfo(BaseModel):
    username: str


class PortalConfig(BaseModel):
    grafana_public_url: str
    refresh_interval_seconds: int
    is_external_grafana: bool = False
    evaluation_group_optional: bool = False
    baseline_folder_uid: str = "global"
    app_version: str = "0.1.0"


class AppVersionInfo(BaseModel):
    current_version: str
    latest_version: str | None = None
    update_available: bool = False
    release_url: str | None = None
    release_name: str | None = None
    published_at: str | None = None
    release_notes: str | None = None
    checked_at: str | None = None
    error: str | None = None
    ghcr_status: str | None = None
    ghcr_message: str | None = None


class UpgradeTriggerRequest(BaseModel):
    target_version: str | None = None


class UpgradeTriggerResponse(BaseModel):
    status: Literal["upgrading", "manual_action_required", "error"]
    message: str
    target_version: str | None = None
    started_at: str | None = None


class UpgradeStatusResponse(BaseModel):
    status: Literal["idle", "upgrading", "completed", "failed", "manual_action_required"]
    last_upgraded_at: str | None = None
    target_version: str | None = None
    current_version: str
    message: str | None = None


class HealthStatus(BaseModel):
    status: Literal["ok"]
    version: str | None = None


class ReadinessStatus(BaseModel):
    status: Literal["ok", "degraded"]
    grafana_reachable: bool
    grafana_token_configured: bool


# --- Regras de detecÃ§Ã£o -----------------------------------------------------
class RuleSummary(BaseModel):
    uid: str
    title: str
    folder_uid: str
    folder_title: str
    rule_group: str
    rule_type: Literal["alerting", "recording"]
    labels: dict[str, str]
    annotations: dict[str, str]
    is_paused: bool
    for_duration: str | None
    state: RuleState
    health: str | None
    last_evaluation: str | None
    last_error: str | None
    active_instances: int
    updated: str | None
    # Contact Point amarrado Ã  regra (rota de notificaÃ§Ã£o) e o estÃ¡gio de deploy
    # que ele representa para o operador (Ativa / HomologaÃ§Ã£o / Pausada / Sem CP).
    contact_point: str | None = None
    deploy_status: DeployStatus = "unassigned"
    silenced_instances: int = 0


class RuleQuery(BaseModel):
    ref_id: str
    datasource_uid: str | None
    relative_time_range: dict[str, Any] | None
    model: dict[str, Any]


class RuleDetail(RuleSummary):
    condition: str | None
    no_data_state: str | None
    exec_err_state: str | None
    provenance: str | None
    queries: list[RuleQuery]


# --- Alertas ----------------------------------------------------------------
class AlertInstance(BaseModel):
    fingerprint: str
    alertname: str
    rule_uid: str | None
    state: AlertState
    silenced_by: list[str]
    inhibited_by: list[str]
    labels: dict[str, str]
    annotations: dict[str, str]
    starts_at: str | None
    updated_at: str | None


class GenerateSyntheticAlertsRequest(BaseModel):
    rule_uid: str | None = None
    count: int = 15


class ClearSyntheticAlertsResponse(BaseModel):
    status: str
    cleared: int


class AlertHistoryEvent(BaseModel):
    id: str
    alertname: str
    rule_uid: str | None = None
    timestamp: str
    state: str
    labels: dict[str, str] = Field(default_factory=dict)
    text: str = ""


class AlertHistoryResponse(BaseModel):
    window_hours: float
    total_events: int
    firing_count: int
    silenced_count: int
    events: list[AlertHistoryEvent] = Field(default_factory=list)


# --- Silences ---------------------------------------------------------------
class SilenceMatcher(BaseModel):
    name: str
    value: str
    is_regex: bool
    is_equal: bool


class SilencedAlertSummary(BaseModel):
    fingerprint: str
    alertname: str
    grafana_folder: str | None = None
    severity: str | None = "medium"
    starts_at: str | None = None
    state: str | None = "suppressed"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)


class Silence(BaseModel):
    id: str
    state: SilenceState
    kind: SilenceKind = "manual"
    matchers: list[SilenceMatcher]
    starts_at: str | None
    ends_at: str | None
    updated_at: str | None
    created_by: str
    comment: str
    silenced_alerts_count: int = 0
    silenced_alerts: list[SilencedAlertSummary] = Field(default_factory=list)


class CreateSilenceMatcher(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=512)
    is_regex: bool = False
    is_equal: bool = True


class CreateSilenceRequest(BaseModel):
    matchers: list[CreateSilenceMatcher] = Field(min_length=1)
    starts_at: str | None = None
    ends_at: str
    comment: str = Field(min_length=1, max_length=1000)
    kind: SilenceKind = "manual"
    """Natureza declarada pelo operador; vira tag no comentÃ¡rio (origem explÃ­cita)."""


class CreateSilenceResponse(BaseModel):
    silence_id: str


class ExtendSilenceRequest(BaseModel):
    duration: Literal["2h", "4h", "8h", "24h", "3d", "10y"]


class ToggleRulePauseRequest(BaseModel):
    paused: bool


class BatchToggleRulesPauseRequest(BaseModel):
    uids: list[str] = Field(min_length=1, max_length=500)
    paused: bool


class BatchToggleRulesPauseResponse(BaseModel):
    message: str
    total: int
    succeeded: list[str]
    failed: list[dict[str, str]]


class PausedRuleMatchItem(BaseModel):
    rule_uid: str
    rule_title: str
    folder_uid: str
    folder_title: str
    matched_events_count: int = 0
    matched_window: str = "15m"
    sample_logs: list[str] = Field(default_factory=list)


class PausedRulesMatchesResponse(BaseModel):
    total_paused: int
    matching_rules_count: int
    total_events: int
    evaluated_at: str
    window: str = "15m"
    rules: list[PausedRuleMatchItem] = Field(default_factory=list)



# --- Pastas / Clientes SIEM (Tenants) ----------------------------------------
class FolderItem(BaseModel):
    id: int | None = None
    uid: str
    title: str


class CreateFolderRequest(BaseModel):
    title: str = Field(min_length=1, max_length=128)
    uid: str | None = Field(default=None, max_length=40)


class TenantSummary(BaseModel):
    id: int | None = None
    uid: str
    title: str
    rules_count: int
    active_rules_count: int
    paused_rules_count: int
    rules_uids: list[str] = Field(default_factory=list)
    # Data source Loki dedicado ao tenant (segregaÃ§Ã£o lÃ³gica por cliente).
    loki_datasource_name: str | None = None
    loki_datasource_uid: str | None = None
    loki_datasource_url: str | None = None
    loki_datasource_present: bool = False
    loki_datasource_url_matches: bool = True
    """``False`` quando o data source existe mas aponta para URL diferente da padrÃ£o."""
    # Grupo de avaliaÃ§Ã£o do tenant (Evaluation group and interval no Grafana).
    evaluation_group: str | None = None
    evaluation_group_interval: str | None = None
    evaluation_group_present: bool = False
    evaluation_groups: list[dict[str, Any]] = Field(default_factory=list)
    """Grupos de avaliaÃ§Ã£o existentes na pasta do tenant (inclui nome, intervalo e contagem de regras)."""
    evaluation_group_optional: bool = False
    """Se o grupo de avaliaÃ§Ã£o padrÃ£o Ã© opcional no modo atual (Grafana externo)."""
    # Escaneamento de tecnologias (evidÃªncia de logs no Loki do prÃ³prio tenant).
    technologies_count: int = 0
    technologies_scanned_at: str | None = None
    # Data source Loki de Sandbox do tenant (laboratório e testes isolados).
    sandbox_datasource_present: bool = False
    sandbox_datasource_name: str | None = None
    sandbox_datasource_uid: str | None = None


class TenantTechnologyScanRequest(BaseModel):
    """Janela de anÃ¡lise do escaneamento de tecnologias de um tenant."""

    window_seconds: int = Field(default=3600, ge=60, le=86400)


class TenantTechnologyScanItem(BaseModel):
    """Tecnologia do catÃ¡logo com a contagem de logs observada no tenant."""

    slug: str
    name: str
    icon: str = ""
    description: str = ""
    logs_count: int = 0
    found: bool = False


class TenantTechnologyScanResponse(BaseModel):
    """Resultado do escaneamento de tecnologias de um cliente."""

    message: str
    tenant_uid: str
    client_name: str
    datasource: str | None = None
    datasource_uid: str | None = None
    window_seconds: int
    scanned_at: str
    available: bool
    technologies_detected: int
    technologies_total: int
    technologies: list[TenantTechnologyScanItem] = Field(default_factory=list)


class TenantTechnologyBaselineState(BaseModel):
    """Estado de uma tecnologia no cliente frente ao baseline da pasta global."""

    slug: str
    name: str
    icon: str = ""
    description: str = ""
    # EvidÃªncia de telemetria no Loki do tenant (Ãºltimo escaneamento).
    detected: bool = False
    logs_count: int = 0
    # Estado do baseline no cliente.
    baseline_rules: int = 0
    implemented_rules: int = 0
    paused_rules: int = 0
    existing_rules: int = 0
    compliance_pct: float = 0.0
    status: TechnologyComplianceStatus = "none"


class TenantTechnologiesResponse(BaseModel):
    """Tecnologias do cliente com o estado de conformidade de cada baseline."""

    tenant_uid: str
    client_name: str
    scanned_at: str | None = None
    window_seconds: int | None = None
    datasource: str | None = None
    available: bool = False
    technologies_detected: int = 0
    technologies_total: int = 0
    technologies: list[TenantTechnologyBaselineState] = Field(default_factory=list)


class CreateTenantRequest(BaseModel):
    title: str = Field(min_length=1, max_length=128)
    uid: str | None = Field(default=None, max_length=40)
    loki_url: str | None = Field(default=None, max_length=200)
    """URL do Loki do cliente. Vazio = usa ``LOKI_TENANT_DATASOURCE_URL`` (Loki da stack)."""


class CreateTenantDatasourceRequest(BaseModel):
    """Recria o data source Loki de um tenant jÃ¡ existente (backfill/correÃ§Ã£o)."""

    loki_url: str | None = Field(default=None, max_length=200)


class TenantDatasourceResponse(BaseModel):
    message: str
    uid: str
    datasource_name: str
    datasource_uid: str
    datasource_url: str


class TenantSandboxResponse(BaseModel):
    """Resposta da operação de ativação ou desativação do data source de sandbox do tenant."""

    message: str
    uid: str
    sandbox_datasource_name: str
    sandbox_datasource_uid: str
    present: bool


class RepairEvaluationGroupRequest(BaseModel):
    """CorreÃ§Ã£o do grupo de avaliaÃ§Ã£o de um tenant legado/desviante.

    ``migrate_rules`` move para o grupo canônico ``5m`` as regras
    de detecÃ§Ã£o do tenant que estejam em outro grupo (ex.: grupo antigo do
    Grafana), evitando dois grupos concorrentes na mesma pasta.
    """

    migrate_rules: bool = True


class TenantEvaluationGroupResponse(BaseModel):
    """Resultado da materializaÃ§Ã£o/recuperaÃ§Ã£o do grupo de avaliaÃ§Ã£o do tenant."""

    message: str
    uid: str
    evaluation_group: str
    evaluation_group_interval: str | None = None
    evaluation_group_present: bool = False
    anchor_created: bool = False
    anchor_rule_uid: str | None = None
    migrated_rules: list[str] = Field(default_factory=list)
    migration_failures: list[dict[str, str]] = Field(default_factory=list)


class ToggleTenantPauseRequest(BaseModel):
    paused: bool = True



# --- DuplicaÃ§Ã£o de Regra e Teste LogQL ----------------------------------------
class DuplicateRuleRequest(BaseModel):
    target_folder_uid: str = Field(min_length=1, max_length=40)
    target_folder_title: str | None = None
    new_title: str = Field(min_length=1, max_length=190)
    new_rule_group: str | None = None
    client_name: str = Field(min_length=1, max_length=64)
    custom_logql: str | None = None


class TestLogQLRequest(BaseModel):
    logql_query: str = Field(min_length=1)
    log_line: str = Field(min_length=1)
    stream_labels: dict[str, str] | None = None


# --- Matriz de Regras Globais por Cliente -----------------------------------
ClientRuleStatusType = Literal["active", "paused", "not_implemented"]


class ClientRuleCoverage(BaseModel):
    client_uid: str
    client_name: str
    status: ClientRuleStatusType
    rule_uid: str | None = None
    rule_title: str | None = None


class GlobalRuleMatrixItem(BaseModel):
    global_uid: str
    global_title: str
    labels: dict[str, str]
    annotations: dict[str, str]
    total_clients: int
    implemented_clients_count: int
    active_clients_count: int
    paused_clients_count: int
    not_implemented_clients_count: int
    clients: list[ClientRuleCoverage]


# =============================================================================
# Tecnologias / Data Sources (mapeamento rule_groups / ss_groups -> tecnologia)
# =============================================================================


class TechnologyOut(BaseModel):
    """Tecnologia exposta à UI, já com o seletor LogQL pronto e perímetro mapeado."""

    slug: str
    name: str
    rule_groups_regex: str = ""
    ss_groups_regex: str = ""
    job: str
    description: str
    icon: str
    enabled: bool
    perimeter: str = "other"
    perimeter_name: str = "Outro"
    logql_selector: str

    @model_validator(mode="before")
    @classmethod
    def _sync_groups(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("rule_groups_regex") or data.get("ss_groups_regex") or ""
            if val:
                data.setdefault("rule_groups_regex", val)
                data.setdefault("ss_groups_regex", val)
        return data


class DetectionPerimeterOut(BaseModel):
    """Perímetro de segurança canônico (ex: Firewall, WAF, Antimalware/EDR)."""

    slug: str
    name: str
    icon: str = "category"
    description: str = ""
    keywords: list[str] = Field(default_factory=list)
    technologies_count: int = 0


class TechnologyUpsertRequest(BaseModel):
    """Criação/atualização de tecnologia na base do portal.
    
    Suporta 'rule_groups_regex' (padrão público do Wazuh) e 'ss_groups_regex' (legado).
    """

    slug: str = Field(min_length=2, max_length=32)
    name: str = Field(min_length=1, max_length=64)
    rule_groups_regex: str | None = Field(default=None, min_length=1, max_length=200)
    ss_groups_regex: str | None = Field(default=None, min_length=1, max_length=200)
    job: str = Field(default="wazuh", min_length=1, max_length=32)
    description: str = Field(default="", max_length=500)
    icon: str = Field(default="", max_length=8)
    enabled: bool = True
    perimeter: str = Field(default="other", max_length=32)
    # Confirmação explícita do operador para cadastrar uma tecnologia cujo
    # recorte de rule_groups ainda não produziu logs no Loki (o backend recusa a
    # criação sem esse aceite quando a telemetria é consultável).
    confirm_without_logs: bool = False

    @model_validator(mode="before")
    @classmethod
    def _sync_regexes(cls, data: Any) -> Any:
        if isinstance(data, dict):
            rg = data.get("rule_groups_regex") or data.get("ss_groups_regex")
            if rg:
                data.setdefault("rule_groups_regex", rg)
                data.setdefault("ss_groups_regex", rg)
        return data

    @property
    def effective_groups_regex(self) -> str:
        return self.rule_groups_regex or self.ss_groups_regex or ""


class TechnologyDeleteResponse(BaseModel):
    message: str
    slug: str


# --- CriaÃ§Ã£o e Teste de Regras de DetecÃ§Ã£o -----------------------------------
RuleScope = Literal["baseline", "client"]
RuleSeverity = Literal["low", "medium", "high", "critical"]


ImplementedRuleStatus = Literal["created", "skipped", "failed"]


class ImplementedRuleResult(BaseModel):
    """Resultado individual da implementaÃ§Ã£o de uma regra de baseline."""

    uid: str
    title: str
    status: ImplementedRuleStatus
    detail: str | None = None


class CreateRuleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=190)
    description: str | None = None
    scope: RuleScope
    target_client_uid: str | None = None
    logql_query: str = Field(min_length=1)
    severity: RuleSeverity
    mitre_tactic: str = Field(min_length=1, max_length=64)
    mitre_technique: str = Field(min_length=1, max_length=64)
    evaluation_group: str | None = Field(
        default=None,
        max_length=128,
        description="Grupo de avaliaÃ§Ã£o (evaluation group) no Grafana Alerting para a regra.",
    )
    technology: str | None = Field(
        default=None,
        max_length=32,
        description=(
            "Slug da tecnologia (data source) que a regra irÃ¡ observar. Se omitido, o "
            "backend tenta inferir a partir do matcher ss_groups da query."
        ),
    )
    replicate_to_clients: bool = Field(
        default=False,
        description=(
            "Quando True em regras de baseline, replica automaticamente a regra "
            "para todos os clientes que possuem a tecnologia amarrada Ã  regra."
        ),
    )


class CreateRuleResponse(BaseModel):
    message: str
    uid: str
    title: str
    folder_uid: str
    folder_title: str
    scope: RuleScope
    severity: RuleSeverity
    technology: str | None = None
    technology_name: str | None = None
    labels: dict[str, str]
    # EstÃ¡gio de deploy com que a regra nasceu (regra de negÃ³cio: sempre 'dev').
    contact_point: str | None = None
    # Data source Loki vinculado Ã  regra no Grafana ("Loki" no baseline ou data source do cliente).
    datasource_uid: str | None = None
    datasource_name: str | None = None
    replicated_to_clients: bool = False
    replicated_count: int = 0
    replicated_rules: list[ImplementedRuleResult] = Field(default_factory=list)


# =============================================================================
# Curadoria / Avaliacao de Regras de Deteccao
# =============================================================================
CurationCandidateQuality = Literal["excellent", "good", "bad"]
CurationSourceId = Literal["sigmahq", "detection_fyi", "splunk_research", "elastic_rules"]


class CurationFieldMapping(BaseModel):
    """Mapeamento de campo da regra original para o formato LogQL/Wazuh do D.A.N.T.E."""

    original_field: str
    logql_field: str
    compatible: bool = True
    observed_in_logs: bool = False
    sample_values: list[str] = Field(default_factory=list)


class CurationQualificationFactor(BaseModel):
    """Fator determinante para qualificar a regra como excelente, boa ou ma candidata."""

    criterion: str
    status: Literal["met", "partial", "not_met"] = "met"
    impact: Literal["excellent", "good", "bad"] = "good"
    summary: str


class CurationClientEvaluation(BaseModel):
    """Resultado da avaliacao da regra LogQL convertida no Loki de um cliente."""

    client_uid: str
    client_name: str
    datasource_uid: str | None = None
    datasource_name: str | None = None
    classification: CurationCandidateQuality
    matched_lines_count: int = 0
    tech_logs_count: int = 0
    field_compatibility_pct: float = 100.0
    log_presence_score: float = 0.0
    threat_context_score: float = 0.0
    scenario_match_score: float = 0.0
    matched_fields: list[str] = Field(default_factory=list)
    observed_fields_in_logs: list[str] = Field(default_factory=list)
    missing_fields_in_logs: list[str] = Field(default_factory=list)
    total_observed_log_fields: list[str] = Field(default_factory=list)
    observed_field_compatibility_pct: float = 0.0
    has_query_results: bool = False
    matched_window: str | None = None
    windows_evaluated: list[str] = Field(default_factory=list)
    timed_out: bool = False
    timeout_detail: str | None = None
    query_executed: str = ""
    sample_matched_logs: list[str] = Field(default_factory=list)
    sample_tech_logs: list[str] = Field(default_factory=list)
    qualification_factors: list[CurationQualificationFactor] = Field(default_factory=list)
    reason: str
    already_implemented: bool = False


# --- ImportaÃ§Ã£o de Regras de DetecÃ§Ã£o (Loki Ruler) ----------------------------
class RuleImportFileInput(BaseModel):
    filename: str = Field(description="Nome do arquivo importado")
    content: str = Field(description="ConteÃºdo bruto do arquivo (JSON ou YAML)")


class RuleImportPreviewRequest(BaseModel):
    content: str | None = Field(
        default=None,
        description="ConteÃºdo bruto de arquivo Ãºnico (JSON ou YAML) para importaÃ§Ã£o",
    )
    files: list[RuleImportFileInput] = Field(
        default_factory=list,
        description="Lista de mÃºltiplos arquivos para importaÃ§Ã£o automÃ¡tica",
    )


class RuleImportItemValidation(BaseModel):
    index: int
    title: str
    description: str | None = None
    query: str
    threshold_operator: str = "gt"
    threshold_value: float = 0.0
    severity: RuleSeverity = "medium"
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    technology: str | None = None
    technology_name: str | None = None
    for_duration: str = "0s"
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    already_exists: bool = False
    filename: str | None = None
    technology_missing: bool = False
    suggested_technology_slug: str | None = None
    suggested_technology_name: str | None = None
    suggested_rule_groups_regex: str | None = None
    suggested_ss_groups_regex: str | None = None

    # Campos de Curadoria, Parecer Tecnico de IA e Compatibilidade de Campos
    classification: CurationCandidateQuality | None = None
    classification_reason: str | None = None
    field_compatibility_pct: float = 100.0
    log_presence_score: float = 0.0
    threat_context_score: float = 0.0
    scenario_match_score: float = 0.0
    observed_field_compatibility_pct: float = 0.0
    total_matched_results: int = 0
    total_tech_logs_seen: int = 0
    has_query_results: bool = False
    matched_windows_summary: list[str] = Field(default_factory=list)
    observed_fields_in_logs: list[str] = Field(default_factory=list)
    missing_fields_in_logs: list[str] = Field(default_factory=list)
    sample_query_results: list[str] = Field(default_factory=list)
    mapped_fields: list[CurationFieldMapping] = Field(default_factory=list)
    qualification_factors: list[CurationQualificationFactor] = Field(default_factory=list)
    client_evaluations: list[CurationClientEvaluation] = Field(default_factory=list)
    excellent_clients_count: int = 0
    good_clients_count: int = 0
    ai_model: str | None = None
    ai_rationale: str | None = None
    curation_engine: Literal["ai", "heuristic"] = "heuristic"
    curated_at: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _sync_suggested_groups(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("suggested_rule_groups_regex") or data.get("suggested_ss_groups_regex")
            if val:
                data.setdefault("suggested_rule_groups_regex", val)
                data.setdefault("suggested_ss_groups_regex", val)
        return data


class RuleImportPreviewResponse(BaseModel):
    total_rules: int
    valid_count: int
    invalid_count: int
    missing_tech_count: int = 0
    qualified_count: int = 0
    high_compatibility_count: int = 0
    discarded_count: int = 0
    items: list[RuleImportItemValidation]
    general_error: str | None = None
    files_count: int = 0


class RuleImportExecuteRequest(BaseModel):
    rules: list[RuleImportItemValidation] = Field(min_length=1)
    datasource_uid: str | None = Field(
        default=None,
        description="UID do data source Loki interno onde as regras serão apontadas. Se omitido, usa o data source padrão.",
    )
    evaluation_group: str | None = Field(
        default=None,
        description="Grupo de avaliação (evaluation group / ruleGroup) no Grafana Alerting. Se omitido, usa o grupo padrão 'global-detections'.",
    )


class RuleImportExecuteResponse(BaseModel):
    message: str
    total: int
    imported_count: int
    failed_count: int
    imported_uids: list[str] = Field(default_factory=list)
    imported_titles: list[str] = Field(default_factory=list)
    failed: list[dict[str, str]] = Field(default_factory=list)


class ExecuteQueryRequest(BaseModel):
    query: str = Field(min_length=1)
    time_range_from: str = "now-1h"
    time_range_to: str = "now"
    limit: int = 50
    scope: str | None = None
    client_uid: str | None = None


class LogLineResult(BaseModel):
    timestamp: str
    line: str
    labels: dict[str, str] = Field(default_factory=dict)


class EnvironmentQueryResult(BaseModel):
    """Resultado da execução de query LogQL em um ambiente específico (sandbox ou produção)."""

    environment: str = Field(description="'sandbox' ou 'production'")
    environment_label: str = Field(description="Rótulo formatado ('Ambiente Sandbox' ou 'Ambiente de Produção')")
    datasource_name: str
    datasource_uid: str
    success: bool
    total_lines: int
    lines: list[LogLineResult] = Field(default_factory=list)
    duration_ms: float
    error: str | None = None
    is_timeout: bool = False


class ExecuteQueryResult(BaseModel):
    success: bool
    query: str
    total_lines: int
    lines: list[LogLineResult]
    duration_ms: float
    is_timeout: bool = False
    error: str | None = None
    datasource_name: str | None = None
    environments: list[EnvironmentQueryResult] | None = None


# --- Tecnologias: validaÃ§Ã£o de telemetria e conformidade de baseline ----------
class TechnologyLogCheckRequest(BaseModel):
    """VerificaÃ§Ã£o implÃ­cita de presenÃ§a de logs para um recorte de ``ss_groups``.

    A query LogQL Ã© montada somente no backend e nunca Ã© devolvida ao cliente.
    """

    slug: str | None = Field(default=None, max_length=32)
    rule_groups_regex: str | None = Field(default=None, max_length=200)
    ss_groups_regex: str | None = Field(default=None, max_length=200)
    job: str | None = Field(default=None, max_length=32)
    window_seconds: int = Field(default=60, ge=30, le=3600)

    @model_validator(mode="before")
    @classmethod
    def _sync_presence_regex(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("rule_groups_regex") or data.get("ss_groups_regex")
            if val:
                data.setdefault("rule_groups_regex", val)
                data.setdefault("ss_groups_regex", val)
        return data


class TechnologyLogCheckResult(BaseModel):
    """Resultado da consulta implÃ­cita ao Loki (sem expor a query executada)."""

    available: bool
    found: bool
    count: int = 0
    window_seconds: int = 60
    datasource: str | None = None
    checked_at: str
    message: str


class TechnologyClientCompliance(BaseModel):
    """Conformidade de um cliente (pasta) frente ao baseline de uma tecnologia.

    ``applicable`` indica se a tecnologia faz parte do footprint do cliente. CÃ©lulas
    fora do footprint recebem ``status='not_applicable'`` e nÃ£o entram no
    denominador do baseline â€” o cliente nÃ£o pode ser penalizado por uma tecnologia
    que nÃ£o possui no SIEM.
    """

    client_uid: str
    client_name: str
    integrated: bool
    applicable: bool = True
    footprint_source: TechnologyFootprintSource = "none"
    implemented_rules: int
    paused_rules: int
    total_baseline_rules: int
    compliance_pct: float
    status: TechnologyComplianceStatus


class TechnologyOverviewItem(BaseModel):
    """Tecnologia do catálogo com distribuição por cliente, conformidade e perímetro."""

    slug: str
    name: str
    icon: str = ""
    description: str = ""
    rule_groups_regex: str = ""
    ss_groups_regex: str = ""
    job: str
    enabled: bool
    perimeter: str = "other"
    perimeter_name: str = "Outro"
    baseline_rules_count: int
    client_rules_count: int
    integrated_clients_count: int
    applicable_clients_count: int = 0
    excluded_clients_count: int = 0

    @model_validator(mode="before")
    @classmethod
    def _sync_overview_regex(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("rule_groups_regex") or data.get("ss_groups_regex") or ""
            if val:
                data.setdefault("rule_groups_regex", val)
                data.setdefault("ss_groups_regex", val)
        return data
    implemented_baseline_rules: int
    total_baseline_slots: int
    compliance_pct: float
    clients: list[TechnologyClientCompliance] = Field(default_factory=list)


class TechnologyOverviewMetrics(BaseModel):
    """Indicadores de topo da pÃ¡gina de Tecnologias."""

    unique_technologies: int
    enabled_technologies: int
    baseline_rules_total: int
    baseline_rules_unmapped: int
    clients_total: int
    clients_with_technology: int
    client_rules_total: int
    implemented_baseline_rules: int
    total_baseline_slots: int
    not_applicable_slots: int = 0
    compliance_pct: float


class TechnologyOverviewResponse(BaseModel):
    """VisÃ£o consolidada: mÃ©tricas, distribuiÃ§Ã£o e mapa de conformidade."""

    metrics: TechnologyOverviewMetrics
    technologies: list[TechnologyOverviewItem]
    generated_at: str


class TenantTechnologyFootprintRequest(BaseModel):
    """InventÃ¡rio declarado de tecnologias de um cliente (substituiÃ§Ã£o total)."""

    technologies: list[str] = Field(default_factory=list, max_length=200)


class TenantTechnologyFootprintOut(BaseModel):
    """Footprint efetivo de um cliente: derivado + declarado."""

    client_uid: str
    client_name: str
    derived: list[str] = Field(default_factory=list)
    declared: list[str] = Field(default_factory=list)
    effective: list[str] = Field(default_factory=list)
    updated_at: str


class ImplementBaselineRequest(BaseModel):
    """ImplementaÃ§Ã£o em lote do baseline de uma tecnologia em um cliente."""

    target_folder_uid: str = Field(min_length=1, max_length=40)
    target_folder_title: str | None = Field(default=None, max_length=190)
    confirm_client_without_technology: bool = False
    evaluation_group: str | None = Field(
        default=None,
        max_length=128,
        description="Grupo de avaliação (evaluation group / ruleGroup) de destino no cliente. Se omitido, usa o padrão do tenant '5m'.",
    )


class ImplementBaselineResponse(BaseModel):
    """Resumo da implementaÃ§Ã£o automÃ¡tica do baseline de uma tecnologia."""

    message: str
    technology: str
    technology_name: str
    client_uid: str
    client_name: str
    total: int
    created: int
    skipped: int
    failed: int
    rules: list[ImplementedRuleResult] = Field(default_factory=list)
    contact_point: str | None = Field(default=None, description="Contact Point do Grafana atribuído às regras implementadas (estágio 'stg').")
    evaluation_group: str | None = Field(default=None, description="Grupo de avaliação (ruleGroup) atribuído às regras implementadas no cliente.")


# --- Loki / laboratÃ³rio de logs sintÃ©ticos ----------------------------------
class LokiDatasourceItem(BaseModel):
    """Data source Loki disponível no Grafana para consulta ou injeção."""

    uid: str
    name: str
    type: str = "loki"
    url: str | None = None
    is_internal: bool = True
    is_default: bool = False
    is_sandbox: bool = False
    can_inject: bool = True
    client_name: str | None = None


class LokiStatusResponse(BaseModel):
    """Disponibilidade do Loki e labels conhecidas (para autocompletar a UI)."""

    available: bool
    ready: bool
    datasource: str | None = None
    datasource_uid: str | None = None
    url: str | None = None
    labels: list[str] = Field(default_factory=list)
    message: str


class LokiSyntheticRequest(BaseModel):
    """InjeÃ§Ã£o de linhas JSON fictÃ­cias em um stream do Loki."""

    datasource_uid: str | None = Field(
        default=None,
        description="UID do data source Loki de destino (apenas internos sÃ£o permitidos).",
    )
    stream: dict[str, str]
    """Labels do stream; ``job`` Ã© obrigatÃ³rio (normalmente ``wazuh``)."""

    lines: list[dict[str, Any]] = Field(min_length=1, max_length=200)
    """Corpo JSON de cada linha (objetos; serializados compactos no push)."""

    spread_seconds: int = Field(default=300, ge=0, le=86400)
    """Distribui as linhas nos Ãºltimos N segundos (timestamps no passado)."""

    mark_synthetic: bool = True
    """Adiciona ``synthetic="true"`` / ``synthetic_source="portal"`` Ã s labels."""


class LokiSyntheticResponse(BaseModel):
    """Resultado da injeÃ§Ã£o, jÃ¡ verificado por consulta ao prÃ³prio Loki."""

    status: Literal["ok"]
    datasource: str
    datasource_uid: str
    stream: dict[str, str]
    lines_sent: int
    bytes_sent: int
    logql: str
    verified_count: int
    verified: bool
    grafana_explore_url: str | None = None
    message: str






# --- HomologaÃ§Ã£o (estado de deploy por Contact Point) -----------------------
class ContactPointInfo(BaseModel):
    """Contact Point provisionado no Grafana e o estÃ¡gio que ele representa."""

    name: str
    uid: str | None = None
    type: str | None = None
    # 'prod' | 'homolog' | 'other' (nomes fora do padrÃ£o do portal)
    tier: Literal["prod", "homolog", "other"] = "other"
    standard: bool = False


class HomologationMetrics(BaseModel):
    """Contagem de regras por estÃ¡gio de deploy."""

    total_rules: int
    active: int
    homolog: int
    paused: int
    unassigned: int


class HomologationClientBreakdown(BaseModel):
    """DistribuiÃ§Ã£o dos estÃ¡gios de deploy dentro de um tenant (pasta)."""

    folder_uid: str
    folder_title: str
    total: int
    active: int
    homolog: int
    paused: int
    unassigned: int


class HomologationOverview(BaseModel):
    """VisÃ£o de homologaÃ§Ã£o: contact points, mÃ©tricas, clientes e regras."""

    generated_at: str
    contact_points: list[ContactPointInfo] = Field(default_factory=list)
    # Contact Points canÃ´nicos ausentes na instÃ¢ncia do Grafana (dev/stg/prod).
    missing_contact_points: list[str] = Field(default_factory=list)
    stage_contact_points: dict[str, str] = Field(default_factory=dict)
    metrics: HomologationMetrics
    clients: list[HomologationClientBreakdown] = Field(default_factory=list)
    rules: list[RuleSummary] = Field(default_factory=list)


class UpdateStageContactPointsRequest(BaseModel):
    """Mapeamento de cada estÃ¡gio (stg, dev, prod) para Contact Points reais do Grafana."""

    stage_contact_points: dict[str, str] = Field(
        description="DicionÃ¡rio com chaves 'stg', 'dev', 'prod' e os nomes dos Contact Points correspondentes."
    )


class SetRuleContactPointRequest(BaseModel):
    """PromoÃ§Ã£o/rebaixamento explÃ­cito do estÃ¡gio de deploy de uma regra."""

    contact_point: str = Field(min_length=1, max_length=64)


class SetRuleContactPointResponse(BaseModel):
    message: str
    uid: str
    title: str
    contact_point: str | None
    deploy_status: DeployStatus
    previous_contact_point: str | None = None
    previous_deploy_status: DeployStatus | None = None


RuleAlertEventKind = Literal["firing", "resolved", "pending", "nodata", "error", "other"]


class RuleAlertHistoryEvent(BaseModel):
    """Evento de transiÃ§Ã£o de estado de uma regra de detecÃ§Ã£o registrado no Grafana."""

    id: str
    timestamp: str
    new_state: str
    prev_state: str
    kind: RuleAlertEventKind
    text: str = ""
    labels: dict[str, str] = Field(default_factory=dict)
    values: dict[str, float] = Field(default_factory=dict)


class RuleAlertHistogramBucket(BaseModel):
    """Intervalo temporal do histograma de alertas e transiÃ§Ãµes de uma regra."""

    bucket_start: str
    bucket_end: str
    label: str
    firing_count: int = 0
    resolved_count: int = 0
    other_count: int = 0
    total_events: int = 0


class RuleHomologationHistoryResponse(BaseModel):
    """VisÃ£o volumÃ©trica e qualitativa de uma regra em homologaÃ§Ã£o (antes de virar para prod)."""

    uid: str
    title: str
    folder_uid: str
    folder_title: str
    contact_point: str | None = None
    deploy_status: DeployStatus
    state: RuleState
    is_paused: bool = False
    severity: str | None = None
    technology_name: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    logql_query: str | None = None
    window_hours: int = 24
    generated_at: str
    # MÃ©tricas volumÃ©tricas consolidadas na janela
    total_events: int = 0
    firing_events_count: int = 0
    resolved_events_count: int = 0
    pending_events_count: int = 0
    error_events_count: int = 0
    active_alerts_count: int = 0
    suppressed_alerts_count: int = 0
    peak_bucket_firing: int = 0
    avg_firing_per_hour: float = 0.0
    last_firing_at: str | None = None
    last_evaluation: str | None = None
    # Instâncias ativas/suprimidas agora no Alertmanager e histórico/histograma
    active_alerts: list[AlertInstance] = Field(default_factory=list)
    histogram: list[RuleAlertHistogramBucket] = Field(default_factory=list)
    events: list[RuleAlertHistoryEvent] = Field(default_factory=list)
    ai_evaluation: RuleHomologationAIEvaluation | None = None


class RuleHomologationAIEvaluation(BaseModel):
    """Parecer técnico da IA sobre o comportamento e histórico de alertas de uma regra."""

    rule_uid: str
    rule_title: str
    folder_title: str
    window_hours: int
    is_in_production: bool
    ai_provider: str
    ai_model: str
    verdict: str
    threat_analysis: str
    noise_reduction_actions: list[str] = Field(default_factory=list)
    improvements: list[str] = Field(default_factory=list)
    calibration_for_prod: str
    summary: str
    generated_at: str


# --- Baseline Folder Arbitration --------------------------------------------
class BaselineFolderConfig(BaseModel):
    """Pasta do Grafana arbitrada para atuar como repositÃ³rio Baseline Global."""

    baseline_folder_uid: str
    baseline_folder_title: str | None = None


class SetBaselineFolderRequest(BaseModel):
    """Define a pasta do Grafana que representarÃ¡ o Baseline Global."""

    baseline_folder_uid: str = Field(min_length=1, max_length=40)


# --- Baseline Rule Prefix Settings ------------------------------------------
class BaselinePrefixSettings(BaseModel):
    """Configurações de prefixo para títulos de regras de detecção."""

    enabled: bool = Field(
        default=True,
        description="Habilita ou desabilita a aplicação do prefixo no baseline e clientes.",
    )
    template: str = Field(
        default="Baseline - ",
        description="Template do prefixo (ex: 'Baseline - ', '[{{tenant}}] [{{technology}}] - ').",
    )


class BaselinePrefixPreviewRequest(BaseModel):
    """Solicitação de renderização imediata de prefixo para teste/preview."""

    template: str = Field(..., description="Template do prefixo a ser testado.")
    title: str = Field(
        default="Detecção de Força Bruta contra RDP",
        description="Título base de exemplo.",
    )
    technology: str | None = Field(default="ad_windows", description="Tecnologia de exemplo.")
    technology_name: str | None = Field(default=None, description="Nome da tecnologia de exemplo.")
    tactic: str | None = Field(default="credential_access", description="Tática MITRE de exemplo.")
    severity: str | None = Field(default="high", description="Severidade de exemplo.")
    tenant: str | None = Field(
        default=None,
        description="Nome do tenant ou None/vazio para simular o Baseline Global.",
    )


class BaselinePrefixPreviewResponse(BaseModel):
    """Resultado do preview imediato do prefixo."""

    preview_title: str
    evaluated_prefix: str


# =============================================================================
# Curadoria de Regras de Detecção
# =============================================================================
CurationCandidateQuality = Literal["excellent", "good", "bad"]
CurationSourceId = Literal["sigmahq", "detection_fyi", "splunk_research", "elastic_rules"]


class CurationSourceInfo(BaseModel):
    """Fonte confiável pesquisada pela curadoria de regras de detecção."""

    id: CurationSourceId
    name: str
    url: str
    format_label: str
    description: str
    curated_count: int = 0
    canonical_rules_count: int = 0
    status: str = "verified"


class CuratedRuleItem(BaseModel):
    """Regra de detecção curada (apenas excelente ou boa candidata)."""

    id: str
    external_id: str
    source_id: CurationSourceId
    source_name: str
    source_url: str
    title: str
    original_title: str
    description: str
    original_format: str
    original_syntax: str
    logql_query: str
    technology: str
    technology_name: str
    perimeter: str = "other"
    perimeter_name: str = "Outro"
    rule_groups_regex: str = ""
    ss_groups_regex: str = ""
    job: str = "wazuh"

    @model_validator(mode="before")
    @classmethod
    def _sync_curation_regex(cls, data: Any) -> Any:
        if isinstance(data, dict):
            val = data.get("rule_groups_regex") or data.get("ss_groups_regex") or ""
            if val:
                data.setdefault("rule_groups_regex", val)
                data.setdefault("ss_groups_regex", val)
        return data
    severity: RuleSeverity = "high"
    mitre_tactic: str
    mitre_technique: str
    threshold_operator: str = "gt"
    threshold_value: float = 0.0
    for_duration: str = "0s"
    classification: CurationCandidateQuality
    classification_reason: str
    field_compatibility_pct: float = 100.0
    log_presence_score: float = 0.0
    threat_context_score: float = 0.0
    scenario_match_score: float = 0.0
    observed_field_compatibility_pct: float = 0.0
    total_matched_results: int = 0
    total_tech_logs_seen: int = 0
    has_query_results: bool = False
    matched_windows_summary: list[str] = Field(default_factory=list)
    observed_fields_in_logs: list[str] = Field(default_factory=list)
    missing_fields_in_logs: list[str] = Field(default_factory=list)
    sample_query_results: list[str] = Field(default_factory=list)
    qualification_factors: list[CurationQualificationFactor] = Field(default_factory=list)
    mapped_fields: list[CurationFieldMapping] = Field(default_factory=list)
    lint_valid: bool = True
    lint_message: str = ""
    client_evaluations: list[CurationClientEvaluation] = Field(default_factory=list)
    excellent_clients_count: int = 0
    good_clients_count: int = 0
    curated_at: str
    curation_engine: Literal["ai", "heuristic"] = "heuristic"
    ai_model: str | None = None
    ai_rationale: str | None = None
    implemented: bool = False
    implemented_at: str | None = None
    baseline_rule_uid: str | None = None
    implemented_clients: list[str] = Field(default_factory=list)
    ignored: bool = False
    ignored_at: str | None = None
    discarded: bool = False
    discard_reason: str | None = None


class CurationRunSummary(BaseModel):
    """Resumo da última execução do pipeline de curadoria."""

    ran_at: str
    trigger: Literal["scheduled_08h00", "manual", "startup_bootstrap"] = "manual"
    fetched_count: int = 0
    compatible_tech_count: int = 0
    converted_logql_count: int = 0
    new_curated_count: int = 0
    excellent_added: int = 0
    good_added: int = 0
    discarded_bad_count: int = 0
    skipped_duplicates_count: int = 0
    evaluated_clients_count: int = 0
    timed_out_clients_count: int = 0
    ai_curated_count: int = 0
    heuristic_curated_count: int = 0
    ai_provider_used: str | None = None
    ai_model_used: str | None = None
    timed_out_clients: list[str] = Field(default_factory=list)


class CurationProgressState(BaseModel):
    """Estado em tempo real da execução da curadoria (progresso, cliente, janela e verbosidade)."""

    running: bool = False
    percent: int = 0
    phase: str = "Aguardando execução"
    current_action: str = "Pronto para iniciar a curadoria de regras de detecção."
    current_client_name: str | None = None
    current_client_uid: str | None = None
    current_client_index: int = 0
    total_clients: int = 0
    current_rule_title: str | None = None
    current_rule_source: str | None = None
    current_rule_index: int = 0
    total_rules: int = 0
    current_window_label: str | None = None
    current_window_step: int = 0
    total_window_steps: int = 5
    ai_curated_count: int = 0
    heuristic_curated_count: int = 0
    ai_provider_used: str | None = None
    ai_model_used: str | None = None
    windows_evaluated_current: list[str] = Field(default_factory=list)
    timed_out_clients: list[str] = Field(default_factory=list)
    recent_logs: list[str] = Field(default_factory=list)
    started_at: str | None = None
    updated_at: str | None = None
    finished_at: str | None = None


class CurationScheduleInfo(BaseModel):
    """Estado do agendador diário (todos os dias às 08h00)."""

    enabled: bool = True
    cron_expression: str = "0 8 * * *"
    daily_time: str = "08:00"
    timezone: str = "America/Sao_Paulo (UTC-03:00)"
    last_run_at: str | None = None
    next_run_at: str
    last_run_summary: CurationRunSummary | None = None


class CurationMetrics(BaseModel):
    """Indicadores consolidados da página de Curadoria."""

    total_curated: int = 0
    excellent_count: int = 0
    good_count: int = 0
    high_compatibility_count: int = 0
    medium_compatibility_count: int = 0
    pending_count: int = 0
    implemented_count: int = 0
    ignored_count: int = 0
    total_evaluated_history: int = 0
    discarded_bad_count: int = 0
    skipped_duplicates_count: int = 0


class CurationOverviewResponse(BaseModel):
    """Visão completa da página de Curadoria de Regras de Detecção."""

    generated_at: str
    schedule: CurationScheduleInfo
    sources: list[CurationSourceInfo] = Field(default_factory=list)
    metrics: CurationMetrics
    rules: list[CuratedRuleItem] = Field(default_factory=list)
    discarded_rules: list[CuratedRuleItem] = Field(default_factory=list)
    progress: CurationProgressState = Field(default_factory=CurationProgressState)


class CurationRunResponse(BaseModel):
    """Resposta da execução manual ou agendada do ciclo de curadoria."""

    message: str
    summary: CurationRunSummary | None = None
    total_curated: int
    next_run_at: str
    progress: CurationProgressState | None = None


class ImplementCuratedRuleRequest(BaseModel):
    """Pedido de implementação de uma regra curada no Baseline e nos clientes indicados."""

    client_uids: list[str] = Field(
        default_factory=list,
        description="UIDs dos clientes (pastas) onde a regra será implementada. Se vazio, usa todos os clientes recomendados.",
    )
    confirm: bool = Field(
        default=False,
        description="Confirmação explícita obrigatória do operador no pop-up de confirmação.",
    )
    evaluation_group: str | None = Field(
        default=None,
        max_length=128,
        description="Grupo de avaliação opcional nos clientes (padrão: '5m').",
    )


class ImplementCuratedRuleResponse(BaseModel):
    """Resultado da implementação de uma regra curada no Baseline e clientes."""

    message: str
    rule_id: str
    baseline_rule_uid: str
    baseline_rule_title: str
    baseline_folder_uid: str
    technology: str
    technology_name: str
    contact_point: str
    total_clients_targeted: int
    created_in_clients: int
    skipped_in_clients: int
    failed_in_clients: int
    client_results: list[ImplementedRuleResult] = Field(default_factory=list)
    implemented_at: str


class CurationStopResponse(BaseModel):
    """Resposta da interrupção do ciclo de curadoria."""

    status: Literal["stopped", "not_running"]
    message: str
    progress: CurationProgressState


class CurationIgnoreRequest(BaseModel):
    """Pedido para ignorar ou restaurar uma regra curada."""

    ignored: bool = Field(default=True, description="Se true, ignora a regra; se false, restaura.")


class CurationClearResponse(BaseModel):
    """Resposta da limpeza e reset completo do catálogo de curadoria."""

    status: Literal["cleared"] = "cleared"
    message: str = Field(description="Mensagem descritiva da operação de limpeza.")
    cleared_count: int = Field(description="Quantidade de regras curadas removidas.")




# =============================================================================
# Schemas de Inteligência Artificial / LLM (Curadoria Cognitiva)
# =============================================================================
AIProvider = Literal["deepseek", "openai", "gemini", "anthropic", "ollama"]


class AISettingsData(BaseModel):
    """Configurações persistidas do provedor de IA no system-settings.json."""

    provider: AIProvider = "deepseek"
    model: str = "deepseek-chat"
    api_key: str = ""
    api_base_url: str | None = None
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    enabled: bool = True
    ai_analysis_enabled: bool = True
    curation_enabled: bool = True
    cache_enabled: bool = True


class AISettingsPublicResponse(BaseModel):
    """Visão pública das configurações de IA (com chave mascarada para segurança)."""

    provider: AIProvider
    model: str
    is_configured: bool
    masked_key: str
    api_base_url: str | None = None
    temperature: float
    enabled: bool
    ai_analysis_enabled: bool = True
    curation_enabled: bool = True
    cache_enabled: bool
    available_providers: list[dict[str, Any]]
    cached_rules_count: int = 0


class AISettingsUpdateRequest(BaseModel):
    """Requisição para atualizar parâmetros e credenciais de IA."""

    provider: AIProvider
    model: str
    api_key: str | None = None
    api_base_url: str | None = None
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    enabled: bool = True
    ai_analysis_enabled: bool = True
    curation_enabled: bool = True
    cache_enabled: bool = True


class AITestConnectionRequest(BaseModel):
    """Parâmetros para testar a conectividade com o modelo de IA em tempo real."""

    provider: AIProvider
    model: str
    api_key: str | None = None
    api_base_url: str | None = None


class AITestConnectionResponse(BaseModel):
    """Resultado do teste de conexão com o provedor de IA."""

    success: bool
    message: str
    latency_ms: int = 0
    model: str = ""


class AIClearCacheResponse(BaseModel):
    """Resultado da limpeza de cache de regras curadas por IA."""

    cleared_count: int
    message: str


class RuleImprovementEvaluation(BaseModel):
    """Parecer técnico da IA sobre oportunidades de melhoria em uma regra de detecção."""

    rule_uid: str
    rule_title: str
    verdict: str
    verdict_level: Literal["excellent", "good", "warning", "critical"] = "good"
    threat_context: str
    improvements: list[str] = Field(default_factory=list)
    noise_reduction_actions: list[str] = Field(default_factory=list)
    suggested_logql_query: str | None = None
    suggested_for_duration: str | None = None
    suggested_labels: dict[str, str] = Field(default_factory=dict)
    suggested_annotations: dict[str, str] = Field(default_factory=dict)
    diff_summary: list[str] = Field(default_factory=list)
    can_implement: bool = False
    evaluated_at: str
    engine: Literal["ai", "heuristic"] = "heuristic"
    model: str | None = None
    # Avaliação de Telemetria Real no Cliente (janelas progressivas 15m -> 1h -> 6h -> 24h -> 3d)
    telemetry_evaluated: bool = False
    client_name: str | None = None
    client_uid: str | None = None
    windows_evaluated: list[str] = Field(default_factory=list)
    matched_window: str | None = None
    matched_events_count: int = 0
    sample_logs: list[str] = Field(default_factory=list)
    observed_fields: list[str] = Field(default_factory=list)
    field_compatibility_pct: float | None = None
    is_paused_rule: bool = False
    is_cached: bool = False


class ApplyRuleAISuggestionsRequest(BaseModel):
    """Parâmetros opcionais para aplicar as sugestões da IA na regra."""

    suggested_logql_query: str | None = None
    suggested_for_duration: str | None = None
    suggested_labels: dict[str, str] = Field(default_factory=dict)
    suggested_annotations: dict[str, str] = Field(default_factory=dict)


class ApplyRuleAISuggestionsResponse(BaseModel):
    """Resultado da aplicação de sugestões da IA em uma regra existente."""

    message: str
    rule_uid: str
    rule: RuleDetail
