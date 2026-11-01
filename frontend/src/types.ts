export type RuleState =
  | "firing"
  | "pending"
  | "recovering"
  | "normal"
  | "paused"
  | "error"
  | "nodata"
  | "unknown";

export type AlertState = "active" | "suppressed" | "unprocessed";
export type SilenceState = "active" | "pending" | "expired";

/**
 * Natureza do silence — base da segregação da tela de Silences:
 *  - permanent: exceção permanente a uma regra de detecção (whitelist)
 *  - antiflood: supressão temporária criada pelo antiflood
 *  - maintenance: janela de manutenção planejada
 *  - manual: supressão temporária ad hoc criada pelo operador
 */
export type SilenceKind = "permanent" | "antiflood" | "maintenance" | "manual";

export interface UserInfo {
  username: string;
}

export interface PortalConfig {
  grafana_public_url: string;
  refresh_interval_seconds: number;
  is_external_grafana?: boolean;
  evaluation_group_optional?: boolean;
  baseline_folder_uid?: string;
  app_version?: string;
}

export interface AppVersionInfo {
  current_version: string;
  latest_version?: string | null;
  update_available: boolean;
  release_url?: string | null;
  release_name?: string | null;
  published_at?: string | null;
  release_notes?: string | null;
  checked_at?: string | null;
  error?: string | null;
  ghcr_status?: string | null;
  ghcr_message?: string | null;
}

export interface UpgradeTriggerResponse {
  status: "upgrading" | "manual_action_required" | "error";
  message: string;
  target_version?: string | null;
  started_at?: string | null;
}

export interface UpgradeStatusResponse {
  status: "idle" | "upgrading" | "completed" | "failed" | "manual_action_required";
  last_upgraded_at?: string | null;
  target_version?: string | null;
  current_version: string;
  message?: string | null;
}


export interface RuleSummary {
  uid: string;
  title: string;
  folder_uid: string;
  folder_title: string;
  rule_group: string;
  rule_type: "alerting" | "recording";
  labels: Record<string, string>;
  annotations: Record<string, string>;
  is_paused: boolean;
  for_duration: string | null;
  state: RuleState;
  health: string | null;
  last_evaluation: string | null;
  last_error: string | null;
  active_instances: number;
  updated: string | null;
  /** Contact Point amarrado à regra (destino da notificação). */
  contact_point: string | null;
  /** Estágio de deploy derivado do Contact Point. */
  deploy_status: DeployStatus;
  /** Quantidade de instâncias de alerta atualmente silenciadas/suprimidas por exceções. */
  silenced_instances?: number;
}

/**
 * Estágio de deploy da regra, derivado do Contact Point amarrado a ela:
 *  - active:     regra avaliando com Contact Point "prod"
 *  - homolog:    regra avaliando com Contact Point "dev"/"stg"
 *  - paused:     regra pausada (independente do Contact Point)
 *  - unassigned: regra avaliando sem Contact Point conhecido (ninguém recebe o alerta)
 */
export type DeployStatus = "active" | "homolog" | "paused" | "unassigned";

export interface RuleQuery {
  ref_id: string;
  datasource_uid: string | null;
  relative_time_range: Record<string, unknown> | null;
  model: Record<string, unknown>;
}

export interface RuleDetail extends RuleSummary {
  condition: string | null;
  no_data_state: string | null;
  exec_err_state: string | null;
  provenance: string | null;
  queries: RuleQuery[];
}

export interface AlertHistoryEvent {
  id: string;
  alertname: string;
  rule_uid?: string | null;
  timestamp: string;
  state: "firing" | "silenced";
  labels: Record<string, string>;
  text: string;
}

export interface AlertHistoryResponse {
  window_hours: number;
  total_events: number;
  firing_count: number;
  silenced_count: number;
  events: AlertHistoryEvent[];
}

export interface AlertInstance {
  fingerprint: string;
  alertname: string;
  rule_uid: string | null;
  state: AlertState;
  silenced_by: string[];
  inhibited_by: string[];
  labels: Record<string, string>;
  annotations: Record<string, string>;
  starts_at: string | null;
  updated_at: string | null;
}

export interface SilenceMatcher {
  name: string;
  value: string;
  is_regex: boolean;
  is_equal: boolean;
}

export interface SilencedAlertSummary {
  fingerprint: string;
  alertname: string;
  grafana_folder?: string | null;
  severity?: string | null;
  starts_at?: string | null;
  state?: string | null;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
}

export interface Silence {
  id: string;
  state: SilenceState;
  kind: SilenceKind;
  matchers: SilenceMatcher[];
  starts_at: string | null;
  ends_at: string | null;
  updated_at: string | null;
  created_by: string;
  comment: string;
  silenced_alerts_count: number;
  silenced_alerts?: SilencedAlertSummary[];
}

export interface CreateSilencePayload {
  matchers: {
    name: string;
    value: string;
    is_regex?: boolean;
    is_equal?: boolean;
  }[];
  starts_at?: string;
  ends_at: string;
  comment: string;
  kind?: SilenceKind;
}

export interface FolderItem {
  id?: number | null;
  uid: string;
  title: string;
}

export interface DuplicateRulePayload {
  target_folder_uid: string;
  target_folder_title?: string;
  new_title: string;
  new_rule_group?: string;
  client_name: string;
  custom_logql?: string;
}

export interface StageResult {
  stage: string;
  name: string;
  matched: boolean;
  details: string;
  extracted?: Record<string, unknown>;
}

export interface LogQLValidationReport {
  is_compatible: boolean;
  logql_query: string;
  message: string;
  extracted_fields: Record<string, unknown>;
  stages: StageResult[];
}

export type ClientRuleStatus = "active" | "paused" | "not_implemented";

export interface ClientRuleCoverage {
  client_uid: string;
  client_name: string;
  status: ClientRuleStatus;
  rule_uid: string | null;
  rule_title: string | null;
}

export interface GlobalRuleMatrixItem {
  global_uid: string;
  global_title: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
  total_clients: number;
  implemented_clients_count: number;
  active_clients_count: number;
  paused_clients_count: number;
  not_implemented_clients_count: number;
  clients: ClientRuleCoverage[];
}

export type RuleScope = "baseline" | "client";
export type RuleSeverity = "low" | "medium" | "high" | "critical";

/**
 * Tecnologia (data source) mapeada para um recorte da label `ss_groups` do Loki.
 * tenant = grafana_folder; tecnologia = rule_groups.
 */
export interface Technology {
  slug: string;
  name: string;
  rule_groups_regex: string;
  job: string;
  description: string;
  icon: string;
  enabled: boolean;
  perimeter: string;
  perimeter_name: string;
  logql_selector: string;
}

export interface DetectionPerimeter {
  slug: string;
  name: string;
  icon: string;
  description: string;
  keywords: string[];
  technologies_count: number;
}

export interface TechnologyPayload {
  slug: string;
  name: string;
  rule_groups_regex?: string;
  job?: string;
  description?: string;
  icon?: string;
  enabled?: boolean;
  perimeter?: string;
  /** Aceite explícito para cadastrar tecnologia sem logs prévios no Loki. */
  confirm_without_logs?: boolean;
}

/** Resultado da checagem implícita de telemetria no Loki (query não exposta). */
export interface TechnologyLogCheckResult {
  available: boolean;
  found: boolean;
  count: number;
  window_seconds: number;
  datasource: string | null;
  checked_at: string;
  message: string;
}

export type TechnologyComplianceStatus =
  | "complete"
  | "partial"
  | "none"
  | "not_applicable";

/** Origem da evidência de que o cliente possui a tecnologia no SIEM. */
export type TechnologyFootprintSource = "derived" | "declared" | "both" | "none";

export interface TechnologyClientCompliance {
  client_uid: string;
  client_name: string;
  integrated: boolean;
  /** Tecnologia faz parte do footprint do cliente (fora dele não entra no denominador). */
  applicable: boolean;
  footprint_source: TechnologyFootprintSource;
  implemented_rules: number;
  paused_rules: number;
  total_baseline_rules: number;
  compliance_pct: number;
  status: TechnologyComplianceStatus;
}

export interface TechnologyOverviewItem {
  slug: string;
  name: string;
  icon: string;
  description: string;
  rule_groups_regex: string;
  job: string;
  enabled: boolean;
  perimeter: string;
  perimeter_name: string;
  baseline_rules_count: number;
  client_rules_count: number;
  integrated_clients_count: number;
  applicable_clients_count: number;
  excluded_clients_count: number;
  implemented_baseline_rules: number;
  total_baseline_slots: number;
  compliance_pct: number;
  clients: TechnologyClientCompliance[];
}

export interface TechnologyOverviewMetrics {
  unique_technologies: number;
  enabled_technologies: number;
  baseline_rules_total: number;
  baseline_rules_unmapped: number;
  clients_total: number;
  clients_with_technology: number;
  client_rules_total: number;
  implemented_baseline_rules: number;
  total_baseline_slots: number;
  /** Slots (regra x cliente) descartados por o cliente não possuir a tecnologia. */
  not_applicable_slots: number;
  compliance_pct: number;
}

export interface TechnologyOverview {
  metrics: TechnologyOverviewMetrics;
  technologies: TechnologyOverviewItem[];
  generated_at: string;
}

/** Footprint efetivo de um cliente: evidência derivada + inventário declarado. */
export interface TenantTechnologyFootprint {
  client_uid: string;
  client_name: string;
  derived: string[];
  declared: string[];
  effective: string[];
  updated_at: string;
}

export interface ImplementedRuleResult {
  uid: string;
  title: string;
  status: "created" | "skipped" | "failed";
  detail?: string | null;
}

export interface ImplementBaselineResult {
  message: string;
  technology: string;
  technology_name: string;
  client_uid: string;
  client_name: string;
  total: number;
  created: number;
  skipped: number;
  failed: number;
  contact_point?: string | null;
  evaluation_group?: string | null;
  rules: ImplementedRuleResult[];
}

export interface CreateRulePayload {
  name: string;
  description?: string;
  scope: RuleScope;
  target_client_uid?: string;
  logql_query: string;
  severity: RuleSeverity;
  mitre_tactic: string;
  mitre_technique: string;
  /** Grupo de avaliação (evaluation group) no Grafana Alerting para a regra. */
  evaluation_group?: string;
  /** Slug da tecnologia (data source) observada pela regra. */
  technology?: string;
  /** Quando true em regras de baseline, replica automaticamente para os clientes que possuem a tecnologia. */
  replicate_to_clients?: boolean;
}

export interface CreateRuleResponse {
  message: string;
  uid: string;
  title: string;
  folder_uid: string;
  folder_title: string;
  scope: RuleScope;
  severity: RuleSeverity;
  technology?: string | null;
  technology_name?: string | null;
  contact_point?: string | null;
  deploy_status?: DeployStatus;
  datasource_uid?: string | null;
  datasource_name?: string | null;
  replicated_to_clients?: boolean;
  replicated_count?: number;
  replicated_rules?: ImplementedRuleResult[];
  labels: Record<string, string>;
}

export interface RuleImportFileInput {
  filename: string;
  content: string;
}

export interface RuleImportItemValidation {
  index: number;
  title: string;
  description?: string | null;
  query: string;
  threshold_operator: string;
  threshold_value: number;
  severity: RuleSeverity;
  mitre_tactic?: string | null;
  mitre_technique?: string | null;
  technology?: string | null;
  technology_name?: string | null;
  for_duration: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
  already_exists: boolean;
  filename?: string | null;
  technology_missing?: boolean;
  suggested_technology_slug?: string | null;
  suggested_technology_name?: string | null;
  suggested_rule_groups_regex?: string | null;
}

export interface RuleImportPreviewResponse {
  total_rules: number;
  valid_count: number;
  invalid_count: number;
  missing_tech_count?: number;
  items: RuleImportItemValidation[];
  general_error?: string | null;
  files_count?: number;
}

export interface RuleImportExecuteResponse {
  message: string;
  total: number;
  imported_count: number;
  failed_count: number;
  imported_uids: string[];
  imported_titles: string[];
  failed: Array<{ title: string; error: string }>;
}

export interface LintIssue {
  level: "error" | "warning" | "info";
  message: string;
  field?: string | null;
}

export interface LogQLLintResult {
  is_valid: boolean;
  query: string;
  normalized_query: string;
  stream_selector: string | null;
  metric_function: string | null;
  pipeline_stages: string[];
  issues: LintIssue[];
  message: string;
  rule_groups_values: string[];
  job_value: string | null;
  technologies: string[];
}

export interface LogLineResult {
  timestamp: string;
  line: string;
  labels: Record<string, string>;
}

export interface EnvironmentQueryResult {
  environment: "sandbox" | "production" | string;
  environment_label: string;
  datasource_name: string;
  datasource_uid: string;
  success: boolean;
  total_lines: number;
  lines: LogLineResult[];
  duration_ms: number;
  error?: string | null;
  is_timeout?: boolean;
}

export interface ExecuteQueryResult {
  success: boolean;
  query: string;
  total_lines: number;
  lines: LogLineResult[];
  duration_ms: number;
  is_timeout: boolean;
  error?: string | null;
  datasource_name?: string | null;
  environments?: EnvironmentQueryResult[] | null;
}

export interface BatchToggleRulesResponse {
  message: string;
  total: number;
  succeeded: string[];
  failed: Array<{ uid: string; error: string }>;
}

export interface TenantSummary {
  id?: number | null;
  uid: string;
  title: string;
  rules_count: number;
  active_rules_count: number;
  paused_rules_count: number;
  rules_uids: string[];
  /** Data source Loki dedicado ao tenant (nome = nome do tenant). */
  loki_datasource_name: string | null;
  loki_datasource_uid: string | null;
  loki_datasource_url: string | null;
  loki_datasource_present: boolean;
  /** false quando o data source existe mas aponta para uma URL diferente da padrão. */
  loki_datasource_url_matches: boolean;
  sandbox_datasource_present?: boolean;
  sandbox_datasource_name?: string | null;
  sandbox_datasource_uid?: string | null;
  /** Grupo de avaliação do tenant (Evaluation group and interval no Grafana). */
  evaluation_group: string | null;
  evaluation_group_interval: string | null;
  evaluation_group_present: boolean;
  evaluation_groups?: Array<{
    name: string;
    interval: string | null;
    rules_count: number;
  }>;
  evaluation_group_optional?: boolean;
  /** Tecnologias com logs no último escaneamento (snapshot persistido). */
  technologies_count: number;
  /** Timestamp ISO do último escaneamento de tecnologias (null = nunca escaneado). */
  technologies_scanned_at: string | null;
}

export interface TenantTechnologyScanItem {
  slug: string;
  name: string;
  icon: string;
  description: string;
  logs_count: number;
  found: boolean;
}

export interface TenantTechnologyScanResult {
  message: string;
  tenant_uid: string;
  client_name: string;
  datasource: string | null;
  datasource_uid: string | null;
  window_seconds: number;
  scanned_at: string;
  available: boolean;
  technologies_detected: number;
  technologies_total: number;
  technologies: TenantTechnologyScanItem[];
}

export type TenantTechnologyBaselineStatus = "complete" | "partial" | "none";

export interface TenantTechnologyBaselineState {
  slug: string;
  name: string;
  icon: string;
  description: string;
  detected: boolean;
  logs_count: number;
  baseline_rules: number;
  implemented_rules: number;
  paused_rules: number;
  existing_rules: number;
  compliance_pct: number;
  status: TenantTechnologyBaselineStatus;
}

export interface TenantTechnologiesResult {
  tenant_uid: string;
  client_name: string;
  scanned_at: string | null;
  window_seconds: number | null;
  datasource: string | null;
  available: boolean;
  technologies_detected: number;
  technologies_total: number;
  technologies: TenantTechnologyBaselineState[];
}

export interface CreateTenantPayload {
  title: string;
  uid?: string;
  /** URL do Loki do cliente; vazio = Loki padrão da stack. */
  loki_url?: string;
}

export interface TenantSandboxResponse {
  message: string;
  uid: string;
  sandbox_datasource_name: string;
  sandbox_datasource_uid: string;
  present: boolean;
}

export interface TenantDatasourceResult {
  message: string;
  uid: string;
  datasource_name: string;
  datasource_uid: string;
  datasource_url: string;
}

/** Resultado da correção do grupo de avaliação canônico do tenant. */
export interface TenantEvaluationGroupResult {
  message: string;
  uid: string;
  evaluation_group: string;
  evaluation_group_interval: string | null;
  evaluation_group_present: boolean;
  anchor_created: boolean;
  anchor_rule_uid: string | null;
  migrated_rules: string[];
  migration_failures: Array<{ uid: string; error: string }>;
}

/**
 * Laboratório de logs sintéticos (Loki).
 * O backend injeta as linhas e confirma a ingestão consultando o Loki.
 */
export interface LokiDatasourceItem {
  uid: string;
  name: string;
  type: string;
  url: string | null;
  is_internal: boolean;
  is_default: boolean;
  is_sandbox?: boolean;
  can_inject?: boolean;
  client_name?: string | null;
}

export interface LokiStatus {
  available: boolean;
  ready: boolean;
  datasource: string | null;
  datasource_uid: string | null;
  url: string | null;
  labels: string[];
  message: string;
}

export interface LokiSyntheticPayload {
  datasource_uid?: string;
  stream: Record<string, string>;
  lines: Array<Record<string, unknown>>;
  spread_seconds?: number;
  mark_synthetic?: boolean;
}

export interface LokiSyntheticResult {
  status: "ok";
  datasource: string;
  datasource_uid: string;
  stream: Record<string, string>;
  lines_sent: number;
  bytes_sent: number;
  logql: string;
  verified_count: number;
  verified: boolean;
  grafana_explore_url: string | null;
  message: string;
}





/** Contact Point provisionado no Grafana e o estágio que ele representa. */
export interface ContactPointInfo {
  name: string;
  uid: string | null;
  type: string | null;
  tier: "prod" | "homolog" | "other";
  standard: boolean;
}

export interface HomologationMetrics {
  total_rules: number;
  active: number;
  homolog: number;
  paused: number;
  unassigned: number;
}

export interface HomologationClientBreakdown {
  folder_uid: string;
  folder_title: string;
  total: number;
  active: number;
  homolog: number;
  paused: number;
  unassigned: number;
}

/** Visão da página Homologação: estágio de deploy por regra e por cliente. */
export interface HomologationOverview {
  generated_at: string;
  contact_points: ContactPointInfo[];
  missing_contact_points: string[];
  stage_contact_points?: Record<string, string>;
  metrics: HomologationMetrics;
  clients: HomologationClientBreakdown[];
  rules: RuleSummary[];
}

export interface BaselineFolderConfig {
  baseline_folder_uid: string;
  baseline_folder_title?: string | null;
}

export interface SetRuleContactPointResult {
  message: string;
  uid: string;
  title: string;
  contact_point: string | null;
  deploy_status: DeployStatus;
  previous_contact_point: string | null;
  previous_deploy_status: DeployStatus | null;
}

export type RuleAlertEventKind =
  | "firing"
  | "resolved"
  | "pending"
  | "nodata"
  | "error"
  | "other";

export interface RuleAlertHistoryEvent {
  id: string;
  timestamp: string;
  new_state: string;
  prev_state: string;
  kind: RuleAlertEventKind;
  text: string;
  labels: Record<string, string>;
  values: Record<string, number>;
}

export interface RuleAlertHistogramBucket {
  bucket_start: string;
  bucket_end: string;
  label: string;
  firing_count: number;
  resolved_count: number;
  other_count: number;
  total_events: number;
}

export interface RuleHomologationHistory {
  uid: string;
  title: string;
  folder_uid: string;
  folder_title: string;
  contact_point: string | null;
  deploy_status: DeployStatus;
  state: RuleState;
  is_paused: boolean;
  severity: string | null;
  technology_name: string | null;
  mitre_tactic: string | null;
  mitre_technique: string | null;
  logql_query: string | null;
  window_hours: number;
  generated_at: string;
  total_events: number;
  firing_events_count: number;
  resolved_events_count: number;
  pending_events_count: number;
  error_events_count: number;
  active_alerts_count: number;
  suppressed_alerts_count: number;
  peak_bucket_firing: number;
  avg_firing_per_hour: number;
  last_firing_at: string | null;
  last_evaluation: string | null;
  active_alerts: AlertInstance[];
  histogram: RuleAlertHistogramBucket[];
  events: RuleAlertHistoryEvent[];
  ai_evaluation?: RuleHomologationAIEvaluation | null;
}

export interface RuleHomologationAIEvaluation {
  rule_uid: string;
  rule_title: string;
  folder_title: string;
  window_hours: number;
  is_in_production: boolean;
  ai_provider: string;
  ai_model: string;
  verdict: string;
  threat_analysis: string;
  noise_reduction_actions: string[];
  improvements: string[];
  calibration_for_prod: string;
  summary: string;
  generated_at: string;
}

export type CurationCandidateQuality = "excellent" | "good" | "bad";
export type CurationSourceId =
  | "sigmahq"
  | "detection_fyi"
  | "splunk_research"
  | "elastic_rules";

export interface CurationSourceInfo {
  id: CurationSourceId;
  name: string;
  url: string;
  format_label: string;
  description: string;
  curated_count: number;
}

export interface CurationFieldMapping {
  original_field: string;
  logql_field: string;
  compatible: boolean;
  observed_in_logs?: boolean;
  sample_values?: string[];
}

export interface CurationQualificationFactor {
  criterion: string;
  status: "met" | "partial" | "not_met";
  impact: "excellent" | "good" | "bad";
  summary: string;
}

export interface CurationClientEvaluation {
  client_uid: string;
  client_name: string;
  datasource_uid: string | null;
  datasource_name: string | null;
  classification: CurationCandidateQuality;
  matched_lines_count: number;
  tech_logs_count: number;
  field_compatibility_pct: number;
  log_presence_score?: number;
  threat_context_score?: number;
  scenario_match_score?: number;
  matched_fields: string[];
  observed_fields_in_logs?: string[];
  missing_fields_in_logs?: string[];
  total_observed_log_fields?: string[];
  observed_field_compatibility_pct?: number;
  has_query_results?: boolean;
  matched_window?: string | null;
  windows_evaluated?: string[];
  timed_out?: boolean;
  timeout_detail?: string | null;
  query_executed?: string;
  sample_matched_logs?: string[];
  sample_tech_logs?: string[];
  qualification_factors?: CurationQualificationFactor[];
  reason: string;
  already_implemented: boolean;
}

export interface CuratedRuleItem {
  id: string;
  external_id: string;
  source_id: CurationSourceId;
  source_name: string;
  source_url: string;
  title: string;
  original_title: string;
  description: string;
  original_format: string;
  original_syntax: string;
  logql_query: string;
  technology: string;
  technology_name: string;
  perimeter: string;
  perimeter_name: string;
  rule_groups_regex: string;
  job: string;
  severity: RuleSeverity;
  mitre_tactic: string;
  mitre_technique: string;
  threshold_operator: string;
  threshold_value: number;
  for_duration: string;
  classification: CurationCandidateQuality;
  classification_reason: string;
  field_compatibility_pct: number;
  log_presence_score?: number;
  threat_context_score?: number;
  scenario_match_score?: number;
  observed_field_compatibility_pct?: number;
  total_matched_results?: number;
  total_tech_logs_seen?: number;
  has_query_results?: boolean;
  matched_windows_summary?: string[];
  observed_fields_in_logs?: string[];
  missing_fields_in_logs?: string[];
  sample_query_results?: string[];
  qualification_factors?: CurationQualificationFactor[];
  mapped_fields: CurationFieldMapping[];
  lint_valid: boolean;
  lint_message: string;
  client_evaluations: CurationClientEvaluation[];
  excellent_clients_count: number;
  good_clients_count: number;
  curated_at: string;
  curation_engine?: "ai" | "heuristic";
  ai_model?: string | null;
  ai_rationale?: string | null;
  implemented: boolean;
  implemented_at: string | null;
  baseline_rule_uid: string | null;
  implemented_clients: string[];
  ignored?: boolean;
  ignored_at?: string | null;
  discarded?: boolean;
  discard_reason?: string | null;
}

export interface CurationRunSummary {
  ran_at: string;
  trigger: "scheduled_08h00" | "manual" | "startup_bootstrap";
  fetched_count: number;
  compatible_tech_count: number;
  converted_logql_count: number;
  new_curated_count: number;
  excellent_added: number;
  good_added: number;
  discarded_bad_count: number;
  skipped_duplicates_count: number;
  evaluated_clients_count: number;
  timed_out_clients_count?: number;
  timed_out_clients?: string[];
  ai_curated_count?: number;
  heuristic_curated_count?: number;
  ai_provider_used?: string | null;
  ai_model_used?: string | null;
}

export interface CurationProgressState {
  running: boolean;
  percent: number;
  phase: string;
  current_action: string;
  current_client_name: string | null;
  current_client_uid: string | null;
  current_client_index: number;
  total_clients: number;
  current_rule_title: string | null;
  current_rule_source: string | null;
  current_rule_index: number;
  total_rules: number;
  current_window_label: string | null;
  current_window_step: number;
  total_window_steps: number;
  windows_evaluated_current: string[];
  timed_out_clients: string[];
  ai_curated_count?: number;
  heuristic_curated_count?: number;
  ai_provider_used?: string | null;
  ai_model_used?: string | null;
  recent_logs: string[];
  started_at: string | null;
  updated_at: string | null;
  finished_at: string | null;
}

export interface CurationScheduleInfo {
  enabled: boolean;
  cron_expression: string;
  daily_time: string;
  timezone: string;
  last_run_at: string | null;
  next_run_at: string;
  last_run_summary: CurationRunSummary | null;
}

export interface CurationMetrics {
  total_curated: number;
  excellent_count: number;
  good_count: number;
  high_compatibility_count?: number;
  medium_compatibility_count?: number;
  pending_count: number;
  implemented_count: number;
  ignored_count?: number;
  total_evaluated_history: number;
  discarded_bad_count: number;
  skipped_duplicates_count: number;
}

export interface CurationOverviewResponse {
  generated_at: string;
  schedule: CurationScheduleInfo;
  sources: CurationSourceInfo[];
  metrics: CurationMetrics;
  rules: CuratedRuleItem[];
  discarded_rules?: CuratedRuleItem[];
  progress?: CurationProgressState;
}

export interface CurationRunResponse {
  message: string;
  summary: CurationRunSummary | null;
  total_curated: number;
  next_run_at: string;
  progress?: CurationProgressState | null;
}

export interface ImplementCuratedRuleRequest {
  client_uids?: string[];
  confirm: boolean;
  evaluation_group?: string;
}

export interface ImplementCuratedRuleResponse {
  message: string;
  rule_id: string;
  baseline_rule_uid: string;
  baseline_rule_title: string;
  baseline_folder_uid: string;
  technology: string;
  technology_name: string;
  contact_point: string;
  total_clients_targeted: number;
  created_in_clients: number;
  skipped_in_clients: number;
  failed_in_clients: number;
  client_results: ImplementedRuleResult[];
  implemented_at: string;
}

export interface CurationStopResponse {
  status: "stopped" | "not_running";
  message: string;
  progress: CurationProgressState;
}

export interface CurationIgnoreRequest {
  ignored: boolean;
}

export interface CurationClearResponse {
  status: "cleared";
  message: string;
  cleared_count: number;
}

// End Curation Types


// --- AI / LLM Types ---
export type AIProvider = "deepseek" | "openai" | "gemini" | "anthropic" | "ollama";

export interface AIModelOption {
  id: string;
  name: string;
  description?: string;
}

export interface AIProviderInfo {
  id: AIProvider;
  name: string;
  badge?: string;
  description: string;
  default_model: string;
  models: AIModelOption[];
  requires_api_key: boolean;
  default_base_url?: string;
  api_key_placeholder?: string;
  help_url?: string;
}

export interface AISettingsPublicResponse {
  provider: AIProvider;
  model: string;
  is_configured: boolean;
  masked_key: string;
  api_base_url?: string | null;
  temperature: number;
  enabled: boolean;
  ai_analysis_enabled: boolean;
  curation_enabled: boolean;
  cache_enabled: boolean;
  available_providers: AIProviderInfo[];
  cached_rules_count: number;
}

export interface AISettingsUpdateRequest {
  provider: AIProvider;
  model: string;
  api_key?: string | null;
  api_base_url?: string | null;
  temperature: number;
  enabled?: boolean;
  ai_analysis_enabled: boolean;
  curation_enabled: boolean;
  cache_enabled: boolean;
}

export interface AITestConnectionRequest {
  provider: AIProvider;
  model: string;
  api_key?: string | null;
  api_base_url?: string | null;
}

export interface AITestConnectionResponse {
  success: boolean;
  message: string;
  latency_ms: number;
  model: string;
}

export interface AIClearCacheResponse {
  cleared_count: number;
  message: string;
}


export interface RuleImprovementEvaluation {
  rule_uid: string;
  rule_title: string;
  verdict: string;
  verdict_level: "excellent" | "good" | "warning" | "critical";
  threat_context: string;
  improvements: string[];
  noise_reduction_actions: string[];
  suggested_logql_query?: string | null;
  suggested_for_duration?: string | null;
  suggested_labels: Record<string, string>;
  suggested_annotations: Record<string, string>;
  diff_summary: string[];
  can_implement: boolean;
  evaluated_at: string;
  engine: "ai" | "heuristic";
  model?: string | null;
  // Telemetria real no cliente (janelas progressivas 15m -> 1h -> 6h -> 24h -> 3d)
  telemetry_evaluated?: boolean;
  client_name?: string | null;
  client_uid?: string | null;
  windows_evaluated?: string[];
  matched_window?: string | null;
  matched_events_count?: number;
  sample_logs?: string[];
  observed_fields?: string[];
  field_compatibility_pct?: number | null;
  is_paused_rule?: boolean;
  is_cached?: boolean;
}

export interface ApplyRuleAISuggestionsRequest {
  suggested_logql_query?: string | null;
  suggested_for_duration?: string | null;
  suggested_labels?: Record<string, string>;
  suggested_annotations?: Record<string, string>;
}

export interface ApplyRuleAISuggestionsResponse {
  message: string;
  rule_uid: string;
  rule: RuleDetail;
}

export interface PausedRuleMatchItem {
  rule_uid: string;
  rule_title: string;
  folder_uid: string;
  folder_title: string;
  matched_events_count: number;
  matched_window: string;
  sample_logs: string[];
}

export interface PausedRulesMatchesResponse {
  total_paused: number;
  matching_rules_count: number;
  total_events: number;
  evaluated_at: string;
  window: string;
  rules: PausedRuleMatchItem[];
}