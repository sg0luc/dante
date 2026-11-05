import {
  AlertHistoryResponse,
  AlertInstance,
  AppVersionInfo,
  BaselineAdherence,
  SetTenantHiddenResult,
  BaselinePrefixPreviewRequest,
  BaselinePrefixPreviewResponse,
  BaselinePrefixSettings,
  UpgradeTriggerResponse,
  UpgradeStatusResponse,
  BatchToggleRulesResponse,
  CreateRulePayload,
  CreateRuleResponse,
  CreateSilencePayload,
  CreateTenantPayload,
  CuratedRuleItem,
  CurationOverviewResponse,
  CurationProgressState,
  CurationRunResponse,
  CurationStopResponse,
  CurationClearResponse,
  ImplementCuratedRuleRequest,
  ImplementCuratedRuleResponse,
  AIClearCacheResponse,
  AISettingsPublicResponse,
  AISettingsUpdateRequest,
  AITestConnectionRequest,
  AITestConnectionResponse,
  DuplicateRulePayload,
  ExecuteQueryResult,
  FolderItem,
  GlobalRuleMatrixItem,
  HomologationOverview,
  LogQLLintResult,
  LogQLValidationReport,
  LokiDatasourceItem,
  LokiStatus,
  LokiSyntheticPayload,
  LokiSyntheticResult,
  PortalConfig,
  RuleDetail,
  RuleImportAIOpinionRequest,
  RuleImportAIOpinionResponse,
  RuleImportExecuteResponse,
  RuleImportFileInput,
  RuleImportItemValidation,
  RuleImportPreviewResponse,
  RuleHomologationAIEvaluation,
  RuleImprovementEvaluation,
  ApplyRuleAISuggestionsRequest,
  ApplyRuleAISuggestionsResponse,
  RuleHomologationHistory,
  RuleSummary,
  PausedRulesMatchesResponse,
  SetRuleContactPointResult,
  Silence,
  Technology,
  DetectionPerimeter,
  TechnologyLogCheckResult,
  TechnologyOverview,
  TechnologyPayload,
  TenantTechnologyFootprint,
  ImplementBaselineResult,
  TenantDatasourceResult,
  TenantSandboxResponse,
  TenantEvaluationGroupResult,
  TenantTechnologiesResult,
  TenantTechnologyScanResult,
  TenantSummary,
  UserInfo,
  FieldDictionaryDetailOut,
  FieldDictionarySummaryOut,
  FieldDictionaryScanResponse,
  FieldDictionaryAIAnalysisOut,
  ScheduleSettingsOut,
  ScheduleSettingsUpdateRequest,
} from "./types";

const CSRF_HEADER = "X-Requested-With";
const CSRF_VALUE = "hunter-portal";

async function request<T>(
  url: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set("Accept", "application/json");

  // Requisições com métodos mutantes enviam o cabeçalho anti-CSRF exigido pelo backend
  const method = (options.method || "GET").toUpperCase();
  if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
    headers.set(CSRF_HEADER, CSRF_VALUE);
    if (!headers.has("Content-Type") && options.body) {
      headers.set("Content-Type", "application/json");
    }
  }

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });

  if (response.status === 204) {
    return {} as T;
  }

  if (!response.ok) {
    let errorMessage = `Erro HTTP ${response.status}`;
    try {
      const errorData = await response.json();
      if (errorData?.detail) {
        errorMessage = errorData.detail;
      }
    } catch {
      // Ignora erro de parsing JSON de erro
    }
    const error = new Error(errorMessage);
    (error as unknown as { status: number }).status = response.status;
    throw error;
  }

  return response.json();
}

export const api = {
  // Autenticação
  login: (username: string, password: string): Promise<UserInfo> =>
    request<UserInfo>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),

  logout: (): Promise<void> =>
    request<void>("/api/auth/logout", {
      method: "POST",
    }),

  getMe: (): Promise<UserInfo> => request<UserInfo>("/api/auth/me"),

  getConfig: (): Promise<PortalConfig> =>
    request<PortalConfig>("/api/config"),

  getHealth: (): Promise<{ status: string; version?: string }> =>
    request<{ status: string; version?: string }>("/api/health"),

  getVersion: (force = false): Promise<AppVersionInfo> =>
    request<AppVersionInfo>(force ? "/api/system/version?force=true" : "/api/system/version"),

  checkVersion: (): Promise<AppVersionInfo> =>
    request<AppVersionInfo>("/api/system/version/check", {
      method: "POST",
    }),

  triggerUpgrade: (targetVersion?: string): Promise<UpgradeTriggerResponse> =>
    request<UpgradeTriggerResponse>("/api/system/upgrade", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target_version: targetVersion }),
    }),

  getUpgradeStatus: (): Promise<UpgradeStatusResponse> =>
    request<UpgradeStatusResponse>("/api/system/upgrade/status"),


  // Regras
    getPausedRulesMatches: (window = "15m"): Promise<PausedRulesMatchesResponse> =>
    request<PausedRulesMatchesResponse>(`/api/rules/paused-matches?window=${encodeURIComponent(window)}`),

  getRules: (): Promise<RuleSummary[]> =>
    request<RuleSummary[]>("/api/rules"),

  /** Página Homologação: estágio de deploy de todas as regras por Contact Point. */
  getHomologation: (): Promise<HomologationOverview> =>
    request<HomologationOverview>("/api/homologation"),

  /** Configura o mapeamento de Contact Points reais do Grafana para os estágios (stg, dev, prod). */
  updateStageContactPoints: (
    stageContactPoints: Record<string, string>
  ): Promise<Record<string, string>> =>
    request<Record<string, string>>("/api/homologation/stage-contact-points", {
      method: "PUT",
      body: JSON.stringify({ stage_contact_points: stageContactPoints }),
    }),

  /** Consulta a pasta do Grafana arbitrada como baseline global. */
  getBaselineFolder: (): Promise<{ baseline_folder_uid: string; baseline_folder_title?: string | null }> =>
    request<{ baseline_folder_uid: string; baseline_folder_title?: string | null }>("/api/baseline/folder"),

  /** Define a pasta do Grafana que representará o baseline global. */
  setBaselineFolder: (
    folderUid: string
  ): Promise<{ baseline_folder_uid: string; baseline_folder_title?: string | null }> =>
    request<{ baseline_folder_uid: string; baseline_folder_title?: string | null }>("/api/baseline/folder", {
      method: "PUT",
      body: JSON.stringify({ baseline_folder_uid: folderUid }),
    }),

  /** Promove/rebaixa o estágio de deploy de uma regra (contact point dev/stg/prod). */
  setRuleContactPoint: (
    uid: string,
    contactPoint: string
  ): Promise<SetRuleContactPointResult> =>
    request<SetRuleContactPointResult>(
      `/api/homologation/rules/${encodeURIComponent(uid)}/contact-point`,
      {
        method: "POST",
        body: JSON.stringify({ contact_point: contactPoint }),
      }
    ),

  /** Volume, histograma temporal e histórico de alertas de uma regra em homologação. */
  getRuleHomologationHistory: (
    uid: string,
    windowHours = 24,
    bucketCount = 12
  ): Promise<RuleHomologationHistory> =>
    request<RuleHomologationHistory>(
      `/api/homologation/rules/${encodeURIComponent(uid)}/alert-history?window_hours=${windowHours}&bucket_count=${bucketCount}`
    ),

  /** Parecer técnico da IA sobre os alertas e volumetria de uma regra em homologação/produção. */
  getRuleHomologationAIEvaluation: (
    uid: string,
    windowHours = 24
  ): Promise<RuleHomologationAIEvaluation> =>
    request<RuleHomologationAIEvaluation>(
      `/api/homologation/rules/${encodeURIComponent(uid)}/ai-evaluation?window_hours=${windowHours}`
    ),

  getRule: (uid: string): Promise<RuleDetail> =>
    request<RuleDetail>(`/api/rules/${encodeURIComponent(uid)}`),

  toggleRulePause: (
    uid: string,
    paused: boolean
  ): Promise<{ message: string; uid: string; paused: string }> =>
    request(`/api/rules/${encodeURIComponent(uid)}/toggle-pause`, {
      method: "POST",
      body: JSON.stringify({ paused }),
    }),

  batchToggleRulesPause: (
    uids: string[],
    paused: boolean
  ): Promise<BatchToggleRulesResponse> =>
    request<BatchToggleRulesResponse>("/api/rules/batch-pause", {
      method: "POST",
      body: JSON.stringify({ uids, paused }),
    }),

  // Tecnologias / Data Sources (mapeamento rule_groups -> tecnologia)
  getTechnologies: (): Promise<Technology[]> =>
    request<Technology[]>("/api/technologies"),

  createTechnology: (payload: TechnologyPayload): Promise<Technology> =>
    request<Technology>("/api/technologies", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  updateTechnology: (
    slug: string,
    payload: TechnologyPayload
  ): Promise<Technology> =>
    request<Technology>(`/api/technologies/${encodeURIComponent(slug)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  deleteTechnology: (slug: string): Promise<{ message: string; slug: string }> =>
    request<{ message: string; slug: string }>(
      `/api/technologies/${encodeURIComponent(slug)}`,
      { method: "DELETE" }
    ),

  resolveTechnologies: (query: string): Promise<Technology[]> =>
    request<Technology[]>("/api/technologies/resolve", {
      method: "POST",
      body: JSON.stringify({ query }),
    }),

  /** Lista os perímetros canônicos de segurança (Firewall, WAF, Antimalware/EDR, etc.). */
  getPerimeters: (): Promise<DetectionPerimeter[]> =>
    request<DetectionPerimeter[]>("/api/technologies/perimeters"),

  /** Visão consolidada: métricas, distribuição por cliente e conformidade. */
  getTechnologyOverview: (): Promise<TechnologyOverview> =>
    request<TechnologyOverview>("/api/technologies/overview"),

  /** Footprint de tecnologias por cliente (derivado das regras + declarado). */
  getTechnologyFootprints: (): Promise<TenantTechnologyFootprint[]> =>
    request<TenantTechnologyFootprint[]>("/api/technologies/footprints"),

  /**
   * Declara (substituição total) as tecnologias que o cliente possui no SIEM.
   * O que foi derivado das regras da pasta permanece no footprint.
   */
  setTenantTechnologyFootprint: (
    clientUid: string,
    technologies: string[]
  ): Promise<TenantTechnologyFootprint> =>
    request<TenantTechnologyFootprint>(
      `/api/technologies/footprints/${encodeURIComponent(clientUid)}`,
      {
        method: "PUT",
        body: JSON.stringify({ technologies }),
      }
    ),

  /**
   * Validação implícita de telemetria (Loki). A query é montada no backend e
   * nunca retorna para o cliente.
   */
  checkTechnologyLogs: (payload: {
    slug?: string;
    rule_groups_regex?: string;
    job?: string;
    window_seconds?: number;
  }): Promise<TechnologyLogCheckResult> =>
    request<TechnologyLogCheckResult>("/api/technologies/log-presence", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  /** Implementa todo o baseline da tecnologia na pasta do cliente. */
  implementTechnologyBaseline: (
    slug: string,
    payload: {
      target_folder_uid: string;
      target_folder_title?: string;
      confirm_client_without_technology?: boolean;
      evaluation_group?: string;
    }
  ): Promise<ImplementBaselineResult> =>
    request<ImplementBaselineResult>(
      `/api/technologies/${encodeURIComponent(slug)}/implement-baseline`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    ),

  // Dicionário de Campos de Tecnologias
  getFieldDictionary: (slug: string): Promise<FieldDictionaryDetailOut> =>
    request<FieldDictionaryDetailOut>(
      `/api/technologies/${encodeURIComponent(slug)}/fields`
    ),

  rescanFieldDictionary: (slug: string): Promise<FieldDictionaryScanResponse> =>
    request<FieldDictionaryScanResponse>(
      `/api/technologies/${encodeURIComponent(slug)}/fields/rescan`,
      { method: "POST" }
    ),

  analyzeFieldDictionaryAI: (slug: string): Promise<FieldDictionaryAIAnalysisOut> =>
    request<FieldDictionaryAIAnalysisOut>(
      `/api/technologies/${encodeURIComponent(slug)}/fields/ai-analysis`,
      { method: "POST" }
    ),

  getFieldDictionarySummaries: (): Promise<Record<string, FieldDictionarySummaryOut>> =>
    request<Record<string, FieldDictionarySummaryOut>>(
      "/api/technologies/fields/summaries"
    ),

  // Agendamentos Automatizados (Dicionário + Curadoria)
  getSystemSchedules: (): Promise<ScheduleSettingsOut> =>
    request<ScheduleSettingsOut>("/api/system/schedules"),

  updateSystemSchedules: (
    payload: ScheduleSettingsUpdateRequest
  ): Promise<ScheduleSettingsOut> =>
    request<ScheduleSettingsOut>("/api/system/schedules", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),

  getAlertHistory: (hours?: number): Promise<AlertHistoryResponse> =>
    request<AlertHistoryResponse>(
      `/api/alerts/history${hours !== undefined ? `?hours=${hours}` : ""}`
    ),

  // Alertas
  getAlerts: (): Promise<AlertInstance[]> =>
    request<AlertInstance[]>("/api/alerts"),

  generateSyntheticAlerts: (
    ruleUid?: string,
    count: number = 15
  ): Promise<AlertInstance[]> =>
    request<AlertInstance[]>("/api/alerts/synthetic/generate", {
      method: "POST",
      body: JSON.stringify({ rule_uid: ruleUid, count }),
    }),

  clearSyntheticAlerts: (): Promise<{ status: string; cleared: number }> =>
    request<{ status: string; cleared: number }>("/api/alerts/synthetic", {
      method: "DELETE",
    }),

  // Silences
  getSilences: (): Promise<Silence[]> =>
    request<Silence[]>("/api/silences"),

  createSilence: (
    payload: CreateSilencePayload
  ): Promise<{ silence_id: string }> =>
    request<{ silence_id: string }>("/api/silences", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  deleteSilence: (silenceId: string): Promise<void> =>
    request<void>(`/api/silences/${encodeURIComponent(silenceId)}`, {
      method: "DELETE",
    }),

  extendSilence: (
    silenceId: string,
    duration: "2h" | "4h" | "8h" | "24h" | "3d" | "10y"
  ): Promise<{ message: string; silence_id: string; ends_at: string }> =>
    request<{ message: string; silence_id: string; ends_at: string }>(
      `/api/silences/${encodeURIComponent(silenceId)}/extend`,
      {
        method: "POST",
        body: JSON.stringify({ duration }),
      }
    ),

  // Pastas / Clientes SIEM
  getFolders: (): Promise<FolderItem[]> =>
    request<FolderItem[]>("/api/folders"),

  createFolder: (title: string, uid?: string): Promise<FolderItem> =>
    request<FolderItem>("/api/folders", {
      method: "POST",
      body: JSON.stringify({ title, uid }),
    }),

  // Tenants (Clientes SIEM)
  getTenants: (): Promise<TenantSummary[]> =>
    request<TenantSummary[]>("/api/tenants"),

  /** Marca/desmarca o tenant como Oculto (fora de conformidade e métricas). */
  setTenantHidden: (uid: string, hidden: boolean): Promise<SetTenantHiddenResult> =>
    request<SetTenantHiddenResult>(`/api/tenants/${encodeURIComponent(uid)}/hidden`, {
      method: "PUT",
      body: JSON.stringify({ hidden }),
    }),

  createTenant: (payload: CreateTenantPayload): Promise<TenantSummary> =>
    request<TenantSummary>("/api/tenants", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  createTenantDatasource: (
    uid: string,
    lokiUrl?: string
  ): Promise<TenantDatasourceResult> =>
    request<TenantDatasourceResult>(
      `/api/tenants/${encodeURIComponent(uid)}/datasource`,
      {
        method: "POST",
        body: JSON.stringify({ loki_url: lokiUrl || undefined }),
      }
    ),

  /** Escaneia a presença de logs de cada tecnologia do catálogo no Loki do tenant. */
  scanTenantTechnologies: (
    uid: string,
    windowSeconds?: number
  ): Promise<TenantTechnologyScanResult> =>
    request<TenantTechnologyScanResult>(
      `/api/tenants/${encodeURIComponent(uid)}/technologies/scan`,
      {
        method: "POST",
        body: JSON.stringify({ window_seconds: windowSeconds }),
      }
    ),

  /** Tecnologias do tenant com o estado de conformidade de cada baseline. */
  getTenantTechnologies: (uid: string): Promise<TenantTechnologiesResult> =>
    request<TenantTechnologiesResult>(
      `/api/tenants/${encodeURIComponent(uid)}/technologies`
    ),

  /** Materializa/recupera o grupo de avaliação canônico do tenant (backfill). */
  repairTenantEvaluationGroup: (
    uid: string,
    migrateRules = true
  ): Promise<TenantEvaluationGroupResult> =>
    request<TenantEvaluationGroupResult>(
      `/api/tenants/${encodeURIComponent(uid)}/evaluation-group`,
      {
        method: "POST",
        body: JSON.stringify({ migrate_rules: migrateRules }),
      }
    ),

  deleteTenant: (uid: string): Promise<{ message: string; uid: string }> =>
    request<{ message: string; uid: string }>(
      `/api/tenants/${encodeURIComponent(uid)}`,
      {
        method: "DELETE",
      }
    ),

  toggleTenantPause: (
    uid: string,
    paused: boolean
  ): Promise<BatchToggleRulesResponse> =>
    request<BatchToggleRulesResponse>(
      `/api/tenants/${encodeURIComponent(uid)}/toggle-pause`,
      {
        method: "POST",
        body: JSON.stringify({ paused }),
      }
    ),

  enableTenantSandbox: (uid: string): Promise<TenantSandboxResponse> =>
    request<TenantSandboxResponse>(
      `/api/tenants/${encodeURIComponent(uid)}/sandbox`,
      {
        method: "POST",
      }
    ),

  disableTenantSandbox: (uid: string): Promise<TenantSandboxResponse> =>
    request<TenantSandboxResponse>(
      `/api/tenants/${encodeURIComponent(uid)}/sandbox`,
      {
        method: "DELETE",
      }
    ),



  // Duplicação de Regra
  duplicateRule: (
    uid: string,
    payload: DuplicateRulePayload
  ): Promise<{ message: string; uid: string; title: string; client: string }> =>
    request(`/api/rules/${encodeURIComponent(uid)}/duplicate`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Validação LogQL
  testLogQL: (
    logql_query: string,
    log_line: string,
    stream_labels?: Record<string, string>
  ): Promise<LogQLValidationReport> =>
    request<LogQLValidationReport>("/api/rules/test-logql", {
      method: "POST",
      body: JSON.stringify({
        logql_query,
        log_line,
        stream_labels,
      }),
    }),

  // Mapa de Adesão ao Baseline (conformidade por cliente, tecnologia e regra)
  getBaselineAdherence: (): Promise<BaselineAdherence> =>
    request<BaselineAdherence>("/api/baseline/adherence"),

  // Matriz de Regras Globais por Cliente
  getGlobalMatrix: (): Promise<GlobalRuleMatrixItem[]> =>
    request<GlobalRuleMatrixItem[]>("/api/rules/global-matrix"),

  // Grupos de Avaliação (Evaluation Groups)
  getEvaluationGroups: (): Promise<string[]> =>
    request<string[]>("/api/rules/evaluation-groups"),

  // Criação e Validação de Regra de Detecção
  previewImportRules: (
    payload: string | { content?: string; files?: RuleImportFileInput[] }
  ): Promise<RuleImportPreviewResponse> => {
    const body = typeof payload === "string" ? { content: payload } : payload;
    return request<RuleImportPreviewResponse>("/api/rules/import/preview", {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  executeImportRules: (
    rules: RuleImportItemValidation[],
    datasourceUid?: string,
    evaluationGroup?: string
  ): Promise<RuleImportExecuteResponse> =>
    request<RuleImportExecuteResponse>("/api/rules/import", {
      method: "POST",
      body: JSON.stringify({
        rules,
        datasource_uid: datasourceUid || undefined,
        evaluation_group: evaluationGroup?.trim() || undefined,
      }),
    }),

  generateRuleImportAIOpinion: (
    payload: RuleImportAIOpinionRequest
  ): Promise<RuleImportAIOpinionResponse> =>
    request<RuleImportAIOpinionResponse>("/api/rules/import/ai-opinion", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  createRule: (payload: CreateRulePayload): Promise<CreateRuleResponse> =>
    request<CreateRuleResponse>("/api/rules", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  lintLogQL: (query: string): Promise<LogQLLintResult> =>
    request<LogQLLintResult>("/api/rules/lint-logql", {
      method: "POST",
      body: JSON.stringify({ query }),
    }),

  executeQuery: (
    query: string,
    time_range_from: string = "now-1h",
    time_range_to: string = "now",
    limit: number = 25,
    options?: {
      scope?: "baseline" | "client";
      client_uid?: string;
    }
  ): Promise<ExecuteQueryResult> =>
    request<ExecuteQueryResult>("/api/rules/execute-query", {
      method: "POST",
      body: JSON.stringify({
        query,
        time_range_from,
        time_range_to,
        limit,
        scope: options?.scope,
        client_uid: options?.client_uid,
      }),
    }),

  // Loki — laboratório de logs sintéticos
  getLokiStatus: (datasourceUid?: string): Promise<LokiStatus> =>
    request<LokiStatus>(
      datasourceUid
        ? `/api/loki/status?datasource_uid=${encodeURIComponent(datasourceUid)}`
        : "/api/loki/status"
    ),

  getLokiDatasources: (): Promise<LokiDatasourceItem[]> =>
    request<LokiDatasourceItem[]>("/api/loki/datasources"),

  // Curadoria de Regras de Detecção
  getCurationOverview: (nonBlocking = true): Promise<CurationOverviewResponse> =>
    request<CurationOverviewResponse>(
      nonBlocking ? "/api/curation?non_blocking=true" : "/api/curation"
    ),

  getCurationProgress: (): Promise<CurationProgressState> =>
    request<CurationProgressState>("/api/curation/progress"),

  runCuration: (asyncRun = true): Promise<CurationRunResponse> =>
    request<CurationRunResponse>(
      asyncRun ? "/api/curation/run?async_run=true" : "/api/curation/run",
      {
        method: "POST",
      }
    ),

  stopCuration: (): Promise<CurationStopResponse> =>
    request<CurationStopResponse>("/api/curation/stop", {
      method: "POST",
    }),

  clearCuration: (): Promise<CurationClearResponse> =>
    request<CurationClearResponse>("/api/curation/clear", {
      method: "POST",
    }),

  ignoreCuratedRule: (
    ruleId: string,
    ignored = true
  ): Promise<CuratedRuleItem> =>
    request<CuratedRuleItem>(
      `/api/curation/rules/${encodeURIComponent(ruleId)}/ignore`,
      {
        method: "POST",
        body: JSON.stringify({ ignored }),
      }
    ),

  implementCuratedRule: (
    ruleId: string,
    payload: ImplementCuratedRuleRequest
  ): Promise<ImplementCuratedRuleResponse> =>
    request<ImplementCuratedRuleResponse>(
      `/api/curation/rules/${encodeURIComponent(ruleId)}/implement`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    ),

  injectSyntheticLogs: (
    payload: LokiSyntheticPayload
  ): Promise<LokiSyntheticResult> =>
    request<LokiSyntheticResult>("/api/loki/logs", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Inteligência Artificial / LLM
  getAISettings: (): Promise<AISettingsPublicResponse> =>
    request<AISettingsPublicResponse>("/api/ai/settings"),

  updateAISettings: (
    payload: AISettingsUpdateRequest
  ): Promise<AISettingsPublicResponse> =>
    request<AISettingsPublicResponse>("/api/ai/settings", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  testAIConnection: (
    payload: AITestConnectionRequest
  ): Promise<AITestConnectionResponse> =>
    request<AITestConnectionResponse>("/api/ai/test-connection", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  clearAICache: (): Promise<AIClearCacheResponse> =>
    request<AIClearCacheResponse>("/api/ai/clear-cache", {
      method: "POST",
    }),

  // Avaliação e Melhoria de Regras por IA
  getRuleAIEvaluation: (uid: string, refresh = false): Promise<RuleImprovementEvaluation> =>
    request<RuleImprovementEvaluation>(
      `/api/rules/${encodeURIComponent(uid)}/ai-evaluation${refresh ? "?refresh=true" : ""}`
    ),

  applyRuleAISuggestions: (
    uid: string,
    payload?: ApplyRuleAISuggestionsRequest
  ): Promise<ApplyRuleAISuggestionsResponse> =>
    request<ApplyRuleAISuggestionsResponse>(
      `/api/rules/${encodeURIComponent(uid)}/apply-ai-suggestions`,
      {
        method: "POST",
        body: JSON.stringify(payload || {}),
      }
    ),
  // Prefixo Baseline
  getBaselinePrefixSettings: (): Promise<BaselinePrefixSettings> =>
    request<BaselinePrefixSettings>("/api/system/baseline/prefix"),

  setBaselinePrefixSettings: (
    data: BaselinePrefixSettings
  ): Promise<BaselinePrefixSettings> =>
    request<BaselinePrefixSettings>("/api/system/baseline/prefix", {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  previewBaselinePrefix: (
    data: BaselinePrefixPreviewRequest
  ): Promise<BaselinePrefixPreviewResponse> =>
    request<BaselinePrefixPreviewResponse>("/api/system/baseline/prefix/preview", {
      method: "POST",
      body: JSON.stringify(data),
    }),
};
