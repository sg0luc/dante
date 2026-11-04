import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Modal } from "../components/Modal";
import { ConfirmModal } from "../components/ConfirmModal";
import {
  FieldDictionaryDetailOut,
  FieldDictionarySummaryOut,
  ScheduleSettingsOut,
  TechnologyClientCompliance,
  TechnologyLogCheckResult,
  TechnologyOverview,
  TechnologyOverviewItem,
  TechnologyPayload,
  TenantSummary,
} from "../types";

interface TechnologyFormState {
  slug: string;
  name: string;
  perimeter: string;
  rule_groups_regex: string;
  job: string;
  description: string;
  icon: string;
  enabled: boolean;
}

const EMPTY_FORM: TechnologyFormState = {
  slug: "",
  name: "",
  perimeter: "firewall",
  rule_groups_regex: "",
  job: "wazuh",
  description: "",
  icon: "",
  enabled: true,
};

export const PERIMETER_CONFIG: Record<
  string,
  { label: string; icon: string; badgeClass: string }
> = {
  firewall: {
    label: "Firewall",
    icon: "local_fire_department",
    badgeClass: "bg-amber-950/70 text-amber-300 border border-amber-500/40",
  },
  waf_web: {
    label: "WAF / Web",
    icon: "language",
    badgeClass: "bg-purple-950/70 text-purple-300 border border-purple-500/40",
  },
  endpoint_edr: {
    label: "Antimalware/EDR",
    icon: "shield",
    badgeClass: "bg-emerald-950/70 text-emerald-300 border border-emerald-500/40",
  },
  identity_iam: {
    label: "Identidade",
    icon: "badge",
    badgeClass: "bg-blue-950/70 text-blue-300 border border-blue-500/40",
  },
  cloud_saas: {
    label: "Cloud / SaaS",
    icon: "cloud",
    badgeClass: "bg-sky-950/70 text-sky-300 border border-sky-500/40",
  },
  os_host: {
    label: "Sistema Operacional",
    icon: "terminal",
    badgeClass: "bg-slate-900 text-slate-300 border border-slate-600/40",
  },
  network_ids: {
    label: "Rede / IDS / DNS",
    icon: "hub",
    badgeClass: "bg-indigo-950/70 text-indigo-300 border border-indigo-500/40",
  },
  email_gateway: {
    label: "Email Gateway",
    icon: "mail",
    badgeClass: "bg-pink-950/70 text-pink-300 border border-pink-500/40",
  },
  other: {
    label: "Outro",
    icon: "category",
    badgeClass: "bg-surface-container-high text-outline border border-outline-variant/30",
  },
};

const formatPct = (value: number): string =>
  `${value.toLocaleString("pt-BR", { minimumFractionDigits: 1, maximumFractionDigits: 1 })}%`;

export const TechnologiesPage: React.FC = () => {
  const [overview, setOverview] = useState<TechnologyOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [perimeterFilter, setPerimeterFilter] = useState<string>("all");

  // Formulário (cadastro/edição)
  const [formOpen, setFormOpen] = useState(false);
  const [editingSlug, setEditingSlug] = useState<string | null>(null);
  const [form, setForm] = useState<TechnologyFormState>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [checkingLogs, setCheckingLogs] = useState(false);
  const [logWarning, setLogWarning] = useState<TechnologyLogCheckResult | null>(null);
  const [pendingPayload, setPendingPayload] = useState<TechnologyPayload | null>(null);

  // Exclusão
  const [deleteTarget, setDeleteTarget] = useState<TechnologyOverviewItem | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Tenants
  const [tenants, setTenants] = useState<TenantSummary[]>([]);

  // Implementação de baseline
  const [baselineTech, setBaselineTech] = useState<TechnologyOverviewItem | null>(null);
  const [baselineClientUid, setBaselineClientUid] = useState<string>("");
  const [baselineEvaluationGroup, setBaselineEvaluationGroup] = useState<string>("");
  const [baselineRunning, setBaselineRunning] = useState(false);
  const [baselineError, setBaselineError] = useState<string | null>(null);
  const [baselineConfirmOpen, setBaselineConfirmOpen] = useState(false);

  // Dicionário de Campos e Modal
  const [fieldSummaries, setFieldSummaries] = useState<Record<string, FieldDictionarySummaryOut>>({});
  const [selectedDictTech, setSelectedDictTech] = useState<TechnologyOverviewItem | null>(null);
  const [dictDetail, setDictDetail] = useState<FieldDictionaryDetailOut | null>(null);
  const [dictLoading, setDictLoading] = useState(false);
  const [dictRescanning, setDictRescanning] = useState(false);
  const [dictAiAnalyzing, setDictAiAnalyzing] = useState(false);
  const [dictActiveTab, setDictActiveTab] = useState<"clients" | "ai">("clients");
  const [dictModalError, setDictModalError] = useState<string | null>(null);

  // Agendamentos (Dicionário + Curadoria)
  const [schedulesModalOpen, setSchedulesModalOpen] = useState(false);
  const [schedulesData, setSchedulesData] = useState<ScheduleSettingsOut | null>(null);
  const [schedulesSaving, setSchedulesSaving] = useState(false);
  const [schedulesSuccess, setSchedulesSuccess] = useState<string | null>(null);

  const loadFieldSummaries = useCallback(async () => {
    try {
      const summaries = await api.getFieldDictionarySummaries();
      setFieldSummaries(summaries);
    } catch {
      // Ignora erro silencioso de resumo
    }
  }, []);

  const openDictionaryModal = async (tech: TechnologyOverviewItem) => {
    setSelectedDictTech(tech);
    setDictLoading(true);
    setDictActiveTab("clients");
    setDictModalError(null);
    try {
      const data = await api.getFieldDictionary(tech.slug);
      setDictDetail(data);
      if (data.last_error) {
        setDictModalError(`Último erro registrado na coleta: ${data.last_error}`);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Erro ao carregar o dicionário de campos.";
      setDictModalError(msg);
      setActionError(msg);
    } finally {
      setDictLoading(false);
    }
  };

  const handleRescanDictionary = async () => {
    if (!selectedDictTech) return;
    setDictRescanning(true);
    setDictModalError(null);
    try {
      await api.rescanFieldDictionary(selectedDictTech.slug);
      setActionSuccess(`Reanálise de campos iniciada para ${selectedDictTech.name}.`);
      // Recarrega os dados após breve intervalo
      setTimeout(async () => {
        try {
          const updated = await api.getFieldDictionary(selectedDictTech.slug);
          setDictDetail(updated);
          if (updated.last_error) {
            setDictModalError(`Erro durante a varredura: ${updated.last_error}`);
          }
          loadFieldSummaries();
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : "Falha ao consultar atualização do dicionário.";
          setDictModalError(msg);
        } finally {
          setDictRescanning(false);
        }
      }, 3000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Erro ao disparar reanálise de campos.";
      setDictModalError(msg);
      setActionError(msg);
      setDictRescanning(false);
    }
  };

  const handleRunAiAnalysis = async () => {
    if (!selectedDictTech) return;
    setDictAiAnalyzing(true);
    setDictModalError(null);
    try {
      const analysis = await api.analyzeFieldDictionaryAI(selectedDictTech.slug);
      setDictDetail((prev) => (prev ? { ...prev, ai_analysis: analysis } : null));
      setDictActiveTab("ai");
      setActionSuccess("Análise de IA concluída com sucesso.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Erro ao executar análise de IA.";
      setDictModalError(msg);
      setActionError(msg);
    } finally {
      setDictAiAnalyzing(false);
    }
  };

  const openSchedulesModal = async () => {
    setSchedulesModalOpen(true);
    setSchedulesSuccess(null);
    try {
      const data = await api.getSystemSchedules();
      setSchedulesData(data);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Erro ao carregar agendamentos.");
    }
  };

  const handleSaveSchedules = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!schedulesData) return;
    setSchedulesSaving(true);
    try {
      const updated = await api.updateSystemSchedules({
        field_dictionary: schedulesData.field_dictionary,
        curation: schedulesData.curation,
      });
      setSchedulesData(updated);
      setSchedulesSuccess("Configurações de agendamento salvas com sucesso.");
      setTimeout(() => setSchedulesModalOpen(false), 1200);
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Erro ao salvar agendamentos.");
    } finally {
      setSchedulesSaving(false);
    }
  };

  const loadOverview = useCallback(async () => {
    try {
      setError(null);
      const [data, tenantsData] = await Promise.all([
        api.getTechnologyOverview(),
        api.getTenants().catch(() => [] as TenantSummary[]),
        loadFieldSummaries(),
      ]);
      setOverview(data);
      if (tenantsData && tenantsData.length > 0) {
        setTenants(tenantsData);
      }
    } catch (err: unknown) {
      setError(
        err instanceof Error ? err.message : "Erro ao carregar o catálogo de tecnologias."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  const technologies = useMemo(() => overview?.technologies ?? [], [overview]);

  const clients = useMemo<TechnologyClientCompliance[]>(() => {
    const byUid = new Map<string, TechnologyClientCompliance>();
    technologies.forEach((tech) => {
      tech.clients.forEach((client) => {
        if (!byUid.has(client.client_uid)) byUid.set(client.client_uid, client);
      });
    });
    return Array.from(byUid.values()).sort((a, b) =>
      a.client_name.localeCompare(b.client_name, "pt-BR")
    );
  }, [technologies]);

  const filteredTechnologies = useMemo(() => {
    const term = search.trim().toLowerCase();
    return technologies.filter((tech) => {
      const matchSearch =
        !term ||
        tech.name.toLowerCase().includes(term) ||
        tech.slug.toLowerCase().includes(term) ||
        tech.rule_groups_regex.toLowerCase().includes(term) ||
        (tech.perimeter_name && tech.perimeter_name.toLowerCase().includes(term));
      const matchPerimeter =
        perimeterFilter === "all" || tech.perimeter === perimeterFilter;
      return matchSearch && matchPerimeter;
    });
  }, [technologies, search, perimeterFilter]);

  const selectedBaselineClient = useMemo<TechnologyClientCompliance | null>(() => {
    if (!baselineTech) return null;
    return (
      baselineTech.clients.find((client) => client.client_uid === baselineClientUid) ?? null
    );
  }, [baselineTech, baselineClientUid]);

  const getDefaultEvaluationGroup = useCallback(
    (clientUid: string) => {
      const t = tenants.find((tenant) => tenant.uid === clientUid);
      if (t?.evaluation_group) return t.evaluation_group;
      return "5m";
    },
    [tenants]
  );

  const availableEvaluationGroups = useMemo(() => {
    if (!selectedBaselineClient) return [];
    const groups = new Set<string>();
    const t = tenants.find((item) => item.uid === selectedBaselineClient.client_uid);
    if (t) {
      if (t.evaluation_group) groups.add(t.evaluation_group);
      (t.evaluation_groups || []).forEach((g) => {
        if (g.name) groups.add(g.name);
      });
    }
    const fallback = getDefaultEvaluationGroup(selectedBaselineClient.client_uid);
    groups.add(fallback);
    return Array.from(groups);
  }, [selectedBaselineClient, tenants, getDefaultEvaluationGroup]);

  const openCreateForm = () => {
    setEditingSlug(null);
    setForm(EMPTY_FORM);
    setFormError(null);
    setLogWarning(null);
    setPendingPayload(null);
    setFormOpen(true);
  };

  const openEditForm = (tech: TechnologyOverviewItem) => {
    setEditingSlug(tech.slug);
    setForm({
      slug: tech.slug,
      name: tech.name,
      perimeter: tech.perimeter || "other",
      rule_groups_regex: tech.rule_groups_regex,
      job: tech.job || "wazuh",
      description: tech.description ?? "",
      icon: tech.icon ?? "",
      enabled: tech.enabled,
    });
    setFormError(null);
    setLogWarning(null);
    setPendingPayload(null);
    setFormOpen(true);
  };

  const closeForm = () => {
    if (saving || checkingLogs) return;
    setFormOpen(false);
    setLogWarning(null);
    setPendingPayload(null);
  };

  const buildPayload = (): TechnologyPayload => ({
    slug: form.slug.trim().toLowerCase(),
    name: form.name.trim(),
    perimeter: form.perimeter,
    rule_groups_regex: form.rule_groups_regex.trim(),
    job: form.job.trim() || "wazuh",
    description: form.description.trim(),
    icon: form.icon.trim(),
    enabled: form.enabled,
  });

  const persistTechnology = async (payload: TechnologyPayload, confirmWithoutLogs: boolean) => {
    setSaving(true);
    setFormError(null);
    try {
      if (editingSlug) {
        await api.updateTechnology(editingSlug, payload);
        setActionSuccess(`Tecnologia "${payload.name}" atualizada com sucesso.`);
      } else {
        await api.createTechnology({
          ...payload,
          confirm_without_logs: confirmWithoutLogs || undefined,
        });
        setActionSuccess(
          confirmWithoutLogs
            ? `Tecnologia "${payload.name}" cadastrada sem logs confirmados.`
            : `Tecnologia "${payload.name}" cadastrada com telemetria validada.`
        );
      }
      setFormOpen(false);
      setLogWarning(null);
      setPendingPayload(null);
      await loadOverview();
      setTimeout(() => setActionSuccess(null), 5000);
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Erro ao salvar a tecnologia.");
    } finally {
      setSaving(false);
    }
  };

  const handleFormSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload = buildPayload();

    if (!payload.slug || !payload.name || !payload.rule_groups_regex) {
      setFormError("Slug, nome e recorte de rule_groups são obrigatórios.");
      return;
    }

    if (editingSlug) {
      await persistTechnology(payload, false);
      return;
    }

    setCheckingLogs(true);
    setFormError(null);
    setLogWarning(null);
    try {
      const presence = await api.checkTechnologyLogs({
        rule_groups_regex: payload.rule_groups_regex,
        job: payload.job,
      });
      if (presence.found) {
        await persistTechnology(payload, false);
      } else {
        setLogWarning(presence);
        setPendingPayload(payload);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Erro ao validar a telemetria.";
      if ((err as { status?: number })?.status === 409) {
        setLogWarning({
          available: true,
          found: false,
          count: 0,
          window_seconds: 60,
          datasource: null,
          checked_at: new Date().toISOString(),
          message,
        });
        setPendingPayload(payload);
      } else {
        setFormError(message);
      }
    } finally {
      setCheckingLogs(false);
    }
  };

  const handleCreateWithoutLogs = async () => {
    if (!pendingPayload) return;
    await persistTechnology(pendingPayload, true);
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      const res = await api.deleteTechnology(deleteTarget.slug);
      setActionSuccess(res.message);
      setDeleteTarget(null);
      await loadOverview();
      setTimeout(() => setActionSuccess(null), 5000);
    } catch (err: unknown) {
      setDeleteError(err instanceof Error ? err.message : "Erro ao remover a tecnologia.");
    } finally {
      setDeleting(false);
    }
  };

  const openBaselineModal = (tech: TechnologyOverviewItem) => {
    setBaselineTech(tech);
    setBaselineError(null);
    const preferred =
      tech.clients.find((client) => client.integrated) ?? tech.clients[0] ?? null;
    if (preferred) {
      setBaselineClientUid(preferred.client_uid);
      setBaselineEvaluationGroup(getDefaultEvaluationGroup(preferred.client_uid));
    } else {
      setBaselineClientUid("");
      setBaselineEvaluationGroup("5m");
    }
    setBaselineConfirmOpen(false);
  };

  const handleExecuteBaseline = async () => {
    if (!baselineTech || !baselineClientUid) return;
    setBaselineRunning(true);
    setBaselineError(null);
    try {
      const result = await api.implementTechnologyBaseline(baselineTech.slug, {
        target_folder_uid: baselineClientUid,
        evaluation_group: baselineEvaluationGroup || "5m",
        confirm_client_without_technology: true,
      });
      setBaselineConfirmOpen(false);
      setActionSuccess(result.message);
      await loadOverview();
      setTimeout(() => setActionSuccess(null), 5000);
    } catch (err: unknown) {
      setBaselineError(err instanceof Error ? err.message : "Falha ao implementar o baseline.");
    } finally {
      setBaselineRunning(false);
    }
  };

  const metrics = overview?.metrics;

  return (
    <div className="flex flex-col w-full pb-16 space-y-space-lg text-on-surface">
      {/* Page Header & Action Bar */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md pt-space-xs">
        <div className="flex flex-col space-y-1">
          <div className="flex items-center gap-2 font-code-sm text-code-sm text-outline tracking-wider uppercase">
            <span>DANTE</span>
            <span>/</span>
            <span>Telemetria &amp; Validação</span>
            <span>/</span>
            <span className="text-primary font-semibold">Tecnologias</span>
          </div>
          <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">Tecnologias</h1>
          <p className="font-body-md text-body-md text-on-surface-variant max-w-4xl">
            Catálogo de <span className="font-code-sm text-code-sm bg-surface-container-highest px-1.5 py-0.5 rounded text-secondary font-mono">rule_groups</span> (data sources) do SIEM: telemetria validada, distribuição por cliente e conformidade ao baseline operacional.
          </p>
        </div>

        <div className="flex items-center gap-space-sm self-start lg:self-center shrink-0">
          <button
            className="h-8 px-space-md rounded bg-surface-container-high hover:bg-surface-bright text-on-surface flex items-center gap-1.5 font-headline-md text-body-sm transition-all shadow-sm active:scale-95 disabled:opacity-50"
            onClick={openSchedulesModal}
            type="button"
            title="Configurar dia e horário da coleta automática de campos e curadoria"
          >
            <span className="material-symbols-outlined text-[16px] text-tertiary">schedule</span>
            <span>Agendamentos</span>
          </button>
          <button
            className="h-8 px-space-md rounded bg-surface-container-high hover:bg-surface-bright text-on-surface flex items-center gap-1.5 font-headline-md text-body-sm transition-all shadow-sm active:scale-95 disabled:opacity-50"
            onClick={loadOverview}
            disabled={loading}
            type="button"
          >
            <span className="material-symbols-outlined text-[16px]">refresh</span>
            <span>Atualizar</span>
          </button>
          <button
            className="h-8 px-space-md rounded bg-primary-container hover:bg-primary text-on-primary flex items-center gap-1.5 font-headline-md text-body-sm transition-all shadow-sm active:scale-95 font-semibold"
            onClick={openCreateForm}
            type="button"
          >
            <span className="material-symbols-outlined text-[16px]">add</span>
            <span>Cadastrar Tecnologia</span>
          </button>
        </div>
      </div>

      {actionSuccess && (
        <div className="p-space-sm rounded-lg bg-tertiary/15 border border-tertiary/30 text-tertiary text-sm flex justify-between items-center">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-xs text-on-surface underline">Fechar</button>
        </div>
      )}

      {actionError && (
        <div className="p-space-sm rounded-lg bg-error-container text-on-error-container text-sm flex justify-between items-center">
          <span>{actionError}</span>
          <button onClick={() => setActionError(null)} className="text-xs text-on-surface underline">Fechar</button>
        </div>
      )}

      {error && (
        <div className="p-space-sm rounded-lg bg-error-container text-on-error-container text-sm">
          {error}
        </div>
      )}

      {/* KPI Metricas Scorecards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md">
        {/* KPI 1 */}
        <div className="relative overflow-hidden bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Tecnologias Únicas</span>
            <span className="material-symbols-outlined text-secondary text-[20px]">dns</span>
          </div>
          <div className="mt-space-md">
            <div className="font-metric-display text-metric-display text-on-surface font-bold tracking-tight">
              {metrics?.unique_technologies ?? 0}
            </div>
            <div className="font-body-sm text-body-sm text-on-surface-variant mt-1 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
              <span>{metrics?.enabled_technologies ?? 0} habilitada(s) no catálogo</span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest">
            <div className="h-full bg-secondary" style={{ width: "100%" }}></div>
          </div>
        </div>

        {/* KPI 2 */}
        <div className="relative overflow-hidden bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Regras Baseline (Global)</span>
            <span className="material-symbols-outlined text-outline text-[20px]">verified</span>
          </div>
          <div className="mt-space-md">
            <div className="font-metric-display text-metric-display text-on-surface font-bold tracking-tight">
              {metrics?.baseline_rules_total ?? 0}
            </div>
            <div className="font-body-sm text-body-sm text-outline mt-1 flex items-center gap-1">
              <span className="material-symbols-outlined text-[14px] text-outline">help_outline</span>
              <span>{metrics?.baseline_rules_unmapped ?? 0} sem tecnologia mapeada</span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest">
            <div className="h-full bg-primary" style={{ width: "90%" }}></div>
          </div>
        </div>

        {/* KPI 3 */}
        <div className="relative overflow-hidden bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Clientes com Tecnologia</span>
            <span className="material-symbols-outlined text-tertiary text-[20px]">group_work</span>
          </div>
          <div className="mt-space-md">
            <div className="flex items-baseline gap-1">
              <span className="font-metric-display text-metric-display text-on-surface font-bold tracking-tight">
                {metrics?.clients_with_technology ?? 0}
              </span>
              <span className="font-headline-md text-headline-md text-outline">
                / {metrics?.clients_total ?? 0}
              </span>
            </div>
            <div className="font-body-sm text-body-sm text-on-surface-variant mt-1">
              <span>{metrics?.implemented_baseline_rules ?? 0} regra(s) em clientes</span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest">
            <div className="h-full bg-tertiary" style={{ width: "100%" }}></div>
          </div>
        </div>

        {/* KPI 4 */}
        <div className="relative overflow-hidden bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Conformidade Global</span>
            <span className="material-symbols-outlined text-secondary-container text-[20px]">pie_chart</span>
          </div>
          <div className="mt-space-md">
            <div className="font-metric-display text-metric-display text-secondary-fixed-dim font-bold tracking-tight">
              {formatPct(metrics?.compliance_pct ?? 0)}
            </div>
            <div className="font-body-sm text-body-sm text-outline mt-1 truncate">
              {metrics?.total_baseline_slots ?? 0} slots no escopo
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest">
            <div className="h-full bg-secondary-container" style={{ width: `${Math.min(100, metrics?.compliance_pct ?? 0)}%` }}></div>
          </div>
        </div>
      </div>

      {/* SEÇÃO 1: Distribuição de Tecnologias por Clientes */}
      <section className="bg-surface-container-lowest rounded-xl p-space-lg shadow-sm flex flex-col space-y-space-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm">
          <div>
            <h2 className="font-headline-lg text-headline-lg text-on-surface font-semibold flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-primary">lan</span>
              <span>Distribuição de Tecnologias por Clientes</span>
            </h2>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
              Cliente possui a tecnologia quando há regra de detecção dela no escopo do tenant ou integração declarada.
            </p>
          </div>
          <span className="font-code-sm text-code-sm px-2 py-1 rounded bg-surface-container-high text-outline self-start sm:self-auto">
            {technologies.length} Fontes Ativas
          </span>
        </div>

        <div className="overflow-x-auto rounded-lg bg-surface-container-low">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-high text-outline font-label-uppercase text-label-uppercase uppercase tracking-wider">
                <th className="py-2.5 px-space-md w-48 font-semibold">Tecnologia</th>
                <th className="py-2.5 px-space-md w-44 font-semibold">Perímetro</th>
                <th className="py-2.5 px-space-md w-44 font-semibold">rule_groups</th>
                <th className="py-2.5 px-space-md w-36 font-semibold text-center">Dicionário</th>
                <th className="py-2.5 px-space-md w-56 font-semibold">Cobertura por Cliente</th>
                <th className="py-2.5 px-space-md font-semibold">Clientes Atribuídos</th>
                <th className="py-2.5 px-space-md text-right w-36 font-semibold">Regras em Clientes</th>
              </tr>
            </thead>
            <tbody className="font-body-sm text-body-sm text-on-surface divide-y-0">
              {technologies.map((tech) => {
                const totalClients = (tech.integrated_clients_count + tech.excluded_clients_count) || (clients.length || 1);
                const integratedCount = tech.integrated_clients_count || 0;
                const coveragePct = Math.round((integratedCount / totalClients) * 100);
                const pConf = PERIMETER_CONFIG[tech.perimeter] || PERIMETER_CONFIG.other;

                return (
                  <tr key={tech.slug} className="hover:bg-surface-container-high/60 transition-colors">
                    <td className="py-3 px-space-md">
                      <div className="flex flex-col">
                        <span className="font-headline-md text-body-md font-bold text-on-surface">{tech.name}</span>
                        <span className="font-code-sm text-code-sm text-outline">{tech.slug}</span>
                      </div>
                    </td>
                    <td className="py-3 px-space-md">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${pConf.badgeClass}`}>
                        <span className="material-symbols-outlined text-[14px]">{pConf.icon}</span>
                        <span>{tech.perimeter_name || pConf.label}</span>
                      </span>
                    </td>
                    <td className="py-3 px-space-md">
                      <span className="font-code-sm text-code-sm bg-surface-container-highest px-2 py-0.5 rounded text-secondary-fixed-dim">
                        {tech.rule_groups_regex}
                      </span>
                    </td>
                    <td className="py-3 px-space-md text-center">
                      {(() => {
                        const dictSum = fieldSummaries[tech.slug.toLowerCase()];
                        const count = dictSum?.total_unique_fields ?? 0;
                        const isScanning = Boolean(dictSum?.is_scanning);
                        const hasError = Boolean(dictSum?.last_error);

                        return (
                          <button
                            type="button"
                            onClick={() => openDictionaryModal(tech)}
                            className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-on-surface transition-all font-code-sm text-code-sm cursor-pointer shadow-sm active:scale-95 group ${
                              hasError
                                ? "bg-error-container/20 border-error/50 hover:bg-error-container/30 text-error"
                                : "bg-surface-container hover:bg-surface-container-high border border-outline/20 hover:border-primary/40 hover:text-primary"
                            }`}
                            title={
                              hasError
                                ? `Erro na última varredura: ${dictSum?.last_error} (Clique para detalhes)`
                                : "Clique para ver o dicionário de campos por cliente e análise de IA"
                            }
                          >
                            <span
                              className={`material-symbols-outlined text-[15px] ${
                                isScanning
                                  ? "animate-spin text-tertiary"
                                  : hasError
                                  ? "text-error"
                                  : "text-primary group-hover:scale-110 transition-transform"
                              }`}
                            >
                              {isScanning ? "sync" : hasError ? "error" : "menu_book"}
                            </span>
                            <span className="font-semibold">
                              {count > 0 ? `${count} campos` : "0 campos"}
                            </span>
                            {hasError && (
                              <span className="w-1.5 h-1.5 rounded-full bg-error animate-ping"></span>
                            )}
                          </button>
                        );
                      })()}
                    </td>
                    <td className="py-3 px-space-md">
                      <div className="flex flex-col space-y-1">
                        <div className="flex justify-between font-code-sm text-code-sm text-outline">
                          <span>{integratedCount} de {totalClients} cliente(s)</span>
                          <span className={`font-semibold ${coveragePct > 0 ? "text-primary" : "text-outline"}`}>{coveragePct}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden">
                          <div
                            className={`h-full ${coveragePct > 0 ? "bg-primary-container" : "bg-surface-variant"}`}
                            style={{ width: `${coveragePct}%` }}
                          ></div>
                        </div>
                      </div>
                    </td>
                    <td className="py-3 px-space-md">
                      <div className="flex flex-wrap gap-1.5 items-center">
                        {tech.clients.filter((c) => c.integrated).length === 0 ? (
                          <span className="font-body-sm text-body-sm text-outline italic">Nenhum cliente associado</span>
                        ) : (
                          tech.clients
                            .filter((c) => c.integrated)
                            .map((c) => (
                              <span
                                key={c.client_uid}
                                className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-surface-container-highest font-code-sm text-code-sm text-on-surface"
                              >
                                <span>{c.client_name}</span>
                                <span className="px-1 rounded bg-surface-container-high text-primary font-bold">
                                  {c.implemented_rules}
                                </span>
                              </span>
                            ))
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-space-md text-right">
                      <span className={`font-code-md text-headline-md font-bold ${tech.client_rules_count > 0 ? "text-on-surface" : "text-outline"}`}>
                        {tech.client_rules_count}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* SEÇÃO 2: Mapa de Conformidade ao Baseline por Tecnologia (Matriz) */}
      <section className="bg-surface-container-lowest rounded-xl p-space-lg shadow-sm flex flex-col space-y-space-md">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-sm pb-space-xs">
          <div>
            <h2 className="font-headline-lg text-headline-lg text-on-surface font-semibold flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-tertiary">grid_on</span>
              <span>Mapa de Conformidade ao Baseline por Tecnologia</span>
            </h2>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
              Cada célula mostra quantas regras do baseline global da tecnologia estão implementadas no cliente.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-space-sm bg-surface-container-low px-space-md py-1.5 rounded-lg text-body-sm">
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-tertiary"></span>
              <span className="text-on-surface font-medium">Completo</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-secondary-container"></span>
              <span className="text-on-surface font-medium">Parcial</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-error"></span>
              <span className="text-on-surface font-medium">Não implementado</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-outline"></span>
              <span className="text-outline">Fora do escopo</span>
            </div>
          </div>
        </div>

        <div className="overflow-x-auto rounded-lg bg-surface-container-low">
          <table className="w-full text-center border-collapse">
            <thead>
              <tr className="bg-surface-container-high text-outline font-label-uppercase text-label-uppercase uppercase tracking-wider">
                <th className="py-2.5 px-space-md text-left w-64 font-semibold">Cliente</th>
                {technologies.map((tech) => (
                  <th key={tech.slug} className="py-2.5 px-space-sm font-semibold">
                    <div className="flex flex-col items-center">
                      <span>{tech.name.toUpperCase()}</span>
                      <span className="font-code-sm text-code-sm normal-case font-normal text-outline">
                        {tech.baseline_rules_count} regra(s) baseline
                      </span>
                    </div>
                  </th>
                ))}
                <th className="py-2.5 px-space-md font-semibold text-right">Global</th>
              </tr>
            </thead>
            <tbody className="font-body-sm text-body-sm divide-y-0">
              {clients.map((client) => {
                const clientTechItems = technologies.map((t) =>
                  t.clients.find((c) => c.client_uid === client.client_uid)
                );
                const inScopeItems = clientTechItems.filter((item) => item?.integrated);
                const totalBaselineSlots = inScopeItems.reduce(
                  (acc, cur) => acc + (cur?.total_baseline_rules ?? 0),
                  0
                );
                const totalImplementedSlots = inScopeItems.reduce(
                  (acc, cur) => acc + (cur?.implemented_rules ?? 0),
                  0
                );
                const clientOverallPct =
                  totalBaselineSlots > 0
                    ? Math.round((totalImplementedSlots / totalBaselineSlots) * 100)
                    : 0;

                return (
                  <tr key={client.client_uid} className="hover:bg-surface-container-high/50 transition-colors">
                    <td className="py-3 px-space-md text-left">
                      <div className="flex flex-col">
                        <span className="font-headline-md text-body-md font-bold text-on-surface">{client.client_name}</span>
                        <span className="font-code-sm text-code-sm text-outline">{client.client_uid}</span>
                      </div>
                    </td>

                    {technologies.map((tech) => {
                      const compliance = tech.clients.find(
                        (c) => c.client_uid === client.client_uid
                      );
                      if (!compliance || !compliance.integrated) {
                        return (
                          <td key={tech.slug} className="py-3 px-space-sm">
                            <span className="font-code-sm text-code-sm text-outline">n/a</span>
                          </td>
                        );
                      }

                      const badgeClass =
                        compliance.status === "complete"
                          ? "bg-tertiary-container/30 text-tertiary"
                          : compliance.status === "partial"
                          ? "bg-secondary-container/20 text-secondary-fixed-dim"
                          : "bg-error-container/20 text-error";

                      return (
                        <td key={tech.slug} className="py-3 px-space-sm">
                          <span className={`inline-block px-3 py-1 rounded font-code-sm text-code-sm font-bold shadow-sm ${badgeClass}`}>
                            {compliance.implemented_rules}/{compliance.total_baseline_rules}
                          </span>
                        </td>
                      );
                    })}

                    <td className="py-3 px-space-md text-right">
                      <div className="flex flex-col items-end">
                        <span className="font-headline-md text-body-md font-bold text-on-surface">
                          {formatPct(clientOverallPct)}
                        </span>
                        <span className="font-code-sm text-code-sm text-outline">
                          {inScopeItems.length}/{technologies.length} no escopo
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* SEÇÃO 3: Catálogo e Gestão de Tecnologias */}
      <section className="bg-surface-container-lowest rounded-xl p-space-lg shadow-sm flex flex-col space-y-space-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm">
          <div className="flex flex-col sm:flex-row gap-2 flex-1 max-w-2xl">
            <div className="relative flex-1">
              <span className="material-symbols-outlined absolute left-3 top-2.5 text-[18px] text-outline">search</span>
              <input
                className="w-full h-9 pl-9 pr-8 rounded bg-surface-container-low text-on-surface font-body-sm text-body-sm placeholder:text-outline focus:outline-none focus:bg-surface-container-high transition-colors"
                placeholder="Buscar por nome, slug, rule_groups ou perímetro..."
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <span className="font-code-sm text-code-sm absolute right-2.5 top-2.5 px-1.5 py-0.5 rounded bg-surface-container text-outline">/</span>
            </div>

            <select
              value={perimeterFilter}
              onChange={(e) => setPerimeterFilter(e.target.value)}
              className="h-9 px-3 rounded bg-surface-container-low text-on-surface font-body-sm text-xs focus:outline-none border border-outline-variant/30"
            >
              <option value="all">Todos os Perímetros</option>
              <option value="firewall">Firewall</option>
              <option value="waf_web">WAF / Web</option>
              <option value="endpoint_edr">Antimalware/EDR</option>
              <option value="identity_iam">Identidade</option>
              <option value="cloud_saas">Cloud / SaaS</option>
              <option value="os_host">Sistema Operacional</option>
              <option value="network_ids">Rede / IDS / DNS</option>
              <option value="email_gateway">Email Gateway</option>
              <option value="other">Outro</option>
            </select>
          </div>

          <div className="flex items-center gap-2 text-outline font-code-sm text-code-sm">
            <span className="font-semibold text-on-surface">{filteredTechnologies.length}</span> de {technologies.length} tecnologias
          </div>
        </div>

        <div className="space-y-space-sm">
          {filteredTechnologies.map((tech) => {
            const pConf = PERIMETER_CONFIG[tech.perimeter] || PERIMETER_CONFIG.other;

            return (
              <div
                key={tech.slug}
                className="bg-surface-container-low rounded-lg p-space-md flex flex-col xl:flex-row xl:items-center justify-between gap-space-md hover:bg-surface-container transition-all"
              >
                <div className="flex flex-col space-y-1.5 flex-1 max-w-xl">
                  <div className="flex items-center gap-space-sm flex-wrap">
                    <span className="font-headline-md text-headline-md font-bold text-on-surface">{tech.name}</span>
                    <span className="font-code-sm text-code-sm text-outline font-mono">{tech.slug}</span>
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold ${pConf.badgeClass}`}>
                      <span className="material-symbols-outlined text-[13px]">{pConf.icon}</span>
                      <span>{tech.perimeter_name || pConf.label}</span>
                    </span>
                    <span className={`px-2 py-0.5 rounded font-label-uppercase text-label-uppercase font-semibold ${
                      tech.enabled ? "bg-tertiary-container/30 text-tertiary" : "bg-surface-container-high text-outline"
                    }`}>
                      {tech.enabled ? "Habilitada" : "Desabilitada"}
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    {tech.description || "Nenhuma descrição fornecida."}
                  </p>
                </div>

              <div className="flex flex-wrap items-center gap-space-md">
                <div className="flex items-center gap-1.5 bg-surface-container-highest px-space-sm py-1.5 rounded font-code-sm text-code-sm text-secondary-fixed-dim font-mono">
                  <span className="material-symbols-outlined text-[15px] text-outline">terminal</span>
                  <span>job="{tech.job || "wazuh"}", rule_groups=~"{tech.rule_groups_regex}"</span>
                </div>

                <div className="font-body-sm text-body-sm text-on-surface flex items-center gap-1">
                  <span className="font-bold font-code-md text-body-md text-primary">{tech.baseline_rules_count}</span>
                  <span className="text-outline">regra(s) global</span>
                </div>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => openBaselineModal(tech)}
                    className="h-8 px-space-sm rounded bg-primary-container hover:bg-primary text-on-primary font-headline-md text-body-sm transition-all shadow-sm active:scale-95 flex items-center gap-1 font-semibold"
                    type="button"
                  >
                    <span className="material-symbols-outlined text-[15px]">rule</span>
                    <span>Implementar baseline</span>
                  </button>
                  <button
                    onClick={() => openEditForm(tech)}
                    className="h-8 px-2.5 rounded bg-surface-container-high hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors"
                    type="button"
                  >
                    Editar
                  </button>
                  <button
                    onClick={() => setDeleteTarget(tech)}
                    className="h-8 px-2.5 rounded bg-surface-container-high hover:bg-error-container hover:text-on-error-container text-outline font-body-sm text-body-sm transition-colors"
                    type="button"
                  >
                    Excluir
                  </button>
                </div>
              </div>
            </div>
          );
        })}
        </div>
      </section>

      {/* Modal Formulário Tecnologia (Criar / Editar) */}
      <Modal
        isOpen={formOpen}
        onClose={closeForm}
        maxWidth="640px"
        title={editingSlug ? `Editar Tecnologia — ${form.name}` : "Cadastrar Nova Tecnologia"}
      >
        <form onSubmit={handleFormSubmit} className="flex flex-col gap-space-md text-on-surface">
          {formError && (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">{formError}</div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-space-sm">
            <div>
              <label className="text-xs text-outline uppercase block mb-1">Slug / Identificador *</label>
              <input
                type="text"
                required
                disabled={Boolean(editingSlug)}
                placeholder="ex.: ad_windows"
                className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm focus:outline-none disabled:opacity-50"
                value={form.slug}
                onChange={(e) => setForm({ ...form, slug: e.target.value })}
              />
            </div>
            <div>
              <label className="text-xs text-outline uppercase block mb-1">Nome Exibido *</label>
              <input
                type="text"
                required
                placeholder="ex.: Fortigate, CrowdStrike, WAF Akamai"
                className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm focus:outline-none"
                value={form.name}
                onChange={(e) => {
                  const newName = e.target.value;
                  const updates: Partial<TechnologyFormState> = { name: newName };
                  if (!editingSlug) {
                    const lower = newName.toLowerCase();
                    if (/forti|palo|check|firewall|pfsense|cisco/.test(lower)) updates.perimeter = "firewall";
                    else if (/waf|akamai|cloudflare|modsec|web/.test(lower)) updates.perimeter = "waf_web";
                    else if (/crowd|symantec|kaspersky|sophos|edr|defender|antivirus|sentinel/.test(lower)) updates.perimeter = "endpoint_edr";
                    else if (/ad|windows|active|kerberos|okta|entra|ldap/.test(lower)) updates.perimeter = "identity_iam";
                    else if (/office|m365|cloud|aws|azure|gcp|saas/.test(lower)) updates.perimeter = "cloud_saas";
                    else if (/linux|syslog|auditd|sshd/.test(lower)) updates.perimeter = "os_host";
                    else if (/dns|ids|snort|suricata|zeek/.test(lower)) updates.perimeter = "network_ids";
                    else if (/email|mail|proofpoint/.test(lower)) updates.perimeter = "email_gateway";
                  }
                  setForm({ ...form, ...updates });
                }}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-space-sm">
            <div>
              <label className="text-xs text-outline uppercase block mb-1">Perímetro de Segurança *</label>
              <select
                className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm focus:outline-none border border-outline-variant/30"
                value={form.perimeter}
                onChange={(e) => setForm({ ...form, perimeter: e.target.value })}
              >
                <option value="firewall">Firewall (Fortigate, Palo Alto, Check Point, pfSense)</option>
                <option value="waf_web">WAF / Web (Akamai, Cloudflare, AWS WAF, Nginx)</option>
                <option value="endpoint_edr">Antimalware/EDR (CrowdStrike, Symantec, Kaspersky, Sophos, Defender)</option>
                <option value="identity_iam">Identidade (Active Directory, Kerberos, Okta, Entra ID)</option>
                <option value="cloud_saas">Cloud / SaaS (Microsoft 365, AWS CloudTrail, Google Workspace)</option>
                <option value="os_host">Sistema Operacional (Linux Syslog, Auditd, Windows OS, macOS)</option>
                <option value="network_ids">Rede / IDS / DNS (Snort, Suricata, Zeek, DNS Query)</option>
                <option value="email_gateway">Email Gateway (Proofpoint, Mimecast, Cisco IronPort)</option>
                <option value="other">Outro / Customizado</option>
              </select>
            </div>
            <div>
              <label className="text-xs text-outline uppercase block mb-1">Pipeline Wazuh (Job)</label>
              <input
                type="text"
                placeholder="wazuh"
                className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface font-mono text-sm focus:outline-none"
                value={form.job}
                onChange={(e) => setForm({ ...form, job: e.target.value })}
              />
            </div>
          </div>

          <div>
            <label className="text-xs text-outline uppercase block mb-1">Grupo de Regras Wazuh (rule_groups) *</label>
            <input
              type="text"
              required
              placeholder="ex.: .*windows.*"
              className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface font-mono text-sm focus:outline-none"
              value={form.rule_groups_regex}
              onChange={(e) => setForm({ ...form, rule_groups_regex: e.target.value })}
            />
          </div>

          <div>
            <label className="text-xs text-outline uppercase block mb-1">Descrição</label>
            <textarea
              rows={2}
              placeholder="Descrição operacional da tecnologia e fontes de logs..."
              className="w-full p-3 rounded bg-surface-container-lowest text-on-surface text-sm focus:outline-none"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="tech-enabled"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="rounded bg-surface-container-lowest text-primary-container"
            />
            <label htmlFor="tech-enabled" className="text-sm cursor-pointer">
              Tecnologia habilitada no catálogo operacional
            </label>
          </div>

          {logWarning && (
            <div className="p-space-sm rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 text-xs space-y-2">
              <p>Nenhum log recente retornado pela telemetria para este recorte de <code>rule_groups</code>.</p>
              <button
                type="button"
                className="px-3 py-1 rounded bg-amber-500 text-black font-semibold text-xs"
                onClick={handleCreateWithoutLogs}
              >
                Prosseguir e Salvar Sem Telemetria Confirmada
              </button>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={closeForm}
              disabled={saving || checkingLogs}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={saving || checkingLogs}
              className="px-4 py-1.5 rounded bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold disabled:opacity-50"
            >
              {checkingLogs ? "Validando telemetria..." : saving ? "Salvando..." : "Salvar Tecnologia"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal Implementar Baseline */}
      <Modal
        isOpen={Boolean(baselineTech) && !baselineConfirmOpen}
        onClose={() => setBaselineTech(null)}
        maxWidth="600px"
        title={baselineTech ? `Implementar Baseline — ${baselineTech.name}` : "Implementar Baseline"}
      >
        {baselineTech && (
          <div className="flex flex-col gap-space-md text-on-surface">
            <p className="text-sm text-outline">
              Provisione todas as {baselineTech.baseline_rules_count} regras do baseline global desta tecnologia no tenant selecionado.
            </p>

            {baselineError && (
              <div className="p-2 rounded bg-error-container text-on-error-container text-xs">{baselineError}</div>
            )}

            <div>
              <label className="text-xs text-outline uppercase block mb-1">Cliente / Tenant de Destino</label>
              <select
                className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm"
                value={baselineClientUid}
                onChange={(e) => setBaselineClientUid(e.target.value)}
              >
                {baselineTech.clients.map((c) => (
                  <option key={c.client_uid} value={c.client_uid}>
                    {c.client_name} ({c.implemented_rules}/{baselineTech.baseline_rules_count} regras já ativas)
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-outline uppercase block mb-1">Grupo de Avaliação</label>
              <select
                className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm"
                value={baselineEvaluationGroup}
                onChange={(e) => setBaselineEvaluationGroup(e.target.value)}
              >
                {availableEvaluationGroups.map((g) => (
                  <option key={g} value={g}>{g}</option>
                ))}
              </select>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
              <button
                type="button"
                className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
                onClick={() => setBaselineTech(null)}
              >
                Cancelar
              </button>
              <button
                type="button"
                className="px-4 py-1.5 rounded bg-primary-container text-on-primary text-sm font-semibold"
                onClick={() => setBaselineConfirmOpen(true)}
              >
                Prosseguir para Confirmação
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* ConfirmModal Baseline */}
      <ConfirmModal
        isOpen={Boolean(baselineTech) && baselineConfirmOpen}
        onClose={() => setBaselineConfirmOpen(false)}
        onConfirm={handleExecuteBaseline}
        title="Confirmar Implementação de Baseline"
        confirmLabel="Confirmar e Provisionar Regras"
        cancelLabel="Voltar"
        variant="warning"
        isLoading={baselineRunning}
        message={
          baselineTech ? (
            <div className="space-y-2 text-sm">
              <p>
                Deseja replicar as <strong>{baselineTech.baseline_rules_count} regras</strong> do baseline de <strong>{baselineTech.name}</strong> para o cliente selecionado?
              </p>
              <p className="text-xs text-outline">
                As regras serão vinculadas ao datasource do cliente no grupo {baselineEvaluationGroup || "5m"}.
              </p>
            </div>
          ) : null
        }
      />

      {/* ConfirmModal Excluir Tecnologia */}
      <ConfirmModal
        isOpen={Boolean(deleteTarget)}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Excluir Tecnologia"
        confirmLabel="Excluir Tecnologia"
        cancelLabel="Cancelar"
        variant="danger"
        isLoading={deleting}
        message={
          deleteTarget ? (
            <div className="space-y-2 text-sm">
              <p>
                Tem certeza que deseja remover a tecnologia <strong>{deleteTarget.name}</strong> ({deleteTarget.slug})?
              </p>
              <p className="text-xs text-outline">
                Esta ação remove o mapeamento do catálogo do portal.
              </p>
              {deleteError && (
                <div className="p-2 rounded bg-error-container/30 text-error text-xs font-semibold">
                  {deleteError}
                </div>
              )}
            </div>
          ) : null
        }
      />

      {/* Modal Pop-up do Dicionário de Campos */}
      <Modal
        isOpen={Boolean(selectedDictTech)}
        onClose={() => {
          setSelectedDictTech(null);
          setDictDetail(null);
          setDictModalError(null);
        }}
        title={`Dicionário de Campos — ${selectedDictTech?.name ?? ""}`}
        maxWidth="840px"
      >
        <div className="flex flex-col space-y-space-md text-on-surface">
          {dictModalError && (
            <div className="p-3 rounded-lg bg-error-container/30 border border-error/40 text-error text-xs font-semibold flex items-start justify-between gap-2">
              <div className="flex items-start gap-2">
                <span className="material-symbols-outlined text-[18px] shrink-0 mt-0.5">error</span>
                <span className="leading-relaxed whitespace-pre-wrap">{dictModalError}</span>
              </div>
              <button
                type="button"
                onClick={() => setDictModalError(null)}
                className="text-outline hover:text-on-surface text-xs underline shrink-0"
              >
                Dispensar
              </button>
            </div>
          )}

          {/* Header do Dicionário */}
          <div className="p-3 rounded-lg bg-surface-container-high/40 border border-outline/10 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-headline-md font-bold text-on-surface">
                  {selectedDictTech?.name}
                </span>
                <span className="font-code-sm text-outline font-mono">
                  {selectedDictTech?.slug}
                </span>
              </div>
              <p className="font-body-sm text-on-surface-variant mt-0.5">
                Total de <strong className="text-primary">{dictDetail?.total_unique_fields ?? 0} campos únicos</strong> mapeados na telemetria de <strong>{dictDetail?.client_count ?? 0} cliente(s)</strong>.
              </p>
            </div>

            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={handleRescanDictionary}
                disabled={dictRescanning || dictLoading}
                className="h-8 px-3 rounded bg-surface-container-high hover:bg-surface-bright text-on-surface text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm active:scale-95 disabled:opacity-50"
                title="Reanalisa e atualiza o schema de logs nos clientes"
              >
                <span className={`material-symbols-outlined text-[15px] ${dictRescanning ? "animate-spin text-tertiary" : "text-tertiary"}`}>
                  sync
                </span>
                <span>{dictRescanning ? "Reanalisando..." : "Reanalisar Tecnologia"}</span>
              </button>

              <button
                type="button"
                onClick={handleRunAiAnalysis}
                disabled={dictAiAnalyzing || dictLoading || !dictDetail || dictDetail.client_count === 0}
                className="h-8 px-3 rounded bg-sky-950/70 border border-sky-500/40 hover:bg-sky-900/80 text-sky-300 text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm active:scale-95 disabled:opacity-50"
                title="Executar análise de discrepâncias e schemas via IA"
              >
                <span className={`material-symbols-outlined text-[15px] ${dictAiAnalyzing ? "animate-spin text-sky-400" : "text-sky-400"}`}>
                  psychology
                </span>
                <span>{dictAiAnalyzing ? "Analisando..." : "Análise com IA"}</span>
              </button>
            </div>
          </div>

          {/* Abas do Pop-up */}
          <div className="flex border-b border-outline-variant/30 gap-2">
            <button
              type="button"
              onClick={() => setDictActiveTab("clients")}
              className={`pb-2 px-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
                dictActiveTab === "clients"
                  ? "border-primary text-primary"
                  : "border-transparent text-outline hover:text-on-surface"
              }`}
            >
              <span className="material-symbols-outlined text-[16px]">group</span>
              <span>Campos por Cliente ({dictDetail?.client_count ?? 0})</span>
            </button>
            <button
              type="button"
              onClick={() => setDictActiveTab("ai")}
              className={`pb-2 px-3 text-sm font-semibold border-b-2 transition-colors flex items-center gap-1.5 ${
                dictActiveTab === "ai"
                  ? "border-sky-400 text-sky-300"
                  : "border-transparent text-outline hover:text-on-surface"
              }`}
            >
              <span className="material-symbols-outlined text-[16px]">psychology</span>
              <span>Parecer da IA &amp; Discrepâncias</span>
              {dictDetail?.ai_analysis && (
                <span className="w-2 h-2 rounded-full bg-sky-400 animate-pulse"></span>
              )}
            </button>
          </div>

          {/* Conteúdo Aba 1: Clientes */}
          {dictActiveTab === "clients" && (
            <div className="space-y-3 max-h-[460px] overflow-y-auto pr-1">
              {dictLoading ? (
                <div className="py-12 flex flex-col items-center justify-center text-outline gap-2">
                  <span className="material-symbols-outlined text-[28px] animate-spin text-primary">sync</span>
                  <span className="text-sm">Carregando dicionário de campos...</span>
                </div>
              ) : !dictDetail || dictDetail.clients.length === 0 ? (
                <div className="py-8 text-center text-outline text-sm">
                  Nenhum campo coletado para esta tecnologia ainda. Clique em "Reanalisar Tecnologia" para varrer o Loki de todos os clientes.
                </div>
              ) : (
                dictDetail.clients.map((c) => (
                  <div
                    key={c.client_uid}
                    className="p-3 rounded-lg bg-surface-container-low border border-outline/10 flex flex-col space-y-2 hover:bg-surface-container transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-on-surface">{c.client_name}</span>
                        <span className="font-code-sm text-outline text-xs">({c.client_uid})</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-surface-container-highest text-primary font-code-sm text-xs font-bold">
                        {c.total_fields} campos mapeados
                      </span>
                    </div>

                    {c.fields.length > 0 ? (
                      <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto pt-1">
                        {c.fields.map((f) => (
                          <span
                            key={f}
                            className="px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant font-code-sm text-[11px] font-mono hover:text-primary transition-colors"
                            title={c.sample_values[f]?.length ? `Exemplos: ${c.sample_values[f].join(", ")}` : f}
                          >
                            {f}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-outline italic">Nenhum evento desta tecnologia registrado no Loki deste cliente.</p>
                    )}
                  </div>
                ))
              )}
            </div>
          )}

          {/* Conteúdo Aba 2: IA & Discrepâncias */}
          {dictActiveTab === "ai" && (
            <div className="space-y-4 max-h-[460px] overflow-y-auto pr-1">
              {!dictDetail?.ai_analysis ? (
                <div className="py-12 flex flex-col items-center justify-center text-outline gap-3 text-center">
                  <span className="material-symbols-outlined text-[36px] text-sky-400">psychology</span>
                  <div className="max-w-md">
                    <p className="text-sm font-semibold text-on-surface mb-1">Nenhuma análise de IA gerada ainda</p>
                    <p className="text-xs text-outline">
                      A IA pode comparar os clientes e identificar campos encontrados no cliente X mas ausentes no cliente Y, avaliando versões de log, formato, idioma e riscos de compatibilidade.
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={handleRunAiAnalysis}
                    disabled={dictAiAnalyzing || !dictDetail || dictDetail.client_count === 0}
                    className="mt-2 px-4 py-1.5 rounded bg-primary-container hover:bg-primary text-on-primary text-xs font-semibold flex items-center gap-1.5"
                  >
                    <span className="material-symbols-outlined text-[15px]">play_arrow</span>
                    <span>Executar Análise de IA Agora</span>
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  {/* Banner Parecer Executivo */}
                  <div className="p-3.5 rounded-lg bg-sky-950/40 border border-sky-500/30 text-sky-200 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5 font-semibold text-sm">
                        <span className="material-symbols-outlined text-[18px] text-sky-400">auto_awesome</span>
                        <span>Parecer da IA ({dictDetail.ai_analysis.ai_model_used || "DeepSeek"})</span>
                      </div>
                      <span className="text-[11px] font-mono text-outline">
                        {dictDetail.ai_analysis.analyzed_at ? new Date(dictDetail.ai_analysis.analyzed_at).toLocaleString("pt-BR") : ""}
                      </span>
                    </div>
                    <p className="text-xs text-on-surface leading-relaxed">{dictDetail.ai_analysis.summary}</p>
                  </div>

                  {/* Grid de Diagnósticos */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                    <div className="p-2.5 rounded bg-surface-container-low border border-outline/10 space-y-1">
                      <div className="flex items-center gap-1 text-xs font-semibold text-amber-300">
                        <span className="material-symbols-outlined text-[15px]">layers</span>
                        <span>Versão do Produto/Log</span>
                      </div>
                      <p className="text-xs text-outline-variant">{dictDetail.ai_analysis.version_analysis || "Versões homogêneas."}</p>
                    </div>

                    <div className="p-2.5 rounded bg-surface-container-low border border-outline/10 space-y-1">
                      <div className="flex items-center gap-1 text-xs font-semibold text-secondary">
                        <span className="material-symbols-outlined text-[15px]">schema</span>
                        <span>Formato do Schema</span>
                      </div>
                      <p className="text-xs text-outline-variant">{dictDetail.ai_analysis.format_and_schema_analysis || "Formato de ingestão padronizado."}</p>
                    </div>

                    <div className="p-2.5 rounded bg-surface-container-low border border-outline/10 space-y-1">
                      <div className="flex items-center gap-1 text-xs font-semibold text-tertiary">
                        <span className="material-symbols-outlined text-[15px]">translate</span>
                        <span>Idioma / Localização</span>
                      </div>
                      <p className="text-xs text-outline-variant">{dictDetail.ai_analysis.language_and_localization || "Canais sem divergência de locale."}</p>
                    </div>
                  </div>

                  {/* Discrepâncias Entre Clientes */}
                  {dictDetail.ai_analysis.discrepancies.length > 0 && (
                    <div className="space-y-1.5 pt-2">
                      <h4 className="text-xs font-semibold text-outline uppercase tracking-wider flex items-center gap-1">
                        <span className="material-symbols-outlined text-[14px] text-amber-400">warning</span>
                        <span>Campos Divergentes Entre Clientes ({dictDetail.ai_analysis.discrepancies.length})</span>
                      </h4>
                      <div className="space-y-1.5 max-h-48 overflow-y-auto">
                        {dictDetail.ai_analysis.discrepancies.map((d, i) => (
                          <div key={i} className="p-2 rounded bg-surface-container-high/60 text-xs flex flex-col space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-bold text-on-surface">{d.field}</span>
                              <span className={`px-1.5 py-0.2 rounded text-[10px] font-semibold uppercase ${
                                d.impact === "high" ? "bg-error-container/40 text-error" : "bg-amber-950/40 text-amber-300"
                              }`}>
                                Impacto {d.impact}
                              </span>
                            </div>
                            <div className="flex flex-wrap gap-x-3 text-[11px]">
                              <span className="text-tertiary">
                                Presente em: {d.present_in_clients.join(", ") || "Nenhum"}
                              </span>
                              <span className="text-error">
                                Ausente em: {d.missing_in_clients.join(", ") || "Nenhum"}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recomendações */}
                  {dictDetail.ai_analysis.recommendations.length > 0 && (
                    <div className="p-3 rounded-lg bg-surface-container-low border border-outline/10 space-y-1.5">
                      <div className="text-xs font-semibold text-primary flex items-center gap-1">
                        <span className="material-symbols-outlined text-[15px]">lightbulb</span>
                        <span>Recomendações da IA para Curadoria</span>
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-xs text-on-surface-variant">
                        {dictDetail.ai_analysis.recommendations.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="flex justify-end pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={() => setSelectedDictTech(null)}
            >
              Fechar
            </button>
          </div>
        </div>
      </Modal>

      {/* Modal de Agendamentos Automatizados (Dicionário + Curadoria) */}
      <Modal
        isOpen={schedulesModalOpen}
        onClose={() => setSchedulesModalOpen(false)}
        title="Agendamentos Automatizados do D.A.N.T.E."
        maxWidth="640px"
      >
        <form onSubmit={handleSaveSchedules} className="space-y-4 text-on-surface">
          <p className="text-xs text-outline">
            Configure os dias e horários para execução das rotinas autônomas de coleta semanal de campos e curadoria de regras.
          </p>

          {schedulesSuccess && (
            <div className="p-2.5 rounded bg-tertiary-container/30 border border-tertiary/40 text-tertiary text-xs font-semibold flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[16px]">check_circle</span>
              <span>{schedulesSuccess}</span>
            </div>
          )}

          {schedulesData && (
            <div className="space-y-4">
              {/* Seção 1: Dicionário de Campos Semanal */}
              <div className="p-3.5 rounded-lg bg-surface-container-low border border-outline/10 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-semibold text-sm">
                    <span className="material-symbols-outlined text-primary text-[18px]">menu_book</span>
                    <span>Coleta Semanal de Campos (Dicionário)</span>
                  </div>
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={schedulesData.field_dictionary.enabled}
                      onChange={(e) =>
                        setSchedulesData({
                          ...schedulesData,
                          field_dictionary: {
                            ...schedulesData.field_dictionary,
                            enabled: e.target.checked,
                          },
                        })
                      }
                      className="rounded accent-primary"
                    />
                    <span>Ativo</span>
                  </label>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block text-outline mb-1 font-semibold">Dia da Semana</label>
                    <select
                      className="w-full p-2 rounded bg-surface-container-high text-on-surface border border-outline/20"
                      value={schedulesData.field_dictionary.day_of_week}
                      onChange={(e) =>
                        setSchedulesData({
                          ...schedulesData,
                          field_dictionary: {
                            ...schedulesData.field_dictionary,
                            day_of_week: parseInt(e.target.value, 10),
                          },
                        })
                      }
                    >
                      <option value={0}>Segunda-feira</option>
                      <option value={1}>Terça-feira</option>
                      <option value={2}>Quarta-feira</option>
                      <option value={3}>Quinta-feira</option>
                      <option value={4}>Sexta-feira</option>
                      <option value={5}>Sábado</option>
                      <option value={6}>Domingo</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-outline mb-1 font-semibold">Horário (HH:MM)</label>
                    <div className="flex items-center gap-1">
                      <input
                        type="number"
                        min={0}
                        max={23}
                        value={schedulesData.field_dictionary.hour}
                        onChange={(e) =>
                          setSchedulesData({
                            ...schedulesData,
                            field_dictionary: {
                              ...schedulesData.field_dictionary,
                              hour: parseInt(e.target.value, 10) || 0,
                            },
                          })
                        }
                        className="w-16 p-2 rounded bg-surface-container-high text-on-surface border border-outline/20 text-center font-mono"
                      />
                      <span>:</span>
                      <input
                        type="number"
                        min={0}
                        max={59}
                        value={schedulesData.field_dictionary.minute}
                        onChange={(e) =>
                          setSchedulesData({
                            ...schedulesData,
                            field_dictionary: {
                              ...schedulesData.field_dictionary,
                              minute: parseInt(e.target.value, 10) || 0,
                            },
                          })
                        }
                        className="w-16 p-2 rounded bg-surface-container-high text-on-surface border border-outline/20 text-center font-mono"
                      />
                      <span className="text-outline text-[11px] ml-1">UTC-3</span>
                    </div>
                  </div>
                </div>

                {schedulesData.next_field_dictionary_run_at && (
                  <p className="text-[11px] text-outline font-mono">
                    Próxima coleta: {new Date(schedulesData.next_field_dictionary_run_at).toLocaleString("pt-BR")}
                  </p>
                )}
              </div>

              {/* Seção 2: Curadoria de Regras Diária */}
              <div className="p-3.5 rounded-lg bg-surface-container-low border border-outline/10 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-semibold text-sm">
                    <span className="material-symbols-outlined text-secondary text-[18px]">verified</span>
                    <span>Curadoria de Regras (Diária)</span>
                  </div>
                  <label className="flex items-center gap-1.5 text-xs cursor-pointer">
                    <input
                      type="checkbox"
                      checked={schedulesData.curation.enabled}
                      onChange={(e) =>
                        setSchedulesData({
                          ...schedulesData,
                          curation: {
                            ...schedulesData.curation,
                            enabled: e.target.checked,
                          },
                        })
                      }
                      className="rounded accent-secondary"
                    />
                    <span>Ativo</span>
                  </label>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="block text-outline mb-1 font-semibold">Frequência</label>
                    <input
                      type="text"
                      disabled
                      value="Todos os dias"
                      className="w-full p-2 rounded bg-surface-container-high/50 text-outline border border-outline/20 cursor-not-allowed"
                    />
                  </div>

                  <div>
                    <label className="block text-outline mb-1 font-semibold">Horário Diário (HH:MM)</label>
                    <div className="flex items-center gap-1">
                      <input
                        type="number"
                        min={0}
                        max={23}
                        value={schedulesData.curation.hour}
                        onChange={(e) =>
                          setSchedulesData({
                            ...schedulesData,
                            curation: {
                              ...schedulesData.curation,
                              hour: parseInt(e.target.value, 10) || 0,
                            },
                          })
                        }
                        className="w-16 p-2 rounded bg-surface-container-high text-on-surface border border-outline/20 text-center font-mono"
                      />
                      <span>:</span>
                      <input
                        type="number"
                        min={0}
                        max={59}
                        value={schedulesData.curation.minute}
                        onChange={(e) =>
                          setSchedulesData({
                            ...schedulesData,
                            curation: {
                              ...schedulesData.curation,
                              minute: parseInt(e.target.value, 10) || 0,
                            },
                          })
                        }
                        className="w-16 p-2 rounded bg-surface-container-high text-on-surface border border-outline/20 text-center font-mono"
                      />
                      <span className="text-outline text-[11px] ml-1">UTC-3</span>
                    </div>
                  </div>
                </div>

                {schedulesData.next_curation_run_at && (
                  <p className="text-[11px] text-outline font-mono">
                    Próxima curadoria: {new Date(schedulesData.next_curation_run_at).toLocaleString("pt-BR")}
                  </p>
                )}
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={() => setSchedulesModalOpen(false)}
              disabled={schedulesSaving}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={schedulesSaving}
              className="px-4 py-1.5 rounded bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold disabled:opacity-50"
            >
              {schedulesSaving ? "Salvando..." : "Salvar Agendamentos"}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
