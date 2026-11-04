import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Modal } from "../components/Modal";
import { ConfirmModal } from "../components/ConfirmModal";
import {
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

  const loadOverview = useCallback(async () => {
    try {
      setError(null);
      const [data, tenantsData] = await Promise.all([
        api.getTechnologyOverview(),
        api.getTenants().catch(() => [] as TenantSummary[]),
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
                <th className="py-2.5 px-space-md w-44 font-semibold">Recorte SS_Groups</th>
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
    </div>
  );
};
