import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Modal } from "../components/Modal";
import {
  DeployStatus,
  HomologationOverview,
  RuleAlertEventKind,
  RuleHomologationAIEvaluation,
  RuleHomologationHistory,
  RuleSummary,
} from "../types";

const DEPLOY_OPTIONS: { value: DeployStatus | "all"; label: string }[] = [
  { value: "all", label: "Todos os estágios" },
  { value: "homolog", label: "Homologação (dev/stg)" },
  { value: "active", label: "Produção (prod)" },
  { value: "paused", label: "Pausadas" },
  { value: "unassigned", label: "Sem Contact Point" },
];

const WINDOW_OPTIONS: { hours: number; label: string; buckets: number }[] = [
  { hours: 6, label: "6 horas", buckets: 12 },
  { hours: 24, label: "24 horas", buckets: 12 },
  { hours: 48, label: "48 horas", buckets: 16 },
  { hours: 168, label: "7 dias", buckets: 14 },
];

const EVENT_KIND_META: Record<
  RuleAlertEventKind,
  { label: string; color: string; bg: string }
> = {
  firing: {
    label: "Disparo (Alerting)",
    color: "text-error",
    bg: "bg-error-container/30 text-error",
  },
  resolved: {
    label: "Normalizado",
    color: "text-tertiary",
    bg: "bg-tertiary/15 text-tertiary",
  },
  pending: {
    label: "Pending",
    color: "text-amber-400",
    bg: "bg-amber-500/15 text-amber-300",
  },
  error: {
    label: "Erro",
    color: "text-error",
    bg: "bg-error-container text-on-error-container",
  },
  nodata: {
    label: "Sem Dados (NoData)",
    color: "text-outline",
    bg: "bg-surface-container text-outline",
  },
  other: {
    label: "Transição",
    color: "text-secondary",
    bg: "bg-secondary/15 text-secondary",
  },
};

export const HomologationPage: React.FC = () => {
  const [overview, setOverview] = useState<HomologationOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  // Filtros da tabela principal
  const [search, setSearch] = useState("");
  const [selectedClient, setSelectedClient] = useState("all");
  const [selectedStatus, setSelectedStatus] = useState<DeployStatus | "all">("all");

  // Estado de movimentação de Contact Point
  const [movingUid, setMovingUid] = useState<string | null>(null);

  // Modal de gerenciamento de Contact Points (stg, dev, prod)
  const [cpModalOpen, setCpModalOpen] = useState(false);
  const [stageMappingForm, setStageMappingForm] = useState<{ stg: string; dev: string; prod: string }>({
    stg: "stg",
    dev: "dev",
    prod: "prod",
  });
  const [savingCpMapping, setSavingCpMapping] = useState(false);
  const [cpModalError, setCpModalError] = useState<string | null>(null);

  // Pop-up unificado de avaliação em homologação e confirmação de promoção para prod
  const [modalRule, setModalRule] = useState<RuleSummary | null>(null);
  const [modalMode, setModalMode] = useState<"inspect" | "promote">("inspect");
  const [windowHours, setWindowHours] = useState<number>(24);
  const [historyData, setHistoryData] = useState<RuleHomologationHistory | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [selectedBucketIdx, setSelectedBucketIdx] = useState<number | null>(null);
  const [eventFilter, setEventFilter] = useState<string>("all");
  const [aiEval, setAiEval] = useState<RuleHomologationAIEvaluation | null>(null);
  const [aiEvalLoading, setAiEvalLoading] = useState(false);
  const [aiEvalError, setAiEvalError] = useState<string | null>(null);

  const loadOverview = async () => {
    try {
      setError(null);
      const data = await api.getHomologation();
      setOverview(data);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "Erro ao carregar o estado de homologação."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadOverview();
  }, []);

  const fetchAIEval = useCallback(async (uid: string, hours: number) => {
    setAiEvalLoading(true);
    setAiEvalError(null);
    try {
      const data = await api.getRuleHomologationAIEvaluation(uid, hours);
      setAiEval(data);
    } catch (err: unknown) {
      setAiEvalError(
        err instanceof Error
          ? err.message
          : "Não foi possível carregar o parecer técnico da IA."
      );
    } finally {
      setAiEvalLoading(false);
    }
  }, []);

  const fetchRuleHistory = useCallback(async (uid: string, hours: number) => {
    setHistoryLoading(true);
    setHistoryError(null);
    const opt = WINDOW_OPTIONS.find((w) => w.hours === hours) || WINDOW_OPTIONS[1];
    try {
      const data = await api.getRuleHomologationHistory(uid, opt.hours, opt.buckets);
      setHistoryData(data);
    } catch (err: unknown) {
      setHistoryError(
        err instanceof Error
          ? err.message
          : "Não foi possível carregar o histórico de alertas desta regra."
      );
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const openHomologModal = (rule: RuleSummary, mode: "inspect" | "promote") => {
    setModalRule(rule);
    setModalMode(mode);
    setSelectedBucketIdx(null);
    setEventFilter("all");
    setHistoryData(null);
    setAiEval(null);
    setAiEvalError(null);
    void fetchRuleHistory(rule.uid, windowHours);
    void fetchAIEval(rule.uid, windowHours);
  };

  const closeHomologModal = () => {
    if (movingUid !== null) return;
    setModalRule(null);
    setHistoryData(null);
    setHistoryError(null);
    setSelectedBucketIdx(null);
    setAiEval(null);
    setAiEvalError(null);
  };

  const handleWindowChange = (hours: number) => {
    setWindowHours(hours);
    setSelectedBucketIdx(null);
    if (modalRule) {
      void fetchRuleHistory(modalRule.uid, hours);
      void fetchAIEval(modalRule.uid, hours);
    }
  };

  const rules = overview?.rules ?? [];

  const filteredRules = useMemo(() => {
    const term = search.trim().toLowerCase();
    return rules.filter((rule) => {
      const matchSearch =
        !term ||
        rule.title.toLowerCase().includes(term) ||
        rule.folder_title.toLowerCase().includes(term) ||
        (rule.contact_point || "").toLowerCase().includes(term) ||
        Object.entries(rule.labels).some(([k, v]) =>
          `${k}:${v}`.toLowerCase().includes(term)
        );

      const matchClient =
        selectedClient === "all" ||
        rule.folder_uid === selectedClient ||
        rule.folder_title === selectedClient;

      const matchStatus =
        selectedStatus === "all" || rule.deploy_status === selectedStatus;

      return matchSearch && matchClient && matchStatus;
    });
  }, [rules, search, selectedClient, selectedStatus]);

  const applyContactPoint = async (rule: RuleSummary, target: string) => {
    setMovingUid(rule.uid);
    setError(null);
    try {
      const result = await api.setRuleContactPoint(rule.uid, target);
      setFeedback(result.message);
      await loadOverview();
      setTimeout(() => setFeedback(null), 5000);
      setModalRule(null);
      setHistoryData(null);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "Erro ao alterar o Contact Point da regra."
      );
    } finally {
      setMovingUid(null);
    }
  };

  const requestMove = (rule: RuleSummary, target: string) => {
    if (target === "prod") {
      openHomologModal(rule, "promote");
      return;
    }
    void applyContactPoint(rule, target);
  };

  const histogramMax = useMemo(() => {
    if (!historyData || historyData.histogram.length === 0) return 1;
    return Math.max(...historyData.histogram.map((b) => b.total_events), 1);
  }, [historyData]);

  const displayedEvents = useMemo(() => {
    if (!historyData) return [];
    let list = historyData.events;

    if (
      selectedBucketIdx !== null &&
      historyData.histogram[selectedBucketIdx]
    ) {
      const bucket = historyData.histogram[selectedBucketIdx];
      const startMs = new Date(bucket.bucket_start).getTime();
      const endMs = new Date(bucket.bucket_end).getTime();
      list = list.filter((ev) => {
        const t = new Date(ev.timestamp).getTime();
        return selectedBucketIdx === historyData.histogram.length - 1
          ? t >= startMs && t <= endMs + 60000
          : t >= startMs && t < endMs;
      });
    }

    if (eventFilter !== "all") {
      list = list.filter((ev) => ev.kind === eventFilter);
    }

    return list;
  }, [historyData, selectedBucketIdx, eventFilter]);

  const metrics = overview?.metrics;

  return (
    <div className="flex flex-col w-full pb-16 space-y-space-lg text-on-surface">
      {/* Section 1: Header & Control Bar */}
      <div className="flex flex-col gap-space-sm pt-2">
        {/* Breadcrumb navigation */}
        <div className="flex items-center gap-2 font-code-sm text-code-sm">
          <span className="text-outline uppercase tracking-wider">DANTE</span>
          <span className="text-surface-variant">/</span>
          <span className="text-outline uppercase tracking-wider">ENGENHARIA DE DETECÇÃO</span>
          <span className="text-surface-variant">/</span>
          <span className="text-primary font-semibold tracking-wider uppercase">HOMOLOGAÇÃO</span>
        </div>

        {/* Title & Primary Top Action */}
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-space-md mt-1">
          <div className="space-y-1.5 max-w-4xl">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold flex items-center gap-space-sm">
              Homologação
              <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container text-secondary font-medium tracking-normal">
                Provisionamento de Alertas
              </span>
            </h1>
            <p className="font-body-md text-body-md text-on-surface-variant/90 leading-relaxed">
              Estado de deploy das regras de detecção definido pelo Contact Point amarrado a cada regra —{" "}
              <code className="px-1.5 py-0.5 rounded bg-surface-container-high font-code-sm text-code-sm text-tertiary">prod</code> = Ativa,{" "}
              <code className="px-1.5 py-0.5 rounded bg-surface-container-high font-code-sm text-code-sm text-secondary">dev/stg</code> = Homologação,{" "}
              <span className="text-outline font-medium">regra pausada</span> = Pausada. Clique em <span className="text-secondary font-medium">Homologação</span> ou em <span className="text-primary font-semibold">→ prod</span> para inspecionar o volume, o histograma e o histórico de alertas antes de promover para produção.
            </p>
          </div>
          <div className="flex items-center gap-space-sm self-start shrink-0">
            <button
              onClick={loadOverview}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-body-sm font-body-sm font-medium transition-colors shadow-sm disabled:opacity-50"
              disabled={loading}
              type="button"
            >
              <span className="material-symbols-outlined text-[16px] text-primary">sync</span>
              <span>Atualizar</span>
            </button>
          </div>
        </div>
      </div>

      {feedback && (
        <div className="p-space-sm rounded-lg bg-tertiary/15 border border-tertiary/30 text-tertiary text-sm flex justify-between items-center">
          <span>{feedback}</span>
          <button onClick={() => setFeedback(null)} className="text-xs text-on-surface underline">Fechar</button>
        </div>
      )}

      {error && (
        <div className="p-space-sm rounded-lg bg-error-container text-on-error-container text-sm">
          {error}
        </div>
      )}

      {/* Section 2: Operational KPI Grid (5 Cards) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-space-sm">
        {/* KPI 1 */}
        <div className="p-space-md rounded-xl bg-surface-container-low flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Regras sob Avaliação</span>
            <span className="material-symbols-outlined text-outline text-[16px]">rule</span>
          </div>
          <div className="my-space-sm">
            <div className="font-metric-display text-metric-display font-bold text-on-surface tracking-tight">{metrics?.total_rules ?? 0}</div>
          </div>
          <span className="font-body-sm text-body-sm text-outline leading-tight">Regras internas (âncora de grupo) não entram na contagem</span>
        </div>

        {/* KPI 2: Homologação */}
        <div className="p-space-md rounded-xl bg-surface-container-low flex flex-col justify-between shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-secondary/5 rounded-full blur-2xl pointer-events-none"></div>
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-secondary tracking-wider uppercase">Em Homologação (dev/stg)</span>
            <span className="material-symbols-outlined text-secondary text-[16px]">science</span>
          </div>
          <div className="my-space-sm flex items-baseline gap-2">
            <div className="font-metric-display text-metric-display font-bold text-secondary tracking-tight">{metrics?.homolog ?? 0}</div>
            <span className="font-code-sm text-code-sm text-secondary/80 font-medium">
              {metrics?.total_rules ? Math.round(((metrics.homolog) / metrics.total_rules) * 100) : 0}%
            </span>
          </div>
          <span className="font-body-sm text-body-sm text-outline leading-tight">Avaliando, sem impacto em produção</span>
        </div>

        {/* KPI 3: Ativas Prod */}
        <div className="p-space-md rounded-xl bg-surface-container-low flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Ativas (prod)</span>
            <span className="material-symbols-outlined text-tertiary text-[16px]">verified</span>
          </div>
          <div className="my-space-sm flex items-baseline gap-2">
            <div className="font-metric-display text-metric-display font-bold text-tertiary tracking-tight">{metrics?.active ?? 0}</div>
            <span className="font-code-sm text-code-sm text-outline">
              {metrics?.total_rules ? Math.round(((metrics.active) / metrics.total_rules) * 100) : 0}%
            </span>
          </div>
          <span className="font-body-sm text-body-sm text-outline leading-tight">Publicadas: alertas chegam ao time</span>
        </div>

        {/* KPI 4: Pausadas */}
        <div className="p-space-md rounded-xl bg-surface-container-low flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Pausadas</span>
            <span className="material-symbols-outlined text-outline text-[16px]">pause_circle</span>
          </div>
          <div className="my-space-sm">
            <div className="font-metric-display text-metric-display font-bold text-on-surface tracking-tight">{metrics?.paused ?? 0}</div>
          </div>
          <span className="font-body-sm text-body-sm text-outline leading-tight">Independente do Contact Point</span>
        </div>

        {/* KPI 5: Sem Contact Point */}
        <div className="p-space-md rounded-xl bg-surface-container-low flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Sem Contact Point</span>
            <span className="material-symbols-outlined text-outline text-[16px]">error_outline</span>
          </div>
          <div className="my-space-sm">
            <div className="font-metric-display text-metric-display font-bold text-on-surface tracking-tight">{metrics?.unassigned ?? 0}</div>
          </div>
          <span className="font-body-sm text-body-sm text-outline leading-tight">Ativas sem destino de alerta — corrigir</span>
        </div>
      </div>

      {/* Section 3: Contact Points & Stage Mapping */}
      <div className="p-space-md rounded-xl bg-surface-container-low flex flex-col lg:flex-row items-start lg:items-center justify-between gap-space-md shadow-sm">
        <div className="space-y-2">
          <div className="flex items-center gap-space-sm">
            <span className="material-symbols-outlined text-secondary text-[18px]">hub</span>
            <h2 className="font-label-uppercase text-label-uppercase tracking-wider uppercase text-on-surface font-semibold">
              Canais de Notificação (Contact Points) &amp; Estágios
            </h2>
          </div>
          <div className="flex flex-wrap items-center gap-2 font-code-sm text-code-sm text-on-surface-variant">
            <span className="text-outline">Associação atual:</span>
            <span className="text-on-surface font-semibold">stg → {overview?.stage_contact_points?.stg || "stg"}</span>
            <span className="text-surface-variant">|</span>
            <span className="text-on-surface font-semibold">dev → {overview?.stage_contact_points?.dev || "dev"}</span>
            <span className="text-surface-variant">|</span>
            <span className="text-primary font-semibold">prod → {overview?.stage_contact_points?.prod || "prod"}</span>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            {overview?.contact_points.map((cp) => (
              <span
                key={cp.name}
                className={`px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold ${
                  cp.tier === "prod"
                    ? "bg-tertiary-container/30 text-tertiary"
                    : cp.tier === "homolog"
                    ? "bg-surface-container-high text-secondary"
                    : "bg-surface-container text-on-surface-variant"
                }`}
              >
                {cp.name}
              </span>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-space-sm shrink-0 w-full lg:w-auto justify-end">
          <button
            onClick={() => {
              setCpModalError(null);
              setStageMappingForm({
                stg: overview?.stage_contact_points?.stg || "stg",
                dev: overview?.stage_contact_points?.dev || "dev",
                prod: overview?.stage_contact_points?.prod || "prod",
              });
              setCpModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm transition-colors shadow-sm"
            type="button"
          >
            <span className="material-symbols-outlined text-[16px] text-outline">tune</span>
            <span>Gerenciar Contact Points</span>
          </button>
        </div>
      </div>

      {/* Section 4: Summary Table by Client */}
      {overview && overview.clients.length > 0 && (
        <div className="rounded-xl bg-surface-container-low overflow-hidden shadow-sm">
          <div className="px-space-md py-space-sm bg-surface-container flex items-center justify-between">
            <div className="flex items-center gap-space-sm font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase font-semibold">
              <span className="material-symbols-outlined text-[16px]">folder_special</span>
              <span>Distribuição por Cliente &amp; Tenant</span>
            </div>
            <span className="font-code-sm text-code-sm text-outline">{overview.clients.length} pastas ativas</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left font-body-sm text-body-sm">
              <thead className="bg-surface-container-lowest font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">
                <tr>
                  <th className="px-space-md py-2.5 font-semibold">Cliente (Pasta)</th>
                  <th className="px-space-md py-2.5 font-semibold text-right">Total</th>
                  <th className="px-space-md py-2.5 font-semibold text-right">Homologação</th>
                  <th className="px-space-md py-2.5 font-semibold text-right">Ativas</th>
                  <th className="px-space-md py-2.5 font-semibold text-right">Pausadas</th>
                  <th className="px-space-md py-2.5 font-semibold text-right">Sem CP</th>
                </tr>
              </thead>
              <tbody className="divide-none">
                {overview.clients.map((client, idx) => {
                  const bg = idx % 2 === 1 ? "bg-surface-container-lowest/30" : "";
                  return (
                    <tr key={client.folder_uid} className={`hover:bg-surface-container-high transition-colors ${bg}`}>
                      <td className="px-space-md py-2.5 font-medium text-on-surface flex items-center gap-2">
                        <span className="material-symbols-outlined text-[16px] text-outline">folder</span>
                        <span className="font-code-md text-code-md font-semibold text-on-surface">{client.folder_title}</span>
                      </td>
                      <td className="px-space-md py-2.5 font-code-md text-code-md text-right text-on-surface">{client.total}</td>
                      <td className="px-space-md py-2.5 font-code-md text-code-md text-right text-secondary font-semibold">{client.homolog}</td>
                      <td className="px-space-md py-2.5 font-code-md text-code-md text-right text-tertiary">{client.active}</td>
                      <td className="px-space-md py-2.5 font-code-md text-code-md text-right text-outline">{client.paused}</td>
                      <td className={`px-space-md py-2.5 font-code-md text-code-md text-right ${client.unassigned > 0 ? "text-error font-semibold" : "text-outline"}`}>
                        {client.unassigned}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Section 5: Filter & Action Bar for Detailed Rules */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-space-sm bg-surface-container-low p-space-sm rounded-xl shadow-sm">
        <div className="flex-1 flex items-center gap-space-sm bg-surface-container-lowest px-3 py-1.5 rounded-lg">
          <span className="material-symbols-outlined text-outline text-[18px]">search</span>
          <input
            className="w-full bg-transparent font-body-sm text-body-sm text-on-surface placeholder:text-outline focus:outline-none"
            placeholder="Filtrar por regra, cliente ou contact point..."
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-outline">/</span>
        </div>

        <div className="flex flex-wrap items-center gap-space-sm justify-between md:justify-end">
          {/* Client Select */}
          <div className="relative">
            <select
              className="appearance-none bg-surface-container-lowest text-on-surface font-body-sm text-body-sm pl-3 pr-8 py-1.5 rounded-lg focus:outline-none cursor-pointer"
              value={selectedClient}
              onChange={(e) => setSelectedClient(e.target.value)}
            >
              <option value="all">Todos os Clientes</option>
              {(overview?.clients ?? []).map((c) => (
                <option key={c.folder_uid} value={c.folder_uid}>
                  {c.folder_title}
                </option>
              ))}
            </select>
            <span className="material-symbols-outlined text-[16px] text-outline absolute right-2 top-2 pointer-events-none">expand_more</span>
          </div>

          {/* Stage Select */}
          <div className="relative">
            <select
              className="appearance-none bg-surface-container-lowest text-on-surface font-body-sm text-body-sm pl-3 pr-8 py-1.5 rounded-lg focus:outline-none cursor-pointer"
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value as DeployStatus | "all")}
            >
              {DEPLOY_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <span className="material-symbols-outlined text-[16px] text-outline absolute right-2 top-2 pointer-events-none">expand_more</span>
          </div>

          {/* Item Counter */}
          <div className="px-2.5 py-1 rounded bg-surface-container font-code-sm text-code-sm text-outline flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[14px]">tune</span>
            <span className="font-semibold text-on-surface">{filteredRules.length}</span>
            <span>de {rules.length} regras</span>
          </div>
        </div>
      </div>

      {/* Section 6: High-Density Detection Rules Table */}
      <div className="rounded-xl bg-surface-container-low overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-body-sm text-body-sm min-w-[980px]">
            <thead className="bg-surface-container font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">
              <tr>
                <th className="px-space-md py-2.5 font-semibold">Regra de Detecção</th>
                <th className="px-space-md py-2.5 font-semibold">Cliente (Pasta)</th>
                <th className="px-space-md py-2.5 font-semibold">Tecnologia</th>
                <th className="px-space-md py-2.5 font-semibold">Contact Point</th>
                <th className="px-space-md py-2.5 font-semibold">Estado Geral</th>
                <th className="px-space-md py-2.5 font-semibold">Status de Deploy</th>
                <th className="px-space-md py-2.5 font-semibold text-right">Promover / Rebaixar</th>
              </tr>
            </thead>
            <tbody className="divide-none">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-space-md py-8 text-center text-outline">
                    Nenhuma regra de detecção encontrada com os filtros selecionados.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule, idx) => {
                  const isMoving = movingUid === rule.uid;
                  const isHomolog = rule.deploy_status === "homolog";
                  const isProd = rule.deploy_status === "active";
                  const rowBg = idx % 2 === 1 ? "bg-surface-container-lowest/30" : "";

                  return (
                    <tr key={rule.uid} className={`hover:bg-surface-container-high/80 transition-colors group ${rowBg}`}>
                      <td className="px-space-md py-2.5">
                        <div className="flex items-center gap-2">
                          <span className={`w-1.5 h-1.5 rounded-full ${isProd ? "bg-tertiary" : isHomolog ? "bg-secondary" : "bg-outline"}`}></span>
                          <span className="font-medium text-on-surface group-hover:text-primary transition-colors">
                            {rule.title}
                          </span>
                        </div>
                        <div className="text-outline font-code-sm text-code-sm pl-3.5">
                          rule_uid: {rule.uid}
                        </div>
                      </td>

                      <td className="px-space-md py-2.5">
                        <span className="font-code-sm text-code-sm px-2 py-0.5 rounded bg-surface-container text-on-surface font-medium">
                          {rule.folder_title}
                        </span>
                      </td>

                      <td className="px-space-md py-2.5">
                        <span className="font-body-sm text-body-sm text-on-surface-variant flex items-center gap-1">
                          <span className="material-symbols-outlined text-[14px] text-outline">dns</span>
                          {rule.labels["technology_name"] || rule.labels["technology"] || "—"}
                        </span>
                      </td>

                      <td className="px-space-md py-2.5">
                        {rule.contact_point ? (
                          <span className="font-code-sm text-code-sm font-semibold px-2 py-0.5 rounded bg-surface-container-highest text-secondary-fixed">
                            {rule.contact_point}
                          </span>
                        ) : (
                          <span className="text-error font-code-sm text-code-sm">sem CP</span>
                        )}
                      </td>

                      <td className="px-space-md py-2.5">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded font-code-sm text-code-sm ${
                          rule.state === "firing"
                            ? "bg-error-container/30 text-error"
                            : rule.state === "pending"
                            ? "bg-amber-500/15 text-amber-300"
                            : "bg-tertiary-container/20 text-tertiary"
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${rule.state === "firing" ? "bg-error" : rule.state === "pending" ? "bg-amber-400" : "bg-tertiary"}`}></span>
                          {rule.state === "firing" ? "Firing" : rule.state === "pending" ? "Pending" : "Normal"}
                        </span>
                      </td>

                      <td className="px-space-md py-2.5">
                        <button
                          type="button"
                          onClick={isHomolog ? () => openHomologModal(rule, "inspect") : undefined}
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-code-sm text-code-sm font-medium ${
                            isProd
                              ? "bg-tertiary/15 text-tertiary"
                              : isHomolog
                              ? "bg-secondary-container/20 text-secondary hover:bg-secondary-container/30 cursor-pointer"
                              : "bg-surface-container text-outline"
                          }`}
                        >
                          {isHomolog && (
                            <span className="relative flex h-1.5 w-1.5">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-secondary"></span>
                            </span>
                          )}
                          <span>
                            {isProd
                              ? `Ativa (${rule.contact_point || "prod"})`
                              : isHomolog
                              ? `Homologação (${rule.contact_point || "dev"})`
                              : rule.is_paused
                              ? "Pausada"
                              : "Sem CP"}
                          </span>
                        </button>
                      </td>

                      <td className="px-space-md py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1.5 whitespace-nowrap shrink-0">
                          <button
                            onClick={() => openHomologModal(rule, "inspect")}
                            className="p-1.5 rounded bg-surface-container hover:bg-surface-bright text-on-surface-variant hover:text-on-surface transition-colors"
                            title="Avaliar"
                            type="button"
                          >
                            <span className="material-symbols-outlined text-[16px] text-primary">auto_awesome</span>
                          </button>

                          {/* Estágios rápidos */}
                          {rule.contact_point !== "stg" && (
                            <button
                              onClick={() => requestMove(rule, "stg")}
                              disabled={isMoving}
                              className="px-2 py-0.5 rounded bg-surface-container hover:bg-surface-container-high text-xs text-outline hover:text-on-surface"
                              title="Mover para stg"
                            >
                              stg
                            </button>
                          )}

                          {rule.contact_point !== "dev" && (
                            <button
                              onClick={() => requestMove(rule, "dev")}
                              disabled={isMoving}
                              className="px-2 py-0.5 rounded bg-surface-container hover:bg-surface-container-high text-xs text-outline hover:text-on-surface"
                              title="Mover para dev"
                            >
                              dev
                            </button>
                          )}

                          {rule.contact_point !== "prod" && (
                            <button
                              onClick={() => requestMove(rule, "prod")}
                              disabled={isMoving}
                              className="px-2.5 py-1 rounded bg-primary-container hover:bg-primary text-on-primary font-code-sm text-code-sm font-semibold inline-flex items-center gap-1 transition-all active:scale-95 shadow-sm whitespace-nowrap shrink-0"
                              type="button"
                            >
                              <span className="whitespace-nowrap">→ prod</span>
                              <span className="material-symbols-outlined text-[14px]">rocket_launch</span>
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de Histórico e Promoção */}
      <Modal
        isOpen={Boolean(modalRule)}
        onClose={closeHomologModal}
        maxWidth="980px"
        title={modalRule ? `Avaliação de Regra — ${modalRule.title}` : "Avaliação"}
      >
        {modalRule && (
          <div className="flex flex-col gap-space-md text-on-surface">
            <div className="flex flex-wrap items-center justify-between gap-space-sm p-space-sm bg-surface-container-low rounded-lg">
              <div>
                <span className="text-xs text-outline uppercase block">Regra &amp; Cliente</span>
                <span className="font-semibold text-on-surface">{modalRule.title}</span>
                <span className="text-xs text-secondary ml-2 font-mono">({modalRule.folder_title})</span>
              </div>
              <div className="flex items-center gap-1 bg-surface-container-lowest p-1 rounded-lg">
                {WINDOW_OPTIONS.map((w) => (
                  <button
                    key={w.hours}
                    type="button"
                    onClick={() => handleWindowChange(w.hours)}
                    className={`px-2.5 py-1 rounded font-code-sm text-xs transition-colors ${
                      windowHours === w.hours
                        ? "bg-primary-container text-on-primary font-semibold"
                        : "text-outline hover:text-on-surface"
                    }`}
                  >
                    {w.label}
                  </button>
                ))}
              </div>
            </div>

            {historyLoading ? (
              <div className="py-12 text-center text-outline">Carregando telemetria e disparos...</div>
            ) : historyError ? (
              <div className="p-space-sm rounded bg-error-container text-on-error-container text-sm">{historyError}</div>
            ) : historyData ? (
              <div className="space-y-space-md">
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-space-sm">
                  <div className="bg-surface-container-low p-space-sm rounded-lg">
                    <span className="text-xs text-outline uppercase">Disparos (Firing)</span>
                    <p className="text-xl font-bold text-error mt-1">{historyData.firing_events_count}</p>
                  </div>
                  <div className="bg-surface-container-low p-space-sm rounded-lg">
                    <span className="text-xs text-outline uppercase">Normalizados</span>
                    <p className="text-xl font-bold text-tertiary mt-1">{historyData.resolved_events_count}</p>
                  </div>
                  <div className="bg-surface-container-low p-space-sm rounded-lg">
                    <span className="text-xs text-outline uppercase">Alertas Ativos</span>
                    <p className="text-xl font-bold text-secondary mt-1">{historyData.active_alerts_count}</p>
                  </div>
                  <div className="bg-surface-container-low p-space-sm rounded-lg">
                    <span className="text-xs text-outline uppercase">Janela Analisada</span>
                    <p className="text-xl font-bold text-on-surface mt-1">{historyData.window_hours}h</p>
                  </div>
                </div>

                {/* Parecer Técnico da IA sobre os Alertas e Homologação */}
                <div className="rounded-xl border border-sky-500/30 bg-sky-950/20 p-space-md shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-2 mb-3 border-b border-sky-500/20">
                    <div className="flex items-center gap-2 text-sky-300">
                      <span className="material-symbols-outlined text-[20px] text-sky-400">auto_awesome</span>
                      <span className="font-semibold text-sm uppercase tracking-wider">
                        Parecer Técnico da IA {aiEval?.ai_model ? `(${aiEval.ai_model})` : ""}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {aiEval?.verdict && (
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-xs font-semibold ${
                            aiEval.verdict.toLowerCase().includes("pronta") ||
                            aiEval.verdict.toLowerCase().includes("estável")
                              ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                              : aiEval.verdict.toLowerCase().includes("flood") ||
                                aiEval.verdict.toLowerCase().includes("alto volume")
                              ? "bg-error/20 text-error border border-error/30"
                              : "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                          }`}
                        >
                          {aiEval.verdict}
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => modalRule && void fetchAIEval(modalRule.uid, windowHours)}
                        disabled={aiEvalLoading}
                        className="px-2 py-0.5 rounded bg-sky-900/50 hover:bg-sky-800 text-sky-200 text-xs flex items-center gap-1 transition-colors"
                        title="Reavaliar alertas com IA"
                      >
                        <span className={`material-symbols-outlined text-[14px] ${aiEvalLoading ? "animate-spin" : ""}`}>
                          refresh
                        </span>
                        <span>Reavaliar</span>
                      </button>
                    </div>
                  </div>

                  {aiEvalLoading ? (
                    <div className="flex items-center gap-3 py-6 justify-center text-sky-200/80">
                      <span className="material-symbols-outlined text-[22px] animate-pulse text-sky-400">auto_awesome</span>
                      <span className="text-xs">IA analisando telemetria, incidentes reais e calibrando parecer técnico...</span>
                    </div>
                  ) : aiEvalError ? (
                    <div className="p-2.5 rounded bg-error-container/40 text-on-error-container text-xs">
                      {aiEvalError}
                    </div>
                  ) : aiEval ? (
                    <div className="space-y-3">
                      <p className="text-xs text-sky-100/90 leading-relaxed font-body-sm">
                        {aiEval.summary}
                      </p>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-space-sm pt-1">
                        {/* 1. Análise de Possíveis Incidentes Reais */}
                        <div className="p-2.5 rounded-lg bg-surface-container-low/70 border border-outline-variant/20">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-error mb-1">
                            <span className="material-symbols-outlined text-[15px]">security</span>
                            <span>Análise de Possíveis Incidentes Reais</span>
                          </div>
                          <p className="text-xs text-on-surface-variant leading-relaxed">
                            {aiEval.threat_analysis}
                          </p>
                        </div>

                        {/* 2. Ações para Reduzir Falsos Positivos e Floods */}
                        <div className="p-2.5 rounded-lg bg-surface-container-low/70 border border-outline-variant/20">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-300 mb-1">
                            <span className="material-symbols-outlined text-[15px]">filter_alt</span>
                            <span>Ações para Reduzir Falsos Positivos e Floods</span>
                          </div>
                          <ul className="text-xs text-on-surface-variant space-y-1 list-disc list-inside">
                            {aiEval.noise_reduction_actions.map((act, i) => (
                              <li key={i}>{act}</li>
                            ))}
                          </ul>
                        </div>

                        {/* 3. Pontos de Melhoria */}
                        <div className="p-2.5 rounded-lg bg-surface-container-low/70 border border-outline-variant/20">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-secondary mb-1">
                            <span className="material-symbols-outlined text-[15px]">tune</span>
                            <span>Pontos de Melhoria na Regra</span>
                          </div>
                          <ul className="text-xs text-on-surface-variant space-y-1 list-disc list-inside">
                            {aiEval.improvements.map((imp, i) => (
                              <li key={i}>{imp}</li>
                            ))}
                          </ul>
                        </div>

                        {/* 4. Calibração para Produção / Calibração Contínua */}
                        <div className="p-2.5 rounded-lg bg-surface-container-low/70 border border-outline-variant/20">
                          <div className="flex items-center gap-1.5 text-xs font-semibold text-tertiary mb-1">
                            <span className="material-symbols-outlined text-[15px]">
                              {aiEval.is_in_production ? "verified" : "rocket_launch"}
                            </span>
                            <span>
                              {aiEval.is_in_production
                                ? "Calibração e Monitoramento em Produção"
                                : "Calibração para Virar para Produção"}
                            </span>
                          </div>
                          <p className="text-xs text-on-surface-variant leading-relaxed">
                            {aiEval.calibration_for_prod}
                          </p>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>

                {/* Histograma em Barras */}
                <div className="bg-surface-container-low p-space-md rounded-lg">
                  <span className="font-label-uppercase text-xs text-outline uppercase block mb-3">
                    Histograma de Disparos por Intervalo de Tempo
                  </span>
                  <div className="flex items-end gap-1 h-24 pt-4 border-b border-outline-variant/30">
                    {historyData.histogram.map((b, idx) => {
                      const heightPct = Math.round((b.total_events / histogramMax) * 100);
                      const isSelected = selectedBucketIdx === idx;
                      return (
                        <div
                          key={idx}
                          onClick={() => setSelectedBucketIdx(isSelected ? null : idx)}
                          className="flex-1 flex flex-col items-center justify-end h-full cursor-pointer group"
                        >
                          <div
                            className={`w-full rounded-t transition-all ${
                              isSelected
                                ? "bg-primary-container"
                                : b.firing_count > 0
                                ? "bg-error/70 group-hover:bg-error"
                                : "bg-surface-container-highest group-hover:bg-outline"
                            }`}
                            style={{ height: `${Math.max(4, heightPct)}%` }}
                            title={`${b.total_events} eventos (${b.firing_count} firing)`}
                          ></div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Eventos recentes */}
                <div>
                  <div className="flex justify-between items-center mb-2">
                    <span className="font-label-uppercase text-xs text-outline uppercase">
                      Eventos Detalhados ({displayedEvents.length})
                    </span>
                    <select
                      className="bg-surface-container-lowest text-xs text-on-surface px-2 py-1 rounded"
                      value={eventFilter}
                      onChange={(e) => setEventFilter(e.target.value)}
                    >
                      <option value="all">Todos os tipos</option>
                      <option value="firing">Apenas Firing</option>
                      <option value="resolved">Apenas Resolvidos</option>
                    </select>
                  </div>
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {displayedEvents.length === 0 ? (
                      <div className="text-center py-4 text-xs text-outline">Nenhum evento no período selecionado.</div>
                    ) : (
                      displayedEvents.map((ev, idx) => (
                        <div key={idx} className="flex justify-between items-center p-2 rounded bg-surface-container-low text-xs">
                          <span className={`px-2 py-0.5 rounded font-code-sm ${EVENT_KIND_META[ev.kind]?.bg || "bg-surface-container"}`}>
                            {EVENT_KIND_META[ev.kind]?.label || ev.kind}
                          </span>
                          <span className="font-mono text-outline">{new Date(ev.timestamp).toLocaleTimeString("pt-BR")}</span>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            ) : null}

            {modalMode === "promote" && (
              <div className="p-space-md rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 text-sm">
                <strong>Confirmar virada para Produção (prod):</strong>
                <p className="text-xs text-outline mt-1">
                  A regra {modalRule.title} passará a notificar diretamente o time de SOC no contact point {overview?.stage_contact_points?.prod || "prod"}.
                </p>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-sm"
                onClick={closeHomologModal}
                disabled={movingUid !== null}
              >
                {modalMode === "promote" ? "Cancelar" : "Fechar"}
              </button>
              {modalMode === "inspect" && (modalRule.contact_point || "").toLowerCase() !== "prod" && (
                <button
                  type="button"
                  className="px-4 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold whitespace-nowrap shrink-0 inline-flex items-center gap-1.5"
                  onClick={() => setModalMode("promote")}
                >
                  <span className="whitespace-nowrap">→ prod (Promover para produção)</span>
                </button>
              )}
              {modalMode === "promote" && (
                <button
                  type="button"
                  className="px-4 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold whitespace-nowrap shrink-0"
                  onClick={() => void applyContactPoint(modalRule, "prod")}
                  disabled={movingUid !== null}
                >
                  <span className="whitespace-nowrap">{movingUid === modalRule.uid ? "Promovendo..." : "Confirmar e Virar para Produção"}</span>
                </button>
              )}
            </div>
          </div>
        )}
      </Modal>

      {/* Modal de Mapeamento de Contact Points */}
      <Modal
        isOpen={cpModalOpen}
        onClose={() => { if (!savingCpMapping) setCpModalOpen(false); }}
        title="Gerenciar Contact Points dos Estágios"
        maxWidth="520px"
      >
        <div className="flex flex-col gap-space-md text-on-surface">
          <p className="text-xs text-outline">
            Selecione qual Contact Point (canal) corresponde a cada estágio de deploy (stg, dev e prod).
          </p>

          {cpModalError && (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">{cpModalError}</div>
          )}

          <div className="space-y-3">
            <div>
              <label className="text-xs text-outline uppercase block mb-1">Estágio Staging (stg)</label>
              <select
                className="w-full bg-surface-container-lowest text-on-surface p-2 rounded text-sm"
                value={stageMappingForm.stg}
                onChange={(e) => setStageMappingForm({ ...stageMappingForm, stg: e.target.value })}
              >
                {overview?.contact_points.map((cp) => (
                  <option key={`stg-${cp.name}`} value={cp.name}>{cp.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-outline uppercase block mb-1">Estágio Desenvolvimento (dev)</label>
              <select
                className="w-full bg-surface-container-lowest text-on-surface p-2 rounded text-sm"
                value={stageMappingForm.dev}
                onChange={(e) => setStageMappingForm({ ...stageMappingForm, dev: e.target.value })}
              >
                {overview?.contact_points.map((cp) => (
                  <option key={`dev-${cp.name}`} value={cp.name}>{cp.name}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-outline uppercase block mb-1">Estágio Produção (prod)</label>
              <select
                className="w-full bg-surface-container-lowest text-on-surface p-2 rounded text-sm"
                value={stageMappingForm.prod}
                onChange={(e) => setStageMappingForm({ ...stageMappingForm, prod: e.target.value })}
              >
                {overview?.contact_points.map((cp) => (
                  <option key={`prod-${cp.name}`} value={cp.name}>{cp.name}</option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded-lg bg-surface-container-high text-on-surface text-sm"
              onClick={() => setCpModalOpen(false)}
              disabled={savingCpMapping}
            >
              Cancelar
            </button>
            <button
              type="button"
              className="px-4 py-1.5 rounded-lg bg-primary-container text-on-primary text-sm font-semibold"
              disabled={savingCpMapping}
              onClick={async () => {
                setSavingCpMapping(true);
                setCpModalError(null);
                try {
                  await api.updateStageContactPoints(stageMappingForm);
                  await loadOverview();
                  setCpModalOpen(false);
                } catch (err: unknown) {
                  setCpModalError(err instanceof Error ? err.message : "Erro ao atualizar mapeamento.");
                } finally {
                  setSavingCpMapping(false);
                }
              }}
            >
              {savingCpMapping ? "Salvando..." : "Salvar Mapeamento"}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
