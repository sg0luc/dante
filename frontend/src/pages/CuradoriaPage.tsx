import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { ConfirmModal } from "../components/ConfirmModal";
import { Modal } from "../components/Modal";
import { PERIMETER_CONFIG } from "./TechnologiesPage";
import {
  CuratedRuleItem,
  CurationOverviewResponse,
  CurationProgressState,
  ImplementCuratedRuleResponse,
} from "../types";

interface CompatibilityMeta {
  label: string;
  sublabel: string;
  fullLabel: string;
  bg: string;
  border: string;
  color: string;
  dot: string;
  icon: string;
}

function getCompatibilityMeta(pct: number): CompatibilityMeta {
  const displayLabel = pct % 1 !== 0 ? `${pct.toFixed(1)}%` : `${pct.toFixed(0)}%`;
  if (pct >= 95) {
    return {
      label: displayLabel,
      sublabel: "Excelente (≥ 80%)",
      fullLabel: `${displayLabel} de Compatibilidade (Excelente)`,
      bg: "bg-emerald-500/15",
      border: "border-emerald-500/30",
      color: "text-emerald-400",
      dot: "bg-emerald-400",
      icon: "verified",
    };
  }
  if (pct >= 90) {
    return {
      label: displayLabel,
      sublabel: "Alta (≥ 80%)",
      fullLabel: `${displayLabel} de Compatibilidade (Alta)`,
      bg: "bg-teal-500/15",
      border: "border-teal-500/30",
      color: "text-teal-400",
      dot: "bg-teal-400",
      icon: "task_alt",
    };
  }
  if (pct >= 80) {
    return {
      label: displayLabel,
      sublabel: "Qualificada (≥ 80%)",
      fullLabel: `${displayLabel} de Compatibilidade (Aprovada)`,
      bg: "bg-sky-500/15",
      border: "border-sky-500/30",
      color: "text-sky-400",
      dot: "bg-sky-400",
      icon: "check_circle",
    };
  }
  return {
    label: displayLabel,
    sublabel: "Incompatível (< 80%)",
    fullLabel: `${displayLabel} Incompatível`,
    bg: "bg-error/15",
    border: "border-error/30",
    color: "text-error",
    dot: "bg-error",
    icon: "cancel",
  };
}

const SEVERITY_COLORS: Record<string, { bg: string; text: string }> = {
  critical: { bg: "bg-error-container text-on-error-container", text: "text-error" },
  high: { bg: "bg-amber-500/15 text-amber-300", text: "text-amber-400" },
  medium: { bg: "bg-yellow-500/15 text-yellow-300", text: "text-yellow-400" },
  low: { bg: "bg-secondary/15 text-secondary", text: "text-secondary" },
};

function formatDateTimePt(iso: string | null | undefined): string {
  if (!iso) return "—";
  const parsed = new Date(iso);
  if (Number.isNaN(parsed.getTime())) return iso;
  return parsed.toLocaleString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export const CuradoriaPage: React.FC = () => {
  const [overview, setOverview] = useState<CurationOverviewResponse | null>(null);
  const [progress, setProgress] = useState<CurationProgressState | null>(null);
  const [showLogs, setShowLogs] = useState<boolean>(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [runningCycle, setRunningCycle] = useState(false);
  const [feedbackBanner, setFeedbackBanner] = useState<{
    type: "success" | "info" | "error";
    text: string;
  } | null>(null);

  // Filtros
  const [search, setSearch] = useState("");
  const [qualityFilter, setQualityFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [techFilter, setTechFilter] = useState<string>("all");
  const [perimeterFilter, setPerimeterFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("active");
  const [viewTab, setViewTab] = useState<"qualified" | "discarded">("qualified");
  const [stoppingCycle, setStoppingCycle] = useState(false);

  // Paginação
  const [page, setPage] = useState(1);
  const pageSize = 15;

  // Modal de Detalhes completos da Regra Curada
  const [detailRule, setDetailRule] = useState<CuratedRuleItem | null>(null);

  // Fluxo do botão "Implementar" + Pop-up de Confirmação
  const [ruleToImplement, setRuleToImplement] = useState<CuratedRuleItem | null>(null);
  const [selectedClientUids, setSelectedClientUids] = useState<string[]>([]);
  const [confirmPopupOpen, setConfirmPopupOpen] = useState(false);
  const [implementing, setImplementing] = useState(false);
  const [lastImplementationResult, setLastImplementationResult] =
    useState<ImplementCuratedRuleResponse | null>(null);

  // Limpar Curadoria
  const [isClearModalOpen, setIsClearModalOpen] = useState(false);
  const [clearing, setClearing] = useState(false);
  const isMountedRef = React.useRef(true);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  const loadCuration = useCallback(async () => {
    try {
      setError(null);
      const data = await api.getCurationOverview(true);
      if (isMountedRef.current) {
        setOverview(data);
        if (data.progress) {
          setProgress(data.progress);
          if (data.progress.running) {
            setRunningCycle(true);
          }
        }
      }
    } catch (err: unknown) {
      if (isMountedRef.current) {
        setError(
          err instanceof Error ? err.message : "Falha ao carregar a Curadoria de Regras."
        );
      }
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    loadCuration();
  }, [loadCuration]);

  // Polling em tempo real do progresso enquanto a curadoria estiver rodando
  // Assim que a curadoria atingir 100% ou concluir (running=false), a tabela de regras
  // é populada AUTOMATICAMENTE com os novos dados sem requerer F5 ou reload de página.
  useEffect(() => {
    const isActivelyRunning = runningCycle || Boolean(progress?.running);
    if (!isActivelyRunning) return;

    let pollInterval: number | null = null;
    let isHandlingFinish = false;

    const onCycleCompleted = async () => {
      if (isHandlingFinish) return;
      isHandlingFinish = true;
      if (pollInterval !== null) {
        window.clearInterval(pollInterval);
        pollInterval = null;
      }
      try {
        const freshOverview = await api.getCurationOverview(true);
        if (isMountedRef.current) {
          setOverview(freshOverview);
          if (freshOverview.progress) {
            setProgress(freshOverview.progress);
          }
          setRunningCycle(false);
          setFeedbackBanner({
            type: "success",
            text: "Ciclo de curadoria concluído com sucesso. Tabela de regras atualizada automaticamente.",
          });
        }
      } catch {
        if (isMountedRef.current) {
          setRunningCycle(false);
        }
      }
    };

    pollInterval = window.setInterval(async () => {
      if (isHandlingFinish) return;
      try {
        const liveProg = await api.getCurationProgress();
        if (!isMountedRef.current || isHandlingFinish) return;
        setProgress(liveProg);
        if (!liveProg.running || liveProg.percent === 100 || Boolean(liveProg.finished_at)) {
          await onCycleCompleted();
        }
      } catch {
        // Ignora erro transitório de rede durante polling
      }
    }, 550);

    return () => {
      if (pollInterval !== null) {
        window.clearInterval(pollInterval);
      }
    };
  }, [runningCycle, progress?.running]);

  const handleRunCurationNow = async () => {
    setRunningCycle(true);
    setFeedbackBanner(null);
    try {
      const res = await api.runCuration(true);
      if (res.progress) {
        setProgress(res.progress);
        if (!res.progress.running) {
          setRunningCycle(false);
          setFeedbackBanner({ type: "success", text: res.message });
          await loadCuration();
        }
      } else {
        setRunningCycle(false);
        setFeedbackBanner({ type: "success", text: res.message });
        await loadCuration();
      }
    } catch (err: unknown) {
      setRunningCycle(false);
      setFeedbackBanner({
        type: "error",
        text:
          err instanceof Error
            ? err.message
            : "Erro ao executar o ciclo de curadoria.",
      });
    }
  };

  const handleStopCurationNow = async () => {
    setStoppingCycle(true);
    try {
      const res = await api.stopCuration();
      setProgress(res.progress);
      setRunningCycle(false);
      setFeedbackBanner({
        type: "info",
        text: res.message,
      });
      await loadCuration();
    } catch (err: unknown) {
      setFeedbackBanner({
        type: "error",
        text:
          err instanceof Error
            ? err.message
            : "Erro ao interromper a curadoria.",
      });
    } finally {
      setStoppingCycle(false);
    }
  };

  const handleToggleIgnoreRule = async (rule: CuratedRuleItem) => {
    const nextIgnored = !rule.ignored;
    try {
      const updated = await api.ignoreCuratedRule(rule.id, nextIgnored);
      setOverview((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          rules: prev.rules.map((r) => (r.id === rule.id ? updated : r)),
          metrics: {
            ...prev.metrics,
            ignored_count: Math.max(0, (prev.metrics.ignored_count || 0) + (nextIgnored ? 1 : -1)),
          },
        };
      });
      setFeedbackBanner({
        type: "info",
        text: nextIgnored
          ? `Regra "${rule.title}" foi marcada como ignorada.`
          : `Regra "${rule.title}" foi restaurada com sucesso.`,
      });
    } catch (err: unknown) {
      setFeedbackBanner({
        type: "error",
        text:
          err instanceof Error
            ? err.message
            : "Falha ao alterar estado da regra.",
      });
    }
  };

  const handleConfirmClearCuration = async () => {
    try {
      setClearing(true);
      setError(null);
      setRunningCycle(false);
      const res = await api.clearCuration();
      setIsClearModalOpen(false);
      setRunningCycle(false);
      const idleProgress: CurationProgressState = {
        running: false,
        percent: 0,
        phase: "Aguardando execução",
        current_action: "Curadoria limpa e zerada. Clique em 'Iniciar' ou aguarde o agendamento diário.",
        current_client_name: null,
        current_client_uid: null,
        current_client_index: 0,
        total_clients: 0,
        current_rule_title: null,
        current_rule_source: null,
        current_rule_index: 0,
        total_rules: 0,
        current_window_label: null,
        current_window_step: 0,
        total_window_steps: 5,
        ai_curated_count: 0,
        heuristic_curated_count: 0,
        ai_provider_used: null,
        ai_model_used: null,
        windows_evaluated_current: [],
        timed_out_clients: [],
        recent_logs: [],
        started_at: null,
        updated_at: new Date().toISOString(),
        finished_at: null,
      };
      setProgress(idleProgress);
      setOverview((prev) =>
        prev
          ? {
              ...prev,
              rules: [],
              total_curated_rules: 0,
              pending_rules_count: 0,
              implemented_rules_count: 0,
              progress: idleProgress,
            }
          : prev
      );
      setDetailRule(null);
      setRuleToImplement(null);
      setPage(1);
      setFeedbackBanner({
        type: "success",
        text: res.message || "Curadoria limpa e resetada com sucesso.",
      });
      const fresh = await api.getCurationOverview(true);
      setOverview(fresh);
      if (fresh.progress) {
        setProgress(fresh.progress);
        if (!fresh.progress.running) {
          setRunningCycle(false);
        }
      }
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : "Falha ao limpar a curadoria de regras."
      );
    } finally {
      setClearing(false);
    }
  };

  const technologyOptions = useMemo(() => {
    const map = new Map<string, string>();
    (overview?.rules || []).forEach((r) => {
      if (!map.has(r.technology)) {
        map.set(r.technology, r.technology_name || r.technology);
      }
    });
    return Array.from(map.entries())
      .map(([slug, name]) => ({ slug, name }))
      .sort((a, b) => a.name.localeCompare(b.name, "pt-BR"));
  }, [overview]);

  const filteredRules = useMemo(() => {
    const isDiscardedView = viewTab === "discarded" || statusFilter === "discarded";
    const list = isDiscardedView ? (overview?.discarded_rules || []) : (overview?.rules || []);
    return list.filter((item) => {
      const q = search.trim().toLowerCase();
      const matchSearch =
        !q ||
        item.title.toLowerCase().includes(q) ||
        item.original_title.toLowerCase().includes(q) ||
        item.mitre_technique.toLowerCase().includes(q) ||
        item.mitre_tactic.toLowerCase().includes(q) ||
        item.technology_name.toLowerCase().includes(q) ||
        item.source_name.toLowerCase().includes(q) ||
        item.logql_query.toLowerCase().includes(q) ||
        item.client_evaluations.some((ev) =>
          ev.client_name.toLowerCase().includes(q)
        );

      const compatVal = item.field_compatibility_pct ?? 100;
      let matchQuality = true;
      if (isDiscardedView) {
        matchQuality = true;
      } else if (qualityFilter === "high") {
        matchQuality = compatVal >= 95;
      } else if (qualityFilter === "medium") {
        matchQuality = compatVal >= 80 && compatVal < 95;
      } else if (qualityFilter === "all") {
        matchQuality = compatVal >= 80;
      }

      const matchSource =
        sourceFilter === "all" || item.source_id === sourceFilter;
      const matchTech =
        techFilter === "all" || item.technology === techFilter;
      const matchPerimeter =
        perimeterFilter === "all" || item.perimeter === perimeterFilter;
      const isIgnored = Boolean(item.ignored);
      let matchStatus = true;
      if (isDiscardedView) {
        matchStatus = true;
      } else if (statusFilter === "active") {
        matchStatus = !isIgnored;
      } else if (statusFilter === "pending") {
        matchStatus = !isIgnored && !item.implemented;
      } else if (statusFilter === "implemented") {
        matchStatus = !isIgnored && item.implemented;
      } else if (statusFilter === "ignored") {
        matchStatus = isIgnored;
      } else if (statusFilter === "all") {
        matchStatus = true;
      }

      return (
        matchSearch &&
        matchQuality &&
        matchSource &&
        matchTech &&
        matchPerimeter &&
        matchStatus
      );
    }).sort((a, b) => {
      // Ordenação rigorosa: primeiro as mais próximas de 100% (decrescente)
      const diffCompat = (b.field_compatibility_pct ?? 0) - (a.field_compatibility_pct ?? 0);
      if (Math.abs(diffCompat) > 0.001) return diffCompat;
      const diffHits = (b.total_matched_results ?? 0) - (a.total_matched_results ?? 0);
      if (diffHits !== 0) return diffHits;
      return a.title.localeCompare(b.title, "pt-BR");
    });
  }, [overview, search, qualityFilter, sourceFilter, techFilter, perimeterFilter, statusFilter]);

  const paginatedRules = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredRules.slice(start, start + pageSize);
  }, [filteredRules, page, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filteredRules.length / pageSize));

  const highCompatCount = useMemo(() => {
    return (overview?.rules || []).filter((r) => (r.field_compatibility_pct ?? 100) >= 95).length;
  }, [overview]);

  const mediumCompatCount = useMemo(() => {
    return (overview?.rules || []).filter((r) => {
      const p = r.field_compatibility_pct ?? 100;
      return p >= 80 && p < 95;
    }).length;
  }, [overview]);

  const handleOpenImplementModal = (rule: CuratedRuleItem) => {
    setRuleToImplement(rule);
    const recommended = rule.client_evaluations
      .filter((ev) => (ev.field_compatibility_pct || 0) >= 80 || ev.classification === "excellent" || ev.classification === "good")
      .map((ev) => ev.client_uid);
    setSelectedClientUids(recommended);
    setConfirmPopupOpen(false);
  };

  const toggleClientSelection = (clientUid: string) => {
    setSelectedClientUids((prev) =>
      prev.includes(clientUid)
        ? prev.filter((u) => u !== clientUid)
        : [...prev, clientUid]
    );
  };

  const handleConfirmImplement = async () => {
    if (!ruleToImplement) return;
    setImplementing(true);
    try {
      const result = await api.implementCuratedRule(ruleToImplement.id, {
        client_uids: selectedClientUids,
        confirm: true,
      });
      setLastImplementationResult(result);
      setFeedbackBanner({
        type: "success",
        text: result.message,
      });
      setConfirmPopupOpen(false);
      setRuleToImplement(null);
      await loadCuration();
    } catch (err: unknown) {
      setFeedbackBanner({
        type: "error",
        text:
          err instanceof Error
            ? err.message
            : "Falha ao implementar a regra selecionada.",
      });
      setConfirmPopupOpen(false);
    } finally {
      setImplementing(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px] text-outline font-body-md">
        Carregando motor de Curadoria de Regras de Detecção...
      </div>
    );
  }

  const metrics = overview?.metrics;
  const schedule = overview?.schedule;
  const sources = overview?.sources || [];
  const pct = Math.max(0, Math.min(100, progress?.percent ?? 0));
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (pct / 100) * circumference;

  return (
    <div className="flex flex-col w-full pb-12">
      {/* Top Breadcrumb Tracker */}
      <div className="flex items-center gap-space-sm mb-space-md font-code-sm text-code-sm">
        <span className="text-outline">DANTE</span>
        <span className="text-surface-variant">/</span>
        <span className="text-outline uppercase">Engenharia de Detecção</span>
        <span className="text-surface-variant">/</span>
        <span className="text-primary-fixed-dim uppercase font-semibold">Curadoria de Regras</span>
      </div>

      {/* Header Section */}
      <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-space-lg mb-space-lg">
        <div className="flex flex-col max-w-4xl space-y-space-xs">
          <div className="flex flex-wrap items-center gap-space-sm">
            <h1 className="font-headline-xl text-headline-xl text-on-surface font-bold tracking-tight">
              Curadoria de Regras de Detecção
            </h1>
            <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-tertiary/10 text-tertiary font-code-sm text-code-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary animate-pulse"></span>
              Agendamento Diário • {schedule?.daily_time || "08:00"}
            </div>
          </div>
          <p className="font-body-md text-body-md text-outline leading-relaxed">
            Pesquisa diária automatizada em fontes confiáveis de Threat Intelligence (SigmaHQ, detection.fyi, Splunk Research e Elastic Rules), validação de compatibilidade com o catálogo de tecnologias do D.A.N.T.E., conversão para LogQL e teste real no Loki de todos os clientes.
          </p>
        </div>

        {/* Action Bar */}
        <div className="flex items-center gap-space-sm shrink-0">
          <button
            onClick={() => setShowLogs((prev) => !prev)}
            className="flex items-center gap-2 px-space-md py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-all shadow-sm"
            type="button"
          >
            <span className="material-symbols-outlined text-[18px]">terminal</span>
            <span>{showLogs ? "Ocultar Logs" : "Ver Logs"}</span>
          </button>
          <button
            onClick={handleRunCurationNow}
            disabled={runningCycle || Boolean(progress?.running)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary transition-all shadow-[0_0_16px_rgba(225,29,72,0.4)] active:scale-95 disabled:opacity-50 font-body-sm text-body-sm font-medium"
            title="Iniciar Curadoria"
            type="button"
          >
            {runningCycle || Boolean(progress?.running) ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>Executando...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[18px]">play_arrow</span>
                <span>Iniciar</span>
              </>
            )}
          </button>
          <button
            onClick={handleStopCurationNow}
            disabled={(!runningCycle && !progress?.running) || stoppingCycle}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-950/60 hover:bg-red-900 border border-red-500/40 text-red-300 hover:text-white transition-all shadow-sm active:scale-95 disabled:opacity-30 disabled:pointer-events-none font-body-sm text-body-sm"
            title="Parar Curadoria"
            type="button"
          >
            {stoppingCycle ? (
              <>
                <svg className="animate-spin h-4 w-4 text-red-300" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
                </svg>
                <span>Parando...</span>
              </>
            ) : (
              <>
                <span className="material-symbols-outlined text-[18px]">stop</span>
                <span>Parar</span>
              </>
            )}
          </button>
          <button
            onClick={() => setIsClearModalOpen(true)}
            disabled={runningCycle || Boolean(progress?.running) || ((overview?.rules?.length || 0) === 0 && pct === 0)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-error-container/30 border border-outline/20 hover:border-error/40 text-on-surface hover:text-error transition-all shadow-sm active:scale-95 disabled:opacity-40 disabled:pointer-events-none font-body-sm text-body-sm"
            title="Limpar todas as regras sugeridas e resetar a curadoria para 0%"
            type="button"
          >
            <span className="material-symbols-outlined text-[18px]">delete_sweep</span>
            <span>Limpar Curadoria</span>
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedbackBanner && (
        <div
          className={`mb-space-md px-space-md py-2.5 rounded-lg flex items-center justify-between text-body-sm ${
            feedbackBanner.type === "error"
              ? "bg-error-container text-on-error-container"
              : "bg-tertiary-container/30 border border-tertiary/40 text-tertiary"
          }`}
        >
          <span>{feedbackBanner.text}</span>
          <button
            onClick={() => setFeedbackBanner(null)}
            className="text-on-surface hover:text-white text-xs underline ml-4"
          >
            Fechar
          </button>
        </div>
      )}

      {error && (
        <div className="mb-space-md px-space-md py-2.5 rounded-lg bg-error-container text-on-error-container text-body-sm">
          {error}
        </div>
      )}

      {/* Job Execution Panel / Pipeline Monitor Card */}
      {progress && showLogs && (
        <div className="mb-space-lg rounded-xl bg-surface-container-low p-space-lg shadow-xl relative overflow-hidden transition-all duration-300">
          <div className="absolute -top-16 -left-16 w-64 h-64 bg-tertiary/5 rounded-full blur-3xl pointer-events-none"></div>
          <div className="flex flex-col lg:flex-row gap-space-lg items-stretch">
            {/* Ring & Status Overview */}
            <div className="flex items-center gap-space-lg lg:w-72 shrink-0 p-space-md bg-surface-container-lowest/80 rounded-lg">
              <div className="relative w-20 h-20 shrink-0 flex items-center justify-center">
                <svg className="w-20 h-20 -rotate-90 transform" viewBox="0 0 72 72">
                  <circle className="text-surface-container-high fill-none" cx="36" cy="36" r={radius} stroke="currentColor" strokeWidth="6"></circle>
                  <circle
                    className={`${progress.running ? "text-secondary" : pct === 0 ? "text-outline/40" : "text-tertiary"} fill-none transition-all duration-700`}
                    cx="36"
                    cy="36"
                    r={radius}
                    stroke="currentColor"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    strokeLinecap="round"
                    strokeWidth="6"
                  ></circle>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                  <span className="font-metric-display text-[15px] font-bold text-on-surface leading-none">{pct}%</span>
                  <span className="font-code-sm text-[8px] uppercase tracking-wider text-outline mt-0.5">
                    {progress.running ? "Em curso" : pct === 0 ? "Aguardando" : "Concluído"}
                  </span>
                </div>
              </div>
              <div className="flex flex-col justify-center space-y-1">
                <div className="flex items-center gap-1.5">
                  <span className="relative flex h-2 w-2">
                    {progress.running && (
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-secondary opacity-75"></span>
                    )}
                    <span className={`relative inline-flex rounded-full h-2 w-2 ${progress.running ? "bg-secondary" : pct === 0 ? "bg-outline" : "bg-tertiary"}`}></span>
                  </span>
                  <span className={`font-code-sm text-code-sm font-semibold uppercase tracking-wider ${progress.running ? "text-secondary" : pct === 0 ? "text-outline" : "text-tertiary"}`}>
                    {progress.running ? "Executando" : pct === 0 ? "Ocioso" : "Concluída"}
                  </span>
                </div>
                <p className="font-body-sm text-body-sm text-on-surface-variant font-medium leading-tight">
                  {progress.current_action || (progress.running ? "Avaliação de telemetria..." : pct === 0 ? "Pronto para iniciar a curadoria." : "Pipeline finalizado com sucesso")}
                </p>
                <span className="font-code-sm text-[10px] text-outline">Fase: {progress.phase || (pct === 0 ? "Aguardando execução" : "Motor de Curadoria")}</span>
              </div>
            </div>

            {/* Live Terminal Well */}
            <div className="flex-1 flex flex-col min-w-0">
              <div className="flex items-center justify-between px-space-md py-1.5 bg-surface-container rounded-t-lg">
                <div className="flex items-center gap-space-sm font-code-sm text-code-sm text-on-surface">
                  <span className="material-symbols-outlined text-[16px] text-tertiary">fact_check</span>
                  <span className="font-medium text-tertiary">Curadoria:</span>
                  <span className="text-outline">{overview?.rules.length || 0} regra(s) qualificadas no ciclo</span>
                </div>
                <div className="flex items-center gap-2 font-code-sm text-[10px] text-outline">
                  <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                  Loki cluster sync: 200 OK
                </div>
              </div>
              <div className="bg-surface-container-lowest p-space-md font-code-sm text-code-sm text-on-surface-variant space-y-1.5 overflow-y-auto max-h-36 rounded-b-lg scroll-smooth">
                <div className="text-outline font-semibold mb-1 uppercase text-[10px] tracking-widest">
                  LOG VERBOSO DE EXECUÇÃO POR CLIENTE E JANELA ({progress.recent_logs?.length || 0} EVENTOS):
                </div>
                {progress.recent_logs && progress.recent_logs.length > 0 ? (
                  progress.recent_logs.map((logLine, idx) => (
                    <div key={idx} className="flex items-start gap-2 hover:bg-surface-container-high/40 px-1 py-0.5 rounded transition-colors text-outline">
                      <span className="text-tertiary shrink-0">•</span>
                      <span className="truncate">{logLine}</span>
                    </div>
                  ))
                ) : (
                  <div className="text-outline text-xs">Aguardando novos eventos de curadoria...</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Metadata Strip & Schedule Banner */}
      <div className="mb-space-lg px-space-md py-2.5 rounded-lg bg-surface-container-low flex flex-col md:flex-row items-center justify-between gap-space-md">
        <div className="flex flex-wrap items-center gap-x-space-md gap-y-1 font-body-sm text-body-sm">
          <div className="flex items-center gap-1.5 text-on-surface-variant">
            <span className="material-symbols-outlined text-[16px] text-outline">schedule</span>
            <span className="text-outline">Execução Automática:</span>
            <span className="text-on-surface font-medium">Todos os dias às {schedule?.daily_time || "08:00"} ({schedule?.timezone || "America/Sao_Paulo UTC-03:00"})</span>
          </div>
          <div className="hidden sm:block text-surface-variant">•</div>
          <div className="text-outline font-code-sm text-code-sm">
            Última execução: <span className="text-on-surface font-semibold">{formatDateTimePt(schedule?.last_run_at)}</span>
          </div>
          <div className="hidden sm:block text-surface-variant">•</div>
          <div className="text-outline font-code-sm text-code-sm">
            Próxima execução: <span className="text-tertiary font-semibold">{formatDateTimePt(schedule?.next_run_at)}</span>
          </div>
        </div>
        <div className="flex items-center gap-space-sm shrink-0">
          <span className="px-2 py-0.5 rounded bg-surface-container-high text-on-surface-variant font-code-sm text-[11px] flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
            Filtro Ativo: Apenas Candidatas Qualificadas (Compatibilidade ≥ 80%)
          </span>
          <span className="px-2 py-0.5 rounded bg-surface-container-high text-tertiary font-code-sm text-[11px] flex items-center gap-1">
            <span className="material-symbols-outlined text-[14px]">verified</span>
            Deduplicação Permanente Ativa
          </span>
          {overview?.schedule?.last_run_summary?.ai_curated_count ? (
            <span className="px-2 py-0.5 rounded bg-sky-950/60 border border-sky-500/30 text-sky-300 font-code-sm text-[11px] flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-400 animate-pulse"></span>
              IA: {overview.schedule.last_run_summary.ai_provider_used || "DeepSeek"} ({overview.schedule.last_run_summary.ai_curated_count} regras)
            </span>
          ) : null}
        </div>
      </div>

      {/* Connected Intelligence Sources (4 Cards) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md mb-space-lg">
        {sources.map((src) => (
          <div key={src.id} className="rounded-xl bg-surface-container-low p-space-md hover:bg-surface-container transition-all flex flex-col justify-between group">
            <div>
              <div className="flex items-center justify-between mb-space-xs">
                <a
                  className="flex items-center gap-1 font-headline-md text-headline-md text-on-surface group-hover:text-secondary transition-colors"
                  href={src.url}
                  rel="noreferrer"
                  target="_blank"
                >
                  <span>{src.name}</span>
                  <span className="material-symbols-outlined text-[16px] text-outline group-hover:text-secondary transition-colors">north_east</span>
                </a>
                <span className="px-2 py-0.5 rounded font-code-sm text-[10px] bg-surface-container-highest text-secondary uppercase font-semibold">
                  {src.format_label}
                </span>
              </div>
              <p className="font-code-sm text-[11px] text-outline truncate mb-space-md" title={src.url}>
                {src.url}
              </p>
            </div>
            <div className="flex items-center justify-between pt-space-xs bg-surface-container-lowest/50 -mx-space-md -mb-space-md px-space-md py-2 rounded-b-xl">
              <span className="font-body-sm text-body-sm text-outline">Candidatas aprovadas:</span>
              <span className="font-code-sm text-code-sm font-bold text-tertiary">{src.curated_count} regra(s)</span>
            </div>
          </div>
        ))}
      </div>

      {/* Candidate KPI Scorecards (5 Columns) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-space-md mb-space-lg">
        {/* KPI 1 */}
        <div className="rounded-xl bg-surface-container-low p-space-md flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">Candidatas Qualificadas</span>
            <span className="material-symbols-outlined text-[20px] text-outline">analytics</span>
          </div>
          <div className="my-space-sm">
            <span className="font-metric-display text-metric-display font-bold text-on-surface">{metrics?.total_curated ?? 0}</span>
          </div>
          <div className="flex items-center gap-1.5 text-outline font-body-sm text-body-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-primary-container"></span>
            Compatibilidade ≥ 80% (Aptas ao SIEM)
          </div>
        </div>

        {/* KPI 2 */}
        <div className="rounded-xl bg-surface-container-low p-space-md flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-emerald-400 uppercase tracking-wider">Alta Compatibilidade</span>
            <span className="material-symbols-outlined text-[20px] text-emerald-400">verified_user</span>
          </div>
          <div className="my-space-sm">
            <span className="font-metric-display text-metric-display font-bold text-emerald-400">{highCompatCount}</span>
          </div>
          <p className="text-outline font-body-sm text-[11px] leading-snug">
            Score ≥ 95% (presença, contexto e cenário)
          </p>
        </div>

        {/* KPI 3 */}
        <div className="rounded-xl bg-surface-container-low p-space-md flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-sky-400 uppercase tracking-wider">Compatibilidade 80% - 94%</span>
            <span className="material-symbols-outlined text-[20px] text-sky-400">check_circle</span>
          </div>
          <div className="my-space-sm">
            <span className="font-metric-display text-metric-display font-bold text-sky-400">{mediumCompatCount}</span>
          </div>
          <p className="text-outline font-body-sm text-[11px] leading-snug">
            Aprovadas no limiar mínimo de 80%
          </p>
        </div>

        {/* KPI 4 */}
        <div className="rounded-xl bg-surface-container-low p-space-md flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">Descartadas (&lt; 80%)</span>
            <span className="material-symbols-outlined text-[20px] text-error">block</span>
          </div>
          <div className="my-space-sm">
            <span className="font-metric-display text-metric-display font-bold text-outline">{metrics?.discarded_bad_count ?? 0}</span>
          </div>
          <p className="text-outline font-body-sm text-[11px] leading-snug">
            Barradas por incompatibilidade de schema
          </p>
        </div>

        {/* KPI 5 */}
        <div className="rounded-xl bg-surface-container-low p-space-md flex flex-col justify-between relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-primary uppercase tracking-wider">Implementadas</span>
            <span className="material-symbols-outlined text-[20px] text-primary">published_with_changes</span>
          </div>
          <div className="my-space-sm flex items-baseline gap-2">
            <span className="font-metric-display text-metric-display font-bold text-on-surface">{metrics?.implemented_count ?? 0}</span>
            <span className="font-code-sm text-code-sm text-outline">de {metrics?.total_curated ?? 0}</span>
          </div>
          <div className="flex items-center gap-1.5 text-on-surface-variant font-body-sm text-body-sm">
            <span className="w-2 h-2 rounded-full bg-surface-variant"></span>
            {metrics?.pending_count ?? 0} pendente(s) • {metrics?.ignored_count ?? 0} ignorada(s)
          </div>
        </div>
      </div>

      {/* Abas Qualificadas vs Descartadas */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => {
            setViewTab("qualified");
            if (statusFilter === "discarded") setStatusFilter("active");
            setPage(1);
          }}
          className={`px-4 py-2 rounded-lg font-headline-sm text-body-sm font-semibold transition-all inline-flex items-center gap-2 ${
            viewTab === "qualified" && statusFilter !== "discarded"
              ? "bg-secondary/20 text-secondary border border-secondary/40 shadow-sm"
              : "bg-surface-container-low text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high"
          }`}
        >
          <span className="material-symbols-outlined text-[18px]">verified</span>
          Regras Qualificadas ({overview?.rules?.length || 0})
        </button>
        <button
          type="button"
          onClick={() => {
            setViewTab("discarded");
            setStatusFilter("discarded");
            setPage(1);
          }}
          className={`px-4 py-2 rounded-lg font-headline-sm text-body-sm font-semibold transition-all inline-flex items-center gap-2 ${
            viewTab === "discarded" || statusFilter === "discarded"
              ? "bg-error/20 text-error border border-error/40 shadow-sm"
              : "bg-surface-container-low text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high"
          }`}
        >
          <span className="material-symbols-outlined text-[18px]">block</span>
          Regras Descartadas ({overview?.discarded_rules?.length || overview?.metrics?.discarded_bad_count || 0})
        </button>
      </div>

      {/* Search & Filter Controls */}
      <div className="mb-space-md rounded-xl bg-surface-container-low p-space-sm flex flex-col lg:flex-row items-stretch gap-space-sm">
        {/* Search Input */}
        <div className="relative flex-1">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-[18px] text-outline">search</span>
          <input
            className="w-full bg-surface-container-lowest text-on-surface placeholder:text-outline font-body-md text-body-md pl-10 pr-10 py-1.5 rounded-lg focus:outline-none focus:ring-1 focus:ring-secondary transition-all"
            placeholder="Buscar por regra, técnica MITRE, tecnologia, cliente ou LogQL..."
            type="text"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
          <div className="absolute right-3 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded bg-surface-container-high font-code-sm text-[10px] text-outline">/</div>
        </div>

        {/* Quick Dropdowns */}
        <div className="flex flex-wrap items-center gap-space-xs">
          <select
            className="bg-surface-container-lowest text-on-surface font-body-sm text-body-sm px-space-md py-1.5 rounded-lg focus:outline-none hover:bg-surface-container-high transition-colors"
            value={qualityFilter}
            onChange={(e) => {
              setQualityFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="all">Todas as Candidatas (≥ 80%)</option>
            <option value="high">Alta Compatibilidade (≥ 95%)</option>
            <option value="medium">Compatibilidade 80% a 94%</option>
          </select>

          <select
            className="bg-surface-container-lowest text-on-surface font-body-sm text-body-sm px-space-md py-1.5 rounded-lg focus:outline-none hover:bg-surface-container-high transition-colors"
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="all">Todas as Fontes</option>
            <option value="sigmahq">SigmaHQ</option>
            <option value="detection_fyi">detection.fyi</option>
            <option value="splunk_research">Splunk Research</option>
            <option value="elastic_rules">Elastic Rules</option>
          </select>

          <select
            className="bg-surface-container-lowest text-on-surface font-body-sm text-body-sm px-space-md py-1.5 rounded-lg focus:outline-none hover:bg-surface-container-high transition-colors"
            value={techFilter}
            onChange={(e) => {
              setTechFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="all">Todas as Tecnologias</option>
            {technologyOptions.map((t) => (
              <option key={t.slug} value={t.slug}>
                {t.name}
              </option>
            ))}
          </select>

          <select
            className="bg-surface-container-lowest text-on-surface font-body-sm text-body-sm px-space-md py-1.5 rounded-lg focus:outline-none hover:bg-surface-container-high transition-colors"
            value={perimeterFilter}
            onChange={(e) => {
              setPerimeterFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="all">Todos os Perímetros</option>
            <option value="firewall">Firewall</option>
            <option value="waf_web">WAF / Web</option>
            <option value="endpoint_edr">Antimalware / EDR</option>
            <option value="identity_iam">Identidade</option>
            <option value="cloud_saas">Cloud / SaaS</option>
            <option value="os_host">Sistema Operacional</option>
            <option value="network_ids">Rede / IDS / DNS</option>
            <option value="email_gateway">Email Gateway</option>
            <option value="other">Outro</option>
          </select>

          <select
            className="bg-surface-container-lowest text-on-surface font-body-sm text-body-sm px-space-md py-1.5 rounded-lg focus:outline-none hover:bg-surface-container-high transition-colors"
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="active">Regras Ativas (Ocultar Ignoradas)</option>
            <option value="pending">Pendentes de Homologação</option>
            <option value="implemented">Já Homologadas</option>
            <option value="ignored">Apenas Ignoradas</option>
            <option value="discarded">Regras Descartadas</option>
            <option value="all">Todas (Incluindo Ignoradas)</option>
          </select>
        </div>
      </div>

      {/* Qualified Rules High-Density SecOps Table */}
      <div className="rounded-xl bg-surface-container-low overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-lowest font-code-sm text-code-sm text-outline uppercase tracking-wider">
                <th className="py-3 px-4 w-36">Compatibilidade</th>
                <th className="py-3 px-4 w-44">Fonte / ID</th>
                <th className="py-3 px-4 min-w-[280px]">Regra de Detecção</th>
                <th className="py-3 px-4 w-36">Tecnologia</th>
                <th className="py-3 px-4 min-w-[200px]">MITRE ATT&amp;CK</th>
                <th className="py-3 px-4 min-w-[260px]">LogQL Gerado &amp; Validação</th>
                <th className="py-3 px-4 text-right w-52">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y-0 font-body-sm text-body-sm">
              {filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-outline">
                    Nenhuma regra candidata encontrada para os filtros selecionados.
                  </td>
                </tr>
              ) : (
                paginatedRules.map((rule, idx) => {
                  const compatVal = rule.field_compatibility_pct ?? 100;
                  const cMeta = getCompatibilityMeta(compatVal);
                  const sevMeta = SEVERITY_COLORS[rule.severity] || SEVERITY_COLORS.medium;
                  const matchedCount = rule.total_matched_results ?? 0;
                  const rowBg = idx % 2 === 1 ? "bg-surface-container-lowest/30" : "";

                  return (
                    <tr
                      key={rule.id}
                      className={`hover:bg-surface-container-high/40 transition-colors group cursor-pointer ${rowBg} ${
                        rule.ignored ? "opacity-65" : ""
                      }`}
                      onClick={() => setDetailRule(rule)}
                    >
                      <td className="py-3.5 px-4 align-top">
                        {rule.discarded ? (
                          <div className="flex flex-col gap-0.5">
                            <span
                              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-code-sm text-[12px] bg-error/15 text-error font-bold border border-error/30 shadow-sm"
                              title={rule.discard_reason || "Regra descartada da curadoria"}
                            >
                              <span className="material-symbols-outlined text-[15px]">block</span>
                              {compatVal % 1 !== 0 ? compatVal.toFixed(1) : compatVal.toFixed(0)}%
                            </span>
                            <span className="font-code-sm text-[9px] text-error/90 ml-1 font-semibold">
                              Descartada
                            </span>
                          </div>
                        ) : (
                          <div className="flex flex-col gap-0.5">
                            <span
                              className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-code-sm text-[12px] ${cMeta.bg} ${cMeta.color} font-bold border ${cMeta.border} shadow-sm`}
                              title={`Compatibilidade dinâmica de ${compatVal.toFixed(1)}% com base em presença de logs, contexto de ameaça e correspondência de cenário (Critério mínimo: 80%)`}
                            >
                              <span className="material-symbols-outlined text-[15px]">{cMeta.icon}</span>
                              {compatVal % 1 !== 0 ? compatVal.toFixed(1) : compatVal.toFixed(0)}%
                            </span>
                            <span className="font-code-sm text-[9px] text-outline ml-1">
                              {compatVal >= 80 ? "Candidata (≥ 80%)" : "Incompatível"}
                            </span>
                          </div>
                        )}
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-col">
                          <span className="font-body-md text-body-md text-on-surface font-semibold">{rule.source_name}</span>
                          <span className="font-code-sm text-code-sm text-secondary">#{rule.external_id || rule.id.slice(0, 8)}</span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-col space-y-1">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="font-headline-md text-[13px] font-semibold text-on-surface group-hover:text-primary-fixed-dim transition-colors">
                              {rule.title}
                            </span>
                            {rule.discarded && (
                              <span className="text-[11px] text-error/90 flex items-center gap-1 font-medium w-full mt-0.5">
                                <span className="material-symbols-outlined text-[13px]">info</span>
                                {rule.discard_reason || rule.classification_reason || "Critérios mínimos não atendidos"}
                              </span>
                            )}
                            {rule.curation_engine === "ai" && (
                              <span
                                className="px-1.5 py-0.5 rounded font-mono text-[10px] bg-sky-950/70 border border-sky-500/40 text-sky-300 flex items-center gap-1"
                                title={rule.ai_model ? `Sintetizada com IA (${rule.ai_model})` : "Sintetizada com IA"}
                              >
                                <span className="material-symbols-outlined text-[12px]">psychology</span>
                                IA {rule.ai_model ? `(${rule.ai_model})` : ""}
                              </span>
                            )}
                            {rule.ignored && (
                              <span
                                className="px-1.5 py-0.5 rounded font-code-sm text-[10px] bg-amber-950/70 border border-amber-500/40 text-amber-300 flex items-center gap-1"
                                title={`Regra ignorada em ${rule.ignored_at || "curadoria"}`}
                              >
                                <span className="material-symbols-outlined text-[12px]">visibility_off</span>
                                Ignorada
                              </span>
                            )}
                          </div>
                          <span className="font-body-sm text-outline text-[12px] line-clamp-1">
                            {rule.description}
                          </span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-col gap-1 items-start">
                          {rule.perimeter && (
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border ${
                                PERIMETER_CONFIG[rule.perimeter]?.badgeClass ||
                                "bg-surface-container text-on-surface border-outline-variant/30"
                              }`}
                            >
                              <span className="material-symbols-outlined text-[13px]">
                                {PERIMETER_CONFIG[rule.perimeter]?.icon || "shield"}
                              </span>
                              {rule.perimeter_name || PERIMETER_CONFIG[rule.perimeter]?.label || rule.perimeter}
                            </span>
                          )}
                          <span className="px-2 py-0.5 rounded bg-surface-container font-code-sm text-code-sm text-on-surface">
                            {rule.technology_name}
                          </span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-wrap gap-1">
                          {rule.mitre_tactic && (
                            <span className="px-1.5 py-0.5 rounded bg-secondary/10 text-secondary font-code-sm text-[10px]">
                              tactic={rule.mitre_tactic}
                            </span>
                          )}
                          {rule.mitre_technique && (
                            <span className="px-1.5 py-0.5 rounded bg-secondary/10 text-secondary font-code-sm text-[10px]">
                              tech={rule.mitre_technique}
                            </span>
                          )}
                          <span className={`px-1.5 py-0.5 rounded font-code-sm text-[10px] ${sevMeta.bg}`}>
                            {rule.severity}
                          </span>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-col space-y-1 max-w-sm">
                          <div className="bg-surface-container-lowest px-2 py-1 rounded font-code-sm text-[11px] text-secondary-fixed truncate font-mono">
                            {rule.logql_query}
                          </div>
                          <div className="flex items-center gap-1 font-code-sm text-[10px] text-tertiary">
                            <span className="material-symbols-outlined text-[13px]">
                              {matchedCount > 0 ? "check_circle" : "verified"}
                            </span>
                            <span>
                              {matchedCount > 0
                                ? `Logs reais: ${matchedCount} eventos retornados`
                                : `Campos validados (${(rule.observed_fields_in_logs || []).length}/${rule.mapped_fields.length})`}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 align-top text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {rule.discarded || viewTab === "discarded" || statusFilter === "discarded" ? (
                            <span
                              className="px-2.5 py-1 rounded font-body-sm text-[12px] font-medium bg-error/10 text-error/80 border border-error/20 cursor-not-allowed inline-flex items-center gap-1"
                              title={rule.discard_reason || "Regra descartada da curadoria"}
                            >
                              <span className="material-symbols-outlined text-[14px]">block</span>
                              Descartada
                            </span>
                          ) : (
                            <button
                              className={`px-2.5 py-1 rounded font-body-sm text-[12px] font-medium transition-all shadow-sm active:scale-95 ${
                                rule.implemented
                                  ? "bg-surface-container-high hover:bg-surface-bright text-on-surface"
                                  : "bg-primary-container hover:bg-primary text-on-primary"
                              }`}
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleOpenImplementModal(rule);
                              }}
                            >
                              {rule.implemented ? "Rever" : "Homologar"}
                            </button>
                          )}
                          <button
                            className="p-1 rounded text-outline hover:text-on-surface hover:bg-surface-container-high transition-colors"
                            title="Ver Detalhes & LogQL"
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setDetailRule(rule);
                            }}
                          >
                            <span className="material-symbols-outlined text-[18px]">code</span>
                          </button>
                          <button
                            className={`p-1 rounded transition-colors ${
                              rule.ignored
                                ? "text-amber-400 hover:text-amber-300 hover:bg-amber-950/40"
                                : "text-outline hover:text-on-surface hover:bg-surface-container-high"
                            }`}
                            title={rule.ignored ? "Restaurar Regra (Desfazer Ignorar)" : "Ignorar Regra de Detecção"}
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleToggleIgnoreRule(rule);
                            }}
                          >
                            <span className="material-symbols-outlined text-[18px]">
                              {rule.ignored ? "visibility" : "visibility_off"}
                            </span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table Pagination & Counter */}
        <div className="px-space-md py-3 bg-surface-container-lowest flex flex-col sm:flex-row items-center justify-between gap-space-sm font-body-sm text-body-sm text-outline">
          <div className="flex items-center gap-2">
            <span>
              Exibindo <span className="text-on-surface font-semibold">{filteredRules.length > 0 ? (page - 1) * pageSize + 1 : 0}-{Math.min(page * pageSize, filteredRules.length)}</span> de{" "}
              <span className="text-on-surface font-semibold">{filteredRules.length}</span> candidatas qualificadas
            </span>
            <span className="text-surface-variant">•</span>
            <span className="text-tertiary">{sources.length} fontes conectadas</span>
          </div>
          <div className="flex items-center gap-1">
            <button
              className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-high text-on-surface font-code-sm text-code-sm disabled:opacity-40"
              disabled={page <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              type="button"
            >
              Anterior
            </button>
            {Array.from({ length: totalPages }).slice(0, 5).map((_, i) => (
              <button
                key={i + 1}
                className={`px-2.5 py-1 rounded font-code-sm text-code-sm ${
                  page === i + 1
                    ? "bg-primary-container text-on-primary font-semibold"
                    : "bg-surface-container hover:bg-surface-container-high text-on-surface"
                }`}
                onClick={() => setPage(i + 1)}
                type="button"
              >
                {i + 1}
              </button>
            ))}
            <button
              className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-high text-on-surface font-code-sm text-code-sm disabled:opacity-40"
              disabled={page >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              type="button"
            >
              Próxima
            </button>
          </div>
        </div>
      </div>

      {/* Modal de Detalhes da Regra */}
      <Modal
        isOpen={Boolean(detailRule)}
        onClose={() => setDetailRule(null)}
        maxWidth="1020px"
        title={detailRule ? `Detalhes da Regra — ${detailRule.title}` : "Detalhes da Regra"}
      >
        {detailRule && (
          <div className="flex flex-col gap-space-md text-on-surface">
            {detailRule.discarded && (
              <div className="p-space-md rounded-lg border border-error/30 bg-error/10 text-error flex items-start gap-2">
                <span className="material-symbols-outlined text-[20px] shrink-0 mt-0.5">block</span>
                <div>
                  <strong className="block text-sm font-semibold mb-0.5">Regra Descartada pela Curadoria</strong>
                  <p className="text-xs text-error/90 leading-relaxed">{detailRule.discard_reason || detailRule.classification_reason || "Esta regra não atingiu os critérios mínimos de compatibilidade ou telemetria no Loki."}</p>
                </div>
              </div>
            )}
            {(() => {
              const dCompat = detailRule.field_compatibility_pct ?? 100;
              const dMeta = getCompatibilityMeta(dCompat);
              const dDisplay = dCompat % 1 !== 0 ? dCompat.toFixed(1) : dCompat.toFixed(0);
              return (
                <div className={`p-space-md rounded-lg border ${dMeta.border} ${dMeta.bg}`}>
                  <div className="flex justify-between items-center mb-1">
                    <span className={`font-headline-md font-semibold ${dMeta.color} flex items-center gap-2`}>
                      <span className="material-symbols-outlined text-[20px]">{dMeta.icon}</span>
                      {dDisplay}% de Compatibilidade Dinâmica — {dCompat >= 80 ? "Candidata para Implementação (≥ 80%)" : "Incompatível (< 80%)"}
                    </span>
                    <span className="font-code-sm text-xs px-2 py-0.5 rounded bg-surface-container-lowest text-outline">
                      ID Externo: {detailRule.external_id}
                    </span>
                  </div>
                  <p className="font-body-sm text-outline">{detailRule.classification_reason}</p>
                </div>
              );
            })()}

            {/* Painel dos 3 Eixos da Compatibilidade Dinâmica */}
            <div className="rounded-lg border border-outline-variant/30 bg-surface-container-low p-space-md">
              <span className="font-label-uppercase text-xs text-outline uppercase block mb-2 font-semibold">
                Composição Dinâmica da Compatibilidade (Base Mínima: 80.0%)
              </span>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-space-sm text-xs">
                {/* Eixo 1: Presença de logs */}
                <div className="p-space-sm rounded bg-surface-container-lowest border border-outline-variant/20 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-sky-400 flex items-center gap-1">
                        <span className="material-symbols-outlined text-[16px]">sensors</span>
                        1. Presença de Logs
                      </span>
                      <span className="font-code-sm font-bold text-sky-300">
                        +{(detailRule.log_presence_score ?? 0).toFixed(1)} pts
                      </span>
                    </div>
                    <p className="text-outline text-[11px] leading-tight">
                      Volume de telemetria ({detailRule.total_tech_logs_seen ?? 0} logs no cluster) e recência temporal nas 5 etapas progressivas.
                    </p>
                  </div>
                </div>

                {/* Eixo 2: Contexto de ameaça */}
                <div className="p-space-sm rounded bg-surface-container-lowest border border-outline-variant/20 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-amber-400 flex items-center gap-1">
                        <span className="material-symbols-outlined text-[16px]">warning</span>
                        2. Contexto de Ameaça
                      </span>
                      <span className="font-code-sm font-bold text-amber-300">
                        +{(detailRule.threat_context_score ?? 0).toFixed(1)} pts
                      </span>
                    </div>
                    <p className="text-outline text-[11px] leading-tight">
                      Severidade {detailRule.severity.toUpperCase()}, técnica {detailRule.mitre_technique || "—"} e relevância para o perímetro {detailRule.perimeter_name || "Geral"}.
                    </p>
                  </div>
                </div>

                {/* Eixo 3: Correspondência com o cenário */}
                <div className="p-space-sm rounded bg-surface-container-lowest border border-outline-variant/20 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-semibold text-emerald-400 flex items-center gap-1">
                        <span className="material-symbols-outlined text-[16px]">checklist</span>
                        3. Correspondência Cenário
                      </span>
                      <span className="font-code-sm font-bold text-emerald-300">
                        +{(detailRule.scenario_match_score ?? 0).toFixed(1)} pts
                      </span>
                    </div>
                    <p className="text-outline text-[11px] leading-tight">
                      {detailRule.has_query_results
                        ? `${detailRule.total_matched_results} eventos retornados na query da ameaça`
                        : "Campos de payload suportados e decoders Wazuh ativos para prontidão proativa"}.
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-space-sm">
              <div className="bg-surface-container-low p-space-sm rounded-lg">
                <span className="font-label-uppercase text-xs text-outline uppercase">Fonte Confiável</span>
                <p className="font-body-md font-semibold text-on-surface mt-1">{detailRule.source_name}</p>
                <a href={detailRule.source_url} target="_blank" rel="noreferrer" className="text-secondary text-xs truncate block hover:underline">
                  {detailRule.source_url}
                </a>
              </div>
              <div className="bg-surface-container-low p-space-sm rounded-lg">
                <span className="font-label-uppercase text-xs text-outline uppercase">Perímetro de Detecção</span>
                <div className="mt-1 flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-primary text-[18px]">
                    {PERIMETER_CONFIG[detailRule.perimeter || "other"]?.icon || "shield"}
                  </span>
                  <p className="font-body-md font-semibold text-on-surface">
                    {detailRule.perimeter_name || PERIMETER_CONFIG[detailRule.perimeter || "other"]?.label || "Perímetro Geral"}
                  </p>
                </div>
                <span className="text-xs text-outline">Escopo Tecnológico</span>
              </div>
              <div className="bg-surface-container-low p-space-sm rounded-lg">
                <span className="font-label-uppercase text-xs text-outline uppercase">Tecnologia Ativa</span>
                <p className="font-body-md font-semibold text-on-surface mt-1">{detailRule.technology_name}</p>
                <span className="font-code-sm text-xs text-outline font-mono">rule_groups=~"{detailRule.rule_groups_regex}"</span>
              </div>
              <div className="bg-surface-container-low p-space-sm rounded-lg">
                <span className="font-label-uppercase text-xs text-outline uppercase">MITRE ATT&amp;CK</span>
                <p className="font-body-md font-semibold text-secondary mt-1">{detailRule.mitre_technique || "—"}</p>
                <span className="text-xs text-outline">{detailRule.mitre_tactic || "—"}</span>
              </div>
            </div>

            {detailRule.ai_rationale && (
              <div className="rounded-lg border border-sky-500/30 bg-sky-950/25 p-space-md">
                <div className="flex items-center gap-2 mb-1.5 text-sky-300">
                  <span className="material-symbols-outlined text-[18px] text-sky-400">auto_awesome</span>
                  <span className="font-semibold text-xs uppercase tracking-wider">
                    Parecer Técnico da IA — Contexto de Ameaça {detailRule.ai_model ? `(${detailRule.ai_model})` : ""}
                  </span>
                </div>
                <p className="font-body-sm text-xs text-sky-100/90 leading-relaxed whitespace-pre-line">
                  {detailRule.ai_rationale}
                </p>
              </div>
            )}

            <div>
              <span className="font-label-uppercase text-xs text-outline uppercase block mb-1">LogQL Gerado</span>
              <pre className="p-space-md bg-surface-container-lowest rounded-lg font-mono text-xs text-tertiary overflow-x-auto border border-outline-variant/30">
                {detailRule.logql_query}
              </pre>
            </div>

            <div>
              <span className="font-label-uppercase text-xs text-outline uppercase block mb-1">Avaliação por Cliente ({detailRule.client_evaluations.length})</span>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {detailRule.client_evaluations.map((ev) => {
                  const evCompat = ev.field_compatibility_pct ?? 100;
                  const evMeta = getCompatibilityMeta(evCompat);
                  const evDisplay = evCompat % 1 !== 0 ? evCompat.toFixed(1) : evCompat.toFixed(0);
                  return (
                    <div key={ev.client_uid} className="flex items-center justify-between p-2 rounded bg-surface-container-low text-xs gap-2">
                      <span className="font-medium text-on-surface shrink-0">{ev.client_name}</span>
                      <span className="text-outline truncate">{ev.reason}</span>
                      <span className={`px-2 py-0.5 rounded font-code-sm ${evMeta.bg} ${evMeta.color} border ${evMeta.border} font-semibold shrink-0 flex items-center gap-1`}>
                        <span className="material-symbols-outlined text-[13px]">{evMeta.icon}</span>
                        {evDisplay}%
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-sm"
                onClick={() => setDetailRule(null)}
              >
                Fechar
              </button>
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold"
                onClick={() => {
                  const rule = detailRule;
                  setDetailRule(null);
                  handleOpenImplementModal(rule);
                }}
              >
                Prosseguir para Homologação
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Modal de Homologação / Implementação com Seleção de Clientes */}
      <Modal
        isOpen={Boolean(ruleToImplement) && !confirmPopupOpen}
        onClose={() => setRuleToImplement(null)}
        maxWidth="720px"
        title="Homologar Regra de Detecção Curada"
      >
        {ruleToImplement && (
          <div className="flex flex-col gap-space-md text-on-surface">
            <div>
              <h3 className="font-headline-md font-bold text-on-surface">{ruleToImplement.title}</h3>
              <p className="text-sm text-outline mt-1">{ruleToImplement.description}</p>
            </div>

            <div className="p-space-sm rounded-lg bg-surface-container-low">
              <span className="font-label-uppercase text-xs text-outline uppercase block mb-2">
                Selecione os clientes para provisionamento (Contact Point Homologação):
              </span>
              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                {ruleToImplement.client_evaluations.map((ev) => {
                  const isChecked = selectedClientUids.includes(ev.client_uid);
                  return (
                    <label
                      key={ev.client_uid}
                      className="flex items-center gap-3 p-2 rounded hover:bg-surface-container cursor-pointer transition-colors"
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleClientSelection(ev.client_uid)}
                        className="rounded border-outline bg-surface-container-lowest text-primary-container focus:ring-0"
                      />
                      <div className="flex-1 flex justify-between items-center text-xs">
                        <span className="font-semibold text-on-surface">{ev.client_name}</span>
                        <span className="text-emerald-400 font-code-sm font-semibold">
                          {((ev.field_compatibility_pct ?? 100) % 1 !== 0 ? (ev.field_compatibility_pct ?? 100).toFixed(1) : (ev.field_compatibility_pct ?? 100).toFixed(0))}% compatível
                        </span>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-sm"
                onClick={() => setRuleToImplement(null)}
              >
                Cancelar
              </button>
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold"
                onClick={() => setConfirmPopupOpen(true)}
              >
                Confirmar Homologação ({selectedClientUids.length} clientes)
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* ConfirmModal de Confirmação */}
      <ConfirmModal
        isOpen={Boolean(ruleToImplement) && confirmPopupOpen}
        onClose={() => setConfirmPopupOpen(false)}
        onConfirm={handleConfirmImplement}
        title="Confirmar Homologação da Regra"
        confirmLabel="Confirmar e Homologar"
        cancelLabel="Voltar"
        variant="warning"
        isLoading={implementing}
        message={
          ruleToImplement ? (
            <div className="space-y-2 text-sm">
              <p>
                Você confirma o provisionamento da regra <strong>{ruleToImplement.title}</strong>?
              </p>
              <p className="text-outline text-xs">
                A regra será inserida no Baseline Global e nos {selectedClientUids.length} cliente(s) selecionados com Contact Point em estágio Homologação.
              </p>
            </div>
          ) : null
        }
      />

      {/* Resumo opcional da última implementação */}
      {lastImplementationResult && (
        <Modal
          isOpen={Boolean(lastImplementationResult)}
          onClose={() => setLastImplementationResult(null)}
          title="Resultado da Homologação"
        >
          <div className="flex flex-col gap-space-sm text-on-surface">
            <div className="p-space-sm rounded-lg bg-tertiary-container/20 text-tertiary border border-tertiary/40 text-sm">
              {lastImplementationResult.message}
            </div>
            <div className="text-xs space-y-1">
              <div><strong>UID Baseline:</strong> <code>{lastImplementationResult.baseline_rule_uid}</code></div>
              <div><strong>Contact Point:</strong> <code>{lastImplementationResult.contact_point}</code></div>
            </div>
            <div className="flex justify-end pt-2">
              <button
                type="button"
                className="px-4 py-1.5 rounded-lg bg-primary-container text-on-primary text-sm font-semibold"
                onClick={() => setLastImplementationResult(null)}
              >
                Concluir
              </button>
            </div>
          </div>
        </Modal>
      )}
      {/* ConfirmModal de Limpar Curadoria */}
      <ConfirmModal
        isOpen={isClearModalOpen}
        onClose={() => setIsClearModalOpen(false)}
        onConfirm={handleConfirmClearCuration}
        title="Limpar Curadoria de Regras"
        confirmLabel="Limpar e Resetar"
        cancelLabel="Cancelar"
        variant="danger"
        isLoading={clearing}
        message={
          <div className="space-y-2 text-sm text-on-surface">
            <p>
              Tem certeza de que deseja limpar todas as regras sugeridas pela curadoria?
            </p>
            <p className="text-on-surface-variant text-xs">
              Todas as <strong>{overview?.rules?.length || 0}</strong> regras qualificadas serão removidas do catálogo e a lista será completamente resetada.
            </p>
            <p className="text-outline text-xs">
              O histórico cumulativo será zerado, permitindo que todas as regras sejam reavaliadas do zero na próxima execução.
            </p>
          </div>
        }
      />
    </div>
  );
};
