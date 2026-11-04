import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Modal } from "../components/Modal";
import { FolderItem, Silence, SilenceKind, SilencedAlertSummary } from "../types";

type ViewMode = "permanent" | "temporary";
type CreateKind = "permanent" | "maintenance" | "antiflood";
type Duration = "2h" | "4h" | "8h" | "24h" | "3d" | "10y";

const durationToMs = (duration: Duration): number => {
  switch (duration) {
    case "2h":
      return 2 * 3600 * 1000;
    case "4h":
      return 4 * 3600 * 1000;
    case "8h":
      return 8 * 3600 * 1000;
    case "24h":
      return 24 * 3600 * 1000;
    case "3d":
      return 3 * 24 * 3600 * 1000;
    case "10y":
      return 3650 * 24 * 3600 * 1000;
  }
};

const formatRemaining = (endsAt: string | null): string => {
  if (!endsAt) return "sem prazo";
  const diff = new Date(endsAt).getTime() - Date.now();
  if (Number.isNaN(diff)) return "N/D";
  if (diff <= 0) return "expirado";

  const days = Math.floor(diff / 86_400_000);
  const hours = Math.floor((diff % 86_400_000) / 3_600_000);
  const minutes = Math.floor((diff % 3_600_000) / 60_000);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
};

const cleanComment = (comment: string): string =>
  comment.replace(/^\s*\[[a-z0-9 _-]{2,32}\]\s*/i, "").trim() || "—";

const kindOf = (silence: Silence): SilenceKind => silence.kind ?? "manual";

export const SilencesPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [silences, setSilences] = useState<Silence[]>([]);
  const [foldersList, setFoldersList] = useState<FolderItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Sincronização em tempo real
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [expandedSilenceId, setExpandedSilenceId] = useState<string | null>(null);
  const [onlySilencingAlerts, setOnlySilencingAlerts] = useState(false);

  // Segregação: exceções permanentes x supressões temporárias
  const [view, setView] = useState<ViewMode>("permanent");
  const [originFilter, setOriginFilter] = useState<"all" | SilenceKind>("all");

  // Filtros
  const [stateFilter, setStateFilter] = useState<string>("active");
  const [clientFilter, setClientFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  // Modal Novo Silence
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createKind, setCreateKind] = useState<CreateKind>("permanent");
  const [matchersList, setMatchersList] = useState<
    { name: string; value: string; is_equal: boolean; is_regex: boolean }[]
  >([
    { name: "alertname", value: "", is_equal: true, is_regex: false },
    { name: "grafana_folder", value: "", is_equal: true, is_regex: false },
    { name: "", value: "", is_equal: true, is_regex: false },
  ]);
  const [createDuration, setCreateDuration] = useState<Duration>("4h");
  const [comment, setComment] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Excluir silence
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Prolongar silence
  const [extendModalOpen, setExtendModalOpen] = useState(false);
  const [selectedSilenceForExtend, setSelectedSilenceForExtend] = useState<Silence | null>(null);
  const [extendDuration, setExtendDuration] = useState<Duration>("4h");
  const [extending, setExtending] = useState(false);
  const [extendError, setExtendError] = useState<string | null>(null);

  const clientFolders = useMemo(() => {
    return foldersList.filter(
      (f) =>
        f.uid.toLowerCase() !== "global" &&
        f.title.toLowerCase() !== "global"
    );
  }, [foldersList]);

  const loadSilences = async (silent = false) => {
    try {
      if (!silent) setIsRefreshing(true);
      const data = await api.getSilences();
      setSilences(data);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      if (!silent) {
        if (err instanceof Error) {
          setError(err.message);
        } else {
          setError("Erro ao carregar silences.");
        }
      }
    } finally {
      if (!silent) setIsRefreshing(false);
    }
  };

  const loadData = async () => {
    try {
      setError(null);
      setIsRefreshing(true);
      const [silencesData, foldersData] = await Promise.all([
        api.getSilences(),
        api.getFolders(),
      ]);
      setSilences(silencesData);
      setFoldersList(foldersData);
      setLastUpdated(new Date());
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Erro ao carregar silences e pastas.");
      }
    } finally {
      setLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Polling em tempo real a cada 10 segundos
  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(() => {
      loadSilences(true);
    }, 10000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  useEffect(() => {
    const forAlert = searchParams.get("createFor");
    const requestedKind = searchParams.get("createKind");
    if (!forAlert && !requestedKind) return;

    if (forAlert) {
      setMatchersList([
        { name: "alertname", value: forAlert, is_equal: true, is_regex: false },
        { name: "grafana_folder", value: "", is_equal: true, is_regex: false },
        { name: "", value: "", is_equal: true, is_regex: false },
      ]);
      setComment(`Incidente relacionado a ${forAlert} em análise pelo time.`);
    }
    if (
      requestedKind === "permanent" ||
      requestedKind === "maintenance" ||
      requestedKind === "antiflood"
    ) {
      setCreateKind(requestedKind);
    }
    setCreateModalOpen(true);
    setSearchParams({});
  }, [searchParams, setSearchParams]);

  const handleOpenCreateModal = (defaultKind?: CreateKind) => {
    setActionError(null);
    setCreateKind(defaultKind || (view === "permanent" ? "permanent" : "maintenance"));
    setMatchersList([
      { name: "alertname", value: "", is_equal: true, is_regex: false },
      { name: "grafana_folder", value: "", is_equal: true, is_regex: false },
      { name: "", value: "", is_equal: true, is_regex: false },
    ]);
    setCreateDuration("4h");
    setComment("");
    setCreateModalOpen(true);
  };

  const handleAddMatcher = () => {
    setMatchersList((prev) => [
      ...prev,
      { name: "", value: "", is_equal: true, is_regex: false },
    ]);
  };

  const handleRemoveMatcher = (index: number) => {
    setMatchersList((prev) => prev.filter((_, i) => i !== index));
  };

  const handleMatcherChange = (
    index: number,
    field: "name" | "value" | "is_equal" | "is_regex",
    val: unknown
  ) => {
    setMatchersList((prev) =>
      prev.map((item, idx) => (idx === index ? { ...item, [field]: val } : item))
    );
  };

  const matchesFilters = (silence: Silence): boolean => {
    // Filtro por impacto em tempo real
    if (onlySilencingAlerts && (silence.silenced_alerts_count || 0) === 0) {
      return false;
    }

    const matchState =
      stateFilter === "all" ||
      silence.state.toLowerCase() === stateFilter.toLowerCase();

    const matchClient =
      clientFilter === "all" ||
      silence.matchers.some((m) => {
        const nameLower = m.name.toLowerCase();
        if (
          nameLower === "grafana_folder" ||
          nameLower === "tenant" ||
          nameLower === "client"
        ) {
          return m.value.toLowerCase() === clientFilter.toLowerCase();
        }
        return false;
      });

    const needle = search.toLowerCase();
    const matchSearch =
      needle.length === 0 ||
      silence.comment.toLowerCase().includes(needle) ||
      silence.created_by.toLowerCase().includes(needle) ||
      silence.matchers.some(
        (m) =>
          m.name.toLowerCase().includes(needle) ||
          m.value.toLowerCase().includes(needle)
      );

    return matchState && matchClient && matchSearch;
  };

  const permanentSilences = useMemo(
    () => silences.filter((s) => kindOf(s) === "permanent"),
    [silences]
  );

  const temporarySilences = useMemo(
    () => silences.filter((s) => kindOf(s) !== "permanent"),
    [silences]
  );

  const baseSilences = view === "permanent" ? permanentSilences : temporarySilences;

  const visibleSilences = useMemo(
    () =>
      baseSilences.filter((s) => {
        if (view === "temporary" && originFilter !== "all" && kindOf(s) !== originFilter) {
          return false;
        }
        return matchesFilters(s);
      }),
    [baseSilences, view, originFilter, stateFilter, clientFilter, search, onlySilencingAlerts]
  );

  // Métricas agregadas em tempo real
  const totalActiveSilencedAlerts = useMemo(() => {
    return silences
      .filter((s) => s.state === "active")
      .reduce((acc, curr) => acc + (curr.silenced_alerts_count || 0), 0);
  }, [silences]);

  const totalPermanentSilencedAlerts = useMemo(() => {
    return permanentSilences
      .filter((s) => s.state === "active")
      .reduce((acc, curr) => acc + (curr.silenced_alerts_count || 0), 0);
  }, [permanentSilences]);

  const totalTemporarySilencedAlerts = useMemo(() => {
    return temporarySilences
      .filter((s) => s.state === "active")
      .reduce((acc, curr) => acc + (curr.silenced_alerts_count || 0), 0);
  }, [temporarySilences]);

  const handleCreateSilence = async (e: React.FormEvent) => {
    e.preventDefault();

    const validMatchers = matchersList
      .map((m) => ({
        name: m.name.trim(),
        value: m.value.trim(),
        is_equal: m.is_equal,
        is_regex: m.is_regex,
      }))
      .filter((m) => m.name.length > 0 && m.value.length > 0);

    if (validMatchers.length === 0) {
      setActionError("Preencha ao menos uma label com nome e valor para criar o silence.");
      return;
    }

    if (!comment.trim()) {
      setActionError("Preencha o motivo/comentário do silence.");
      return;
    }

    setSubmitting(true);
    setActionError(null);

    const effectiveDuration: Duration =
      createKind === "permanent" ? "10y" : createDuration;
    const endsAt = new Date(Date.now() + durationToMs(effectiveDuration)).toISOString();

    try {
      await api.createSilence({
        matchers: validMatchers,
        ends_at: endsAt,
        comment: comment.trim(),
        kind: createKind,
      });

      setCreateModalOpen(false);
      setComment("");
      setView(createKind === "permanent" ? "permanent" : "temporary");
      setOriginFilter("all");
      await loadSilences();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setActionError(err.message);
      } else {
        setActionError("Erro ao criar silence.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenExtendModal = (silence: Silence) => {
    setSelectedSilenceForExtend(silence);
    setExtendDuration("4h");
    setExtendError(null);
    setExtendModalOpen(true);
  };

  const handleExtendSilence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSilenceForExtend) return;

    setExtending(true);
    setExtendError(null);

    try {
      await api.extendSilence(selectedSilenceForExtend.id, extendDuration);
      setExtendModalOpen(false);
      await loadSilences();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setExtendError(err.message);
      } else {
        setExtendError("Erro ao prolongar silence.");
      }
    } finally {
      setExtending(false);
    }
  };

  const handleDeleteSilence = async (silence: Silence) => {
    const isPermanent = kindOf(silence) === "permanent";
    const question = isPermanent
      ? "Revogar esta EXCEÇÃO PERMANENTE? A regra de detecção voltará a disparar imediatamente."
      : "Tem certeza que deseja expirar/remover este silence agora?";
    if (!confirm(question)) {
      return;
    }
    setDeletingId(silence.id);
    try {
      await api.deleteSilence(silence.id);
      await loadSilences();
    } catch (err: unknown) {
      if (err instanceof Error) {
        alert(`Erro ao remover silence: ${err.message}`);
      }
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="flex flex-col w-full pb-16 space-y-space-lg">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-space-md pt-space-xs">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 font-code-sm text-code-sm text-outline uppercase tracking-wider mb-0.5">
            <span>DANTE</span>
            <span>/</span>
            <span>MONITORAMENTO</span>
            <span>/</span>
            <span className="text-on-surface font-semibold">SILENCES &amp; EXCEÇÕES</span>
          </div>
          <div className="flex items-center gap-3">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">
              Silences &amp; Exceções
            </h1>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-surface-container-high text-outline font-code-sm text-code-sm">
              Alertmanager Engine v0.26
            </span>
          </div>
          <p className="font-body-md text-body-md text-on-surface-variant max-w-3xl">
            Exceções permanentes às regras de detecção e supressões temporárias programadas para mitigação de falsos positivos e janelas operacionais.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-space-sm self-start md:self-auto">
          {/* Status de Sincronização em Tempo Real */}
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-container-low border border-outline-variant/30 font-code-sm text-code-sm">
            <span className={`w-2 h-2 rounded-full ${autoRefresh ? "bg-tertiary animate-pulse" : "bg-outline"}`}></span>
            <span className="text-on-surface font-medium">Tempo Real: {autoRefresh ? "10s" : "Pausado"}</span>
            <button
              type="button"
              onClick={() => setAutoRefresh(!autoRefresh)}
              className="text-xs text-secondary hover:underline ml-1"
              title={autoRefresh ? "Pausar atualização automática" : "Ativar atualização automática (10s)"}
            >
              {autoRefresh ? "Pausar" : "Ativar"}
            </button>
            <span className="text-outline text-[11px] hidden sm:inline">
              ({lastUpdated.toLocaleTimeString("pt-BR")})
            </span>
          </div>

          <button
            onClick={() => loadSilences(false)}
            disabled={loading || isRefreshing}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors shadow-sm disabled:opacity-50"
            type="button"
          >
            <span className={`material-symbols-outlined text-[16px] text-outline ${isRefreshing ? "animate-spin" : ""}`}>refresh</span>
            <span>Atualizar</span>
          </button>
          <button
            onClick={() => handleOpenCreateModal()}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary font-headline-md text-body-sm tracking-wide shadow-[0_0_14px_rgba(225,29,72,0.35)] transition-all active:scale-[0.98]"
            type="button"
          >
            <span className="material-symbols-outlined text-[18px]">notifications_paused</span>
            <span>+ Novo Silence</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-space-sm rounded-lg bg-error-container text-on-error-container text-sm">
          {error}
        </div>
      )}

      {/* Split Tabs & Métrica de Alertas Silenciados (Grid 3 cards) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
        <button
          onClick={() => {
            setView("permanent");
            setOriginFilter("all");
          }}
          className={`w-full text-left p-space-md rounded-xl transition-all duration-200 relative overflow-hidden group shadow-md ${
            view === "permanent"
              ? "bg-surface-container-low shadow-lg ring-1 ring-primary/40"
              : "bg-surface-container-lowest hover:bg-surface-container-low opacity-75 hover:opacity-100"
          }`}
          type="button"
        >
          <div className={`absolute top-0 left-0 right-0 h-0.5 ${view === "permanent" ? "bg-primary-container" : "bg-transparent"}`}></div>
          <div className="flex items-center justify-between gap-space-sm mb-1">
            <div className="flex items-center gap-2">
              <span className={`material-symbols-outlined text-[20px] ${view === "permanent" ? "text-primary" : "text-outline"}`}>lock_clock</span>
              <span className="font-headline-md text-headline-md text-on-surface font-semibold">Exceções Permanentes</span>
            </div>
            <span className={`font-code-sm text-code-sm px-2 py-0.5 rounded-full font-semibold ${view === "permanent" ? "bg-surface-container-highest text-primary" : "bg-surface-container-high text-outline"}`}>
              {permanentSilences.length}
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-outline mb-2">
            Silences contínuos sem prazo de expiração que suprimem regras específicas para tráfego e serviços conhecidos.
          </p>
          <div className="flex items-center gap-1.5 font-code-sm text-xs">
            <span className="text-outline">Impacto em tempo real:</span>
            <span className={`font-bold px-1.5 py-0.2 rounded ${totalPermanentSilencedAlerts > 0 ? "bg-amber-500/20 text-amber-300" : "bg-surface-container-highest text-outline"}`}>
              {totalPermanentSilencedAlerts} alerta(s) silenciado(s)
            </span>
          </div>
        </button>

        <button
          onClick={() => {
            setView("temporary");
            setOriginFilter("all");
          }}
          className={`w-full text-left p-space-md rounded-xl transition-all duration-200 relative overflow-hidden group shadow-md ${
            view === "temporary"
              ? "bg-surface-container-low shadow-lg ring-1 ring-secondary/40"
              : "bg-surface-container-lowest hover:bg-surface-container-low opacity-75 hover:opacity-100"
          }`}
          type="button"
        >
          <div className={`absolute top-0 left-0 right-0 h-0.5 ${view === "temporary" ? "bg-secondary" : "bg-transparent"}`}></div>
          <div className="flex items-center justify-between gap-space-sm mb-1">
            <div className="flex items-center gap-2">
              <span className={`material-symbols-outlined text-[20px] ${view === "temporary" ? "text-secondary" : "text-outline"}`}>timer</span>
              <span className="font-headline-md text-headline-md text-on-surface font-semibold">Silences Temporários</span>
            </div>
            <span className={`font-code-sm text-code-sm px-2 py-0.5 rounded-full font-semibold ${view === "temporary" ? "bg-surface-container-highest text-secondary" : "bg-surface-container-high text-outline"}`}>
              {temporarySilences.length}
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-outline mb-2">
            Antiflood, janelas de manutenção de infraestrutura e supressões manuais com agendamento estrito.
          </p>
          <div className="flex items-center gap-1.5 font-code-sm text-xs">
            <span className="text-outline">Impacto em tempo real:</span>
            <span className={`font-bold px-1.5 py-0.2 rounded ${totalTemporarySilencedAlerts > 0 ? "bg-amber-500/20 text-amber-300" : "bg-surface-container-highest text-outline"}`}>
              {totalTemporarySilencedAlerts} alerta(s) silenciado(s)
            </span>
          </div>
        </button>

        {/* Card de KPI Global de Alertas Silenciados Agora */}
        <div className="p-space-md rounded-xl bg-surface-container-low relative overflow-hidden shadow-md flex flex-col justify-between border border-outline-variant/20">
          <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-amber-500 to-tertiary"></div>
          <div>
            <div className="flex items-center justify-between gap-space-sm mb-1">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[20px] text-amber-400">notifications_off</span>
                <span className="font-headline-md text-headline-md text-on-surface font-semibold">Alertas Silenciados Agora</span>
              </div>
              <span className={`font-code-sm text-code-sm px-2.5 py-0.5 rounded-full font-bold ${
                totalActiveSilencedAlerts > 0 ? "bg-amber-500/20 text-amber-300 animate-pulse border border-amber-500/40" : "bg-surface-container-highest text-outline"
              }`}>
                {totalActiveSilencedAlerts} Ativo{totalActiveSilencedAlerts > 1 ? "s" : ""}
              </span>
            </div>
            <p className="font-body-sm text-body-sm text-outline">
              Instâncias de telemetria ativamente suprimidas e contidas pelos silences em tempo real no Alertmanager.
            </p>
          </div>

          <div className="pt-2 mt-2 border-t border-outline-variant/20 flex items-center justify-between">
            <button
              type="button"
              onClick={() => setOnlySilencingAlerts(!onlySilencingAlerts)}
              className={`text-xs font-code-sm flex items-center gap-1.5 px-2 py-1 rounded transition-colors ${
                onlySilencingAlerts
                  ? "bg-amber-500/20 text-amber-300 font-semibold border border-amber-500/30"
                  : "bg-surface-container text-outline hover:text-on-surface"
              }`}
            >
              <span className="material-symbols-outlined text-[14px]">
                {onlySilencingAlerts ? "check_box" : "check_box_outline_blank"}
              </span>
              <span>Filtrar apenas com alertas silenciados</span>
            </button>
          </div>
        </div>
      </div>

      {/* Info Banner */}
      <div className="flex items-start gap-3 p-3.5 rounded-xl bg-surface-container-lowest text-on-surface-variant">
        <div className="p-1 rounded bg-secondary-container/10 text-secondary mt-0.5 flex items-center justify-center">
          <span className="material-symbols-outlined text-[18px]">info</span>
        </div>
        <div className="flex-1 font-body-sm text-body-sm leading-relaxed">
          {view === "permanent" ? (
            <span>
              Exceções permanentes não expiram e suprimem a regra de detecção de forma contínua. As instâncias mostradas abaixo refletem a telemetria que está sendo contida <strong className="text-on-surface">em tempo real</strong> pelo engine.
            </span>
          ) : (
            <span>
              Supressões com prazo definido (<span className="text-on-surface font-semibold">antiflood</span> e <span className="text-on-surface font-semibold">janelas de manutenção</span>) expiram automaticamente no término indicado, restaurando os disparos imediatamente para os canais de telemetria integrados.
            </span>
          )}
        </div>
        <div className="hidden sm:flex items-center gap-1.5 px-2 py-1 rounded bg-surface-container-low font-code-sm text-code-sm text-outline">
          <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
          <span>Engine Ativo</span>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-space-md rounded-xl bg-surface-container-low space-y-3 shadow-md">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-space-sm">
          <div className="relative flex-1">
            <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-[18px] text-outline">search</span>
            <input
              className="w-full h-9 pl-9 pr-9 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm placeholder:text-outline/60 focus:outline-none focus:ring-1 focus:ring-secondary"
              placeholder="Filtrar por comentário, usuário ou critério (matcher)..."
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <kbd className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded bg-surface-container font-code-sm text-code-sm text-outline select-none">/</kbd>
          </div>

          <div className="flex flex-wrap items-center gap-space-sm">
            <div className="relative">
              <select
                className="h-9 px-3 pr-8 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm appearance-none cursor-pointer focus:outline-none"
                value={clientFilter}
                onChange={(e) => setClientFilter(e.target.value)}
              >
                <option value="all">Todos os Clientes</option>
                {clientFolders.map((f) => (
                  <option key={f.uid} value={f.title}>
                    Cliente: {f.title}
                  </option>
                ))}
              </select>
              <span className="material-symbols-outlined absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-[16px] text-outline">expand_more</span>
            </div>

            <div className="relative">
              <select
                className="h-9 px-3 pr-8 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm appearance-none cursor-pointer focus:outline-none"
                value={stateFilter}
                onChange={(e) => setStateFilter(e.target.value)}
              >
                <option value="active">Status: Ativos</option>
                <option value="expired">Status: Expirados</option>
                <option value="pending">Status: Agendados</option>
                <option value="all">Status: Todos</option>
              </select>
              <span className="material-symbols-outlined absolute right-2 top-1/2 -translate-y-1/2 pointer-events-none text-[16px] text-outline">expand_more</span>
            </div>

            <div className="flex items-center px-3 py-1.5 rounded-lg bg-surface-container-lowest font-code-sm text-code-sm text-outline">
              <span className="text-on-surface font-semibold text-primary">{visibleSilences.length}</span>
              <span className="ml-1">de {baseSilences.length} silences</span>
            </div>
          </div>
        </div>

        {view === "temporary" && (
          <div className="flex items-center justify-between flex-wrap gap-2 pt-1 border-t border-outline-variant/20">
            <div className="flex items-center gap-1.5 overflow-x-auto py-1">
              <button
                onClick={() => setOriginFilter("all")}
                className={`px-2.5 py-1 rounded font-code-sm text-code-sm font-semibold transition-colors flex items-center gap-1.5 ${
                  originFilter === "all" ? "bg-primary-container text-on-primary-container" : "bg-surface-container-lowest text-on-surface-variant hover:bg-surface-container"
                }`}
                type="button"
              >
                <span>Todos</span>
                <span className="bg-black/20 px-1 rounded text-code-sm">{temporarySilences.length}</span>
              </button>
              <button
                onClick={() => setOriginFilter("antiflood")}
                className={`px-2.5 py-1 rounded font-code-sm text-code-sm transition-colors flex items-center gap-1.5 ${
                  originFilter === "antiflood" ? "bg-primary-container text-on-primary-container font-semibold" : "bg-surface-container-lowest text-on-surface-variant hover:bg-surface-container"
                }`}
                type="button"
              >
                <span>Antiflood</span>
              </button>
              <button
                onClick={() => setOriginFilter("maintenance")}
                className={`px-2.5 py-1 rounded font-code-sm text-code-sm transition-colors flex items-center gap-1.5 ${
                  originFilter === "maintenance" ? "bg-primary-container text-on-primary-container font-semibold" : "bg-surface-container-lowest text-on-surface-variant hover:bg-surface-container"
                }`}
                type="button"
              >
                <span>Manutenção</span>
              </button>
              <button
                onClick={() => setOriginFilter("manual")}
                className={`px-2.5 py-1 rounded font-code-sm text-code-sm transition-colors flex items-center gap-1.5 ${
                  originFilter === "manual" ? "bg-primary-container text-on-primary-container font-semibold" : "bg-surface-container-lowest text-on-surface-variant hover:bg-surface-container"
                }`}
                type="button"
              >
                <span>Manual</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Silences Cards List */}
      <div className="space-y-space-md">
        {loading ? (
          <div className="py-12 text-center text-outline font-body-sm">Carregando supressões e exceções...</div>
        ) : visibleSilences.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-12 rounded-xl bg-surface-container-low text-center space-y-4">
            <div className="w-14 h-14 rounded-full bg-surface-container-highest flex items-center justify-center text-outline shadow-inner">
              <span className="material-symbols-outlined text-[28px]">notifications_paused</span>
            </div>
            <div className="space-y-1 max-w-md">
              <p className="font-headline-md text-headline-md text-on-surface font-semibold">
                Nenhum silence encontrado
              </p>
              <p className="font-body-sm text-body-sm text-outline">
                {onlySilencingAlerts
                  ? "Não há nenhum silence com alertas ativamente silenciados para os filtros atuais."
                  : view === "permanent"
                  ? "Não há nenhuma exceção permanente ativa cadastrada no Alertmanager."
                  : "Não há nenhuma janela de manutenção ou supressão temporária com contagem regressiva ativa para o filtro aplicado."}
              </p>
            </div>
            {onlySilencingAlerts ? (
              <button
                onClick={() => setOnlySilencingAlerts(false)}
                className="px-3 py-1.5 rounded-lg bg-surface-container-highest hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors"
                type="button"
              >
                Limpar filtro de alertas silenciados
              </button>
            ) : view === "temporary" ? (
              <button
                onClick={() => handleOpenCreateModal("maintenance")}
                className="px-3 py-1.5 rounded-lg bg-surface-container-highest hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors inline-flex items-center gap-2"
                type="button"
              >
                <span className="material-symbols-outlined text-[16px] text-primary">add_alarm</span>
                <span>Agendar Janela de Manutenção</span>
              </button>
            ) : null}
          </div>
        ) : (
          visibleSilences.map((silence) => {
            const isPerm = kindOf(silence) === "permanent";
            const isActive = silence.state === "active";
            const isPending = silence.state === "pending";
            const count = silence.silenced_alerts_count || 0;
            const isExpanded = expandedSilenceId === silence.id;

            return (
              <div
                key={silence.id}
                className="rounded-xl bg-surface-container-low p-space-md transition-all hover:bg-surface-container relative overflow-hidden group shadow-md"
              >
                <div
                  className={`absolute left-0 top-0 bottom-0 w-1 ${
                    count > 0
                      ? "bg-amber-400"
                      : isPerm
                      ? "bg-primary-container"
                      : "bg-secondary"
                  }`}
                ></div>

                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-sm pb-space-sm">
                  <div className="flex flex-wrap items-center gap-space-sm">
                    <div className="flex items-center gap-1.5 font-code-sm text-code-sm px-2 py-0.5 rounded bg-surface-container-lowest text-primary font-bold">
                      <span className="material-symbols-outlined text-[14px]">{isPerm ? "lock" : "timer"}</span>
                      <span>#{silence.id.slice(0, 8)}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded font-code-sm text-code-sm uppercase tracking-wide font-semibold ${
                      isPerm ? "bg-primary-container/20 text-primary" : "bg-secondary/20 text-secondary"
                    }`}>
                      {isPerm ? "Permanente" : silence.kind || "Temporário"}
                    </span>
                    <span className="flex items-center gap-1 font-body-sm text-body-sm text-outline">
                      <span className={`w-1.5 h-1.5 rounded-full ${isActive ? "bg-tertiary" : isPending ? "bg-amber-400" : "bg-outline"}`}></span>
                      <span>{isActive ? "Ativo & Em vigor" : isPending ? "Agendado" : "Expirado"}</span>
                    </span>

                    {/* BADGE DESTACADO DE ALERTAS SILENCIADOS EM TEMPO REAL */}
                    {count > 0 ? (
                      <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/40 text-amber-300 font-headline-md text-code-sm shadow-sm animate-pulse">
                        <span className="material-symbols-outlined text-[15px] text-amber-400">notifications_off</span>
                        <span className="font-bold">{count}</span>
                        <span>alerta{count > 1 ? "s" : ""} silenciado{count > 1 ? "s" : ""} agora</span>
                      </div>
                    ) : (
                      <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-surface-container-lowest/80 border border-outline-variant/30 text-outline font-code-sm text-code-sm">
                        <span className="material-symbols-outlined text-[14px] text-outline">notifications_paused</span>
                        <span>0 alertas silenciados no momento</span>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 self-end lg:self-auto">
                    {!isPerm && (isActive || isPending) && (
                      <button
                        onClick={() => handleOpenExtendModal(silence)}
                        className="px-2.5 py-1 rounded bg-surface-container-lowest hover:bg-surface-container-highest text-on-surface-variant hover:text-on-surface font-body-sm text-body-sm transition-colors flex items-center gap-1"
                        title="Prolongar tempo de silenciamento"
                        type="button"
                      >
                        <span className="material-symbols-outlined text-[15px]">update</span>
                        <span>Prolongar</span>
                      </button>
                    )}
                    {(isActive || isPending) && (
                      <button
                        onClick={() => handleDeleteSilence(silence)}
                        disabled={deletingId === silence.id}
                        className="px-2.5 py-1 rounded bg-error-container/20 hover:bg-error-container text-error hover:text-on-error-container font-body-sm text-body-sm transition-colors flex items-center gap-1"
                        title="Revogar supressão"
                        type="button"
                      >
                        <span className="material-symbols-outlined text-[15px]">delete_forever</span>
                        <span>{deletingId === silence.id ? "..." : isPerm ? "Revogar" : "Encerrar"}</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="py-space-xs">
                  <p className="font-headline-md text-headline-md text-on-surface leading-snug font-medium">
                    {cleanComment(silence.comment)}
                  </p>
                  <p className="font-body-sm text-body-sm text-outline mt-1">
                    Criado por <span className="text-on-surface font-medium">{silence.created_by || "SecOps"}</span> em{" "}
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {silence.starts_at ? new Date(silence.starts_at).toLocaleString("pt-BR") : "—"}
                    </span>{" "}
                    • Expiração:{" "}
                    <span className={isPerm ? "text-primary font-medium" : "text-secondary font-medium"}>
                      {isPerm ? "Sem expiração definida (Permanente)" : silence.ends_at ? `${new Date(silence.ends_at).toLocaleString("pt-BR")} (${formatRemaining(silence.ends_at)})` : "—"}
                    </span>
                  </p>
                </div>

                {/* PAINEL INFORMATIVO EM TEMPO REAL: ALERTAS SILENCIADOS */}
                {count > 0 ? (
                  <div className="mt-2.5 p-3 rounded-lg bg-surface-container-lowest/80 border border-amber-500/30 flex flex-col gap-2 shadow-inner">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <span className="material-symbols-outlined text-[18px] text-amber-400 animate-pulse">volume_off</span>
                        <span className="font-headline-md text-body-sm text-on-surface font-medium">
                          Impacto em Tempo Real:{" "}
                          <span className="text-amber-300 font-bold">
                            {count} alerta{count > 1 ? "s" : ""} ativo{count > 1 ? "s" : ""}
                          </span>{" "}
                          suprimido{count > 1 ? "s" : ""} por esta exceção
                        </span>
                      </div>
                      {silence.silenced_alerts && silence.silenced_alerts.length > 0 && (
                        <button
                          type="button"
                          onClick={() => setExpandedSilenceId(isExpanded ? null : silence.id)}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-bright text-xs text-on-surface font-code-sm transition-colors"
                        >
                          <span>{isExpanded ? "Ocultar Alertas" : "Inspecionar Alertas"}</span>
                          <span className="material-symbols-outlined text-[14px]">
                            {isExpanded ? "expand_less" : "expand_more"}
                          </span>
                        </button>
                      )}
                    </div>

                    {/* Detalhes dos alertas silenciados (Dropdown/Expansível) */}
                    {isExpanded && silence.silenced_alerts && silence.silenced_alerts.length > 0 && (
                      <div className="mt-1 pt-2 border-t border-outline-variant/20 space-y-1.5">
                        <div className="text-[11px] text-outline font-code-sm uppercase tracking-wider">
                          Instâncias de Telemetria Suprimidas no Momento:
                        </div>
                        <div className="max-h-48 overflow-y-auto space-y-1.5 pr-1">
                          {silence.silenced_alerts.map((alt: SilencedAlertSummary, aIdx: number) => (
                            <div
                              key={alt.fingerprint || aIdx}
                              className="p-2 rounded bg-surface-container flex items-center justify-between text-xs gap-2"
                            >
                              <div className="flex items-center gap-2 flex-1 min-w-0">
                                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0"></span>
                                <span className="font-semibold text-on-surface truncate">{alt.alertname}</span>
                                {alt.grafana_folder && (
                                  <span className="px-1.5 py-0.2 rounded bg-surface-container-highest text-outline font-code-sm">
                                    {alt.grafana_folder}
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2 flex-shrink-0 text-outline font-code-sm text-[11px]">
                                {alt.severity && (
                                  <span className={`px-1.5 py-0.2 rounded uppercase font-bold text-[10px] ${
                                    alt.severity === "critical"
                                      ? "bg-error-container text-error"
                                      : "bg-amber-500/20 text-amber-300"
                                  }`}>
                                    {alt.severity}
                                  </span>
                                )}
                                <span>
                                  {alt.starts_at ? new Date(alt.starts_at).toLocaleTimeString("pt-BR") : "—"}
                                </span>
                                <span className="text-outline/70">#{alt.fingerprint.slice(0, 8)}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="mt-2 px-2.5 py-1.5 rounded-lg bg-surface-container-lowest/40 border border-outline-variant/20 flex items-center gap-2 text-xs text-outline">
                    <span className="material-symbols-outlined text-[15px] text-tertiary">check_circle</span>
                    <span>Nenhum alerta correspondente ativo no momento (telemetria normal e não afetada).</span>
                  </div>
                )}

                <div className="mt-3 pt-3 bg-surface-container-lowest/60 -mx-space-md -mb-space-md p-space-md rounded-b-xl flex flex-col md:flex-row md:items-center justify-between gap-space-sm">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="font-label-uppercase text-label-uppercase uppercase text-outline mr-1 tracking-wider text-xs">Matchers:</span>
                    {silence.matchers.map((m, idx) => (
                      <div key={idx} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface border border-outline-variant/20">
                        <span className="text-outline">{m.name}</span>
                        <span className={m.is_regex ? "text-tertiary" : "text-primary"}>
                          {m.is_equal ? (m.is_regex ? "=~" : "=") : (m.is_regex ? "!~" : "!=")}
                        </span>
                        <span className="text-secondary font-medium">"{m.value}"</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Modal Criar Silence */}
      <Modal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        maxWidth="680px"
        title="Criar Nova Supressão (Silence)"
      >
        <form onSubmit={handleCreateSilence} className="flex flex-col gap-space-md text-on-surface">
          <div className="grid grid-cols-2 gap-space-sm p-1 rounded-lg bg-surface-container-lowest">
            <button
              type="button"
              onClick={() => setCreateKind("permanent")}
              className={`flex items-center justify-center gap-2 py-1.5 px-3 rounded-md font-body-sm text-body-sm font-semibold transition-all ${
                createKind === "permanent" ? "bg-primary-container text-on-primary-container shadow" : "text-outline hover:text-on-surface"
              }`}
            >
              <span className="material-symbols-outlined text-[16px]">lock</span>
              <span>Exceção Permanente</span>
            </button>
            <button
              type="button"
              onClick={() => setCreateKind("maintenance")}
              className={`flex items-center justify-center gap-2 py-1.5 px-3 rounded-md font-body-sm text-body-sm font-semibold transition-all ${
                createKind !== "permanent" ? "bg-primary-container text-on-primary-container shadow" : "text-outline hover:text-on-surface"
              }`}
            >
              <span className="material-symbols-outlined text-[16px]">timer</span>
              <span>Supressão Temporária</span>
            </button>
          </div>

          {actionError && (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">
              {actionError}
            </div>
          )}

          <div className="space-y-1">
            <label className="font-label-uppercase text-xs text-outline uppercase block">
              Justificativa / Comentário Operacional *
            </label>
            <input
              type="text"
              required
              className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm placeholder:text-outline/60 focus:outline-none focus:ring-1 focus:ring-primary"
              placeholder="Ex.: Manutenção preventiva no host srv-sql-01 ou falso positivo homologado"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
            />
          </div>

          {createKind !== "permanent" && (
            <div className="space-y-1">
              <label className="font-label-uppercase text-xs text-outline uppercase block">
                Duração da Supressão
              </label>
              <select
                className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none"
                value={createDuration}
                onChange={(e) => setCreateDuration(e.target.value as Duration)}
              >
                <option value="2h">2 Horas</option>
                <option value="4h">4 Horas (Padrão)</option>
                <option value="8h">8 Horas</option>
                <option value="24h">24 Horas (1 dia)</option>
                <option value="3d">3 Dias</option>
              </select>
            </div>
          )}

          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="font-label-uppercase text-xs text-outline uppercase">
                Critérios de Supressão (Matchers)
              </label>
              <button
                type="button"
                onClick={handleAddMatcher}
                className="font-code-sm text-xs text-secondary hover:underline flex items-center gap-1"
              >
                <span className="material-symbols-outlined text-[14px]">add</span>
                <span>Adicionar Matcher</span>
              </button>
            </div>

            <div className="p-space-sm rounded-lg bg-surface-container-lowest space-y-2">
              {matchersList.map((m, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="label_name"
                    className="w-1/3 h-8 px-2.5 rounded bg-surface-container text-on-surface font-code-sm text-xs focus:outline-none"
                    value={m.name}
                    onChange={(e) => handleMatcherChange(idx, "name", e.target.value)}
                  />
                  <select
                    className="w-20 h-8 px-1 rounded bg-surface-container text-on-surface font-code-sm text-xs focus:outline-none"
                    value={m.is_equal ? (m.is_regex ? "=~" : "=") : (m.is_regex ? "!~" : "!=")}
                    onChange={(e) => {
                      const val = e.target.value;
                      handleMatcherChange(idx, "is_equal", val === "=" || val === "=~");
                      handleMatcherChange(idx, "is_regex", val === "=~" || val === "!~");
                    }}
                  >
                    <option value="=">=</option>
                    <option value="=~">=~ (Regex)</option>
                    <option value="!=">!=</option>
                    <option value="!~">!~</option>
                  </select>
                  <input
                    type="text"
                    placeholder="valor ou regex"
                    className="flex-1 h-8 px-2.5 rounded bg-surface-container text-on-surface font-code-sm text-xs focus:outline-none"
                    value={m.value}
                    onChange={(e) => handleMatcherChange(idx, "value", e.target.value)}
                  />
                  {matchersList.length > 1 && (
                    <button
                      type="button"
                      onClick={() => handleRemoveMatcher(idx)}
                      className="text-outline hover:text-error p-1"
                    >
                      <span className="material-symbols-outlined text-[16px]">close</span>
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-sm"
              onClick={() => setCreateModalOpen(false)}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold shadow disabled:opacity-50"
            >
              {submitting ? "Criando..." : "Confirmar e Ativar Silence"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal Prolongar Silence */}
      <Modal
        isOpen={extendModalOpen}
        onClose={() => setExtendModalOpen(false)}
        maxWidth="480px"
        title="Prolongar Silence"
      >
        <form onSubmit={handleExtendSilence} className="flex flex-col gap-space-md text-on-surface">
          <p className="text-sm text-outline">
            Estenda o tempo de silenciamento deste alerta a partir do momento atual.
          </p>

          {extendError && (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">
              {extendError}
            </div>
          )}

          <div>
            <label className="text-xs text-outline uppercase block mb-1">Tempo Adicional</label>
            <select
              className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none"
              value={extendDuration}
              onChange={(e) => setExtendDuration(e.target.value as Duration)}
            >
              <option value="2h">+ 2 Horas</option>
              <option value="4h">+ 4 Horas</option>
              <option value="8h">+ 8 Horas</option>
              <option value="24h">+ 24 Horas (1 dia)</option>
              <option value="3d">+ 3 Dias</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded-lg bg-surface-container-high text-on-surface text-sm"
              onClick={() => setExtendModalOpen(false)}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={extending}
              className="px-4 py-1.5 rounded-lg bg-primary-container text-on-primary text-sm font-semibold disabled:opacity-50"
            >
              {extending ? "Prolongando..." : "Confirmar Prolongamento"}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
