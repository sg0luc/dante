import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { Modal } from "../components/Modal";
import { AlertInstance } from "../types";

export const AlertsPage: React.FC = () => {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState<AlertInstance[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [syncCountdown, setSyncCountdown] = useState<number>(10);
  const [selectedAlertForDetail, setSelectedAlertForDetail] = useState<AlertInstance | null>(null);

  // Filtros avançados
  const [search, setSearch] = useState("");
  const [selectedTenant, setSelectedTenant] = useState<string>("all");
  const [selectedState, setSelectedState] = useState<string>("all");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedMitre, setSelectedMitre] = useState<string>("all");
  const searchInputRef = useRef<HTMLInputElement>(null);

  const loadAlerts = async () => {
    try {
      setError(null);
      const data = await api.getAlerts();
      setAlerts(data);
      setSyncCountdown(10);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Erro ao carregar instâncias de alerta.");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(() => {
      setSyncCountdown((prev) => {
        if (prev <= 1) {
          loadAlerts();
          return 10;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Atalho de teclado '/' para focar na busca
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "/" && document.activeElement !== searchInputRef.current) {
        e.preventDefault();
        searchInputRef.current?.focus();
        searchInputRef.current?.select();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Clientes únicos identificados nos alertas
  const availableTenants = useMemo(() => {
    const set = new Set<string>();
    alerts.forEach((a) => {
      const client = a.labels.client || a.labels.grafana_folder;
      if (client) set.add(client);
    });
    return Array.from(set).sort();
  }, [alerts]);

  // Técnicas MITRE únicas identificadas nos alertas
  const availableMitreTechniques = useMemo(() => {
    const set = new Set<string>();
    alerts.forEach((a) => {
      const tech = a.labels.mitre_technique;
      if (tech) set.add(tech);
    });
    return Array.from(set).sort();
  }, [alerts]);

  // Alertas filtrados
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      const term = search.toLowerCase().trim();
      const matchSearch =
        !term ||
        a.alertname.toLowerCase().includes(term) ||
        Object.entries(a.labels).some(([k, v]) =>
          `${k}=${v}`.toLowerCase().includes(term) || `${k}:${v}`.toLowerCase().includes(term)
        );

      const client = a.labels.client || a.labels.grafana_folder || "";
      const matchTenant = selectedTenant === "all" || client.toLowerCase() === selectedTenant.toLowerCase();

      const state = (a.state || "").toLowerCase();
      const isFiring = state === "active" || state === "firing" || state === "alerting";
      const isSilenced = a.silenced_by && a.silenced_by.length > 0;
      let matchState = true;
      if (selectedState === "firing") {
        matchState = isFiring && !isSilenced;
      } else if (selectedState === "silenced") {
        matchState = isSilenced || state === "suppressed";
      } else if (selectedState === "resolved") {
        matchState = state === "normal" || state === "ok" || state === "resolved";
      }

      const sev = (a.labels.severity || "medium").toLowerCase();
      const matchSeverity = selectedSeverity === "all" || sev === selectedSeverity.toLowerCase();

      const tech = a.labels.mitre_technique || "";
      const matchMitre = selectedMitre === "all" || tech.toLowerCase() === selectedMitre.toLowerCase();

      return matchSearch && matchTenant && matchState && matchSeverity && matchMitre;
    });
  }, [alerts, search, selectedTenant, selectedState, selectedSeverity, selectedMitre]);

  // Contadores para os scorecards
  const firingCount = useMemo(() => {
    return alerts.filter(
      (a) => (a.state?.toLowerCase() === "active" || a.state?.toLowerCase() === "firing" || a.state?.toLowerCase() === "alerting") && (!a.silenced_by || a.silenced_by.length === 0)
    ).length;
  }, [alerts]);

  const silencedCount = useMemo(() => {
    return alerts.filter((a) => (a.silenced_by && a.silenced_by.length > 0) || a.state?.toLowerCase() === "suppressed").length;
  }, [alerts]);

  const criticalCount = useMemo(() => {
    return alerts.filter((a) => {
      const sev = (a.labels.severity || "").toLowerCase();
      return sev === "critical" || sev === "high";
    }).length;
  }, [alerts]);

  const formatRelativeTime = (isoString?: string) => {
    if (!isoString) return "N/D";
    const date = new Date(isoString);
    if (isNaN(date.getTime())) return "N/D";
    const diffMs = Date.now() - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHours = Math.floor(diffMin / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffDays > 0) return `há ${diffDays}d`;
    if (diffHours > 0) return `há ${diffHours}h`;
    if (diffMin > 0) return `há ${diffMin} min`;
    return `há ${Math.max(1, diffSec)}s`;
  };

  const handleCreateSilenceForAlert = (alert: AlertInstance) => {
    const params = new URLSearchParams();
    params.set("create", "1");
    if (alert.labels.client) params.set("client", alert.labels.client);
    if (alert.alertname) params.set("alertname", alert.alertname);
    if (alert.labels.host) params.set("host", alert.labels.host);
    navigate(`/silences?${params.toString()}`);
  };

  return (
    <div className="flex flex-col w-full pb-12">
      {/* Sub-header Breadcrumb & Operational State Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-space-lg gap-space-sm">
        <div className="flex flex-col gap-space-xs">
          <div className="flex items-center gap-space-xs font-code-sm text-code-sm text-outline">
            <span className="hover:text-on-surface transition-colors cursor-pointer">DANTE</span>
            <span>/</span>
            <span className="hover:text-on-surface transition-colors cursor-pointer">MONITORAMENTO &amp; OPERAÇÃO</span>
            <span>/</span>
            <span className="text-primary font-semibold">ALERTAS</span>
          </div>
          <div className="flex items-baseline gap-space-md">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">
              Alertas
            </h1>
            <span className="font-code-sm text-code-sm text-on-surface-variant bg-surface-container-high px-2 py-0.5 rounded-sm">
              Alertmanager Live Feed v2.4
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-outline max-w-2xl">
            Instâncias ativas e suprimidas pelo Alertmanager (atualização automática a cada 10s via SSE / Prometheus Engine).
          </p>
        </div>

        {/* Quick Action / Polling Telemetry Controls */}
        <div className="flex items-center gap-space-sm self-start md:self-auto">
          <div className="flex items-center gap-2 px-space-sm py-1.5 rounded-lg bg-surface-container-low shadow-sm">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-tertiary"></span>
            </span>
            <span className="font-code-sm text-code-sm text-on-surface-variant">
              Sync: <span className="text-tertiary font-semibold">{syncCountdown}s</span>
            </span>
          </div>
          <button
            onClick={loadAlerts}
            disabled={loading}
            className="flex items-center gap-1.5 px-space-md py-1.5 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-container-highest transition-all duration-150 active:scale-[0.98] font-body-sm text-body-sm shadow-sm"
            type="button"
            title="Atualizar lista de alertas"
          >
            <span className={`material-symbols-outlined text-[16px] text-tertiary ${loading ? "animate-spin" : ""}`}>
              refresh
            </span>
            <span>Atualizar</span>
          </button>
          <Link
            to="/silences"
            className="flex items-center gap-1.5 px-space-md py-1.5 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-variant transition-all duration-150 font-body-sm text-body-sm shadow-sm"
            title="Gerenciar silences e exceções"
          >
            <span className="material-symbols-outlined text-[16px] text-outline">notifications_paused</span>
            <span className="hidden sm:inline">Silences</span>
          </Link>
          <Link
            to="/rules"
            className="flex items-center gap-1 px-space-sm py-1.5 rounded-lg bg-primary-container text-on-primary-container hover:opacity-90 transition-opacity font-body-sm text-body-sm font-semibold shadow-sm"
            title="Nova regra de detecção"
          >
            <span className="material-symbols-outlined text-[16px]">add_alert</span>
            <span className="hidden lg:inline">Nova Regra</span>
          </Link>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-space-md rounded-xl bg-error-container/20 border border-error-container text-error font-body-sm">
          {error}
        </div>
      )}

      {/* Operational Telemetry Bar / KPI Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-space-sm mb-space-lg">
        {/* Card 1: Instâncias Firing */}
        <div className="bg-surface-container-low p-space-md rounded-lg flex flex-col justify-between shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-outline font-label-uppercase text-label-uppercase uppercase">
            <span>Instâncias Firing</span>
            <span className="material-symbols-outlined text-primary-container text-[18px]">local_fire_department</span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-metric-display text-metric-display text-primary font-bold">
              {firingCount}
            </span>
            <span className="font-code-sm text-code-sm text-primary-container font-semibold">
              {alerts.length ? `${Math.round((firingCount / alerts.length) * 100)}% ativos` : "0%"}
            </span>
          </div>
          <div className="w-full bg-surface-container-highest h-1 rounded-full mt-3 overflow-hidden">
            <div
              className="bg-primary-container h-full transition-all"
              style={{ width: `${alerts.length ? (firingCount / alerts.length) * 100 : 0}%` }}
            ></div>
          </div>
        </div>

        {/* Card 2: Silenciados (Muted) */}
        <div className="bg-surface-container-low p-space-md rounded-lg flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between text-outline font-label-uppercase text-label-uppercase uppercase">
            <span>Silenciados (Muted)</span>
            <span className="material-symbols-outlined text-secondary text-[18px]">notifications_off</span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-metric-display text-metric-display text-on-surface font-bold">
              {silencedCount}
            </span>
            <span className="font-code-sm text-code-sm text-outline">
              {silencedCount === 1 ? "1 supressão ativa" : `${silencedCount} supressões ativas`}
            </span>
          </div>
          <div className="w-full bg-surface-container-highest h-1 rounded-full mt-3 overflow-hidden">
            <div
              className="bg-secondary-container h-full transition-all"
              style={{ width: `${alerts.length ? (silencedCount / alerts.length) * 100 : 0}%` }}
            ></div>
          </div>
        </div>

        {/* Card 3: Críticos & Alto Impacto */}
        <div className="bg-surface-container-low p-space-md rounded-lg flex flex-col justify-between shadow-sm">
          <div className="flex items-center justify-between text-outline font-label-uppercase text-label-uppercase uppercase">
            <span>Críticos &amp; Alto Impacto</span>
            <span className="material-symbols-outlined text-error text-[18px]">crisis_alert</span>
          </div>
          <div className="flex items-baseline gap-2 mt-2">
            <span className="font-metric-display text-metric-display text-error font-bold">
              {criticalCount}
            </span>
            <span className="font-code-sm text-code-sm text-outline">
              {alerts.length ? `${Math.round((criticalCount / alerts.length) * 100)}% da fila` : "0%"}
            </span>
          </div>
          <div className="w-full bg-surface-container-highest h-1 rounded-full mt-3 overflow-hidden">
            <div
              className="bg-error h-full transition-all"
              style={{ width: `${alerts.length ? (criticalCount / alerts.length) * 100 : 0}%` }}
            ></div>
          </div>
        </div>
      </div>

      {/* Advanced SIEM Filter Command Strip */}
      <div className="bg-surface-container-low p-space-md rounded-lg mb-space-md flex flex-col gap-space-sm shadow-md">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center gap-space-sm justify-between">
          {/* Primary Search Input with Hotkey */}
          <div className="relative flex-1 min-w-[280px]">
            <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-outline text-[18px]">
              search
            </span>
            <input
              ref={searchInputRef}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-8 pl-8 pr-12 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm placeholder:text-outline/70 focus:outline-none focus:ring-1 focus:ring-secondary transition-all"
              placeholder="Buscar por nome do alerta ou labels (ex: host=srv-*, mitre_technique=T1055)..."
              type="text"
            />
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-outline">
              /
            </span>
          </div>

          {/* Quick Dropdown Controls */}
          <div className="flex flex-wrap items-center gap-space-xs">
            {/* Tenant Filter */}
            <div className="relative">
              <select
                value={selectedTenant}
                onChange={(e) => setSelectedTenant(e.target.value)}
                className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container font-body-sm text-body-sm text-on-surface focus:outline-none cursor-pointer hover:bg-surface-container-high transition-colors"
              >
                <option value="all">Todos os Clientes</option>
                {availableTenants.map((tenant) => (
                  <option key={tenant} value={tenant}>
                    {tenant}
                  </option>
                ))}
              </select>
              <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[16px] pointer-events-none">
                expand_more
              </span>
            </div>

            {/* Status Filter */}
            <div className="relative">
              <select
                value={selectedState}
                onChange={(e) => setSelectedState(e.target.value)}
                className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container font-body-sm text-body-sm text-on-surface focus:outline-none cursor-pointer hover:bg-surface-container-high transition-colors"
              >
                <option value="all">Todos os Estados</option>
                <option value="firing">Ativo (Firing)</option>
                <option value="silenced">Silenciado (Muted)</option>
                <option value="resolved">Resolvido (Histórico)</option>
              </select>
              <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[16px] pointer-events-none">
                expand_more
              </span>
            </div>

            {/* Severity Filter */}
            <div className="relative">
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container font-body-sm text-body-sm text-on-surface focus:outline-none cursor-pointer hover:bg-surface-container-high transition-colors"
              >
                <option value="all">Severidade: Todas</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[16px] pointer-events-none">
                expand_more
              </span>
            </div>

            {/* MITRE Technique Filter */}
            <div className="relative">
              <select
                value={selectedMitre}
                onChange={(e) => setSelectedMitre(e.target.value)}
                className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container font-body-sm text-body-sm text-on-surface focus:outline-none cursor-pointer hover:bg-surface-container-high transition-colors"
              >
                <option value="all">Técnica MITRE</option>
                {availableMitreTechniques.map((tech) => (
                  <option key={tech} value={tech}>
                    {tech}
                  </option>
                ))}
              </select>
              <span className="material-symbols-outlined absolute right-1.5 top-1/2 -translate-y-1/2 text-outline text-[16px] pointer-events-none">
                expand_more
              </span>
            </div>
          </div>
        </div>

        {/* Active Tag Query Chips Bar & Realtime Count */}
        <div className="flex items-center justify-between pt-1 text-outline">
          <div className="flex flex-wrap items-center gap-space-xs font-code-sm text-code-sm">
            <span className="text-outline uppercase text-[10px] tracking-widest font-semibold mr-1">
              Filtros Ativos:
            </span>
            {search && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-high text-on-surface">
                <span>busca = {search}</span>
                <button onClick={() => setSearch("")} className="hover:text-primary transition-colors leading-none" type="button">
                  <span className="material-symbols-outlined text-[12px]">close</span>
                </button>
              </span>
            )}
            {selectedTenant !== "all" && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-high text-on-surface">
                <span>client = {selectedTenant}</span>
                <button onClick={() => setSelectedTenant("all")} className="hover:text-primary transition-colors leading-none" type="button">
                  <span className="material-symbols-outlined text-[12px]">close</span>
                </button>
              </span>
            )}
            {selectedState !== "all" && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-high text-on-surface">
                <span>state = {selectedState}</span>
                <button onClick={() => setSelectedState("all")} className="hover:text-primary transition-colors leading-none" type="button">
                  <span className="material-symbols-outlined text-[12px]">close</span>
                </button>
              </span>
            )}
            {selectedSeverity !== "all" && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-high text-on-surface">
                <span>severity = {selectedSeverity}</span>
                <button onClick={() => setSelectedSeverity("all")} className="hover:text-primary transition-colors leading-none" type="button">
                  <span className="material-symbols-outlined text-[12px]">close</span>
                </button>
              </span>
            )}
            {selectedMitre !== "all" && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-high text-on-surface">
                <span>mitre = {selectedMitre}</span>
                <button onClick={() => setSelectedMitre("all")} className="hover:text-primary transition-colors leading-none" type="button">
                  <span className="material-symbols-outlined text-[12px]">close</span>
                </button>
              </span>
            )}
            {(search || selectedTenant !== "all" || selectedState !== "all" || selectedSeverity !== "all" || selectedMitre !== "all") && (
              <button
                onClick={() => {
                  setSearch("");
                  setSelectedTenant("all");
                  setSelectedState("all");
                  setSelectedSeverity("all");
                  setSelectedMitre("all");
                }}
                className="text-secondary hover:underline ml-1"
                type="button"
              >
                Limpar todos
              </button>
            )}
          </div>
          <div className="font-code-sm text-code-sm text-outline flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
            <span className="text-on-surface font-semibold">{filteredAlerts.length}</span> de <span>{alerts.length}</span> alertas listados
          </div>
        </div>
      </div>

      {/* High-Density Alert Table Feed */}
      <div className="bg-surface-container-lowest rounded-lg shadow-xl overflow-hidden mb-space-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[1020px]">
            <thead>
              <tr className="bg-surface-container-low text-outline font-label-uppercase text-label-uppercase uppercase">
                <th className="py-2.5 px-space-md w-28">Estado</th>
                <th className="py-2.5 px-space-md w-[320px]">Alerta &amp; Descrição</th>
                <th className="py-2.5 px-space-md">Labels / Metadata Técnica</th>
                <th className="py-2.5 px-space-md w-36">Disparado em</th>
                <th className="py-2.5 px-space-md w-32 text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="font-body-sm text-body-sm divide-y divide-surface-container/30">
              {loading ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-outline font-body-sm">
                    Carregando feed de alertas em tempo real...
                  </td>
                </tr>
              ) : filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-outline font-body-sm">
                    Nenhum alerta correspondente aos filtros aplicados.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert) => {
                  const state = (alert.state || "").toLowerCase();
                  const isFiring = state === "active" || state === "firing" || state === "alerting";
                  const isSilenced = alert.silenced_by && alert.silenced_by.length > 0;
                  const severity = (alert.labels.severity || "medium").toUpperCase();
                  const description =
                    alert.annotations.description ||
                    alert.annotations.summary ||
                    alert.annotations.message ||
                    "Sem descrição operacional detalhada.";

                  const startsAtDate = alert.starts_at ? new Date(alert.starts_at) : null;
                  const formattedDate = startsAtDate && !isNaN(startsAtDate.getTime())
                    ? startsAtDate.toLocaleDateString("pt-BR")
                    : "—";
                  const formattedTime = startsAtDate && !isNaN(startsAtDate.getTime())
                    ? startsAtDate.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" }) + " UTC"
                    : "—";

                  return (
                    <tr key={alert.fingerprint || `${alert.alertname}-${alert.starts_at}`} className="hover:bg-surface-container/60 transition-colors group">
                      <td className="py-3 px-space-md align-top">
                        {isFiring && !isSilenced ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-error-container text-on-error-container font-code-sm text-code-sm font-semibold shadow-[0_0_8px_rgba(225,29,72,0.2)]">
                            <span className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-container opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-primary-container"></span>
                            </span>
                            Ativo
                          </span>
                        ) : isSilenced ? (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-surface-container-highest text-secondary font-code-sm text-code-sm font-semibold">
                            <span className="material-symbols-outlined text-[13px]">notifications_off</span>
                            Silenciado
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-tertiary-container/30 text-tertiary font-code-sm text-code-sm font-semibold">
                            <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                            Normal
                          </span>
                        )}
                        <div className="mt-1.5 font-code-sm text-code-sm text-primary font-semibold">
                          SEV: {severity}
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <div className="flex flex-col gap-1">
                          <button
                            type="button"
                            onClick={() => setSelectedAlertForDetail(alert)}
                            className="text-left font-headline-md text-headline-md text-on-surface hover:text-secondary transition-colors font-bold leading-snug cursor-pointer"
                          >
                            {alert.alertname}
                          </button>
                          <p className="font-body-sm text-body-sm text-outline leading-tight">
                            {description}
                            {alert.labels.host && (
                              <> em <span className="font-code-sm text-code-sm text-on-surface bg-surface-container px-1 py-0.5 rounded">{alert.labels.host}</span></>
                            )}
                          </p>
                          <div className="flex items-center gap-2 mt-1 flex-wrap">
                            {alert.labels.mitre_tactic && (
                              <span className="inline-flex items-center gap-1 text-[11px] font-code-sm text-secondary bg-surface-container px-1.5 py-0.5 rounded">
                                <span className="material-symbols-outlined text-[12px]">security</span>
                                {alert.labels.mitre_tactic}
                              </span>
                            )}
                            {alert.labels.rule_uid && (
                              <span className="text-[11px] font-code-sm text-outline">
                                UID: {alert.labels.rule_uid}
                              </span>
                            )}
                          </div>
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <div className="flex flex-wrap gap-1 font-code-sm text-code-sm">
                          {Object.entries(alert.labels).map(([key, val]) => {
                            let badgeStyle = "bg-surface-container text-on-surface";
                            if (key === "severity") badgeStyle = "bg-surface-container-high text-primary font-semibold";
                            if (key === "mitre_technique") badgeStyle = "bg-secondary-container/20 text-secondary font-semibold";
                            if (key === "mitre_tactic") badgeStyle = "bg-surface-container text-secondary";
                            if (key === "synthetic") badgeStyle = "bg-surface-container text-tertiary";
                            if (key === "client") badgeStyle = "bg-surface-container text-tertiary-fixed font-semibold";
                            if (key === "host") badgeStyle = "bg-surface-container text-on-surface font-semibold";

                            return (
                              <span
                                key={key}
                                className={`inline-block px-1.5 py-0.5 rounded max-w-[280px] truncate ${badgeStyle}`}
                                title={`${key}=${val}`}
                              >
                                <span className="text-outline">{key}=</span>
                                {val}
                              </span>
                            );
                          })}
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top whitespace-nowrap">
                        <div className="font-code-sm text-code-sm text-on-surface font-medium">{formattedDate}</div>
                        <div className="font-code-sm text-code-sm text-outline">{formattedTime}</div>
                        <div className="font-body-sm text-body-sm text-primary font-medium mt-0.5">
                          {formatRelativeTime(alert.starts_at || undefined)}
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top text-right">
                        <div className="flex flex-col items-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => handleCreateSilenceForAlert(alert)}
                            className="w-full flex items-center justify-center gap-1 px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-variant text-on-surface font-body-sm text-body-sm transition-colors shadow-sm"
                            title="Criar silence com base neste alerta"
                          >
                            <span className="material-symbols-outlined text-[14px]">notifications_off</span>
                            <span>Silenciar</span>
                          </button>
                          <div className="flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => setSelectedAlertForDetail(alert)}
                              className="p-1 rounded text-outline hover:text-secondary hover:bg-surface-container transition-colors"
                              title="Ver detalhes técnicos completos"
                            >
                              <span className="material-symbols-outlined text-[16px]">info</span>
                            </button>
                            <Link
                              to={`/rules?search=${encodeURIComponent(alert.labels.rule_uid || alert.alertname)}`}
                              className="p-1 rounded text-outline hover:text-secondary hover:bg-surface-container transition-colors"
                              title="Localizar regra no catálogo"
                            >
                              <span className="material-symbols-outlined text-[16px]">code_blocks</span>
                            </Link>
                            <Link
                              to="/loki"
                              className="p-1 rounded text-outline hover:text-tertiary hover:bg-surface-container transition-colors"
                              title="Testar telemetria no laboratório"
                            >
                              <span className="material-symbols-outlined text-[16px]">terminal</span>
                            </Link>
                          </div>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Table Footer / Pagination & Quick Diagnostics */}
        <div className="bg-surface-container-low px-space-md py-2.5 flex flex-col sm:flex-row items-center justify-between gap-space-sm font-code-sm text-code-sm text-outline border-t border-outline-variant/20">
          <div className="flex items-center gap-space-sm">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-tertiary"></span>
              Alerting &amp; Telemetry Engine: OK
            </span>
            <span className="text-surface-variant">|</span>
            <span>Alertmanager Ingest: Ativo</span>
          </div>
          <div className="flex items-center gap-space-md">
            <span>Total exibido: <strong className="text-on-surface">{filteredAlerts.length}</strong></span>
          </div>
        </div>
      </div>

      {/* Alert Detail Modal */}
      {selectedAlertForDetail && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedAlertForDetail(null)}
          title={`Detalhes do Alerta: ${selectedAlertForDetail.alertname}`}
        >
          <div className="space-y-4 font-body-sm text-body-sm">
            <div className="p-3 rounded-lg bg-surface-container-low flex items-center justify-between">
              <div>
                <span className="font-label-uppercase text-label-uppercase uppercase text-outline block">
                  Estado Operacional
                </span>
                <span className="font-headline-md text-headline-md text-on-surface font-bold uppercase">
                  {selectedAlertForDetail.state}
                </span>
              </div>
              <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-error-container text-on-error-container font-semibold">
                SEV: {(selectedAlertForDetail.labels.severity || "medium").toUpperCase()}
              </span>
            </div>

            <div>
              <span className="font-label-uppercase text-label-uppercase uppercase text-outline block mb-1">
                Anotações
              </span>
              <div className="p-3 rounded-lg bg-surface-container-lowest font-code-sm text-code-sm space-y-1">
                {Object.entries(selectedAlertForDetail.annotations).map(([k, v]) => (
                  <div key={k} className="flex flex-col">
                    <span className="text-outline font-semibold">{k}:</span>
                    <span className="text-on-surface whitespace-pre-wrap">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <span className="font-label-uppercase text-label-uppercase uppercase text-outline block mb-1">
                Labels de Telemetria
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5 p-3 rounded-lg bg-surface-container-lowest font-code-sm text-code-sm max-h-56 overflow-y-auto">
                {Object.entries(selectedAlertForDetail.labels).map(([k, v]) => (
                  <div key={k} className="flex items-center justify-between px-2 py-1 rounded bg-surface-container">
                    <span className="text-outline">{k}:</span>
                    <span className="text-on-surface font-semibold">{v}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-outline-variant/30">
              <button
                type="button"
                onClick={() => setSelectedAlertForDetail(null)}
                className="px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface"
              >
                Fechar
              </button>
              <button
                type="button"
                onClick={() => {
                  const alertToSilence = selectedAlertForDetail;
                  setSelectedAlertForDetail(null);
                  handleCreateSilenceForAlert(alertToSilence);
                }}
                className="px-3 py-1.5 rounded-lg bg-primary-container text-on-primary-container font-semibold"
              >
                Silenciar Este Alerta
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
