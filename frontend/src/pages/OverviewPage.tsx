import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import {
  AlertHistoryResponse,
  AlertInstance,
  GlobalRuleMatrixItem,
  RuleSummary,
  Silence,
  TechnologyOverview,
  PausedRulesMatchesResponse,
} from "../types";

/** A pasta `global` é o baseline de referência, não um cliente integrado. */
const isBaselineFolder = (folderUid: string, folderTitle: string): boolean =>
  folderUid.toLowerCase() === "global" || folderTitle.toLowerCase() === "global";

const normalizeRuleTitle = (title: string): string =>
  (title || "").replace(/^\[.*?\]\s*/, "").trim().toLowerCase();

export type TimelineTimeRange = "1h" | "6h" | "12h" | "24h" | "3d" | "7d";

interface TimeRangeConfig {
  key: TimelineTimeRange;
  label: string;
  durationMs: number;
  bucketCount: number;
  formatBucketLabel: (start: Date, end: Date) => string;
}

const TIME_RANGE_CONFIGS: Record<TimelineTimeRange, TimeRangeConfig> = {
  "1h": {
    key: "1h",
    label: "1 hora",
    durationMs: 1 * 60 * 60 * 1000,
    bucketCount: 12,
    formatBucketLabel: (start) =>
      `${start.getHours().toString().padStart(2, "0")}:${start.getMinutes().toString().padStart(2, "0")}`,
  },
  "6h": {
    key: "6h",
    label: "6 horas",
    durationMs: 6 * 60 * 60 * 1000,
    bucketCount: 12,
    formatBucketLabel: (start) =>
      `${start.getHours().toString().padStart(2, "0")}:${start.getMinutes().toString().padStart(2, "0")}`,
  },
  "12h": {
    key: "12h",
    label: "12 horas",
    durationMs: 12 * 60 * 60 * 1000,
    bucketCount: 12,
    formatBucketLabel: (start) =>
      `${start.getHours().toString().padStart(2, "0")}:00`,
  },
  "24h": {
    key: "24h",
    label: "24 horas",
    durationMs: 24 * 60 * 60 * 1000,
    bucketCount: 24,
    formatBucketLabel: (start) =>
      `${start.getHours().toString().padStart(2, "0")}:00`,
  },
  "3d": {
    key: "3d",
    label: "3 dias",
    durationMs: 3 * 24 * 60 * 60 * 1000,
    bucketCount: 12,
    formatBucketLabel: (start) =>
      `${start.getDate().toString().padStart(2, "0")}/${(start.getMonth() + 1).toString().padStart(2, "0")} ${start.getHours().toString().padStart(2, "0")}h`,
  },
  "7d": {
    key: "7d",
    label: "7 dias",
    durationMs: 7 * 24 * 60 * 60 * 1000,
    bucketCount: 14,
    formatBucketLabel: (start) =>
      `${start.getDate().toString().padStart(2, "0")}/${(start.getMonth() + 1).toString().padStart(2, "0")} ${start.getHours().toString().padStart(2, "0")}h`,
  },
};

export const OverviewPage: React.FC = () => {
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [alerts, setAlerts] = useState<AlertInstance[]>([]);
  const [alertHistory, setAlertHistory] = useState<AlertHistoryResponse | null>(null);
  const [silences, setSilences] = useState<Silence[]>([]);
  const [globalMatrix, setGlobalMatrix] = useState<GlobalRuleMatrixItem[]>([]);
  const [techOverview, setTechOverview] = useState<TechnologyOverview | null>(null);
  const [pausedMatches, setPausedMatches] = useState<PausedRulesMatchesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timelineTimeRange, setTimelineTimeRange] = useState<TimelineTimeRange>("24h");
  const [clientSearch, setClientSearch] = useState("");
  const [syncSeconds, setSyncSeconds] = useState(0);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [r, a, s, gm, tech, hist, pm] = await Promise.all([
        api.getRules(),
        api.getAlerts(),
        api.getSilences(),
        api.getGlobalMatrix().catch(() => []),
        api.getTechnologyOverview().catch(() => null),
        api.getAlertHistory(168).catch(() => null),
        api.getPausedRulesMatches("15m").catch(() => null),
      ]);
      setRules(r);
      setAlerts(a);
      setSilences(s);
      setGlobalMatrix(gm);
      setTechOverview(tech);
      setAlertHistory(hist);
      setPausedMatches(pm);
      setSyncSeconds(0);
    } catch (err: any) {
      setError(err.message || "Erro ao carregar visão geral do portal");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      setSyncSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Baseline x Custom
  const baselineRules = useMemo(
    () => rules.filter((r) => isBaselineFolder(r.folder_uid, r.folder_title)),
    [rules]
  );
  const baselineRuleTitles = useMemo(
    () => new Set(baselineRules.map((r) => normalizeRuleTitle(r.title))),
    [baselineRules]
  );
  const customRules = useMemo(
    () =>
      rules.filter(
        (r) =>
          !isBaselineFolder(r.folder_uid, r.folder_title) &&
          !baselineRuleTitles.has(normalizeRuleTitle(r.title))
      ),
    [rules, baselineRuleTitles]
  );


  const suppressedAlerts = useMemo(
    () => alerts.filter((a) => a.state?.toLowerCase() === "suppressed"),
    [alerts]
  );

  const activeSilences = useMemo(
    () => silences.filter((s) => s.state === "active"),
    [silences]
  );

  const firingRulesCount = useMemo(
    () => rules.filter((r) => r.state?.toLowerCase() === "firing" || r.state?.toLowerCase() === "alerting").length,
    [rules]
  );

  const pausedRulesCount = useMemo(
    () => rules.filter((r) => r.is_paused).length,
    [rules]
  );

  // Alertas ativos nos ltimos 15 minutos segregados por severidade (crtico > alto > mdio)
  const recentActiveAlerts = useMemo(() => {
    const now = Date.now();
    const fifteenMinutesAgo = now - 15 * 60 * 1000;
    return alerts.filter((a) => {
      const state = (a.state || "").toLowerCase();
      if (state !== "active" && state !== "firing") return false;
      if (!a.starts_at) return true;
      const ts = new Date(a.starts_at).getTime();
      return isNaN(ts) || ts >= fifteenMinutesAgo;
    });
  }, [alerts]);

  const activeAlertsSeverityCounts = useMemo(() => {
    let critical = 0;
    let high = 0;
    let medium = 0;
    recentActiveAlerts.forEach((a) => {
      const sev = (a.labels?.severity || "").toLowerCase();
      if (sev === "critical") critical++;
      else if (sev === "high") high++;
      else if (sev === "medium" || sev === "warning") medium++;
    });
    return { critical, high, medium, total: recentActiveAlerts.length };
  }, [recentActiveAlerts]);

  // Alertas suprimidos nos ltimos 15 minutos (por silences)
  const recentSuppressedAlertsCount = useMemo(() => {
    const now = Date.now();
    const fifteenMinutesAgo = now - 15 * 60 * 1000;
    return alerts.filter((a) => {
      const state = (a.state || "").toLowerCase();
      if (state !== "suppressed") return false;
      if (!a.starts_at) return true;
      const ts = new Date(a.starts_at).getTime();
      return isNaN(ts) || ts >= fifteenMinutesAgo;
    }).length;
  }, [alerts]);

  // Silences segregados: permanentes vs temporrios
  const permanentSilencesCount = useMemo(
    () => activeSilences.filter((s) => s.kind === "permanent").length,
    [activeSilences]
  );
  const temporarySilencesCount = useMemo(
    () => activeSilences.filter((s) => s.kind !== "permanent").length,
    [activeSilences]
  );


  // Clientes integrados
  const clientDistribution = useMemo(() => {
    const map = new Map<
      string,
      {
        folderUid: string;
        folderTitle: string;
        total: number;
        active: number;
        paused: number;
        firing: number;
      }
    >();

    rules.forEach((r) => {
      const folderKey = r.folder_uid;
      const existing = map.get(folderKey) || {
        folderUid: r.folder_uid,
        folderTitle: r.folder_title || r.folder_uid,
        total: 0,
        active: 0,
        paused: 0,
        firing: 0,
      };

      existing.total += 1;
      if (r.is_paused) existing.paused += 1;
      else existing.active += 1;
      if (r.state === "firing") existing.firing += 1;

      map.set(folderKey, existing);
    });

    return Array.from(map.values())
      .filter((client) => !isBaselineFolder(client.folderUid, client.folderTitle))
      .sort((a, b) => b.total - a.total);
  }, [rules]);

  // Tecnologias por cliente
  const clientTechnologies = useMemo(() => {
    const map = new Map<string, { count: number; names: string[] }>();
    (techOverview?.technologies ?? []).forEach((tech) => {
      tech.clients.forEach((client) => {
        if (!client.integrated) return;
        const current = map.get(client.client_uid) || { count: 0, names: [] };
        current.count += 1;
        current.names.push(tech.name);
        map.set(client.client_uid, current);
      });
    });
    return map;
  }, [techOverview]);

  // Conformidade Baseline
  const clientComplianceMap = useMemo(() => {
    const map = new Map<
      string,
      { implementedBaseline: number; totalBaseline: number; compliancePct: number }
    >();
    const totalBaseline = globalMatrix.length || baselineRules.length || 1;

    globalMatrix.forEach((gRule) => {
      gRule.clients.forEach((c) => {
        const cur = map.get(c.client_uid) || {
          implementedBaseline: 0,
          totalBaseline,
          compliancePct: 0,
        };
        if (c.status === "active" || c.status === "paused") {
          cur.implementedBaseline += 1;
        }
        map.set(c.client_uid, cur);
      });
    });

    map.forEach((val) => {
      val.compliancePct =
        totalBaseline > 0
          ? Math.min(100, Math.round((val.implementedBaseline / totalBaseline) * 100))
          : 0;
    });

    return { map, totalBaseline };
  }, [globalMatrix, baselineRules]);

  // Filtro de clientes na tabela
  const filteredClients = useMemo(() => {
    if (!clientSearch.trim()) return clientDistribution;
    const term = clientSearch.toLowerCase();
    return clientDistribution.filter(
      (c) =>
        c.folderTitle.toLowerCase().includes(term) ||
        c.folderUid.toLowerCase().includes(term)
    );
  }, [clientDistribution, clientSearch]);

  // Histograma de alertas (buckets dinâmicos alimentados pelo histórico real)
  const histogramBuckets = useMemo(() => {
    const cfg = TIME_RANGE_CONFIGS[timelineTimeRange];
    const now = Date.now();
    const windowStart = now - cfg.durationMs;
    const bucketDuration = cfg.durationMs / cfg.bucketCount;

    const buckets = Array.from({ length: cfg.bucketCount }, (_, i) => {
      const bStart = windowStart + i * bucketDuration;
      const bEnd = bStart + bucketDuration;
      return {
        start: new Date(bStart),
        end: new Date(bEnd),
        firing: 0,
        silenced: 0,
      };
    });

    const seenEventKeys = new Set<string>();

    // 1. Eventos reais históricos (anotações de transição do Grafana + sintéticos)
    const historyEvents = alertHistory?.events || [];
    historyEvents.forEach((ev) => {
      const ts = ev.timestamp ? new Date(ev.timestamp).getTime() : NaN;
      if (!isNaN(ts) && ts >= windowStart && ts <= now) {
        seenEventKeys.add(`${ev.alertname}-${Math.floor(ts / 60000)}`);
        const bIdx = Math.min(
          cfg.bucketCount - 1,
          Math.max(0, Math.floor((ts - windowStart) / bucketDuration))
        );
        if (ev.state === "silenced") {
          buckets[bIdx].silenced += 1;
        } else {
          buckets[bIdx].firing += 1;
        }
      }
    });

    // 2. Instâncias ativas/suprimidas no Alertmanager que possam ainda não ter virado anotação
    alerts.forEach((alert) => {
      if (!alert.starts_at) return;
      const ts = new Date(alert.starts_at).getTime();
      if (!isNaN(ts) && ts >= windowStart && ts <= now) {
        const key = `${alert.alertname}-${Math.floor(ts / 60000)}`;
        if (!seenEventKeys.has(key)) {
          seenEventKeys.add(key);
          const bIdx = Math.min(
            cfg.bucketCount - 1,
            Math.max(0, Math.floor((ts - windowStart) / bucketDuration))
          );
          if (alert.state?.toLowerCase() === "suppressed") {
            buckets[bIdx].silenced += 1;
          } else {
            buckets[bIdx].firing += 1;
          }
        }
      }
    });

    return buckets;
  }, [alertHistory, alerts, timelineTimeRange]);

  // Totais agregados do período selecionado
  const timelinePeriodTotals = useMemo(() => {
    let firing = 0;
    let silenced = 0;
    histogramBuckets.forEach((b) => {
      firing += b.firing;
      silenced += b.silenced;
    });
    return {
      firing,
      silenced,
      total: firing + silenced,
    };
  }, [histogramBuckets]);

  // Rótulos dinâmicos do eixo X (horários e datas abaixo dos buckets)
  const timelineTicks = useMemo(() => {
    const cfg = TIME_RANGE_CONFIGS[timelineTimeRange];
    const now = Date.now();
    const windowStart = now - cfg.durationMs;

    const pad = (n: number) => n.toString().padStart(2, "0");

    const formatTick = (ts: number, isLast: boolean): string => {
      if (isLast) return "Agora";
      const d = new Date(ts);

      if (timelineTimeRange === "1h" || timelineTimeRange === "6h" || timelineTimeRange === "12h") {
        return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
      }
      if (timelineTimeRange === "24h") {
        return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
      }
      if (timelineTimeRange === "3d") {
        return `${pad(d.getDate())}/${pad(d.getMonth() + 1)} ${pad(d.getHours())}h`;
      }
      // 7d
      return `${pad(d.getDate())}/${pad(d.getMonth() + 1)}`;
    };

    const tickCount = timelineTimeRange === "7d" ? 7 : 6;
    const ticks: { label: string; isLast: boolean; timeStr: string }[] = [];

    for (let i = 0; i < tickCount; i++) {
      const ts = windowStart + (i / (tickCount - 1)) * cfg.durationMs;
      const isLast = i === tickCount - 1;
      const d = new Date(ts);
      ticks.push({
        label: formatTick(ts, isLast),
        isLast,
        timeStr: `${pad(d.getHours())}:${pad(d.getMinutes())}`,
      });
    }

    return ticks;
  }, [timelineTimeRange]);

  return (
    <div className="flex flex-col w-full space-y-space-lg pb-12">
      {/* Top Bar / Page Header Context */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md pt-space-xs">
        <div className="flex flex-col space-y-1">
          <div className="flex items-center gap-space-sm">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight">
              Visão Geral
            </h1>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant max-w-3xl">
            Monitoramento consolidado de regras de detecção, clientes e alertas ativos integrado ao Grafana Alerting e Loki Ruler.
          </p>
        </div>

        {/* Global Controls */}
        <div className="flex items-center flex-wrap gap-space-sm">
          <div className="flex items-center gap-2 px-space-sm py-1.5 rounded-lg bg-surface-container-low text-on-surface-variant font-code-sm text-code-sm">
            <span className="material-symbols-outlined text-[16px] text-tertiary">
              sync
            </span>
            <span>
              Sincronizado há{" "}
              <strong className="text-on-surface font-semibold">
                {syncSeconds}s
              </strong>
            </span>
          </div>

          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface text-body-sm font-body-sm transition-all shadow-sm active:scale-95 disabled:opacity-50"
            title="Atualizar dados agora"
            type="button"
          >
            <span
              className={`material-symbols-outlined text-[16px] ${
                loading ? "animate-spin" : ""
              }`}
            >
              refresh
            </span>
            <span>Atualizar</span>
          </button>

          <Link
            to="/rules"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-primary-container text-on-primary-container text-body-sm font-body-sm font-semibold hover:opacity-90 transition-all shadow-[0_0_14px_rgba(225,29,72,0.3)] active:scale-95"
          >
            <span className="material-symbols-outlined text-[18px]">add</span>
            <span>Nova Regra</span>
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-error-container/20 border border-error-container text-error font-body-sm">
          {error}
        </div>
      )}

      {/* KPI Scorecards Grid (5 Cards mirroring baseline metrics) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-space-sm">
        {/* Card 1: Regras de Detecção */}
        <div className="p-space-md rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between group hover:bg-surface-container transition-colors relative overflow-hidden">
          <div className="flex items-start justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
              Regras de Detecção
            </span>
            <span className="p-1.5 rounded-lg bg-surface-container-high text-secondary">
              <span className="material-symbols-outlined text-[18px]">security</span>
            </span>
          </div>
          <div className="my-space-sm">
            <div className="flex items-baseline gap-2">
              <span className="font-metric-display text-metric-display text-on-surface">
                {rules.length}
              </span>
              <span className="font-code-sm text-code-sm text-tertiary bg-tertiary-container/30 px-1.5 py-0.5 rounded">
                100% OK
              </span>
            </div>
          </div>
          <div className="space-y-1.5">
            <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden flex">
              <div
                className="bg-secondary h-full"
                style={{
                  width: `${rules.length ? (baselineRules.length / rules.length) * 100 : 50}%`,
                }}
              ></div>
              <div
                className="bg-tertiary h-full"
                style={{
                  width: `${rules.length ? (customRules.length / rules.length) * 100 : 20}%`,
                }}
              ></div>
            </div>
            <p className="font-code-sm text-code-sm text-outline-variant flex items-center justify-between">
              <span>{baselineRules.length} base · {customRules.length} cust.</span>
              <span className="text-on-surface-variant font-medium">
                {rules.length - pausedRulesCount} ativas
              </span>
            </p>
          </div>
        </div>

        {/* Card 2: Regras Customizadas */}
        <div className="p-space-md rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between group hover:bg-surface-container transition-colors">
          <div className="flex items-start justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
              Regras Customizadas
            </span>
            <span className="p-1.5 rounded-lg bg-surface-container-high text-secondary-fixed-dim">
              <span className="material-symbols-outlined text-[18px]">tune</span>
            </span>
          </div>
          <div className="my-space-sm">
            <div className="flex items-baseline gap-2">
              <span className="font-metric-display text-metric-display text-on-surface">
                {customRules.length}
              </span>
              <span className="font-code-sm text-code-sm text-secondary bg-surface-container-highest px-1.5 py-0.5 rounded">
                Customizações
              </span>
            </div>
          </div>
          <div className="space-y-1.5">
            <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden">
              <div
                className="bg-secondary-fixed-dim h-full"
                style={{
                  width: `${rules.length ? (customRules.length / rules.length) * 100 : 15}%`,
                }}
              ></div>
            </div>
            <p className="font-code-sm text-code-sm text-outline-variant">
              Fora do Baseline
            </p>
          </div>
        </div>

        {/* Card 3: Regras Pausadas */}
        <div className="p-space-md rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between group hover:bg-surface-container transition-colors">
          <div className="flex items-start justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
              Regras Pausadas
            </span>
            <span
              className={`p-1.5 rounded-lg bg-surface-container-high ${
                pausedRulesCount > 0 ? "text-error" : "text-tertiary"
              }`}
            >
              <span className="material-symbols-outlined text-[18px]">
                {pausedRulesCount > 0 ? "pause_circle" : "check_circle"}
              </span>
            </span>
          </div>
          <div className="my-space-sm">
            <div className="flex items-baseline gap-2">
              <span
                className={`font-metric-display text-metric-display ${
                  pausedRulesCount > 0 ? "text-error" : "text-on-surface"
                }`}
              >
                {pausedRulesCount}
              </span>
              <span
                className={`font-code-sm text-code-sm px-1.5 py-0.5 rounded ${
                  pausedRulesCount > 0
                    ? "text-error bg-error-container/20"
                    : "text-tertiary bg-tertiary-container/20"
                }`}
              >
                {`${pausedMatches?.matching_rules_count ?? 0} Matches Agora`}
              </span>
            </div>
          </div>
          <div className="space-y-1.5">
            <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden">
              <div
                className={`${pausedRulesCount > 0 ? "bg-error" : "bg-tertiary"} h-full`}
                style={{ width: "100%" }}
              ></div>
            </div>
            <p className="font-code-sm text-code-sm text-tertiary flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
              <span>{rules.length - pausedRulesCount} ativas em avaliação contínua</span>
            </p>
          </div>
        </div>

        {/* Card 4: Alertas Ativos (Firing Highlight) */}
        <div className="p-space-md rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between group hover:bg-surface-container transition-colors relative overflow-hidden">
          <div className="absolute -right-6 -bottom-6 w-24 h-24 bg-primary-container/10 rounded-full blur-xl pointer-events-none"></div>
          <div className="flex items-start justify-between">
            <span className="font-label-uppercase text-label-uppercase text-error uppercase tracking-wider">
              Alertas Ativos
            </span>
            <span className="relative flex h-3 w-3">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-container opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-primary-container"></span>
            </span>
          </div>
          <div className="my-space-sm">
            <div className="flex items-baseline gap-2">
              <span
                className={`font-metric-display text-metric-display ${
                  firingRulesCount > 0 ? "text-primary-fixed-dim" : "text-on-surface"
                }`}
              >
                {firingRulesCount}
              </span>
              {activeAlertsSeverityCounts.critical > 0 ? (
                <span className="font-code-sm text-code-sm text-on-error-container bg-error-container px-2 py-0.5 rounded-full font-semibold flex items-center gap-1 animate-pulse">
                  <span className="material-symbols-outlined text-[13px]">warning</span>
                  {activeAlertsSeverityCounts.critical} críticos
                </span>
              ) : activeAlertsSeverityCounts.high > 0 ? (
                <span className="font-code-sm text-code-sm text-orange-200 bg-orange-950/80 border border-orange-500/40 px-2 py-0.5 rounded-full font-semibold flex items-center gap-1 animate-pulse">
                  <span className="material-symbols-outlined text-[13px]">warning</span>
                  {activeAlertsSeverityCounts.high} altos
                </span>
              ) : activeAlertsSeverityCounts.medium > 0 ? (
                <span className="font-code-sm text-code-sm text-amber-200 bg-amber-950/80 border border-amber-500/40 px-2 py-0.5 rounded-full font-semibold flex items-center gap-1">
                  <span className="material-symbols-outlined text-[13px]">info</span>
                  {activeAlertsSeverityCounts.medium} médios
                </span>
              ) : (
                <span className="font-code-sm text-code-sm text-tertiary bg-tertiary-container/30 px-1.5 py-0.5 rounded">
                  Sem Alertas
                </span>
              )}
            </div>
          </div>
          <div className="space-y-1.5">
            <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden flex">
              <div
                className="bg-primary-container h-full"
                style={{
                  width: `${firingRulesCount > 0 ? 75 : 0}%`,
                }}
              ></div>
              <div
                className="bg-secondary-container h-full"
                style={{
                  width: `${suppressedAlerts.length > 0 ? 25 : 0}%`,
                }}
              ></div>
            </div>
            <p className="font-code-sm text-code-sm text-on-surface-variant flex items-center justify-between">
              <span>{firingRulesCount} em alerta</span>
              <span className="text-secondary font-medium">{suppressedAlerts.length} suprimidos</span>
            </p>
          </div>
        </div>

        {/* Card 5: Silences Ativos */}
        <div className="p-space-md rounded-xl bg-surface-container-low shadow-sm flex flex-col justify-between group hover:bg-surface-container transition-colors">
          <div className="flex items-start justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
              Silences Ativos
            </span>
            <span className="p-1.5 rounded-lg bg-surface-container-high text-secondary">
              <span className="material-symbols-outlined text-[18px]">notifications_paused</span>
            </span>
          </div>
          <div className="my-space-sm">
            <div className="flex items-baseline gap-2">
              <span className="font-metric-display text-metric-display text-on-surface">
                {activeSilences.length}
              </span>
              <span className="font-code-sm text-code-sm text-secondary bg-surface-container-highest px-1.5 py-0.5 rounded">
                {`${recentSuppressedAlertsCount} Alertas Suprimidos`}
              </span>
            </div>
          </div>
          <div className="space-y-1.5">
            <div className="w-full bg-surface-container-highest h-1 rounded-full overflow-hidden">
              <div
                className="bg-secondary h-full"
                style={{ width: `${Math.min(100, activeSilences.length * 35)}%` }}
              ></div>
            </div>
            <p className="font-code-sm text-code-sm text-outline-variant">
              {`${permanentSilencesCount} perm. - ${temporarySilencesCount} temp.`}
            </p>
          </div>
        </div>
      </div>

      {/* Clientes Integrados Section (SIEM Dense Table) */}
      <div className="rounded-xl bg-surface-container-lowest p-space-md shadow-md space-y-space-md">
        {/* Section Header & Filters */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-space-sm">
          <div className="space-y-0.5">
            <div className="flex items-center gap-space-sm">
              <span className="material-symbols-outlined text-secondary text-[20px]">
                folder_special
              </span>
              <h2 className="font-headline-md text-headline-md text-on-surface">
                Clientes Integrados
              </h2>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              Regras de detecção e tecnologias integradas por cliente (a pasta global é a referência de 100% do baseline e não entra na lista).
            </p>
          </div>

          <div className="flex items-center gap-space-sm">
            <div className="relative">
              <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-[16px] text-outline">
                search
              </span>
              <input
                value={clientSearch}
                onChange={(e) => setClientSearch(e.target.value)}
                placeholder="Filtrar por nome ou UID..."
                type="text"
                className="h-8 pl-8 pr-3 w-56 lg:w-64 bg-surface-container-low text-on-surface font-body-sm text-body-sm rounded-lg placeholder:text-outline focus:outline-none focus:bg-surface-container transition-all"
              />
            </div>
            <span className="px-2.5 py-1 rounded-lg bg-surface-container-high font-code-sm text-code-sm text-on-surface">
              <strong className="text-tertiary">{filteredClients.length}</strong> cliente(s)
            </span>
          </div>
        </div>

        {/* High-Density Tactical Table */}
        <div className="overflow-x-auto rounded-lg bg-surface-container-low">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container h-9 text-outline font-label-uppercase text-label-uppercase uppercase tracking-wider">
                <th className="px-space-md py-1.5 font-semibold">Cliente</th>
                <th className="px-space-md py-1.5 font-semibold text-center">Total Regras</th>
                <th className="px-space-md py-1.5 font-semibold">Tecnologias</th>
                <th className="px-space-md py-1.5 font-semibold text-center">Status</th>
                <th className="px-space-md py-1.5 font-semibold text-center">Disparos</th>
                <th className="px-space-md py-1.5 font-semibold">Conformidade Baseline</th>
                <th className="px-space-md py-1.5 font-semibold text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container font-body-sm text-body-sm text-on-surface">
              {filteredClients.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-outline">
                    Nenhum cliente cadastrado ou correspondente ao filtro.
                  </td>
                </tr>
              ) : (
                filteredClients.map((client) => {
                  const clientComp = clientComplianceMap.map.get(client.folderUid);
                  const compliancePct = clientComp
                    ? clientComp.compliancePct
                    : Math.min(
                        100,
                        Math.round((client.total / (clientComplianceMap.totalBaseline || 1)) * 100)
                      );
                  const technologies = clientTechnologies.get(client.folderUid);

                  return (
                    <tr
                      key={client.folderUid}
                      className="hover:bg-surface-container/60 transition-colors group"
                    >
                      <td className="px-space-md py-2.5">
                        <div className="flex flex-col">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-tertiary"></span>
                            <span className="font-headline-md text-body-md font-semibold text-on-surface">
                              {client.folderTitle}
                            </span>
                          </div>
                          <span className="font-code-sm text-code-sm text-outline flex items-center gap-1 mt-0.5">
                            UID:{" "}
                            <code className="text-outline-variant font-code-sm">
                              {client.folderUid}
                            </code>
                          </span>
                        </div>
                      </td>

                      <td className="px-space-md py-2.5 text-center">
                        <span className="font-headline-md text-headline-md text-on-surface font-semibold">
                          {client.total}
                        </span>{" "}
                        <span className="font-code-sm text-code-sm text-outline block">regras</span>
                      </td>

                      <td className="px-space-md py-2.5">
                        {technologies && technologies.count > 0 ? (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            {technologies.names.map((n) => {
                              const isLinux = n.toLowerCase().includes("linux");
                              const isWin = n.toLowerCase().includes("win") || n.toLowerCase().includes("ad");
                              return (
                                <span
                                  key={n}
                                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-surface-container-highest text-on-surface font-code-sm text-code-sm"
                                >
                                  <span
                                    className={`material-symbols-outlined text-[13px] ${
                                      isWin ? "text-secondary" : isLinux ? "text-tertiary" : "text-outline"
                                    }`}
                                  >
                                    {isWin ? "grid_view" : isLinux ? "terminal" : "dns"}
                                  </span>
                                  {n}
                                </span>
                              );
                            })}
                          </div>
                        ) : (
                          <span className="text-outline text-code-sm font-code-sm">
                            —
                          </span>
                        )}
                      </td>

                      <td className="px-space-md py-2.5 text-center">
                        <div className="flex flex-col items-center justify-center gap-1">
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-tertiary-container/30 text-tertiary font-code-sm text-code-sm font-semibold">
                            <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                            {client.active} ativas
                          </span>
                          <span className="text-outline text-code-sm font-code-sm">
                            {client.paused > 0 ? `(${client.paused} pausadas)` : "0 pausadas"}
                          </span>
                        </div>
                      </td>

                      <td className="px-space-md py-2.5 text-center">
                        {client.firing > 0 ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded bg-error-container text-on-error-container font-code-sm text-code-sm font-semibold animate-pulse">
                            {client.firing} disparando
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded bg-surface-container-high text-tertiary font-code-sm text-code-sm font-medium">
                            Normal
                          </span>
                        )}
                      </td>

                      <td className="px-space-md py-2.5">
                        <div className="w-48 space-y-1">
                          <div className="flex items-center justify-between font-code-sm text-code-sm">
                            <span className="text-outline">Adequação</span>
                            <span
                              className={`font-semibold ${
                                compliancePct > 70
                                  ? "text-secondary-fixed"
                                  : compliancePct > 30
                                  ? "text-amber-400"
                                  : "text-primary"
                              }`}
                            >
                              {compliancePct}%
                            </span>
                          </div>
                          <div className="h-2 w-full bg-surface-container-highest rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-500 ${
                                compliancePct > 70
                                  ? "bg-secondary-fixed-dim"
                                  : compliancePct > 30
                                  ? "bg-amber-400"
                                  : "bg-primary-container"
                              }`}
                              style={{ width: `${compliancePct}%` }}
                            ></div>
                          </div>
                        </div>
                      </td>

                      <td className="px-space-md py-2.5 text-right">
                        <Link
                          to={`/rules?folder=${encodeURIComponent(client.folderTitle)}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-surface-container hover:bg-surface-container-highest text-on-surface hover:text-secondary font-code-sm text-code-sm transition-all shadow-sm"
                        >
                          <span>Regras</span>
                          <span className="material-symbols-outlined text-[14px]">
                            arrow_forward
                          </span>
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Linha do Tempo de Alertas Section (Histogram & Timeline) */}
      <div className="rounded-xl bg-surface-container-lowest p-space-md shadow-md space-y-space-md">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-sm">
          <div className="space-y-0.5">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-primary-container text-[20px]">
                stacked_bar_chart
              </span>
              <h2 className="font-headline-md text-headline-md text-on-surface">
                Linha do Tempo de Alertas{" "}
                <span className="text-outline font-normal font-code-sm text-code-sm">
                  ({TIME_RANGE_CONFIGS[timelineTimeRange].label})
                </span>
              </h2>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              Histograma cronológico de eventos disparados e suprimidos pelo Alertmanager.
            </p>
          </div>

          {/* Time Range Pills & View All Link */}
          <div className="flex items-center flex-wrap gap-2">
            <div className="inline-flex p-0.5 rounded-lg bg-surface-container-low font-code-sm text-code-sm">
              {(["1h", "6h", "12h", "24h", "3d", "7d"] as TimelineTimeRange[]).map((tr) => (
                <button
                  key={tr}
                  onClick={() => setTimelineTimeRange(tr)}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    timelineTimeRange === tr
                      ? "bg-primary-container text-on-primary-container font-semibold shadow-sm"
                      : "text-outline hover:text-on-surface"
                  }`}
                  type="button"
                >
                  {TIME_RANGE_CONFIGS[tr].label}
                </button>
              ))}
            </div>

            <Link
              to="/alerts"
              className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-surface-container-low hover:bg-surface-container text-on-surface font-code-sm text-code-sm transition-colors"
            >
              <span>Ver Todos ({alerts.length})</span>
              <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
            </Link>
          </div>
        </div>

        {/* Legend and Summary Stats */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm pt-space-xs text-body-sm font-body-sm">
          <div className="flex items-center gap-space-md">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded bg-primary-container"></span>
              <span className="text-on-surface font-medium">Disparos no Período (Firing)</span>
              <span className="font-code-sm text-code-sm px-1.5 py-0.2 rounded bg-surface-container-high text-primary-fixed-dim font-semibold">
                {timelinePeriodTotals.firing}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded bg-secondary-container"></span>
              <span className="text-on-surface font-medium">Suprimidos no Período (Silenced)</span>
              <span className="font-code-sm text-code-sm px-1.5 py-0.2 rounded bg-surface-container-high text-secondary font-semibold">
                {timelinePeriodTotals.silenced}
              </span>
            </div>
          </div>

          <div className="font-code-sm text-code-sm text-outline">
            Total no período ({TIME_RANGE_CONFIGS[timelineTimeRange].label}):{" "}
            <strong className="text-on-surface">{timelinePeriodTotals.total} alertas processados</strong>
          </div>
        </div>

        {/* Inline Vector Histogram Chart */}
        <div className="p-space-md rounded-lg bg-surface-container-low space-y-space-sm">
          <div className="relative w-full h-44 flex items-end gap-1.5 sm:gap-2 pt-6">
            {/* Background grid guides */}
            <div className="absolute inset-0 flex flex-col justify-between pointer-events-none opacity-20">
              <div className="w-full h-px bg-outline"></div>
              <div className="w-full h-px bg-outline"></div>
              <div className="w-full h-px bg-outline"></div>
              <div className="w-full h-px bg-outline"></div>
            </div>

            {/* Histogram Bars */}
            {histogramBuckets.map((b, idx) => {
              const maxVal = Math.max(
                1,
                ...histogramBuckets.map((it) => it.firing + it.silenced)
              );
              const firingH = Math.min(100, (b.firing / maxVal) * 90);
              const silencedH = Math.min(100, (b.silenced / maxVal) * 90);

              return (
                <div
                  key={idx}
                  className="flex-1 flex flex-col justify-end h-full group relative cursor-pointer"
                  title={`${b.start.toLocaleTimeString()} - Firing: ${b.firing}, Silenced: ${b.silenced}`}
                >
                  {b.firing === 0 && b.silenced === 0 ? (
                    <div className="w-full bg-surface-container-high/40 rounded-t h-2 group-hover:bg-primary/50 transition-colors"></div>
                  ) : (
                    <div className="w-full flex flex-col gap-0.5">
                      {b.silenced > 0 && (
                        <div
                          className="w-full bg-secondary-container rounded-t"
                          style={{ height: `${Math.max(6, silencedH)}px` }}
                        ></div>
                      )}
                      {b.firing > 0 && (
                        <div
                          className="w-full bg-primary-container rounded-t shadow-[0_0_12px_rgba(225,29,72,0.4)]"
                          style={{ height: `${Math.max(8, firingH)}px` }}
                        ></div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* X-Axis Labels (Dinâmicos com base no período selecionado) */}
          <div className="flex justify-between items-center text-outline font-code-sm text-code-sm pt-2 px-1">
            {timelineTicks.map((tick, idx) => (
              <span
                key={idx}
                className={tick.isLast ? "text-tertiary font-semibold" : ""}
                title={tick.isLast ? `Agora (${tick.timeStr})` : undefined}
              >
                {tick.label}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
