import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Modal } from "../components/Modal";
import {
  AdherenceClient,
  AdherenceRule,
  AdherenceStatus,
  AdherenceTechnology,
  BaselineAdherence,
  BaselinePrefixSettings,
} from "../types";

type ViewMode = "tree" | "technology" | "client";

const COLORS = {
  complete: "#10b981",
  partial: "#f59e0b",
  none: "#ef4444",
  na: "#64748b",
};

const statusColor = (pct: number, applicable = true): string => {
  if (!applicable) return COLORS.na;
  if (pct >= 100) return COLORS.complete;
  if (pct > 0) return COLORS.partial;
  return COLORS.none;
};

const STATUS_LABEL: Record<AdherenceStatus, string> = {
  complete: "Conforme",
  partial: "Parcial",
  none: "Sem adesão",
  not_applicable: "N/A",
};

const UNMAPPED = "__unmapped__";

// --- Job de implementação ----------------------------------------------------
type Job =
  | { id: string; kind: "tech"; slug: string; label: string; clientUid: string; clientName: string; missing: number }
  | { id: string; kind: "rule"; rule: AdherenceRule; label: string; clientUid: string; clientName: string; missing: number };

type Scope =
  | { type: "all" }
  | { type: "technology"; slug: string; name: string }
  | { type: "rule"; rule: AdherenceRule }
  | { type: "client"; uid: string; name: string };

type JobResult = { state: "pending" | "running" | "done" | "error"; message?: string };

const ProgressBar: React.FC<{ pct: number; applicable?: boolean; height?: number }> = ({
  pct,
  applicable = true,
  height = 6,
}) => (
  <div className="w-full rounded-full bg-surface-container-highest overflow-hidden" style={{ height }}>
    <div
      className="h-full rounded-full transition-all"
      style={{ width: `${Math.max(0, Math.min(100, pct))}%`, background: statusColor(pct, applicable) }}
    />
  </div>
);

const Kpi: React.FC<{ label: string; value: React.ReactNode; hint?: string; accent?: string }> = ({
  label,
  value,
  hint,
  accent,
}) => (
  <div className="bg-surface-container-low rounded-xl border border-outline-variant/30 p-4 flex flex-col gap-1">
    <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">{label}</span>
    <span className="font-metric-display text-metric-display font-bold" style={{ color: accent }}>
      {value}
    </span>
    {hint && <span className="font-body-xs text-body-xs text-on-surface-variant">{hint}</span>}
  </div>
);

const Donut: React.FC<{ pct: number }> = ({ pct }) => {
  const color = statusColor(pct);
  return (
    <div
      className="relative w-36 h-36 rounded-full shrink-0"
      style={{ background: `conic-gradient(${color} ${pct * 3.6}deg, rgba(100,116,139,0.25) 0deg)` }}
    >
      <div className="absolute inset-3 rounded-full bg-surface-container-low flex flex-col items-center justify-center">
        <span className="text-2xl font-bold text-on-surface">{pct.toFixed(1)}%</span>
        <span className="text-[11px] text-outline uppercase tracking-wide">adesão</span>
      </div>
    </div>
  );
};

export const AdherenceMapPage: React.FC = () => {
  const [data, setData] = useState<BaselineAdherence | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<ViewMode>("tree");
  const [search, setSearch] = useState("");
  const [onlyGaps, setOnlyGaps] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set(["root"]));
  const [prefix, setPrefix] = useState<BaselinePrefixSettings | null>(null);

  // Implementação
  const [scope, setScope] = useState<Scope | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [selectedJobs, setSelectedJobs] = useState<Set<string>>(new Set());
  const [results, setResults] = useState<Record<string, JobResult>>({});
  const [running, setRunning] = useState(false);
  const [finished, setFinished] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (silent) setRefreshing(true);
    try {
      setError(null);
      setData(await api.getBaselineAdherence());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro ao carregar o Mapa de Adesão.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    api.getBaselinePrefixSettings().then(setPrefix).catch(() => {});
  }, [load]);

  const toggle = (key: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const rulesByUid = useMemo(() => new Map((data?.rules ?? []).map((r) => [r.uid, r])), [data]);

  const matchesSearch = useCallback(
    (text: string) => !search.trim() || text.toLowerCase().includes(search.trim().toLowerCase()),
    [search]
  );

  // --- construção de jobs por escopo -----------------------------------------
  const buildJobs = useCallback(
    (sc: Scope): Job[] => {
      if (!data) return [];
      const out: Job[] = [];
      const techJobsForClient = (c: AdherenceClient, onlySlug?: string) => {
        for (const t of c.technologies) {
          if (onlySlug && t.slug !== onlySlug) continue;
          if (!t.applicable || t.missing <= 0) continue;
          out.push({
            id: `t:${t.slug}:${c.client_uid}`,
            kind: "tech",
            slug: t.slug,
            label: t.name,
            clientUid: c.client_uid,
            clientName: c.client_name,
            missing: t.missing,
          });
        }
      };
      if (sc.type === "all") data.clients.forEach((c) => techJobsForClient(c));
      else if (sc.type === "technology") data.clients.forEach((c) => techJobsForClient(c, sc.slug));
      else if (sc.type === "client") {
        const c = data.clients.find((x) => x.client_uid === sc.uid);
        if (c) techJobsForClient(c);
      } else {
        for (const cell of sc.rule.clients) {
          if (cell.applicable && cell.status === "not_implemented") {
            out.push({
              id: `r:${sc.rule.uid}:${cell.client_uid}`,
              kind: "rule",
              rule: sc.rule,
              label: sc.rule.base_title,
              clientUid: cell.client_uid,
              clientName: cell.client_name,
              missing: 1,
            });
          }
        }
      }
      return out;
    },
    [data]
  );

  const openImplement = (sc: Scope) => {
    const list = buildJobs(sc);
    setScope(sc);
    setJobs(list);
    setSelectedJobs(new Set(list.map((j) => j.id)));
    setResults({});
    setRunning(false);
    setFinished(false);
  };

  const closeImplement = () => {
    if (running) return;
    const wasFinished = finished;
    setScope(null);
    if (wasFinished) load(true);
  };

  const ruleTitleFor = async (rule: AdherenceRule, clientName: string): Promise<string> => {
    if (prefix?.enabled && /\{\{?tenant\}?\}/i.test(prefix.template || "")) {
      try {
        const res = await api.previewBaselinePrefix({
          template: prefix.template,
          title: rule.base_title,
          technology: rule.technology_slug,
          technology_name: rule.technology_name,
          tactic: rule.mitre_tactic || null,
          severity: rule.severity || null,
          tenant: clientName,
        });
        return res.preview_title;
      } catch {
        /* usa o título-base */
      }
    }
    return rule.base_title;
  };

  const runJobs = async () => {
    const todo = jobs.filter((j) => selectedJobs.has(j.id));
    if (todo.length === 0) return;
    setRunning(true);
    setFinished(false);
    setResults(Object.fromEntries(todo.map((j) => [j.id, { state: "pending" } as JobResult])));
    for (const job of todo) {
      setResults((prev) => ({ ...prev, [job.id]: { state: "running" } }));
      try {
        if (job.kind === "tech") {
          const res = await api.implementTechnologyBaseline(job.slug, {
            target_folder_uid: job.clientUid,
            target_folder_title: job.clientName,
          });
          setResults((prev) => ({
            ...prev,
            [job.id]: {
              state: res.failed > 0 ? "error" : "done",
              message: `${res.created} criada(s), ${res.skipped} já existente(s), ${res.failed} falha(s) · CP ${res.contact_point ?? "-"}`,
            },
          }));
        } else {
          const title = await ruleTitleFor(job.rule, job.clientName);
          const res = await api.duplicateRule(job.rule.uid, {
            target_folder_uid: job.clientUid,
            target_folder_title: job.clientName,
            new_title: title,
            client_name: job.clientName,
            custom_logql: job.rule.logql || undefined,
          });
          setResults((prev) => ({ ...prev, [job.id]: { state: "done", message: res.message } }));
        }
      } catch (err) {
        setResults((prev) => ({
          ...prev,
          [job.id]: { state: "error", message: err instanceof Error ? err.message : "Falha ao implementar." },
        }));
      }
    }
    setRunning(false);
    setFinished(true);
  };

  // --- derivados --------------------------------------------------------------
  const rulesForTech = useCallback(
    (t: AdherenceTechnology): AdherenceRule[] =>
      t.rule_uids.map((u) => rulesByUid.get(u)).filter((r): r is AdherenceRule => !!r),
    [rulesByUid]
  );

  const unmappedRules = useMemo(() => (data?.rules ?? []).filter((r) => !r.counted), [data]);

  if (loading) {
    return (
      <div className="flex items-center justify-center p-16 text-on-surface-variant font-body-sm">
        Carregando Mapa de Adesão...
      </div>
    );
  }
  if (!data) {
    return (
      <div className="px-4 py-3 rounded-lg bg-error/10 border border-error/30 text-error font-body-sm">
        {error || "Não foi possível carregar o Mapa de Adesão."}
      </div>
    );
  }

  const m = data.metrics;
  const maxDist = Math.max(1, ...data.distribution.map((b) => b.count));
  const maxSev = Math.max(1, ...data.severity_breakdown.map((b) => b.count));
  const sevColor: Record<string, string> = {
    critical: "#dc2626",
    high: "#f97316",
    medium: "#f59e0b",
    low: "#3b82f6",
    info: "#64748b",
  };

  // --- renderizadores ---------------------------------------------------------
  const CellChips: React.FC<{ rule: AdherenceRule }> = ({ rule }) => (
    <div className="flex flex-wrap gap-1.5 pt-2">
      {rule.clients.map((c) => {
        const style: Record<string, { bg: string; fg: string; icon: string; title: string }> = {
          active: { bg: "rgba(16,185,129,0.15)", fg: "#34d399", icon: "check_circle", title: "Implementada e ativa" },
          paused: { bg: "rgba(245,158,11,0.15)", fg: "#fbbf24", icon: "pause_circle", title: "Implementada (pausada)" },
          not_implemented: { bg: "rgba(239,68,68,0.15)", fg: "#f87171", icon: "cancel", title: "Não implementada" },
          not_applicable: { bg: "rgba(100,116,139,0.15)", fg: "#94a3b8", icon: "block", title: "Cliente não possui a tecnologia" },
        };
        const s = style[c.status];
        return (
          <span
            key={c.client_uid}
            title={`${c.client_name}: ${s.title}`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs"
            style={{ background: s.bg, color: s.fg }}
          >
            <span className="material-symbols-outlined text-[13px]">{s.icon}</span>
            {c.client_name}
          </span>
        );
      })}
    </div>
  );

  const RuleRow: React.FC<{ rule: AdherenceRule; indent: number }> = ({ rule, indent }) => {
    const key = `rule:${rule.uid}`;
    const open = expanded.has(key);
    return (
      <div style={{ paddingLeft: indent }} className="border-t border-outline-variant/15">
        <div className="flex items-center gap-3 py-2 pr-3 hover:bg-surface-container/60 rounded-md">
          <button type="button" onClick={() => toggle(key)} className="flex items-center gap-2 flex-1 min-w-0 text-left">
            <span className="material-symbols-outlined text-[16px] text-outline">{open ? "expand_more" : "chevron_right"}</span>
            <span className="material-symbols-outlined text-[16px] text-outline">description</span>
            <span className="font-body-sm text-on-surface truncate">{rule.base_title}</span>
            {rule.severity && (
              <span
                className="px-1.5 py-0.5 rounded text-[10px] uppercase font-semibold shrink-0"
                style={{ background: `${sevColor[rule.severity] ?? "#64748b"}22`, color: sevColor[rule.severity] ?? "#94a3b8" }}
              >
                {rule.severity}
              </span>
            )}
            {rule.is_paused && <span className="text-[10px] text-amber-400 shrink-0">pausada no baseline</span>}
          </button>
          <div className="w-28 shrink-0 hidden sm:block">
            <ProgressBar pct={rule.compliance_pct} applicable={rule.applicable_clients > 0} height={5} />
          </div>
          <span className="w-24 text-right text-xs text-on-surface-variant shrink-0">
            {rule.implemented_clients}/{rule.applicable_clients} · {rule.compliance_pct.toFixed(0)}%
          </span>
          <button
            type="button"
            disabled={rule.missing_clients === 0}
            onClick={() => openImplement({ type: "rule", rule })}
            className="px-2.5 py-1 rounded-md text-xs bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20 disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
          >
            Replicar
          </button>
        </div>
        {open && (
          <div className="pb-3 pl-8 pr-3">
            <div className="text-[11px] text-outline">
              {rule.mitre_tactic && <>Tática: {rule.mitre_tactic} · </>}
              Grupo: {rule.rule_group || "-"} · {rule.active_clients} ativa(s), {rule.paused_clients} pausada(s),{" "}
              {rule.missing_clients} faltante(s)
            </div>
            <CellChips rule={rule} />
          </div>
        )}
      </div>
    );
  };

  const FolderRow: React.FC<{
    id: string;
    icon: string;
    title: string;
    subtitle?: string;
    pct: number;
    stat: string;
    indent: number;
    actionLabel?: string;
    actionDisabled?: boolean;
    onAction?: () => void;
    children?: React.ReactNode;
  }> = ({ id, icon, title, subtitle, pct, stat, indent, actionLabel, actionDisabled, onAction, children }) => {
    const open = expanded.has(id);
    return (
      <div style={{ paddingLeft: indent }}>
        <div className="flex items-center gap-3 py-2.5 pr-3 hover:bg-surface-container/60 rounded-md">
          <button type="button" onClick={() => toggle(id)} className="flex items-center gap-2 flex-1 min-w-0 text-left">
            <span className="material-symbols-outlined text-[18px] text-outline">{open ? "expand_more" : "chevron_right"}</span>
            <span className="material-symbols-outlined text-[20px] text-primary">{open ? "folder_open" : icon}</span>
            <span className="font-body-md text-on-surface font-semibold truncate">{title}</span>
            {subtitle && <span className="text-xs text-outline truncate">{subtitle}</span>}
          </button>
          <div className="w-36 shrink-0 hidden sm:block">
            <ProgressBar pct={pct} />
          </div>
          <span className="w-32 text-right text-xs text-on-surface-variant shrink-0">{stat}</span>
          {onAction && (
            <button
              type="button"
              onClick={onAction}
              disabled={actionDisabled}
              className="px-2.5 py-1 rounded-md text-xs bg-primary text-on-primary hover:bg-primary/90 disabled:opacity-30 disabled:cursor-not-allowed shrink-0"
            >
              {actionLabel}
            </button>
          )}
        </div>
        {open && <div>{children}</div>}
      </div>
    );
  };

  const techNode = (t: AdherenceTechnology, indent: number) => {
    const rules = rulesForTech(t).filter((r) => (!onlyGaps || r.missing_clients > 0) && (matchesSearch(r.title) || matchesSearch(t.name)));
    if (rules.length === 0 && (search || onlyGaps)) return null;
    return (
      <FolderRow
        key={t.slug}
        id={`tech:${t.slug}`}
        icon="folder"
        title={t.name}
        subtitle={`${t.baseline_rules_count} regra(s) · ${t.applicable_clients_count} cliente(s)`}
        pct={t.compliance_pct}
        stat={`${t.implemented_slots}/${t.total_slots} · ${t.compliance_pct.toFixed(0)}%`}
        indent={indent}
        actionLabel="Implementar"
        actionDisabled={t.missing_slots === 0}
        onAction={() => openImplement({ type: "technology", slug: t.slug, name: t.name })}
      >
        {rules.map((r) => (
          <RuleRow key={r.uid} rule={r} indent={indent + 24} />
        ))}
      </FolderRow>
    );
  };

  const treeView = (
    <FolderRow
      id="root"
      icon="folder_special"
      title={data.baseline_folder_title}
      subtitle={`Pasta global · ${data.baseline_folder_uid}`}
      pct={m.compliance_pct}
      stat={`${m.implemented_slots}/${m.applicable_slots} · ${m.compliance_pct.toFixed(0)}%`}
      indent={0}
      actionLabel="Implementar tudo"
      actionDisabled={m.missing_slots === 0}
      onAction={() => openImplement({ type: "all" })}
    >
      {data.technologies.map((t) => techNode(t, 20))}
      {unmappedRules.length > 0 && (!search || unmappedRules.some((r) => matchesSearch(r.title))) && (
        <div style={{ paddingLeft: 20 }}>
          <FolderRow
            id={`tech:${UNMAPPED}`}
            icon="folder_off"
            title="Sem tecnologia mapeada"
            subtitle="Fora das métricas globais"
            pct={0}
            stat={`${unmappedRules.length} regra(s)`}
            indent={0}
          >
            {unmappedRules
              .filter((r) => matchesSearch(r.title))
              .map((r) => (
                <RuleRow key={r.uid} rule={r} indent={24} />
              ))}
          </FolderRow>
        </div>
      )}
    </FolderRow>
  );

  const technologyView = (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
      {data.technologies
        .filter((t) => matchesSearch(t.name) && (!onlyGaps || t.missing_slots > 0))
        .map((t) => {
          const clientRows = data.clients
            .map((c) => ({ c, tc: c.technologies.find((x) => x.slug === t.slug) }))
            .filter((x) => x.tc && x.tc.applicable);
          return (
            <div key={t.slug} className="bg-surface-container-low rounded-xl border border-outline-variant/30 p-4 space-y-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="font-headline-md text-on-surface font-semibold">{t.name}</div>
                  <div className="text-xs text-outline">
                    {t.baseline_rules_count} regra(s) · {t.applicable_clients_count} cliente(s) com a tecnologia ·{" "}
                    {t.fully_compliant_clients} 100% conforme(s)
                  </div>
                </div>
                <button
                  type="button"
                  disabled={t.missing_slots === 0}
                  onClick={() => openImplement({ type: "technology", slug: t.slug, name: t.name })}
                  className="px-3 py-1.5 rounded-md text-xs bg-primary text-on-primary hover:bg-primary/90 disabled:opacity-30 shrink-0"
                >
                  Implementar nos clientes
                </button>
              </div>
              <ProgressBar pct={t.compliance_pct} height={8} />
              <div className="text-xs text-on-surface-variant">
                {t.implemented_slots}/{t.total_slots} regras implementadas · {t.missing_slots} faltante(s)
              </div>
              <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                {clientRows.length === 0 && <div className="text-xs text-outline">Nenhum cliente possui esta tecnologia.</div>}
                {clientRows.map(({ c, tc }) => (
                  <div key={c.client_uid} className="flex items-center gap-3 text-xs">
                    <span className="w-40 truncate text-on-surface">{c.client_name}</span>
                    <div className="flex-1">
                      <ProgressBar pct={tc!.compliance_pct} height={5} />
                    </div>
                    <span className="w-16 text-right text-on-surface-variant">
                      {tc!.implemented}/{tc!.total}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
    </div>
  );

  const clientView = (
    <div className="space-y-3">
      {data.clients
        .filter((c) => matchesSearch(c.client_name) && (!onlyGaps || c.missing_slots > 0))
        .map((c) => {
          const key = `client:${c.client_uid}`;
          const open = expanded.has(key);
          return (
            <div key={c.client_uid} className="bg-surface-container-low rounded-xl border border-outline-variant/30">
              <div className="flex items-center gap-3 p-3">
                <button type="button" onClick={() => toggle(key)} className="flex items-center gap-2 flex-1 min-w-0 text-left">
                  <span className="material-symbols-outlined text-[18px] text-outline">{open ? "expand_more" : "chevron_right"}</span>
                  <span className="font-body-md text-on-surface font-semibold truncate">{c.client_name}</span>
                  <span
                    className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase"
                    style={{
                      background: `${statusColor(c.compliance_pct, c.status !== "not_applicable")}22`,
                      color: statusColor(c.compliance_pct, c.status !== "not_applicable"),
                    }}
                  >
                    {STATUS_LABEL[c.status]}
                  </span>
                </button>
                <div className="w-40 hidden sm:block">
                  <ProgressBar pct={c.compliance_pct} applicable={c.status !== "not_applicable"} />
                </div>
                <span className="w-28 text-right text-xs text-on-surface-variant">
                  {c.implemented_slots}/{c.applicable_slots} · {c.compliance_pct.toFixed(0)}%
                </span>
                <button
                  type="button"
                  disabled={c.missing_slots === 0}
                  onClick={() => openImplement({ type: "client", uid: c.client_uid, name: c.client_name })}
                  className="px-2.5 py-1 rounded-md text-xs bg-primary text-on-primary hover:bg-primary/90 disabled:opacity-30"
                >
                  Implementar lacunas
                </button>
              </div>
              {open && (
                <div className="px-4 pb-3 space-y-1.5">
                  {c.technologies.map((t) => (
                    <div key={t.slug} className="flex items-center gap-3 text-xs">
                      <span className="w-48 truncate text-on-surface">{t.name}</span>
                      <div className="flex-1">
                        <ProgressBar pct={t.compliance_pct} applicable={t.applicable} height={5} />
                      </div>
                      <span className="w-28 text-right text-on-surface-variant">
                        {t.applicable ? `${t.implemented}/${t.total}` : "não possui"}
                      </span>
                      <button
                        type="button"
                        disabled={!t.applicable || t.missing === 0}
                        onClick={() => {
                          const sc: Scope = { type: "technology", slug: t.slug, name: `${t.name} — ${c.client_name}` };
                          const list = buildJobs({ type: "technology", slug: t.slug, name: t.name }).filter(
                            (j) => j.clientUid === c.client_uid
                          );
                          setScope(sc);
                          setJobs(list);
                          setSelectedJobs(new Set(list.map((j) => j.id)));
                          setResults({});
                          setRunning(false);
                          setFinished(false);
                        }}
                        className="px-2 py-0.5 rounded text-[11px] bg-primary/10 text-primary border border-primary/30 disabled:opacity-30"
                      >
                        Implementar
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
    </div>
  );

  // --- modal de implementação -------------------------------------------------
  const scopeTitle = !scope
    ? ""
    : scope.type === "all"
    ? "Implementar baseline completo"
    : scope.type === "technology"
    ? `Implementar baseline — ${scope.name}`
    : scope.type === "client"
    ? `Implementar lacunas — ${scope.name}`
    : `Replicar regra — ${scope.rule.base_title}`;
  const selectedCount = jobs.filter((j) => selectedJobs.has(j.id)).length;
  const selectedRules = jobs.filter((j) => selectedJobs.has(j.id)).reduce((acc, j) => acc + j.missing, 0);

  return (
    <div className="flex flex-col w-full pb-12 space-y-5">
      <header className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-3">
        <div>
          <h1 className="font-headline-xl text-headline-xl text-on-surface font-semibold tracking-tight">Mapa de Adesão</h1>
          <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
            Conformidade dos clientes ao baseline de regras de detecção — pasta global{" "}
            <code className="text-secondary font-mono">{data.baseline_folder_title}</code>
            {m.hidden_clients_total > 0 && <> · {m.hidden_clients_total} tenant(s) oculto(s) fora do cálculo</>}
          </p>
        </div>
        <button
          type="button"
          onClick={() => load(true)}
          disabled={refreshing}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-surface-container hover:bg-surface-bright text-on-surface font-body-sm disabled:opacity-50"
        >
          <span className={`material-symbols-outlined text-[18px] ${refreshing ? "animate-spin" : ""}`}>refresh</span>
          Atualizar
        </button>
      </header>

      {error && (
        <div className="px-4 py-3 rounded-lg bg-error/10 border border-error/30 text-error font-body-sm">{error}</div>
      )}

      {/* KPIs */}
      <section className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <Kpi label="Adesão geral" value={`${m.compliance_pct.toFixed(1)}%`} accent={statusColor(m.compliance_pct)} hint={`${m.implemented_slots} de ${m.applicable_slots} implementações`} />
        <Kpi label="Clientes" value={m.clients_total} hint={`${m.clients_complete} conformes · ${m.clients_partial} parciais · ${m.clients_none} sem adesão`} />
        <Kpi label="Regras no baseline" value={m.baseline_rules_total} hint={`${m.technologies_total} tecnologia(s)${m.baseline_rules_unmapped ? ` · ${m.baseline_rules_unmapped} sem tecnologia` : ""}`} />
        <Kpi label="Lacunas" value={m.missing_slots} accent={m.missing_slots > 0 ? COLORS.none : COLORS.complete} hint="regras a implementar nos clientes" />
        <Kpi label="Não aplicáveis" value={m.not_applicable_slots} hint="cliente sem a tecnologia (fora do cálculo)" />
      </section>

      {/* Gráficos */}
      <section className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <div className="bg-surface-container-low rounded-xl border border-outline-variant/30 p-4 flex items-center gap-5">
          <Donut pct={m.compliance_pct} />
          <div className="space-y-2 text-xs text-on-surface-variant">
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full" style={{ background: statusColor(m.compliance_pct) }} />{m.implemented_slots} implementadas</div>
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-slate-500/50" />{m.missing_slots} faltantes</div>
            <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full" style={{ background: COLORS.na }} />{m.not_applicable_slots} N/A</div>
          </div>
        </div>

        <div className="bg-surface-container-low rounded-xl border border-outline-variant/30 p-4">
          <div className="font-body-sm text-on-surface font-semibold mb-3">Clientes por faixa de adesão</div>
          <div className="flex items-end gap-3 h-28">
            {data.distribution.map((b, i) => {
              const colors = [COLORS.complete, "#a3e635", COLORS.partial, COLORS.none, COLORS.na];
              return (
                <div key={b.label} className="flex-1 flex flex-col items-center justify-end h-full gap-1">
                  <span className="text-xs text-on-surface">{b.count}</span>
                  <div className="w-full rounded-t" style={{ height: `${(b.count / maxDist) * 80}%`, minHeight: b.count ? 4 : 1, background: colors[i] }} />
                  <span className="text-[10px] text-outline">{b.label}</span>
                </div>
              );
            })}
          </div>
        </div>

        <div className="bg-surface-container-low rounded-xl border border-outline-variant/30 p-4">
          <div className="font-body-sm text-on-surface font-semibold mb-3">Regras do baseline por severidade</div>
          <div className="space-y-2">
            {data.severity_breakdown.length === 0 && <div className="text-xs text-outline">Sem regras no baseline.</div>}
            {data.severity_breakdown.map((b) => (
              <div key={b.label} className="flex items-center gap-2 text-xs">
                <span className="w-16 uppercase text-outline">{b.label}</span>
                <div className="flex-1 h-2 rounded-full bg-surface-container-highest overflow-hidden">
                  <div className="h-full rounded-full" style={{ width: `${(b.count / maxSev) * 100}%`, background: sevColor[b.label] ?? "#64748b" }} />
                </div>
                <span className="w-6 text-right text-on-surface">{b.count}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Adesão por tecnologia (barras) */}
      <section className="bg-surface-container-low rounded-xl border border-outline-variant/30 p-4">
        <div className="font-body-sm text-on-surface font-semibold mb-3">Adesão por tecnologia</div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2">
          {data.technologies.length === 0 && <div className="text-xs text-outline">Nenhuma tecnologia com regras no baseline.</div>}
          {data.technologies.map((t) => (
            <div key={t.slug} className="flex items-center gap-3 text-xs">
              <span className="w-40 truncate text-on-surface" title={t.name}>{t.name}</span>
              <div className="flex-1"><ProgressBar pct={t.compliance_pct} height={8} /></div>
              <span className="w-24 text-right text-on-surface-variant">{t.implemented_slots}/{t.total_slots} · {t.compliance_pct.toFixed(0)}%</span>
            </div>
          ))}
        </div>
      </section>

      {/* Navegação */}
      <section className="space-y-3">
        <div className="flex flex-col md:flex-row md:items-center gap-3">
          <div className="inline-flex rounded-lg bg-surface-container p-1">
            {([
              ["tree", "Pastas", "folder"],
              ["technology", "Por tecnologia", "dns"],
              ["client", "Por cliente", "domain"],
            ] as [ViewMode, string, string][]).map(([id, label, icon]) => (
              <button
                key={id}
                type="button"
                onClick={() => setView(id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm transition-colors ${
                  view === id ? "bg-primary text-on-primary" : "text-on-surface-variant hover:text-on-surface"
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">{icon}</span>
                {label}
              </button>
            ))}
          </div>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar regra, tecnologia ou cliente..."
            className="flex-1 px-3 py-2 bg-surface-container-highest/60 border border-outline-variant/40 rounded-lg text-on-surface font-body-sm focus:outline-none focus:border-primary/60"
          />
          <label className="inline-flex items-center gap-2 text-sm text-on-surface-variant cursor-pointer">
            <input type="checkbox" checked={onlyGaps} onChange={(e) => setOnlyGaps(e.target.checked)} className="accent-primary" />
            Somente com lacunas
          </label>
          {view === "tree" && (
            <div className="flex gap-2 text-xs">
              <button
                type="button"
                className="text-primary hover:underline"
                onClick={() =>
                  setExpanded(new Set(["root", ...data.technologies.map((t) => `tech:${t.slug}`)]))
                }
              >
                Expandir tecnologias
              </button>
              <button type="button" className="text-outline hover:underline" onClick={() => setExpanded(new Set(["root"]))}>
                Recolher
              </button>
            </div>
          )}
        </div>

        <div className={view === "tree" ? "bg-surface-container-low rounded-xl border border-outline-variant/30 p-3" : ""}>
          {m.baseline_rules_total === 0 ? (
            <div className="text-center text-on-surface-variant py-10 font-body-sm">
              A pasta global não possui regras de detecção. Defina a pasta correta na página Baseline ou crie regras de referência.
            </div>
          ) : view === "tree" ? (
            treeView
          ) : view === "technology" ? (
            technologyView
          ) : (
            clientView
          )}
        </div>
      </section>

      {/* Modal de implementação */}
      <Modal isOpen={scope !== null} onClose={closeImplement} title={scopeTitle} maxWidth="720px">
        <div className="flex flex-col gap-4 text-on-surface">
          {jobs.length === 0 ? (
            <p className="font-body-sm text-on-surface-variant">Nenhuma lacuna para implementar neste escopo.</p>
          ) : (
            <>
              <div className="px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs leading-relaxed">
                Serão criadas até <strong>{selectedRules}</strong> regra(s) em <strong>{new Set(jobs.filter((j) => selectedJobs.has(j.id)).map((j) => j.clientUid)).size}</strong>{" "}
                cliente(s). As regras nascem em Homologação, no Contact Point do estágio <code>stg</code> configurado, usando o data source Loki do cliente. Apenas clientes que possuem a tecnologia são incluídos.
              </div>

              <div className="max-h-80 overflow-y-auto rounded-lg border border-outline-variant/30 divide-y divide-outline-variant/20">
                {!running && !finished && (
                  <label className="flex items-center gap-2 px-3 py-2 text-xs bg-surface-container-high cursor-pointer">
                    <input
                      type="checkbox"
                      className="accent-primary"
                      checked={selectedCount === jobs.length}
                      onChange={(e) => setSelectedJobs(e.target.checked ? new Set(jobs.map((j) => j.id)) : new Set())}
                    />
                    Selecionar todos ({jobs.length})
                  </label>
                )}
                {jobs.map((j) => {
                  const r = results[j.id];
                  return (
                    <div key={j.id} className="flex items-start gap-3 px-3 py-2 text-sm">
                      {!running && !finished ? (
                        <input
                          type="checkbox"
                          className="accent-primary mt-1"
                          checked={selectedJobs.has(j.id)}
                          onChange={(e) =>
                            setSelectedJobs((prev) => {
                              const next = new Set(prev);
                              if (e.target.checked) next.add(j.id);
                              else next.delete(j.id);
                              return next;
                            })
                          }
                        />
                      ) : (
                        <span
                          className={`material-symbols-outlined text-[18px] mt-0.5 ${
                            r?.state === "done" ? "text-emerald-400" : r?.state === "error" ? "text-red-400" : r?.state === "running" ? "animate-spin text-primary" : "text-outline"
                          }`}
                        >
                          {r?.state === "done" ? "check_circle" : r?.state === "error" ? "error" : r?.state === "running" ? "progress_activity" : "schedule"}
                        </span>
                      )}
                      <div className="flex-1 min-w-0">
                        <div className="truncate">
                          <strong>{j.clientName}</strong> <span className="text-outline">← {j.label}</span>
                        </div>
                        <div className="text-xs text-on-surface-variant">
                          {r?.message ?? `${j.missing} regra(s) faltante(s)`}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={closeImplement}
              disabled={running}
              className="px-4 py-2 rounded-lg bg-surface-container hover:bg-surface-bright text-on-surface text-sm disabled:opacity-50"
            >
              {finished ? "Fechar" : "Cancelar"}
            </button>
            {!finished && jobs.length > 0 && (
              <button
                type="button"
                onClick={runJobs}
                disabled={running || selectedCount === 0}
                className="px-4 py-2 rounded-lg bg-primary text-on-primary text-sm font-medium hover:bg-primary/90 disabled:opacity-40"
              >
                {running ? "Implementando..." : `Confirmar e implementar (${selectedCount})`}
              </button>
            )}
          </div>
        </div>
      </Modal>
    </div>
  );
};
