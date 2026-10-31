import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Modal } from "../components/Modal";
import {
  LogLineResult,
  LokiDatasourceItem,
  LokiStatus,
  LokiSyntheticResult,
} from "../types";

interface Preset {
  id: string;
  label: string;
  icon: string;
  description: string;
  stream: Record<string, string>;
  template: string;
  count: number;
  spread: number;
}

const PRESETS: Preset[] = [
  {
    id: "ssh-bruteforce",
    label: "SSH força bruta",
    icon: "terminal",
    description: "Falhas de autenticação SSH consecutivas (T1110).",
    stream: { job: "wazuh", rule_groups: "linux", agent_name: "lab-linux-01" },
    template: `{
  "description": "sshd: Attempt to login using a non-existent user",
  "groups": ["syslog", "sshd", "authentication_failed"],
  "agent": { "id": "001", "name": "lab-linux-01", "ip": "10.10.0.11" },
  "data": {
    "srcip": "{{ip}}",
    "srcuser": "{{user}}",
    "dstuser": "root",
    "pam": { "status": "failed" }
  },
  "full_log": "Failed password for invalid user {{user}} from {{ip}} port 51{{rlen}} ssh2"
}`,
    count: 12,
    spread: 300,
  },
  {
    id: "windows-logon-failure",
    label: "Windows 4625",
    icon: "desktop_windows",
    description: "Falha de logon em controlador de domínio.",
    stream: { job: "wazuh", rule_groups: "windows", agent_name: "lab-dc-01" },
    template: `{
  "description": "Logon Failure - Unknown user or bad password",
  "groups": ["windows", "authentication_failed"],
  "win": {
    "system": { "eventID": "4625", "computer": "LAB-DC-01" },
    "eventdata": {
      "targetUserName": "{{user}}",
      "ipAddress": "{{ip}}",
      "status": "0xc000006d",
      "logonType": "3"
    }
  }
}`,
    count: 8,
    spread: 600,
  },
  {
    id: "dns-tunneling",
    label: "DNS tunneling",
    icon: "travel_explore",
    description: "Consultas TXT de alto volume com subdomínio aleatório (T1071.004).",
    stream: { job: "wazuh", rule_groups: "dns", agent_name: "lab-dns-01" },
    template: `{
  "description": "Possible DNS tunneling activity",
  "groups": ["dns", "exfiltration"],
  "data": {
    "query_name": "{{rand}}-{{rlen}}.exfil.lab.example.com",
    "qtype": "TXT",
    "srcip": "10.10.0.42",
    "response_length": {{rlen}}
  }
}`,
    count: 20,
    spread: 300,
  },
  {
    id: "sudo-root",
    label: "Escalada (sudo)",
    icon: "shield",
    description: "Execução de shell como root via sudo/nsenter.",
    stream: { job: "wazuh", rule_groups: "linux", agent_name: "lab-linux-01" },
    template: `{
  "description": "Successful sudo to ROOT executed",
  "groups": ["syslog", "sudo", "privilege_escalation"],
  "data": {
    "srcuser": "{{user}}",
    "dstuser": "root",
    "tty": "pts/0",
    "command": "/usr/bin/nsenter -t 1 -m -u -i -n -p /bin/sh"
  },
  "full_log": "{{user}} : TTY=pts/0 ; PWD=/home/{{user}} ; USER=root ; COMMAND=/usr/bin/nsenter -t 1 -m -u -i -n -p /bin/sh"
}`,
    count: 3,
    spread: 120,
  },
];

const TOKEN_RE = /\{\{(\w+)\}\}/g;

function randomIp(): string {
  const octet = () => Math.floor(Math.random() * 254) + 1;
  return `10.${octet()}.${octet()}.${octet()}`;
}

function renderLine(template: string, index: number): string {
  const tokens: Record<string, string> = {
    i: String(index + 1),
    ip: randomIp(),
    user: `labuser${(index % 5) + 1}`,
    rand: Math.random().toString(36).slice(2, 10),
    rlen: String(60 + Math.floor(Math.random() * 240)),
    iso: new Date().toISOString(),
  };
  return template.replace(TOKEN_RE, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(tokens, name) ? tokens[name] : match
  );
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleTimeString("pt-BR", { hour12: false });
}

function findDefaultInternalDatasource(list: LokiDatasourceItem[]): LokiDatasourceItem | null {
  const internals = list.filter((d) => d.is_internal);
  if (internals.length === 0) return null;
  return (
    internals.find((d) => d.uid.toLowerCase() === "loki") ||
    internals.find((d) => d.is_default) ||
    internals.find((d) => d.name.toLowerCase() === "loki") ||
    internals[0]
  );
}

export const LokiLabPage: React.FC = () => {
  const [status, setStatus] = useState<LokiStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  // Seleção de Data Source
  const [datasources, setDatasources] = useState<LokiDatasourceItem[]>([]);
  const [selectedDatasourceUid, setSelectedDatasourceUid] = useState<string | null>(null);
  const [datasourcesLoading, setDatasourcesLoading] = useState(false);
  const [datasourcesError, setDatasourcesError] = useState<string | null>(null);
  const [isSelectModalOpen, setIsSelectModalOpen] = useState(false);
  const [candidateDs, setCandidateDs] = useState<LokiDatasourceItem | null>(null);

  const [job, setJob] = useState("wazuh");
  const [ssGroups, setSsGroups] = useState("linux");
  const [extraLabels, setExtraLabels] = useState('{"agent_name": "lab-linux-01"}');
  const [template, setTemplate] = useState(PRESETS[0].template);
  const [count, setCount] = useState(PRESETS[0].count);
  const [spread, setSpread] = useState(PRESETS[0].spread);
  const [markSynthetic, setMarkSynthetic] = useState(true);
  const [activePreset, setActivePreset] = useState<string | null>(PRESETS[0].id);

  const [templateError, setTemplateError] = useState<string | null>(null);
  const [injecting, setInjecting] = useState(false);
  const [injectError, setInjectError] = useState<string | null>(null);
  const [result, setResult] = useState<LokiSyntheticResult | null>(null);

  const [recent, setRecent] = useState<LogLineResult[] | null>(null);
  const [recentLoading, setRecentLoading] = useState(false);
  const [recentError, setRecentError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const loadStatus = useCallback(async (targetUid?: string) => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      const s = await api.getLokiStatus(targetUid);
      setStatus(s);
      if (s.datasource_uid && !targetUid) {
        setSelectedDatasourceUid((prev) => prev || s.datasource_uid);
      }
    } catch (err) {
      setStatusError(err instanceof Error ? err.message : "Falha ao consultar o Loki");
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const loadDatasources = useCallback(async () => {
    setDatasourcesLoading(true);
    setDatasourcesError(null);
    try {
      const list = await api.getLokiDatasources();
      setDatasources(list);
      return list;
    } catch (err) {
      setDatasourcesError(err instanceof Error ? err.message : "Falha ao listar data sources");
      return [];
    } finally {
      setDatasourcesLoading(false);
    }
  }, []);

  const loadRecent = useCallback(async () => {
    setRecentLoading(true);
    setRecentError(null);
    try {
      const response = await api.executeQuery(
        '{synthetic="true"} | json',
        "now-15m",
        "now",
        20
      );
      setRecent(response.lines);
    } catch (err) {
      setRecentError(err instanceof Error ? err.message : "Falha ao consultar as linhas");
      setRecent([]);
    } finally {
      setRecentLoading(false);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function initPage() {
      let dsList: LokiDatasourceItem[] = [];
      try {
        dsList = await loadDatasources();
      } catch {
        dsList = [];
      }
      if (cancelled) return;

      const defaultInternal = findDefaultInternalDatasource(dsList);
      const initialUid = defaultInternal?.uid ?? undefined;
      if (initialUid) {
        setSelectedDatasourceUid(initialUid);
      }
      await loadStatus(initialUid);
    }

    initPage();
    loadRecent();

    return () => {
      cancelled = true;
    };
  }, [loadDatasources, loadRecent, loadStatus]);

  useEffect(() => {
    try {
      const parsed: unknown = JSON.parse(renderLine(template, 0));
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setTemplateError("O template precisa ser um objeto JSON (não array nem valor solto).");
        return;
      }
      setTemplateError(null);
    } catch (err) {
      setTemplateError(err instanceof Error ? err.message : "JSON inválido");
    }
  }, [template]);

  const previewSelector = useMemo(() => {
    const labels: Record<string, string> = { job: job || "wazuh" };
    if (ssGroups.trim()) labels.rule_groups = ssGroups.trim();
    try {
      const parsed: unknown = JSON.parse(extraLabels || "{}");
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        Object.entries(parsed as Record<string, unknown>).forEach(([key, value]) => {
          if (typeof value === "string" && value.trim()) labels[key] = value;
        });
      }
    } catch {
      // Ignora erro sintático temporário
    }
    if (markSynthetic) labels.synthetic = "true";
    return `{${Object.entries(labels)
      .map(([key, value]) => `${key}="${value}"`)
      .join(", ")}}`;
  }, [job, ssGroups, extraLabels, markSynthetic]);

  const applyPreset = (preset: Preset) => {
    setActivePreset(preset.id);
    setTemplate(preset.template);
    setJob(preset.stream.job ?? "wazuh");
    setSsGroups(preset.stream.rule_groups ?? "");
    const rest = Object.entries(preset.stream)
      .filter(([key]) => key !== "job" && key !== "rule_groups")
      .reduce<Record<string, string>>((acc, [key, value]) => {
        acc[key] = value;
        return acc;
      }, {});
    setExtraLabels(JSON.stringify(rest));
    setCount(preset.count);
    setSpread(preset.spread);
    setResult(null);
    setInjectError(null);
  };

  const openDatasourceModal = async () => {
    const list = await loadDatasources();
    const currentUid = selectedDatasourceUid || status?.datasource_uid;
    const current = list.find((d) => d.uid === currentUid) || null;
    const defaultInternal = findDefaultInternalDatasource(list);
    const isEligible = (d: LokiDatasourceItem | null) => Boolean(d && (d.is_internal || d.is_sandbox || d.can_inject));
    setCandidateDs(isEligible(current) ? current : defaultInternal);
    setIsSelectModalOpen(true);
  };

  const handleConfirmDatasourceSelection = async () => {
    if (!candidateDs || (!candidateDs.is_internal && !candidateDs.is_sandbox && !candidateDs.can_inject)) return;
    const newUid = candidateDs.uid;
    setSelectedDatasourceUid(newUid);
    setIsSelectModalOpen(false);
    await loadStatus(newUid);
  };

  const handleInject = async () => {
    setInjectError(null);
    if (templateError) {
      setInjectError(`Template inválido: ${templateError}`);
      return;
    }

    const stream: Record<string, string> = { job: job.trim() || "wazuh" };
    if (ssGroups.trim()) stream.rule_groups = ssGroups.trim();
    if (extraLabels.trim()) {
      try {
        const parsed = JSON.parse(extraLabels) as Record<string, string>;
        for (const [key, value] of Object.entries(parsed)) {
          if (value.trim()) stream[key] = value.trim();
        }
      } catch {
        setInjectError("Objeto JSON de labels inválido.");
        return;
      }
    }

    const lines: Array<Record<string, unknown>> = [];
    for (let index = 0; index < count; index += 1) {
      lines.push(JSON.parse(renderLine(template, index)) as Record<string, unknown>);
    }

    setInjecting(true);
    setResult(null);
    try {
      const response = await api.injectSyntheticLogs({
        datasource_uid: selectedDatasourceUid ?? undefined,
        stream,
        lines,
        spread_seconds: spread,
        mark_synthetic: markSynthetic,
      });
      setResult(response);
      await loadRecent();
    } catch (err) {
      setInjectError(err instanceof Error ? err.message : "Falha ao injetar as linhas");
    } finally {
      setInjecting(false);
    }
  };

  const copyLogQL = () => {
    const query = result?.logql || `${previewSelector} | json`;
    if (navigator.clipboard) {
      navigator.clipboard.writeText(query);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const currentDatasource = useMemo(() => {
    const uid = selectedDatasourceUid || status?.datasource_uid;
    return datasources.find((d) => d.uid === uid) || null;
  }, [datasources, selectedDatasourceUid, status?.datasource_uid]);

  return (
    <div className="flex flex-col w-full pb-10 text-on-surface">
      {/* Top Navigation & Page Header */}
      <div className="flex flex-col gap-space-sm mb-space-lg pt-2">
        <div className="flex items-center gap-2 text-on-surface-variant font-code-sm text-code-sm">
          <span className="text-outline">DANTE</span>
          <span>/</span>
          <span className="text-outline uppercase">Telemetria &amp; Validação</span>
          <span>/</span>
          <span className="text-on-surface font-semibold uppercase">Logs Sintéticos</span>
        </div>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md mt-1">
          <div>
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight flex items-center gap-space-sm font-bold">
              Logs Sintéticos
              <span className="px-2 py-0.5 rounded-full font-code-sm text-code-sm bg-tertiary-container/30 text-tertiary font-medium">
                Loki Push Engine
              </span>
            </h1>
            <p className="font-body-md text-body-md text-on-surface-variant mt-0.5 max-w-3xl">
              Injete linhas JSON de teste no Loki e valide suas regras LogQL no Grafana Explore com simulação em tempo real.
            </p>
          </div>

          {/* Action Bar */}
          <div className="flex items-center flex-wrap gap-2">
            <button
              onClick={openDatasourceModal}
              className="h-8 px-space-sm rounded-lg bg-surface-container-low hover:bg-surface-container-high text-on-surface text-body-sm font-body-sm flex items-center gap-1.5 transition-colors shadow-sm"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px] text-outline">storage</span>
              <span>Selecionar Data Source</span>
            </button>
            <button
              onClick={() => loadStatus(selectedDatasourceUid ?? undefined)}
              className="h-8 px-space-sm rounded-lg bg-surface-container-low hover:bg-surface-container-high text-on-surface text-body-sm font-body-sm flex items-center gap-1.5 transition-colors shadow-sm"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px] text-tertiary">health_and_safety</span>
              <span>Verificar Loki</span>
            </button>
            <button
              onClick={loadRecent}
              className="h-8 px-space-sm rounded-lg bg-surface-container-low hover:bg-surface-container-high text-on-surface text-body-sm font-body-sm flex items-center gap-1.5 transition-colors shadow-sm"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px] text-secondary">sync</span>
              <span>Atualizar consulta</span>
            </button>
          </div>
        </div>
      </div>

      {injectError && (
        <div className="mb-space-md p-space-sm rounded-lg bg-error-container text-on-error-container text-sm">
          {injectError}
        </div>
      )}

      {/* Loki Target Datasource Status Card */}
      <div className="w-full bg-surface-container-lowest rounded-xl p-space-md mb-space-lg shadow-md border border-outline-variant/20">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
          <div className="flex flex-col gap-1.5">
            <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider text-xs">
              Datasource Loki de Injeção
            </span>
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-tertiary"></span>
                </span>
                <span className="font-headline-md text-headline-md text-on-surface font-bold">
                  {currentDatasource?.name || status?.datasource || "Loki"}
                </span>
                <span className={`px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold ${
                  currentDatasource?.is_internal
                    ? "bg-tertiary-container/20 text-tertiary"
                    : currentDatasource?.is_sandbox
                    ? "bg-secondary-container/30 text-secondary"
                    : "bg-surface-container-high text-outline"
                }`}>
                  {currentDatasource?.is_internal
                    ? "Interno"
                    : currentDatasource?.is_sandbox
                    ? `Sandbox: ${currentDatasource.client_name || currentDatasource.name.replace(/^sandbox-/, "")}`
                    : "Produção (Bloqueado)"}
                </span>
              </div>
              <span className="text-surface-variant">|</span>
              <span className="font-body-sm text-body-sm text-on-surface-variant">
                Loki operacional via endpoint REST /loki/api/v1/push
              </span>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex flex-col">
              <span className="font-label-uppercase text-xs text-outline uppercase">UID</span>
              <span className="font-code-sm text-code-sm text-on-surface font-semibold font-mono">
                {selectedDatasourceUid || status?.datasource_uid || "loki"}
              </span>
            </div>
            <div className="flex flex-col">
              <span className="font-label-uppercase text-xs text-outline uppercase">Labels conhecidas</span>
              <span className="font-code-sm text-code-sm text-secondary font-medium font-mono">
                job, rule_groups, synthetic
              </span>
            </div>
            <div className="flex flex-col">
              <span className="font-label-uppercase text-xs text-outline uppercase">Status</span>
              <span className={`font-code-sm text-code-sm font-semibold flex items-center gap-1 ${
                statusError ? "text-error" : statusLoading ? "text-outline" : "text-tertiary"
              }`}>
                <span className="material-symbols-outlined text-[14px]">
                  {statusError ? "error" : statusLoading ? "hourglass_top" : "check_circle"}
                </span>{" "}
                {statusError ? "erro" : statusLoading ? "conectando..." : "pronto para injetar"}
              </span>
            </div>
            <button
              onClick={openDatasourceModal}
              className="h-8 px-space-sm rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface text-body-sm font-body-sm transition-colors shadow-sm"
              type="button"
            >
              Trocar Data Source
            </button>
          </div>
        </div>
      </div>

      {/* Dual Workspace Column Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-space-lg mb-space-lg">
        {/* Left Column: Stream Setup & Synthetic Template */}
        <div className="flex flex-col bg-surface-container-lowest rounded-xl p-space-lg shadow-md space-y-space-md border border-outline-variant/20">
          <div className="flex items-center justify-between pb-space-xs">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg bg-surface-container-high flex items-center justify-center font-code-sm text-code-sm font-bold text-on-surface">1</div>
              <h2 className="font-headline-md text-headline-md text-on-surface font-bold">Stream e template</h2>
            </div>
            <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-primary-container/20 text-primary font-semibold">push JSON</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-space-md">
            <div className="flex flex-col gap-1.5">
              <label className="font-label-uppercase text-xs text-outline uppercase">Label job</label>
              <input
                className="h-8 px-space-sm bg-surface-container rounded-lg font-code-sm text-code-sm text-on-surface placeholder:text-outline focus:outline-none focus:ring-1 focus:ring-secondary"
                type="text"
                value={job}
                onChange={(e) => setJob(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="font-label-uppercase text-xs text-outline uppercase">Label rule_groups</label>
              <input
                className="h-8 px-space-sm bg-surface-container rounded-lg font-code-sm text-code-sm text-on-surface placeholder:text-outline focus:outline-none focus:ring-1 focus:ring-secondary"
                type="text"
                value={ssGroups}
                onChange={(e) => setSsGroups(e.target.value)}
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="font-label-uppercase text-xs text-outline uppercase flex items-center justify-between">
              <span>Labels adicionais (JSON)</span>
              <span className="text-outline font-normal">Indexed stream labels</span>
            </label>
            <input
              className="h-8 px-space-sm bg-surface-container rounded-lg font-code-sm text-code-sm text-secondary placeholder:text-outline focus:outline-none focus:ring-1 focus:ring-secondary font-mono"
              type="text"
              value={extraLabels}
              onChange={(e) => setExtraLabels(e.target.value)}
            />
          </div>

          <div className="p-space-sm bg-surface-container-low rounded-lg flex flex-col gap-1">
            <span className="font-label-uppercase text-xs text-outline uppercase">Seletor resultante</span>
            <code className="font-code-sm text-code-sm text-secondary break-all font-mono">
              {previewSelector}
            </code>
          </div>

          {/* Attack Presets */}
          <div className="flex flex-col gap-space-xs pt-1">
            <span className="font-label-uppercase text-xs text-outline uppercase">Presets de Vetor de Ataque</span>
            <div className="flex flex-wrap gap-1.5">
              {PRESETS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => applyPreset(p)}
                  className={`px-2.5 py-1 rounded font-code-sm text-code-sm font-semibold transition-all flex items-center gap-1.5 ${
                    activePreset === p.id
                      ? "bg-primary-container text-on-primary shadow-sm"
                      : "bg-surface-container-high hover:bg-surface-bright text-on-surface"
                  }`}
                  type="button"
                >
                  <span className="material-symbols-outlined text-[14px]">{p.icon}</span>
                  <span>{p.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* JSON Template Editor */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <label className="font-label-uppercase text-xs text-outline uppercase">Linha em JSON (Tokens Dinâmicos)</label>
              <div className="flex items-center gap-1 font-code-sm text-xs text-outline">
                <span className="px-1 py-0.2 rounded bg-surface-container text-secondary font-mono">{"{{i}}"}</span>
                <span className="px-1 py-0.2 rounded bg-surface-container text-secondary font-mono">{"{{ip}}"}</span>
                <span className="px-1 py-0.2 rounded bg-surface-container text-secondary font-mono">{"{{user}}"}</span>
                <span className="px-1 py-0.2 rounded bg-surface-container text-secondary font-mono">{"{{rand}}"}</span>
              </div>
            </div>
            <div className="relative bg-surface-container-low rounded-lg p-space-sm font-code-sm text-code-sm overflow-hidden border border-outline-variant/20">
              <textarea
                className="w-full bg-transparent text-on-surface font-mono text-xs focus:outline-none resize-none leading-relaxed selection:bg-primary-container selection:text-on-primary-container"
                rows={11}
                spellCheck={false}
                value={template}
                onChange={(e) => setTemplate(e.target.value)}
              />
            </div>
          </div>

          <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 gap-space-md">
            <div className="flex flex-col gap-1.5">
              <label className="font-label-uppercase text-xs text-outline uppercase">Linhas (1-200)</label>
              <input
                className="h-8 px-space-sm bg-surface-container rounded-lg font-code-sm text-code-sm text-on-surface focus:outline-none focus:ring-1 focus:ring-secondary"
                max={200}
                min={1}
                type="number"
                value={count}
                onChange={(e) => setCount(Number(e.target.value))}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="font-label-uppercase text-xs text-outline uppercase">Distribuir em (s)</label>
              <input
                className="h-8 px-space-sm bg-surface-container rounded-lg font-code-sm text-code-sm text-on-surface focus:outline-none focus:ring-1 focus:ring-secondary"
                max={3600}
                min={0}
                type="number"
                value={spread}
                onChange={(e) => setSpread(Number(e.target.value))}
              />
            </div>
          </div>

          <label className="inline-flex items-center gap-2 font-body-sm text-xs text-on-surface cursor-pointer select-none pt-1">
            <input
              type="checkbox"
              checked={markSynthetic}
              onChange={(e) => setMarkSynthetic(e.target.checked)}
              className="rounded bg-surface-container border-outline-variant text-primary-container focus:ring-0"
            />
            <span>Marcar linhas com label <code className="text-secondary font-mono">synthetic="true"</code></span>
          </label>

          <button
            onClick={handleInject}
            disabled={injecting}
            className="w-full h-10 mt-2 rounded-lg bg-primary-container hover:bg-primary text-on-primary font-headline-md text-headline-md font-semibold flex items-center justify-center gap-2 transition-all shadow-md active:scale-[0.99] disabled:opacity-50"
            type="button"
          >
            {injecting ? (
              <svg className="animate-spin h-5 w-5 text-white" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
              </svg>
            ) : (
              <>
                <span className="material-symbols-outlined text-[20px]">bolt</span>
                <span>Injetar Logs</span>
              </>
            )}
          </button>
        </div>

        {/* Right Column: Results, Query Validation & Live Stream */}
        <div className="flex flex-col bg-surface-container-lowest rounded-xl p-space-lg shadow-md space-y-space-md border border-outline-variant/20">
          <div className="flex items-center justify-between pb-space-xs">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-lg bg-surface-container-high flex items-center justify-center font-code-sm text-code-sm font-bold text-on-surface">2</div>
              <h2 className="font-headline-md text-headline-md text-on-surface font-bold">Resultado e verificação</h2>
            </div>
            <span className="font-code-sm text-code-sm text-outline">
              {result ? "HTTP 204 No Content" : "Aguardando envio"}
            </span>
          </div>

          {/* Telemetry Confirmation Header */}
          <div className="grid grid-cols-3 gap-2">
            <div className="p-space-sm bg-surface-container rounded-lg flex flex-col">
              <span className="font-metric-display text-metric-display text-on-surface leading-tight">
                {result?.lines_sent ?? count}
              </span>
              <span className="font-body-sm text-body-sm text-outline">linhas enviadas</span>
            </div>
            <div className="p-space-sm bg-surface-container rounded-lg flex flex-col">
              <span className="font-metric-display text-metric-display text-on-surface leading-tight">
                {result?.verified_count ?? (recent?.length || 0)}
              </span>
              <span className="font-body-sm text-body-sm text-outline">entradas do stream</span>
            </div>
            <div className="p-space-sm bg-surface-container rounded-lg flex flex-col">
              <span className="font-metric-display text-metric-display text-secondary leading-tight">
                {(count * 0.42).toFixed(1)} KB
              </span>
              <span className="font-body-sm text-body-sm text-outline">payload estimado</span>
            </div>
          </div>

          {/* Ingestion Verification Banner */}
          {result && (
            <div className="p-space-md bg-surface-container-low rounded-lg flex flex-col gap-1.5 shadow-sm border border-tertiary/20">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-tertiary-container text-on-tertiary-container font-semibold uppercase flex items-center gap-1">
                  <span className="material-symbols-outlined text-[13px]">done_all</span>
                  Ingestão Confirmada
                </span>
                <span className="font-code-sm text-code-sm text-outline">Loki sync: OK</span>
              </div>
              <p className="font-body-sm text-body-sm text-on-surface mt-1">
                {result.lines_sent} linha(s) injetada(s) com sucesso. O stream agora tem {result.verified_count} entradas consultáveis na janela de verificação.
              </p>
            </div>
          )}

          {/* LogQL Inspector Box */}
          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="font-label-uppercase text-xs text-outline uppercase">Expressão LogQL de Validação</span>
              <span className="font-code-sm text-code-sm text-secondary">Regex match syntax</span>
            </div>
            <div className="p-space-sm bg-surface-container rounded-lg font-code-sm text-code-sm text-secondary overflow-x-auto select-all font-mono">
              <code>{result?.logql || `${previewSelector} | json`}</code>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <button
                onClick={copyLogQL}
                className="h-8 px-space-sm rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm flex items-center gap-1.5 transition-colors"
                type="button"
              >
                <span className="material-symbols-outlined text-[16px]">content_copy</span>
                <span>{copied ? "Copiado!" : "Copiar LogQL"}</span>
              </button>
              {result?.grafana_explore_url && (
                <a
                  href={result.grafana_explore_url}
                  target="_blank"
                  rel="noreferrer"
                  className="h-8 px-space-sm rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm flex items-center gap-1.5 transition-colors"
                >
                  <span>Abrir no Grafana Explore</span>
                  <span className="material-symbols-outlined text-[16px]">north_east</span>
                </a>
              )}
            </div>
          </div>

          {/* Synthetic Stream Live Console Viewer */}
          <div className="flex flex-col gap-1.5 flex-1 pt-1">
            <div className="flex items-center justify-between">
              <span className="font-label-uppercase text-xs text-outline uppercase flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
                Últimas linhas sintéticas (15 min)
              </span>
              <button
                onClick={loadRecent}
                className="h-7 px-space-sm rounded bg-surface-container hover:bg-surface-container-high text-on-surface font-code-sm text-code-sm flex items-center gap-1 transition-colors"
                type="button"
              >
                <span className="material-symbols-outlined text-[14px]">refresh</span>
                <span>Consultar</span>
              </button>
            </div>
            <div className="bg-surface-container-lowest rounded-lg p-space-sm font-code-sm text-code-sm text-on-surface-variant flex flex-col gap-2 max-h-72 overflow-y-auto border border-outline-variant/20 font-mono">
              {recentLoading ? (
                <div className="text-outline text-center py-4">Carregando telemetria...</div>
              ) : recentError ? (
                <div className="text-error text-center py-4">{recentError}</div>
              ) : recent && recent.length > 0 ? (
                recent.map((line, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 group hover:bg-surface-container/40 p-1 rounded transition-colors">
                    <span className="text-outline font-semibold select-none">{formatTime(line.timestamp)}</span>
                    <div className="flex-1 break-all text-on-surface text-xs truncate">
                      {line.line}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-outline text-center py-4">Nenhuma linha sintética recente encontrada.</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Modal Seleção de Datasource */}
      <Modal
        isOpen={isSelectModalOpen}
        onClose={() => setIsSelectModalOpen(false)}
        maxWidth="520px"
        title="Selecionar Data Source Loki"
      >
        <div className="flex flex-col gap-space-md text-on-surface">
          <p className="text-xs text-outline">
            Selecione em qual data source Loki os logs sintéticos devem ser injetados.
          </p>

          <div className="space-y-2 max-h-60 overflow-y-auto">
            {datasourcesLoading ? (
              <div className="text-center py-4 text-xs text-outline">Carregando data sources...</div>
            ) : datasourcesError ? (
              <div className="text-center py-4 text-xs text-error">{datasourcesError}</div>
            ) : (
              datasources.map((ds) => {
                const isEligible = Boolean(ds.is_internal || ds.is_sandbox || ds.can_inject);
                const isSelected = candidateDs?.uid === ds.uid;
                return (
                  <div
                    key={ds.uid}
                    onClick={() => {
                      if (isEligible) {
                        setCandidateDs(ds);
                      }
                    }}
                    className={`p-3 rounded-lg flex items-center justify-between border transition-colors ${
                      !isEligible
                        ? "opacity-55 cursor-not-allowed bg-surface-container-lowest border-outline-variant/10"
                        : isSelected
                        ? "bg-surface-container-high border-secondary cursor-pointer shadow-sm"
                        : "bg-surface-container-low border-outline-variant/20 hover:bg-surface-container cursor-pointer"
                    }`}
                  >
                    <div>
                      <div className="font-semibold text-sm flex items-center gap-2">
                        <span>{ds.name}</span>
                        {ds.is_sandbox && (
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-secondary-container/30 text-secondary font-mono">
                            Cliente: {ds.client_name || ds.name.replace(/^sandbox-/, "")}
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-outline font-mono">{ds.url || "http://loki:3100"}</div>
                      {!isEligible && (
                        <div className="text-[11px] text-error mt-0.5">
                          Produção bloqueada. Utilize o data source sandbox correspondente.
                        </div>
                      )}
                    </div>
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      ds.is_internal
                        ? "bg-tertiary/15 text-tertiary"
                        : ds.is_sandbox
                        ? "bg-secondary/15 text-secondary"
                        : "bg-error/15 text-error"
                    }`}>
                      {ds.is_internal ? "Interno" : ds.is_sandbox ? "Sandbox" : "Produção (Bloqueado)"}
                    </span>
                  </div>
                );
              })
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={() => setIsSelectModalOpen(false)}
            >
              Cancelar
            </button>
            <button
              type="button"
              disabled={!candidateDs || (!candidateDs.is_internal && !candidateDs.is_sandbox && !candidateDs.can_inject)}
              onClick={handleConfirmDatasourceSelection}
              className="px-4 py-1.5 rounded bg-primary-container text-on-primary text-sm font-semibold disabled:opacity-40 cursor-pointer"
            >
              Confirmar Seleção
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
