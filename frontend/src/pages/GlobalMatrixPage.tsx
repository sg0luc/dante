import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { Modal } from "../components/Modal";
import {
  LogQLActionButtons,
  LogQLEditor,
  LogQLLintPanel,
  LogQLQueryResultPanel,
  LogQLTimeoutNotice,
} from "../components/LogQLAssist";
import { useLogQLAssist } from "../hooks/useLogQLAssist";
import {
  ClientRuleStatus,
  GlobalRuleMatrixItem,
  LogQLValidationReport,
  RuleDetail,
} from "../types";

/**
 * Rótulos e classes de badge por status de implementação da regra no cliente.
 * Fonte única usada pela barra de métricas e pelo pop-up de clientes.
 */
const CLIENT_STATUS_META: Record<
  ClientRuleStatus,
  { label: string; badgeClass: string; icon: string }
> = {
  active: { label: "Ativa", badgeClass: "badge badge-normal", icon: "" },
  paused: { label: "Pausada", badgeClass: "badge badge-pending", icon: "" },
  not_implemented: { label: "Não implementada", badgeClass: "badge badge-firing", icon: "" },
};

export const GlobalMatrixPage: React.FC = () => {
  const [matrix, setMatrix] = useState<GlobalRuleMatrixItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filtros
  const [search, setSearch] = useState("");
  const [coverageFilter, setCoverageFilter] = useState<string>("all");
  const [technologyFilter, setTechnologyFilter] = useState<string>("all");

  // Ação de Pausar / Reativar regra no cliente (executada no pop-up de clientes)
  const [togglingRuleUid, setTogglingRuleUid] = useState<string | null>(null);

  // Modal de replicação / duplicação rápida para o cliente
  const [duplicateModalOpen, setDuplicateModalOpen] = useState(false);

  // Modal "Visualizar": lista todos os clientes e o status desta regra em cada um
  const [clientsModalRuleUid, setClientsModalRuleUid] = useState<string | null>(null);
  const [ruleToDuplicate, setRuleToDuplicate] = useState<RuleDetail | null>(null);
  const [targetClient, setTargetClient] = useState<{ uid: string; name: string } | null>(null);
  const [newRuleTitle, setNewRuleTitle] = useState("");
  const [customLogQL, setCustomLogQL] = useState("");
  const [syntheticLogLine, setSyntheticLogLine] = useState("");
  const [validationReport, setValidationReport] = useState<LogQLValidationReport | null>(null);
  const [validatingLogQL, setValidatingLogQL] = useState(false);
  const [submittingDuplicate, setSubmittingDuplicate] = useState(false);
  const [duplicateError, setDuplicateError] = useState<string | null>(null);

  // Pasta arbitrada como Baseline Global
  const [baselineConfig, setBaselineConfig] = useState<{ baseline_folder_uid: string; baseline_folder_title?: string | null }>({
    baseline_folder_uid: "global",
    baseline_folder_title: "global",
  });
  const [foldersList, setFoldersList] = useState<{ uid: string; title: string }[]>([]);
  const [arbitrateModalOpen, setArbitrateModalOpen] = useState(false);
  const [selectedFolderToArbitrate, setSelectedFolderToArbitrate] = useState("");
  const [arbitratingLoading, setArbitratingLoading] = useState(false);
  const [arbitratingError, setArbitratingError] = useState<string | null>(null);

  // Linting e execução real da query LogQL no fluxo de implementação do baseline
  const logqlAssist = useLogQLAssist(customLogQL);

  // Gavetas expansíveis dos cards de regras
  const [expandedDrawers, setExpandedDrawers] = useState<Set<string>>(new Set());
  const toggleDrawer = (uid: string) => {
    setExpandedDrawers((prev) => {
      const next = new Set(prev);
      if (next.has(uid)) next.delete(uid);
      else next.add(uid);
      return next;
    });
  };

  const loadMatrix = async () => {
    try {
      setError(null);
      const [data, bConfig, folders] = await Promise.all([
        api.getGlobalMatrix(),
        api.getBaselineFolder().catch(() => ({ baseline_folder_uid: "global", baseline_folder_title: "global" })),
        api.getFolders().catch(() => []),
      ]);
      setMatrix(data);
      setBaselineConfig(bConfig);
      setFoldersList(folders);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Erro ao carregar matriz de regras globais.");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadMatrix();
  }, []);

  /**
   * Tecnologias disponíveis para filtro: derivadas das labels `technology` /
   * `technology_name` das regras baseline retornadas pela API (o Loki não tem
   * label de tecnologia, ela vive na regra). Sem a label, a regra só aparece
   * em "Todas as Tecnologias".
   */
  const technologyOptions = useMemo(() => {
    const bySlug = new Map<string, string>();
    matrix.forEach((item) => {
      const slug = item.labels.technology;
      if (!slug) return;
      if (!bySlug.has(slug)) bySlug.set(slug, item.labels.technology_name || slug);
    });
    return Array.from(bySlug.entries())
      .map(([slug, name]) => ({ slug, name }))
      .sort((a, b) => a.name.localeCompare(b.name, "pt-BR"));
  }, [matrix]);

  const filteredMatrix = useMemo(() => {
    return matrix.filter((item) => {
      const matchSearch =
        item.global_title.toLowerCase().includes(search.toLowerCase()) ||
        Object.entries(item.labels).some(([k, v]) =>
          `${k}:${v}`.toLowerCase().includes(search.toLowerCase())
        );

      let matchCoverage = true;
      if (coverageFilter === "fully_covered") {
        matchCoverage = item.not_implemented_clients_count === 0 && item.total_clients > 0;
      } else if (coverageFilter === "has_gaps") {
        matchCoverage = item.not_implemented_clients_count > 0;
      } else if (coverageFilter === "has_active") {
        matchCoverage = item.active_clients_count > 0;
      }

      const matchTechnology =
        technologyFilter === "all" || item.labels.technology === technologyFilter;

      return matchSearch && matchCoverage && matchTechnology;
    });
  }, [matrix, search, coverageFilter, technologyFilter]);

  // Estatísticas agregadas
  const stats = useMemo(() => {
    const totalGlobal = matrix.length;
    const allClientsSet = new Set<string>();
    let totalCoverages = 0;
    let totalPossible = 0;

    matrix.forEach((m) => {
      m.clients.forEach((c) => allClientsSet.add(c.client_uid));
      totalCoverages += m.active_clients_count;
      totalPossible += m.total_clients;
    });

    const coveragePct = totalPossible > 0 ? Math.round((totalCoverages / totalPossible) * 100) : 0;
    const fullyCovered = matrix.filter((m) => m.not_implemented_clients_count === 0 && m.total_clients > 0).length;

    return {
      totalGlobal,
      totalClients: allClientsSet.size,
      coveragePct,
      fullyCovered,
    };
  }, [matrix]);

  // Item exibido no pop-up "Visualizar" (recalculado a cada recarga da matriz)
  const clientsModalItem = useMemo(
    () => matrix.find((m) => m.global_uid === clientsModalRuleUid) || null,
    [matrix, clientsModalRuleUid]
  );

  // Alterna o status de pausa da regra no cliente
  const handleToggleClientRulePause = async (ruleUid: string, currentStatus: ClientRuleStatus) => {
    setTogglingRuleUid(ruleUid);
    try {
      await api.toggleRulePause(ruleUid, currentStatus === "active");
      await loadMatrix();
    } catch (err: unknown) {
      if (err instanceof Error) {
        alert(`Erro ao alterar status: ${err.message}`);
      }
    } finally {
      setTogglingRuleUid(null);
    }
  };

  // Abre modal para replicar regra global diretamente no cliente selecionado
  const handleOpenDuplicateForClient = async (
    globalUid: string,
    client: { uid: string; name: string }
  ) => {
    setTargetClient(client);
    setDuplicateError(null);
    setValidationReport(null);
    logqlAssist.reset();

    try {
      const detail = await api.getRule(globalUid);
      setRuleToDuplicate(detail);
      const cleanTitle = detail.title.replace(/^\[.*?\]\s*/, "").trim();
      setNewRuleTitle(cleanTitle);

      let logql = detail.annotations?.logql_query || "";
      if (!logql && detail.queries?.[0]?.model) {
        const m = detail.queries[0].model as Record<string, unknown>;
        logql = (m?.expr as string) || (m?.query as string) || "";
      }
      if (!logql) {
        logql = `{service="auth", client="${client.uid}"} |= "Failed password" | json | attempts >= 5`;
      }
      setCustomLogQL(logql);

      setSyntheticLogLine(
        JSON.stringify(
          {
            timestamp: new Date().toISOString(),
            service: "sshd",
            client: client.uid,
            attempts: 6,
            message: `Failed password for root on ${client.name}`,
            status: "failed",
          },
          null,
          2
        )
      );

      setDuplicateModalOpen(true);
    } catch (err: unknown) {
      if (err instanceof Error) {
        alert(`Erro ao carregar detalhes da regra global: ${err.message}`);
      }
    }
  };

  const handleValidateLogQL = async () => {
    if (!customLogQL.trim() || !syntheticLogLine.trim()) return;
    setValidatingLogQL(true);
    try {
      const res = await api.testLogQL(customLogQL, syntheticLogLine);
      setValidationReport(res);
    } catch (err: unknown) {
      if (err instanceof Error) {
        alert(`Erro na validação do LogQL: ${err.message}`);
      }
    } finally {
      setValidatingLogQL(false);
    }
  };

  // Linting sintático/semântico da query que será implementada no cliente
  const handleLintBaselineLogQL = async () => {
    if (!customLogQL.trim()) {
      setDuplicateError("Informe a query LogQL para validação.");
      return;
    }
    setDuplicateError(null);
    const outcome = await logqlAssist.lint(customLogQL);
    if (outcome.error) {
      setDuplicateError(outcome.error);
    }
  };

  // Execução real da query contra o datasource Loki (mesma função da tela "Regras")
  const handleRunBaselineQuery = async () => {
    if (!customLogQL.trim()) {
      setDuplicateError("Informe a query LogQL para execução.");
      return;
    }
    setDuplicateError(null);
    const outcome = await logqlAssist.run(customLogQL, {
      scope: "client",
      client_uid: targetClient?.uid,
    });
    if (outcome.error) {
      setDuplicateError(`Erro ao consultar query: ${outcome.error}`);
    }
  };

  const handleSubmitDuplicate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ruleToDuplicate || !targetClient) return;

    setDuplicateError(null);

    // REGRA DE NEGÓCIO: a regra replicada nunca é persistida sem linting aprovado
    const gate = await logqlAssist.assertValid(customLogQL);
    if (!gate.ok) {
      setDuplicateError(gate.error);
      return;
    }

    setSubmittingDuplicate(true);
    try {
      await api.duplicateRule(ruleToDuplicate.uid, {
        target_folder_uid: targetClient.uid,
        target_folder_title: targetClient.name,
        new_title: newRuleTitle.trim(),
        client_name: targetClient.name,
        custom_logql: customLogQL.trim(),
      });
      setDuplicateModalOpen(false);
      await loadMatrix();
    } catch (err: unknown) {
      if (err instanceof Error) {
        setDuplicateError(err.message);
      } else {
        setDuplicateError("Erro ao replicar regra para o cliente.");
      }
    } finally {
      setSubmittingDuplicate(false);
    }
  };



  return (
    <div className="flex flex-col w-full pb-12">
      {/* Top Context Header & Actions */}
      <div className="flex flex-col gap-space-md mb-space-lg">
        {/* Breadcrumb & Status Tag */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-space-xs font-code-sm text-code-sm uppercase">
            <span className="text-outline">DANTE</span>
            <span className="text-surface-variant">/</span>
            <span className="text-outline">ENGENHARIA DE DETECÇÃO</span>
            <span className="text-surface-variant">/</span>
            <span className="text-primary-container font-semibold">CONTROLE DE BASELINE</span>
          </div>
          <div className="flex items-center gap-space-sm">
            <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-surface-container-low font-code-sm text-code-sm text-on-surface-variant border border-outline-variant/30">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
              UID Global: <code className="text-secondary font-code-sm">{baselineConfig.baseline_folder_uid}</code>
            </span>
          </div>
        </div>

        {/* Title and Action Toolbar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md">
          <div className="flex flex-col">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight">Controle de Baseline</h1>
            <p className="font-body-md text-body-md text-on-surface-variant">
              Visualização consolidada de regras baseline e status de adoção por cliente
            </p>
          </div>
          <div className="flex items-center flex-wrap gap-space-sm">
            <button
              onClick={() => {
                setSelectedFolderToArbitrate(baselineConfig.baseline_folder_uid);
                setArbitratingError(null);
                setArbitrateModalOpen(true);
              }}
              className="h-8 px-space-md rounded-lg bg-surface-container-low text-on-surface hover:bg-surface-container-high transition-colors font-body-sm text-body-sm flex items-center gap-1.5 shadow-sm border border-outline-variant/30"
              type="button"
            >
              <span className="material-symbols-outlined text-[16px] text-outline">folder_shared</span>
              <span>Arbitrar Pasta Global ({baselineConfig.baseline_folder_title || baselineConfig.baseline_folder_uid})</span>
            </button>
            <button
              onClick={loadMatrix}
              disabled={loading}
              className="h-8 px-space-md rounded-lg bg-surface-container-low text-on-surface hover:bg-surface-container-high transition-colors font-body-sm text-body-sm flex items-center gap-1.5 shadow-sm border border-outline-variant/30 group"
              type="button"
            >
              <span className={`material-symbols-outlined text-[16px] text-secondary ${loading ? "animate-spin" : "group-hover:rotate-180"} transition-transform duration-500`}>
                sync
              </span>
              <span>Atualizar Matriz</span>
            </button>
          </div>
        </div>

        {/* Client Status Micro-Legend */}
        <div className="flex items-center gap-space-md py-1.5 px-space-md rounded-lg bg-surface-container-lowest max-w-fit shadow-inner border border-outline-variant/20">
          <span className="font-code-sm text-code-sm uppercase text-outline">Status nos clientes:</span>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-tertiary"></span>
            <span className="font-body-sm text-body-sm text-on-surface">Ativa</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-secondary"></span>
            <span className="font-body-sm text-body-sm text-on-surface">Pausada</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-primary-container"></span>
            <span className="font-body-sm text-body-sm text-on-surface">Não implementada</span>
          </div>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-space-md rounded-xl bg-error-container/20 border border-error-container text-error font-body-sm">
          {error}
        </div>
      )}

      {/* KPI Scorecards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md mb-space-lg">
        {/* Card 1 */}
        <div className="p-space-lg rounded-xl bg-surface-container-low shadow-md flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute right-3 top-3 w-10 h-10 rounded-lg bg-surface-container flex items-center justify-center text-outline group-hover:text-primary transition-colors">
            <span className="material-symbols-outlined text-[20px]">category</span>
          </div>
          <div>
            <span className="font-code-sm text-code-sm uppercase text-outline tracking-wider">Regras no Catálogo Global</span>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-metric-display text-metric-display text-on-surface font-bold">{stats.totalGlobal}</span>
              <span className="font-code-sm text-code-sm text-tertiary font-medium">100% catalogadas</span>
            </div>
          </div>
          <div className="mt-space-md pt-2 flex items-center justify-between bg-surface-container-lowest/50 px-2 py-1 rounded">
            <span className="font-body-sm text-body-sm text-on-surface-variant truncate">
              Pasta {baselineConfig.baseline_folder_title || baselineConfig.baseline_folder_uid}
            </span>
            <span className="font-code-sm text-code-sm text-secondary">Telemetria OK</span>
          </div>
        </div>

        {/* Card 2 */}
        <div className="p-space-lg rounded-xl bg-surface-container-low shadow-md flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute right-3 top-3 w-10 h-10 rounded-lg bg-surface-container flex items-center justify-center text-outline group-hover:text-primary transition-colors">
            <span className="material-symbols-outlined text-[20px]">hub</span>
          </div>
          <div>
            <span className="font-code-sm text-code-sm uppercase text-outline tracking-wider">Clientes SIEM Monitorados</span>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-metric-display text-metric-display text-primary-container font-bold">{stats.totalClients}</span>
              <span className="font-code-sm text-code-sm text-outline">Tenants ativos</span>
            </div>
          </div>
          <div className="mt-space-md pt-2 flex items-center justify-between bg-surface-container-lowest/50 px-2 py-1 rounded">
            <span className="font-body-sm text-body-sm text-on-surface-variant">Pastas de clientes integrados</span>
            <span className="font-code-sm text-code-sm text-tertiary">100% Online</span>
          </div>
        </div>

        {/* Card 3 */}
        <div className="p-space-lg rounded-xl bg-surface-container-low shadow-md flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute right-3 top-3 w-10 h-10 rounded-lg bg-surface-container flex items-center justify-center text-outline group-hover:text-primary transition-colors">
            <span className="material-symbols-outlined text-[20px]">donut_large</span>
          </div>
          <div>
            <span className="font-code-sm text-code-sm uppercase text-outline tracking-wider">Taxa de Adesão Global</span>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-metric-display text-metric-display text-on-surface font-bold">{stats.coveragePct}%</span>
              <span className="font-code-sm text-code-sm text-outline">Média agregada</span>
            </div>
          </div>
          <div className="mt-space-md">
            <div className="w-full bg-surface-container-lowest rounded-full h-1.5 overflow-hidden flex">
              <div className="bg-tertiary h-full transition-all duration-500" style={{ width: `${stats.coveragePct}%` }}></div>
              <div className="bg-primary-container/40 h-full" style={{ width: `${100 - stats.coveragePct}%` }}></div>
            </div>
            <span className="font-body-sm text-body-sm text-on-surface-variant block mt-1.5">
              Cobertura média das regras nos clientes
            </span>
          </div>
        </div>

        {/* Card 4 */}
        <div className="p-space-lg rounded-xl bg-surface-container-low shadow-md flex flex-col justify-between relative overflow-hidden group">
          <div className="absolute right-3 top-3 w-10 h-10 rounded-lg bg-surface-container flex items-center justify-center text-outline group-hover:text-tertiary transition-colors">
            <span className="material-symbols-outlined text-[20px]">verified</span>
          </div>
          <div>
            <span className="font-code-sm text-code-sm uppercase text-outline tracking-wider">Regras 100% Implementadas</span>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-metric-display text-metric-display text-tertiary font-bold">{stats.fullyCovered}</span>
              <span className="font-code-sm text-code-sm text-on-surface-variant font-medium">de {stats.totalGlobal} regras</span>
            </div>
          </div>
          <div className="mt-space-md pt-2 flex items-center justify-between bg-surface-container-lowest/50 px-2 py-1 rounded">
            <span className="font-body-sm text-body-sm text-on-surface-variant">Sem lacunas em nenhum cliente</span>
            <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-tertiary/10 text-tertiary font-semibold">Auditado</span>
          </div>
        </div>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="p-space-md rounded-xl bg-surface-container-low shadow-sm flex flex-col md:flex-row items-stretch md:items-center justify-between gap-space-md mb-space-md">
        <div className="flex-1 flex items-center gap-space-sm flex-wrap">
          <div className="relative flex-1 min-w-[240px]">
            <span className="material-symbols-outlined absolute left-2.5 top-1/2 -translate-y-1/2 text-outline text-[18px]">search</span>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-8 pl-8 pr-8 rounded-lg bg-surface-container-lowest text-on-surface placeholder:text-outline font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-secondary transition-all"
              placeholder="Buscar regra global por nome ou técnica..."
              type="text"
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-outline hover:text-on-surface"
                type="button"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
              </button>
            )}
          </div>
          <div className="relative">
            <select
              value={technologyFilter}
              onChange={(e) => setTechnologyFilter(e.target.value)}
              className="h-8 px-space-md pr-8 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm appearance-none focus:outline-none focus:ring-1 focus:ring-secondary transition-all cursor-pointer"
            >
              <option value="all">Todas as Tecnologias</option>
              {technologyOptions.map((t) => (
                <option key={t.slug} value={t.slug}>
                  {t.name}
                </option>
              ))}
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-outline text-[16px]">
              expand_more
            </span>
          </div>
          <div className="relative">
            <select
              value={coverageFilter}
              onChange={(e) => setCoverageFilter(e.target.value)}
              className="h-8 px-space-md pr-8 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm appearance-none focus:outline-none focus:ring-1 focus:ring-secondary transition-all cursor-pointer"
            >
              <option value="all">Todas as Regras Globais</option>
              <option value="fully_covered">100% Implementadas</option>
              <option value="has_gaps">Com Lacunas Pendentes</option>
              <option value="has_active">Com ao Menos 1 Ativo</option>
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-outline text-[16px]">
              filter_list
            </span>
          </div>
        </div>

        <div className="flex items-center justify-between md:justify-end gap-space-md shrink-0">
          <span className="font-code-sm text-code-sm text-outline">
            <span className="text-on-surface font-semibold">{filteredMatrix.length}</span> de {matrix.length} regras globais
          </span>
        </div>
      </div>

      {/* Rules Baseline List / Cards */}
      {loading ? (
        <div className="p-8 text-center text-outline font-body-sm bg-surface-container-low rounded-xl">
          Carregando matriz de regras globais...
        </div>
      ) : filteredMatrix.length === 0 ? (
        <div className="p-8 text-center text-outline font-body-sm bg-surface-container-low rounded-xl">
          Nenhuma regra da pasta global encontrada para os filtros selecionados.
        </div>
      ) : (
        <div className="space-y-space-md">
          {filteredMatrix.map((item) => {
            const coveragePercent =
              item.total_clients > 0
                ? Math.round((item.implemented_clients_count / item.total_clients) * 100)
                : 0;
            const isDrawerOpen = expandedDrawers.has(item.global_uid);
            const severity = (item.labels.severity || "high").toUpperCase();

            return (
              <div
                key={item.global_uid}
                className="rounded-xl bg-surface-container-low shadow-sm hover:shadow-md transition-shadow relative overflow-hidden"
              >
                <div
                  className={`absolute left-0 top-0 bottom-0 w-1 ${
                    severity === "CRITICAL" ? "bg-primary-container" : "bg-primary"
                  }`}
                ></div>
                <div className="p-space-lg pl-space-xl">
                  <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-space-sm">
                    <div>
                      <div className="flex items-center flex-wrap gap-2 mb-1.5">
                        <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-secondary-container text-on-secondary-container font-semibold tracking-wider uppercase">
                          Global
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold uppercase ${
                            severity === "CRITICAL"
                              ? "bg-primary-container/20 text-primary"
                              : "bg-surface-container-high text-outline"
                          }`}
                        >
                          {severity}
                        </span>
                        <h2 className="font-headline-md text-headline-md text-on-surface font-semibold">
                          {item.global_title}
                        </h2>
                      </div>
                      <p className="font-body-sm text-body-sm text-on-surface-variant max-w-4xl">
                        {item.annotations.summary || item.annotations.description || "Regra modelo de detecção institucional"}
                      </p>
                    </div>
                    <div className="flex items-center gap-2 self-start shrink-0">
                      <span className="font-code-sm text-code-sm text-outline">
                        UID: {item.global_uid}
                      </span>
                    </div>
                  </div>

                  {/* Monospace Telemetry / Key-Value Badges */}
                  <div className="flex flex-wrap items-center gap-1.5 my-space-md pt-space-xs">
                    <span className="px-2 py-0.5 rounded bg-surface-container-lowest font-code-sm text-code-sm text-outline">
                      client=<span className="text-on-surface">global</span>
                    </span>
                    {Object.entries(item.labels).map(([k, v]) => {
                      let valClass = "text-on-surface";
                      if (k === "mitre_tactic" || k === "mitre_technique") valClass = "text-secondary font-semibold";
                      if (k === "severity") valClass = "text-primary font-semibold";

                      return (
                        <span key={k} className="px-2 py-0.5 rounded bg-surface-container-lowest font-code-sm text-code-sm text-outline">
                          {k}=<span className={valClass}>{v}</span>
                        </span>
                      );
                    })}
                  </div>

                  {/* SIEM Coverage Footer */}
                  <div className="pt-space-sm mt-space-xs flex flex-col md:flex-row md:items-center justify-between gap-space-md bg-surface-container-lowest/60 p-space-md rounded-lg">
                    <div className="flex-1 flex flex-col sm:flex-row sm:items-center gap-space-lg">
                      <div className="flex items-center gap-2">
                        <span className="font-body-sm text-body-sm text-outline">Cobertura nos Clientes SIEM:</span>
                        <span className="font-code-sm text-code-sm text-on-surface font-semibold">
                          {item.implemented_clients_count} / {item.total_clients} Clientes ({coveragePercent}%)
                        </span>
                      </div>

                      {/* Segmented Progress Bar */}
                      <div className="flex items-center gap-1.5 flex-1 max-w-xs">
                        {item.clients.map((c) => (
                          <div
                            key={c.client_uid}
                            className={`h-2 flex-1 rounded-sm ${
                              c.status === "active"
                                ? "bg-tertiary"
                                : c.status === "paused"
                                ? "bg-secondary"
                                : "bg-surface-container-highest"
                            }`}
                            title={`${c.client_name}: ${
                              c.status === "active" ? "Ativa" : c.status === "paused" ? "Pausada" : "Não implementada"
                            }`}
                          ></div>
                        ))}
                      </div>

                      <div className="flex items-center gap-space-md font-code-sm text-code-sm">
                        <span className="text-tertiary">{item.active_clients_count} ativas</span>
                        <span className="text-secondary">{item.paused_clients_count} pausadas</span>
                        <span className="text-primary-container">{item.not_implemented_clients_count} pendentes</span>
                      </div>
                    </div>

                    <button
                      onClick={() => toggleDrawer(item.global_uid)}
                      className="h-7 px-space-md rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors font-body-sm text-body-sm flex items-center gap-1.5 shrink-0"
                      type="button"
                    >
                      <span>Visualizar Detalhes / Tenants</span>
                      <span
                        className={`material-symbols-outlined text-[16px] transition-transform duration-200 ${
                          isDrawerOpen ? "rotate-180" : ""
                        }`}
                      >
                        expand_more
                      </span>
                    </button>
                  </div>

                  {/* Tenant Drilldown Drawer (Expandable) */}
                  {isDrawerOpen && (
                    <div className="mt-space-md pt-space-md space-y-space-sm bg-surface-container-lowest p-space-md rounded-lg">
                      <div className="flex items-center justify-between pb-1">
                        <span className="font-code-sm text-code-sm uppercase text-outline">
                          Status de Propagação por Tenant ({item.clients.length})
                        </span>
                        <button
                          onClick={() => setClientsModalRuleUid(item.global_uid)}
                          className="h-6 px-2 rounded bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors font-code-sm text-code-sm flex items-center gap-1"
                          type="button"
                        >
                          <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                          <span>Abrir Pop-up Completo</span>
                        </button>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-space-sm">
                        {item.clients.map((client) => {
                          const isActive = client.status === "active";
                          const isPaused = client.status === "paused";
                          const isPending = client.status === "not_implemented";

                          return (
                            <div
                              key={client.client_uid}
                              className="p-space-sm rounded bg-surface-container flex items-center justify-between gap-2"
                            >
                              <div className="flex items-center gap-2 min-w-0">
                                <span
                                  className={`w-2 h-2 rounded-full shrink-0 ${
                                    isActive ? "bg-tertiary" : isPaused ? "bg-secondary" : "bg-primary-container"
                                  }`}
                                ></span>
                                <div className="truncate">
                                  <span className="font-body-sm text-body-sm text-on-surface font-semibold block truncate">
                                    {client.client_name}
                                  </span>
                                  <span className="font-code-sm text-code-sm text-outline truncate block">
                                    UID: {client.client_uid}
                                  </span>
                                </div>
                              </div>

                              <div className="flex items-center gap-2 shrink-0">
                                {isPending ? (
                                  <button
                                    onClick={() =>
                                      handleOpenDuplicateForClient(item.global_uid, {
                                        uid: client.client_uid,
                                        name: client.client_name,
                                      })
                                    }
                                    className="h-6 px-2 rounded bg-surface-container-high hover:bg-surface-bright text-on-surface font-code-sm text-code-sm transition-colors"
                                    type="button"
                                  >
                                    Implementar
                                  </button>
                                ) : (
                                  <>
                                    <span
                                      className={`px-2 py-0.5 rounded font-code-sm text-code-sm ${
                                        isActive ? "bg-tertiary/10 text-tertiary" : "bg-secondary/10 text-secondary"
                                      }`}
                                    >
                                      {isActive ? "Ativa" : "Pausada"}
                                    </span>
                                    {client.rule_uid && (
                                      <button
                                        onClick={() =>
                                          handleToggleClientRulePause(client.rule_uid!, client.status)
                                        }
                                        disabled={togglingRuleUid === client.rule_uid}
                                        className="h-6 px-2 rounded bg-surface-container-high hover:bg-surface-bright text-outline hover:text-on-surface font-code-sm text-code-sm transition-colors"
                                        type="button"
                                      >
                                        {togglingRuleUid === client.rule_uid
                                          ? "..."
                                          : isActive
                                          ? "Pausar"
                                          : "Ativar"}
                                      </button>
                                    )}
                                  </>
                                )}
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Modal "Visualizar": todos os clientes e o status desta regra em cada um */}
      <Modal
        isOpen={clientsModalItem !== null}
        onClose={() => setClientsModalRuleUid(null)}
        title="Clientes e status da regra"
        maxWidth="980px"
      >
        {clientsModalItem && (
          <>
            <div
              style={{
                backgroundColor: "rgba(59, 130, 246, 0.1)",
                border: "1px solid rgba(59, 130, 246, 0.3)",
                padding: "10px 14px",
                borderRadius: "6px",
                marginBottom: "16px",
                fontSize: "0.85rem",
              }}
            >
              Regra Baseline: <strong>{clientsModalItem.global_title}</strong>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "12px",
                  flexWrap: "wrap",
                  marginTop: "6px",
                  fontSize: "0.78rem",
                }}
              >
                <span style={{ fontWeight: 700, color: "var(--text-main)" }}>
                  {clientsModalItem.implemented_clients_count} / {clientsModalItem.total_clients} Clientes (
                  {clientsModalItem.total_clients > 0
                    ? Math.round(
                        (clientsModalItem.implemented_clients_count / clientsModalItem.total_clients) * 100
                      )
                    : 0}
                  %)
                </span>
                <span style={{ color: "var(--status-normal)" }}>
                  {clientsModalItem.active_clients_count} ativas
                </span>
                <span style={{ color: "var(--status-pending)" }}>
                  {clientsModalItem.paused_clients_count} pausadas
                </span>
                <span style={{ color: "var(--status-firing)" }}>
                  {clientsModalItem.not_implemented_clients_count} pendentes
                </span>
              </div>
            </div>

            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>Cliente</th>
                    <th>Status nesta regra</th>
                    <th>Regra no cliente</th>
                    <th style={{ textAlign: "right" }}>Ação</th>
                  </tr>
                </thead>
                <tbody>
                  {clientsModalItem.clients.map((c) => {
                    const statusMeta = CLIENT_STATUS_META[c.status];
                    return (
                      <tr key={c.client_uid}>
                        <td style={{ whiteSpace: "nowrap" }}>
                          <strong>{c.client_name}</strong>
                          <div style={{ fontSize: "0.72rem", color: "var(--text-subtle)", fontFamily: "var(--font-mono)" }}>
                            {c.client_uid}
                          </div>
                        </td>
                        <td>
                          <span className={statusMeta.badgeClass} style={{ whiteSpace: "nowrap" }}>
                            {statusMeta.icon} {statusMeta.label}
                          </span>
                        </td>
                        <td style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
                          {c.rule_title || "—"}
                        </td>
                        <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                          {c.status === "not_implemented" && (
                            <button
                              onClick={() => {
                                setClientsModalRuleUid(null);
                                handleOpenDuplicateForClient(clientsModalItem.global_uid, {
                                  uid: c.client_uid,
                                  name: c.client_name,
                                });
                              }}
                              className="btn btn-primary btn-sm"
                              title={`Implantar esta regra global no tenant ${c.client_name}`}
                            >
                              Implementar
                            </button>
                          )}

                          {c.status === "paused" && c.rule_uid && (
                            <button
                              onClick={() => handleToggleClientRulePause(c.rule_uid!, c.status)}
                              disabled={togglingRuleUid === c.rule_uid}
                              className="btn btn-primary btn-sm"
                              title="Reativar avaliação desta regra no tenant"
                            >
                              {togglingRuleUid === c.rule_uid ? "..." : "Reativar"}
                            </button>
                          )}

                          {c.status === "active" && c.rule_uid && (
                            <button
                              onClick={() => handleToggleClientRulePause(c.rule_uid!, c.status)}
                              disabled={togglingRuleUid === c.rule_uid}
                              className="btn btn-secondary btn-sm"
                              title="Pausar avaliação temporariamente no tenant"
                            >
                              {togglingRuleUid === c.rule_uid ? "..." : "Pausar"}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}

                  {clientsModalItem.clients.length === 0 && (
                    <tr>
                      <td colSpan={4} style={{ color: "var(--text-subtle)", fontSize: "0.85rem" }}>
                        Nenhum tenant cadastrado no portal.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <span
              style={{
                display: "block",
                marginTop: "10px",
                fontSize: "0.75rem",
                color: "var(--text-subtle)",
              }}
            >
              As ações são aplicadas imediatamente no cliente. Implementar abre o fluxo de replicação da regra com o LogQL já validado.
            </span>
          </>
        )}
      </Modal>

      {/* Modal de Replicação Rápida de Regra Global para o Cliente */}
      <Modal
        isOpen={duplicateModalOpen}
        onClose={() => setDuplicateModalOpen(false)}
        title={`Replicar Regra Global para ${targetClient?.name || "Cliente"}`}
      >
        {duplicateError && <div className="alert-box">{duplicateError}</div>}

        <form onSubmit={handleSubmitDuplicate}>
          <div
            style={{
              backgroundColor: "rgba(59, 130, 246, 0.1)",
              border: "1px solid rgba(59, 130, 246, 0.3)",
              padding: "10px 14px",
              borderRadius: "6px",
              marginBottom: "16px",
              fontSize: "0.85rem",
            }}
          >
            Regra Global Modelo: <strong>{ruleToDuplicate?.title}</strong>
            <br />
            Cliente Destino: <strong>{targetClient?.name}</strong> (Pasta: <code>{targetClient?.uid}</code>)
          </div>

          <div className="form-group">
            <label className="form-label">Título da Regra no Cliente</label>
            <input
              type="text"
              className="input"
              style={{ width: "100%" }}
              value={newRuleTitle}
              onChange={(e) => setNewRuleTitle(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
              <label className="form-label" style={{ marginBottom: 0 }}>Query em LogQL (Telemetria)</label>
              <LogQLActionButtons
                linting={logqlAssist.linting}
                executing={logqlAssist.executing}
                onLint={handleLintBaselineLogQL}
                onRun={handleRunBaselineQuery}
              />
            </div>
            <LogQLEditor
              value={customLogQL}
              onChange={(val) => setCustomLogQL(val)}
              height="80px"
              required
            />
            <span style={{ fontSize: "0.75rem", color: "var(--text-subtle)", marginTop: "2px", display: "block" }}>
              A query precisa ser aprovada no linting antes de ser implementada no cliente.
            </span>
          </div>

          {/* Resultado do Linting Sintático e Semântico */}
          {logqlAssist.lintResult && <LogQLLintPanel lintResult={logqlAssist.lintResult} />}

          {/* Resultado da execução real da query na telemetria */}
          {logqlAssist.timeoutNotification && <LogQLTimeoutNotice message={logqlAssist.timeoutNotification} />}
          {logqlAssist.queryResult && <LogQLQueryResultPanel queryResult={logqlAssist.queryResult} />}

          {/* Validação Rápida LogQL */}
          <div
            style={{
              backgroundColor: "var(--bg-input)",
              border: "1px solid var(--border-color)",
              padding: "12px",
              borderRadius: "8px",
              marginBottom: "16px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
              <label className="form-label" style={{ marginBottom: 0, fontSize: "0.8rem" }}>
                Teste Sintético de LogQL (Opcional)
              </label>
              <button
                type="button"
                onClick={handleValidateLogQL}
                disabled={validatingLogQL}
                className="btn btn-secondary btn-sm"
                style={{ fontSize: "0.75rem", padding: "2px 8px" }}
              >
                {validatingLogQL ? "Validando..." : "Validar Compatibilidade"}
              </button>
            </div>
            <textarea
              className="input"
              style={{ width: "100%", height: "60px", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}
              value={syntheticLogLine}
              onChange={(e) => setSyntheticLogLine(e.target.value)}
              placeholder="Linha de log fictícia para teste..."
            />

            {validationReport && (
              <div style={{ marginTop: "8px", fontSize: "0.8rem" }}>
                <span style={{ color: validationReport.is_compatible ? "var(--status-normal)" : "var(--status-firing)" }}>
                  {validationReport.is_compatible ? "COMPATÍVEL" : "INCOMPATÍVEL"} - {validationReport.message}
                </span>
              </div>
            )}
          </div>

          <div className="modal-footer" style={{ padding: "12px 0 0 0" }}>
            <button
              type="button"
              onClick={() => setDuplicateModalOpen(false)}
              className="btn btn-secondary"
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={submittingDuplicate}
            >
              {submittingDuplicate ? "Implantando..." : `Confirmar e Ativar em ${targetClient?.name}`}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal para Arbitrar qual repositório é o Baseline Global */}
      <Modal
        isOpen={arbitrateModalOpen}
        onClose={() => {
          if (!arbitratingLoading) setArbitrateModalOpen(false);
        }}
        title="Arbitrar Pasta do Baseline Global"
        maxWidth="520px"
      >
        <div>
          <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "14px" }}>
            O D.A.N.T.E. utiliza uma pasta/repositório como repositório canônico das regras de detecção de referência (Baseline). Em instâncias externas, o identificador geralmente é arbitrado e não será necessariamente <code>global</code>.
          </p>

          {arbitratingError && (
            <div className="alert-box" style={{ marginBottom: "14px" }}>
              {arbitratingError}
            </div>
          )}

          <div className="form-group">
            <label className="form-label" style={{ fontWeight: 600 }}>
              Repositório para o Baseline
            </label>
            <select
              className="select"
              value={selectedFolderToArbitrate}
              onChange={(e) => setSelectedFolderToArbitrate(e.target.value)}
            >
              {foldersList.map((f) => (
                <option key={f.uid} value={f.uid}>
                  {f.title} (UID: {f.uid})
                </option>
              ))}
            </select>
          </div>

          <div style={{ padding: "10px 14px", backgroundColor: "rgba(255, 255, 255, 0.04)", borderRadius: "6px", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "16px" }}>
            Pasta configurada atualmente: <strong>{baselineConfig.baseline_folder_title || baselineConfig.baseline_folder_uid}</strong> (<code>{baselineConfig.baseline_folder_uid}</code>)
          </div>

          <div className="modal-footer" style={{ padding: "14px 0 0 0", borderTop: "1px solid var(--border-color)" }}>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setArbitrateModalOpen(false)}
              disabled={arbitratingLoading}
            >
              Cancelar
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={arbitratingLoading || !selectedFolderToArbitrate}
              onClick={async () => {
                setArbitratingLoading(true);
                setArbitratingError(null);
                try {
                  const res = await api.setBaselineFolder(selectedFolderToArbitrate);
                  setBaselineConfig(res);
                  await loadMatrix();
                  setArbitrateModalOpen(false);
                } catch (err: unknown) {
                  setArbitratingError(
                    err instanceof Error ? err.message : "Erro ao arbitrar a pasta global."
                  );
                } finally {
                  setArbitratingLoading(false);
                }
              }}
            >
              {arbitratingLoading ? "Salvando..." : "Salvar Configuração"}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
