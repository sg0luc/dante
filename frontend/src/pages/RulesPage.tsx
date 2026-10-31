import React, { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { Modal } from "../components/Modal";
import { RuleImportModal } from "../components/RuleImportModal";
import { ConfirmModal } from "../components/ConfirmModal";
import { RuleGrafanaBlocks } from "../components/RuleGrafanaBlocks";
import { RuleAIEvaluationPanel } from "../components/RuleAIEvaluationPanel";
import {
  LogQLActionButtons,
  LogQLEditor,
  LogQLLintPanel,
  LogQLQueryResultPanel,
  LogQLTimeoutNotice,
} from "../components/LogQLAssist";
import { useLogQLAssist } from "../hooks/useLogQLAssist";
import {
  AlertInstance,
  FolderItem,
  RuleDetail,
  RuleImprovementEvaluation,
  RuleScope,
  RuleSeverity,
  RuleSummary,
  Technology,
  TenantSummary,
} from "../types";

/**
 * Infere a tecnologia alvo com base no título da regra de detecção e no catálogo de tecnologias.
 */
export function inferTechnologyFromTitle(
  title: string,
  technologies: Technology[]
): { slug: string; name: string } {
  const lower = title.toLowerCase();

  // 1. Casamentos prioritários com palavras-chave consagradas de telemetria
  if (
    lower.includes("windows") ||
    lower.includes("active directory") ||
    lower.includes("ad/") ||
    lower.includes("kerberos") ||
    lower.includes("powershell") ||
    lower.includes("mimikatz") ||
    lower.includes("lsass") ||
    lower.includes("ntlm") ||
    lower.includes("dusttrap") ||
    lower.includes("4688") ||
    lower.includes("4625") ||
    lower.includes("4769")
  ) {
    const t = technologies.find((x) => x.slug === "ad_windows" || x.slug.includes("windows"));
    return { slug: t?.slug ?? "ad_windows", name: t?.name ?? "AD/Windows" };
  }

  if (
    lower.includes("fortigate") ||
    lower.includes("fortinet") ||
    lower.includes("firewall") ||
    lower.includes("portscan") ||
    lower.includes("varredura de portas")
  ) {
    const t = technologies.find((x) => x.slug === "fortigate" || x.slug.includes("forti"));
    return { slug: t?.slug ?? "fortigate", name: t?.name ?? "Fortigate" };
  }

  if (
    lower.includes("office365") ||
    lower.includes("office 365") ||
    lower.includes("o365") ||
    lower.includes("m365") ||
    lower.includes("entra") ||
    lower.includes("azuread") ||
    lower.includes("azure ad") ||
    lower.includes("exchange") ||
    lower.includes("sharepoint")
  ) {
    const t = technologies.find((x) => x.slug === "office365" || x.slug.includes("office"));
    return { slug: t?.slug ?? "office365", name: t?.name ?? "Office365" };
  }

  if (
    lower.includes("linux") ||
    lower.includes("ssh") ||
    lower.includes("sudo") ||
    lower.includes("bash") ||
    lower.includes("root") ||
    lower.includes("nsenter")
  ) {
    const t = technologies.find((x) => x.slug === "linux");
    return { slug: t?.slug ?? "linux", name: t?.name ?? "Linux" };
  }

  if (lower.includes("dns") || lower.includes("tunelamento dns") || lower.includes("tunneling")) {
    const t = technologies.find((x) => x.slug === "dns");
    return { slug: t?.slug ?? "dns", name: t?.name ?? "DNS" };
  }

  if (lower.includes("checkpoint") || lower.includes("check point")) {
    const t = technologies.find((x) => x.slug === "checkpoint" || x.slug.includes("check"));
    return { slug: t?.slug ?? "checkpoint", name: t?.name ?? "Check Point" };
  }

  // 2. Busca tolerante pelo catálogo carregado (nome, slug ou regex)
  for (const tech of technologies) {
    if (!tech.enabled) continue;
    const techNameLower = tech.name.toLowerCase();
    const techSlugLower = tech.slug.toLowerCase();
    const coreRegex = (tech.rule_groups_regex || "").replace(/\.\*|\^|\$/g, "").trim().toLowerCase();
    if (
      lower.includes(techNameLower) ||
      lower.includes(techSlugLower) ||
      (coreRegex.length >= 3 && lower.includes(coreRegex))
    ) {
      return { slug: tech.slug, name: tech.name };
    }
  }

  const fallback = technologies.find((x) => x.enabled);
  return { slug: fallback?.slug ?? "ad_windows", name: fallback?.name ?? "AD/Windows" };
}

/**
 * Preenche regras de detecção sem labels/tags de telemetria conforme o padrão nativo do D.A.N.T.E.,
 * atribuindo source='grafana' para regras que não possuam a label de origem.
 */
export function enrichRuleTelemetryLabels<T extends RuleSummary>(
  rule: T,
  technologies: Technology[]
): T {
  const labels: Record<string, string> = { ...(rule.labels || {}) };
  const isFromGlobal =
    rule.folder_uid.toLowerCase() === "global" ||
    rule.folder_title.toLowerCase() === "global";

  const hasCompleteTelemetry =
    Boolean(labels.technology) &&
    Boolean(labels.source) &&
    Boolean(labels.scope) &&
    (Boolean(labels.siem_tier) || Boolean(labels.tier));

  if (!hasCompleteTelemetry) {
    // 1. Label source preenchida com o valor 'grafana'
    if (!labels.source) {
      labels.source = "grafana";
    }

    // 2. Escopo, cliente e tier de SIEM
    if (!labels.scope) {
      labels.scope = isFromGlobal ? "baseline" : "client";
    }
    if (!labels.siem_tier) {
      labels.siem_tier = isFromGlobal ? "global" : "client";
    }
    if (!labels.tier) {
      labels.tier = isFromGlobal ? "global" : "client";
    }
    if (!labels.client) {
      labels.client = isFromGlobal ? "global" : (rule.folder_title || "cliente");
    }

    // 3. Tecnologia e nome da tecnologia inferidos pelo nome da regra
    if (!labels.technology || !labels.technology_name) {
      const inferred = inferTechnologyFromTitle(rule.title, technologies);
      if (!labels.technology) labels.technology = inferred.slug;
      if (!labels.technology_name) labels.technology_name = inferred.name;
    }

    // 4. Severidade inferida se ausente
    if (!labels.severity) {
      const lower = rule.title.toLowerCase();
      if (lower.includes("crit") || lower.includes("urgente")) {
        labels.severity = "critical";
      } else if (
        lower.includes("alt") ||
        lower.includes("high") ||
        lower.includes("forca bruta") ||
        lower.includes("privilege") ||
        lower.includes("varredura")
      ) {
        labels.severity = "high";
      } else if (lower.includes("baix") || lower.includes("low")) {
        labels.severity = "low";
      } else {
        labels.severity = "medium";
      }
    }

    // 5. MITRE Técnica e Tática inferidas se ausentes
    if (!labels.mitre_technique) {
      const techMatch = rule.title.match(/T\d{4}(?:\.\d{3})?/i);
      if (techMatch) {
        labels.mitre_technique = techMatch[0].toUpperCase();
      } else {
        const lower = rule.title.toLowerCase();
        if (lower.includes("forca bruta") || lower.includes("password") || lower.includes("login") || lower.includes("ssh")) {
          labels.mitre_technique = "T1110";
        } else if (lower.includes("portscan") || lower.includes("varredura") || lower.includes("discovery")) {
          labels.mitre_technique = "T1046";
        } else if (lower.includes("sudo") || lower.includes("privilegio") || lower.includes("escalad")) {
          labels.mitre_technique = "T1548";
        } else if (lower.includes("tunnel") || lower.includes("tunelamento") || lower.includes("exfiltr")) {
          labels.mitre_technique = "T1071";
        } else {
          labels.mitre_technique = "T1098";
        }
      }
    }

    if (!labels.mitre_tactic) {
      const lower = rule.title.toLowerCase();
      if (lower.includes("forca bruta") || lower.includes("password") || lower.includes("login") || lower.includes("ssh")) {
        labels.mitre_tactic = "credential-access";
      } else if (lower.includes("portscan") || lower.includes("varredura") || lower.includes("discovery")) {
        labels.mitre_tactic = "discovery";
      } else if (lower.includes("sudo") || lower.includes("privilegio") || lower.includes("escalad")) {
        labels.mitre_tactic = "privilege-escalation";
      } else if (lower.includes("tunnel") || lower.includes("tunelamento") || lower.includes("exfiltr")) {
        labels.mitre_tactic = "exfiltration";
      } else {
        labels.mitre_tactic = "persistence";
      }
    }
  }

  return {
    ...rule,
    labels,
  };
}

export const RulesPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const [rules, setRules] = useState<RuleSummary[]>([]);
  const [foldersList, setFoldersList] = useState<FolderItem[]>([]);
  const [tenantsList, setTenantsList] = useState<TenantSummary[]>([]);
  // Catálogo de tecnologias (rule_groups -> datasource), fonte do radio box
  const [technologies, setTechnologies] = useState<Technology[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filtros
  const [search, setSearch] = useState("");
  const [selectedFolder, setSelectedFolder] = useState<string>("all");
  const [selectedState, setSelectedState] = useState<string>("all");
  const [selectedDeployStatus, setSelectedDeployStatus] = useState<string>("all");
  const [selectedTechnology, setSelectedTechnology] = useState<string>("all");

  // Detalhes modal
  const [detailModalOpen, setDetailModalOpen] = useState(false);
  const [selectedRule, setSelectedRule] = useState<RuleDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Avaliação e Melhoria de Regras por IA
  const [aiEvaluation, setAiEvaluation] = useState<RuleImprovementEvaluation | null>(null);
  const [evaluationsCache, setEvaluationsCache] = useState<Record<string, RuleImprovementEvaluation>>({});
  const [loadingAiEvaluation, setLoadingAiEvaluation] = useState(false);
  const [confirmImplementAiModalOpen, setConfirmImplementAiModalOpen] = useState(false);
  const [implementingAi, setImplementingAi] = useState(false);
  const [implementAiFeedback, setImplementAiFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  // Ação de pausar / ativar individual
  const [togglingUid, setTogglingUid] = useState<string | null>(null);

  // Seleção múltipla de regras e Ações em lote
  const [selectedRuleUids, setSelectedRuleUids] = useState<Set<string>>(new Set());
  const [actionsDropdownOpen, setActionsDropdownOpen] = useState(false);
  const [batchProcessing, setBatchProcessing] = useState(false);
  const [batchFeedback, setBatchFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const actionsMenuRef = useRef<HTMLDivElement>(null);

  // Confirmação de ação em lote
  const [confirmBatchModalOpen, setConfirmBatchModalOpen] = useState(false);
  const [pendingBatchPause, setPendingBatchPause] = useState<boolean | null>(null);



  // Modal Criar Nova Regra de Detecção
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createRuleName, setCreateRuleName] = useState("");
  const [createRuleDesc, setCreateRuleDesc] = useState("");
  const [createRuleScope, setCreateRuleScope] = useState<RuleScope>("baseline");
  const [createRuleTargetClientUid, setCreateRuleTargetClientUid] = useState<string>("");
  const [createRuleEvaluationGroup, setCreateRuleEvaluationGroup] = useState<string>("5m");
  const [alertsList, setAlertsList] = useState<AlertInstance[]>([]);
  const [createRuleLogQL, setCreateRuleLogQL] = useState(
    `count_over_time(\n    {job="wazuh", rule_groups=~".*<tecnologia>.*"}\n    | json\n    [5m]\n)`
  );
  const [createRuleSeverity, setCreateRuleSeverity] = useState<RuleSeverity>("high");
  const [createRuleTactic, setCreateRuleTactic] = useState("Credential Access");
  const [createRuleTechnique, setCreateRuleTechnique] = useState("T1110");
  // Tecnologia (data source) selecionada no radio box e gerenciador do catálogo
  const [createRuleTechnology, setCreateRuleTechnology] = useState<string>("");
  const [techManagerOpen, setTechManagerOpen] = useState(false);
  const [techFormOpen, setTechFormOpen] = useState(false);
  const [techSaving, setTechSaving] = useState(false);
  const [techError, setTechError] = useState<string | null>(null);
  const [techToDelete, setTechToDelete] = useState<Technology | null>(null);
  const [techForm, setTechForm] = useState({
    slug: "",
    name: "",
    rule_groups_regex: "",
    job: "wazuh",
    icon: "",
    description: "",
  });

  // Linting + execução de Query LogQL (hook compartilhado com a tela Controle de Baseline)
  const logqlAssist = useLogQLAssist(createRuleLogQL);
  const { lintResult, linting, queryResult: queryExecutionResult, executing: executingQuery, timeoutNotification: queryTimeoutNotification } = logqlAssist;

  // Estado de envio da regra
  const [creatingRule, setCreatingRule] = useState(false);
  const [createRuleError, setCreateRuleError] = useState<string | null>(null);
  const [createRuleSuccess, setCreateRuleSuccess] = useState<string | null>(null);
  const [replicateBaselineModalOpen, setReplicateBaselineModalOpen] = useState(false);


  const loadData = async () => {
    try {
      setError(null);
      const [r, f, t, tenants, al] = await Promise.all([
        api.getRules(),
        api.getFolders(),
        api.getTechnologies(),
        api.getTenants(),
        api.getAlerts().catch(() => []),
      ]);
      const enrichedRules = r.map((rule) => enrichRuleTelemetryLabels(rule, t));
      setRules(enrichedRules);
      setFoldersList(f);
      setTechnologies(t);
      setTenantsList(tenants);
      setAlertsList(al);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Erro ao carregar regras.");
      }
    } finally {
      setLoading(false);
    }
  };

  // Mapa de contagem de alertas silenciados em tempo real por regra (uid ou nome)
  const ruleSilencedCountMap = useMemo(() => {
    const map = new Map<string, number>();
    for (const alert of alertsList) {
      const isSilenced =
        alert.state === "suppressed" ||
        (Array.isArray(alert.silenced_by) && alert.silenced_by.length > 0);
      if (!isSilenced) continue;

      const rUid = alert.rule_uid || alert.labels?.["__alert_rule_uid__"] || alert.labels?.["rule_uid"];
      if (rUid) {
        map.set(rUid, (map.get(rUid) || 0) + 1);
      }
      if (alert.alertname) {
        map.set(alert.alertname, (map.get(alert.alertname) || 0) + 1);
      }
      if (alert.labels?.["alertname"] && alert.labels["alertname"] !== alert.alertname) {
        map.set(alert.labels["alertname"], (map.get(alert.labels["alertname"]) || 0) + 1);
      }
    }
    return map;
  }, [alertsList]);

  useEffect(() => {
    loadData();
  }, []);

  // Sincroniza filtro vindo da URL (ex: ?folder=Hunter%20Detections)
  useEffect(() => {
    const fParam = searchParams.get("folder");
    if (fParam) {
      setSelectedFolder(fParam);
    }
  }, [searchParams]);

  const folders = useMemo(() => {
    const set = new Set<string>();
    rules.forEach((r) => {
      if (r.folder_title) set.add(r.folder_title);
    });
    foldersList.forEach((f) => {
      if (f.title) set.add(f.title);
    });
    return Array.from(set);
  }, [rules, foldersList]);

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const matchSearch =
        r.title.toLowerCase().includes(search.toLowerCase()) ||
        Object.entries(r.labels).some(([k, v]) =>
          `${k}:${v}`.toLowerCase().includes(search.toLowerCase())
        );

      const matchFolder =
        selectedFolder === "all" ||
        r.folder_title === selectedFolder ||
        r.folder_uid === selectedFolder;

      const matchState =
        selectedState === "all" || r.state.toLowerCase() === selectedState.toLowerCase();

      const matchTechnology =
        selectedTechnology === "all" || r.labels["technology"] === selectedTechnology;

      // Estágio de deploy (Contact Point amarrado): Ativa / Homologação / Pausada.
      const matchDeploy =
        selectedDeployStatus === "all" || r.deploy_status === selectedDeployStatus;

      return (
        matchSearch && matchFolder && matchState && matchTechnology && matchDeploy
      );
    });
  }, [
    rules,
    search,
    selectedFolder,
    selectedState,
    selectedTechnology,
    selectedDeployStatus,
  ]);

  // Fecha menus ao clicar fora
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (actionsMenuRef.current && !actionsMenuRef.current.contains(event.target as Node)) {
        setActionsDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Lista de pastas de clientes (excluindo Global)
  const clientFolders = useMemo(() => {
    return foldersList.filter(
      (f) => f.uid.toLowerCase() !== "global" && f.title.toLowerCase() !== "global"
    );
  }, [foldersList]);

  // Cliente atualmente selecionado para criação de regra
  const selectedClient = useMemo(() => {
    return clientFolders.find((f) => f.uid === createRuleTargetClientUid) || null;
  }, [clientFolders, createRuleTargetClientUid]);

  // Tenant correspondente ao cliente selecionado (com grupos de avaliação disponíveis)
  const selectedTenant = useMemo(() => {
    return tenantsList.find((t) => t.uid === createRuleTargetClientUid) || null;
  }, [tenantsList, createRuleTargetClientUid]);

  // Grupos de avaliação disponíveis para o escopo selecionado (baseline ou cliente)
  const availableEvaluationGroups = useMemo(() => {
    const groups = new Set<string>();
    groups.add("5m");
    if (createRuleScope === "baseline") {
      groups.add("global-detections");
      rules
        .filter((r) => r.folder_uid.toLowerCase() === "global")
        .forEach((r) => {
          if (r.rule_group) groups.add(r.rule_group);
        });
    } else {
      if (selectedTenant) {
        if (selectedTenant.evaluation_group) {
          groups.add(selectedTenant.evaluation_group);
        }
        (selectedTenant.evaluation_groups || []).forEach((g) => {
          if (g.name) groups.add(g.name);
        });
      }
      rules
        .filter((r) => r.folder_uid === createRuleTargetClientUid)
        .forEach((r) => {
          if (r.rule_group) groups.add(r.rule_group);
        });
    }
    return Array.from(groups);
  }, [createRuleScope, selectedTenant, selectedClient, createRuleTargetClientUid, rules]);


  // UIDs das regras visíveis conforme os filtros atuais
  const visibleFilteredUids = useMemo(() => {
    return filteredRules.map((r) => r.uid);
  }, [filteredRules]);

  const selectedVisibleCount = useMemo(() => {
    return visibleFilteredUids.filter((uid) => selectedRuleUids.has(uid)).length;
  }, [visibleFilteredUids, selectedRuleUids]);

  const isAllFilteredSelected =
    visibleFilteredUids.length > 0 && selectedVisibleCount === visibleFilteredUids.length;

  const isIndeterminate =
    selectedVisibleCount > 0 && selectedVisibleCount < visibleFilteredUids.length;

  // Alterna a seleção de uma regra específica
  const handleToggleSelectRule = (uid: string, checked: boolean) => {
    setSelectedRuleUids((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(uid);
      } else {
        next.delete(uid);
      }
      return next;
    });
  };

  // Alterna seleção de todas as regras visíveis no filtro atual
  const handleToggleSelectAll = () => {
    if (isAllFilteredSelected) {
      setSelectedRuleUids((prev) => {
        const next = new Set(prev);
        visibleFilteredUids.forEach((uid) => next.delete(uid));
        return next;
      });
    } else {
      setSelectedRuleUids((prev) => {
        const next = new Set(prev);
        visibleFilteredUids.forEach((uid) => next.add(uid));
        return next;
      });
    }
  };

  // Limpa toda a seleção
  const handleDeselectAll = () => {
    setSelectedRuleUids(new Set());
  };

  // Solicita confirmação para ação massiva
  const handleRequestBatchPause = (paused: boolean) => {
    if (selectedRuleUids.size === 0) return;
    setPendingBatchPause(paused);
    setConfirmBatchModalOpen(true);
    setActionsDropdownOpen(false);
  };

  // Pausar ou reativar regras selecionadas em lote
  const handleBatchPause = async (paused: boolean) => {
    const uidsToProcess = Array.from(selectedRuleUids);
    if (uidsToProcess.length === 0) return;

    setBatchProcessing(true);
    setBatchFeedback(null);
    setActionsDropdownOpen(false);

    try {
      const res = await api.batchToggleRulesPause(uidsToProcess, paused);
      setBatchFeedback({
        type: res.failed.length > 0 ? "error" : "success",
        message: res.message,
      });
      await loadData();

      // Mantém selecionadas apenas as regras que eventualmente falharam
      if (res.failed.length === 0) {
        setSelectedRuleUids(new Set());
      } else {
        setSelectedRuleUids((prev) => {
          const next = new Set(prev);
          res.succeeded.forEach((uid) => next.delete(uid));
          return next;
        });
      }
    } catch (err: unknown) {
      setBatchFeedback({
        type: "error",
        message:
          err instanceof Error
            ? err.message
            : "Erro ao processar alteração das regras selecionadas.",
      });
    } finally {
      setBatchProcessing(false);
      setConfirmBatchModalOpen(false);
      setPendingBatchPause(null);
    }
  };

  const handleOpenDetail = async (uid: string) => {
    setLoadingDetail(true);
    setDetailModalOpen(true);
    setImplementAiFeedback(null);
    // Se a regra já foi avaliada anteriormente na sessão, carrega o parecer em cache imediatamente
    const cachedState = evaluationsCache[uid];
    if (cachedState) {
      setAiEvaluation(cachedState);
    } else {
      setAiEvaluation(null);
    }
    try {
      const detail = await api.getRule(uid);
      const enrichedDetail = enrichRuleTelemetryLabels(detail, technologies) as RuleDetail;
      setSelectedRule(enrichedDetail);
      // Busca do backend (que retorna do cache persistente se existir, ou analisa automaticamente pela 1ª vez)
      fetchAiEvaluation(uid, false);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      }
      setDetailModalOpen(false);
    } finally {
      setLoadingDetail(false);
    }
  };

  const fetchAiEvaluation = async (uid: string, refresh = false) => {
    setLoadingAiEvaluation(true);
    try {
      const evalData = await api.getRuleAIEvaluation(uid, refresh);
      setAiEvaluation(evalData);
      setEvaluationsCache((prev) => ({ ...prev, [uid]: evalData }));
    } catch (err) {
      console.warn("Falha ao avaliar oportunidades de melhoria com IA:", err);
    } finally {
      setLoadingAiEvaluation(false);
    }
  };

  const handleApplyAiSuggestions = async () => {
    if (!selectedRule || !aiEvaluation) return;
    setImplementingAi(true);
    setImplementAiFeedback(null);
    try {
      const res = await api.applyRuleAISuggestions(selectedRule.uid, {
        suggested_logql_query: aiEvaluation.suggested_logql_query,
        suggested_for_duration: aiEvaluation.suggested_for_duration,
        suggested_labels: aiEvaluation.suggested_labels,
        suggested_annotations: aiEvaluation.suggested_annotations,
      });
      setSelectedRule(res.rule);
      setImplementAiFeedback({
        type: "success",
        message: res.message || "Melhorias da IA aplicadas com sucesso na regra!",
      });
      setConfirmImplementAiModalOpen(false);
      loadData();
      fetchAiEvaluation(selectedRule.uid, true);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Erro ao aplicar melhorias na regra";
      setImplementAiFeedback({
        type: "error",
        message: msg,
      });
    } finally {
      setImplementingAi(false);
    }
  };

  const handleTogglePause = async (uid: string, currentPaused: boolean) => {
    setTogglingUid(uid);
    try {
      await api.toggleRulePause(uid, !currentPaused);
      await loadData();
    } catch (err: unknown) {
      if (err instanceof Error) {
        alert(`Erro ao alterar status: ${err.message}`);
      }
    } finally {
      setTogglingUid(null);
    }
  };



  // --- Segregação de tecnologia (rule_groups -> data source) -------------------

  /** Monta a query base de uma tecnologia com contagem métrica e indentação:
   * count_over_time(
   *     {job="wazuh", rule_groups=~".*<tecnologia>.*"}
   *     | json
   *     [5m]
   * )
   */
  const buildTechnologyQuery = (tech?: Technology | null): string => {
    const selector = tech ? tech.logql_selector : 'rule_groups=~".*<tecnologia>.*"';
    const job = tech?.job || "wazuh";
    return `count_over_time(\n    {job="${job}", ${selector}}\n    | json\n    [5m]\n)`;
  };

  /**
   * Reaplica a tecnologia selecionada sobre a query atual, preservando os filtros
   * de linha/pipeline já escritos pelo analista. O seletor {..} é o único trecho
   * alterado: `job` e `rule_groups` passam a refletir a tecnologia escolhida.
   */
  const applyTechnologyToQuery = (query: string, tech: Technology): string => {
    const selectorRegex = /\{([^}]*)\}/;
    const selectorMatch = query.match(selectorRegex);
    if (!selectorMatch) return buildTechnologyQuery(tech);

    let inner = selectorMatch[1].trim();
    const ssGroupsRegex = /(?:rule_groups|ss_groups)\s*(=~|!~|!=|=)\s*(?:"[^"]*"|`[^`]*`)/;
    const jobRegex = /job\s*(=~|!~|!=|=)\s*(?:"[^"]*"|`[^`]*`)/;

    if (ssGroupsRegex.test(inner)) {
      inner = inner.replace(ssGroupsRegex, tech.logql_selector);
    } else {
      const trimmed = inner.replace(/,\s*$/, "").trim();
      inner = trimmed ? `${trimmed}, ${tech.logql_selector}` : tech.logql_selector;
    }

    if (jobRegex.test(inner)) {
      inner = inner.replace(jobRegex, `job="${tech.job}"`);
    } else {
      inner = `job="${tech.job}", ${inner}`;
    }

    return query.replace(selectorRegex, `{${inner}}`);
  };

  /** Handler do radio box de tecnologia no modal de criação. */
  const handleSelectTechnology = (slug: string) => {
    setCreateRuleTechnology(slug);
    const tech = technologies.find((t) => t.slug === slug);
    if (!tech) return;
    setCreateRuleLogQL((prev) => applyTechnologyToQuery(prev || "", tech));
  };

  /** Cria uma tecnologia no catálogo (modal Gerenciar Tecnologias). */
  const handleCreateTechnology = async (e: React.FormEvent) => {
    e.preventDefault();
    setTechError(null);
    setTechSaving(true);
    try {
      const created = await api.createTechnology({
        slug: techForm.slug.trim().toLowerCase(),
        name: techForm.name.trim(),
        rule_groups_regex: techForm.rule_groups_regex.trim(),
                job: techForm.job.trim() || "wazuh",
        icon: techForm.icon.trim(),
        description: techForm.description.trim(),
      });
      const updated = await api.getTechnologies();
      setTechnologies(updated);
      setCreateRuleTechnology(created.slug);
      setCreateRuleLogQL((prev) => applyTechnologyToQuery(prev || "", created));
      setTechForm({ slug: "", name: "", rule_groups_regex: "", job: "wazuh", icon: "", description: "" });
      setTechFormOpen(false);
    } catch (err: unknown) {
      setTechError(err instanceof Error ? err.message : "Erro ao cadastrar tecnologia.");
    } finally {
      setTechSaving(false);
    }
  };

  /** Remove uma tecnologia do catálogo (após confirmação explícita). */
  const handleDeleteTechnology = async () => {
    if (!techToDelete) return;
    setTechSaving(true);
    setTechError(null);
    try {
      await api.deleteTechnology(techToDelete.slug);
      const updated = await api.getTechnologies();
      setTechnologies(updated);
      if (createRuleTechnology === techToDelete.slug) {
        setCreateRuleTechnology("");
      }
      setTechToDelete(null);
    } catch (err: unknown) {
      setTechError(err instanceof Error ? err.message : "Erro ao remover tecnologia.");
    } finally {
      setTechSaving(false);
    }
  };

  // Abrir modal de criação de regra
  const handleOpenCreateModal = () => {
    setCreateRuleName("");
    setCreateRuleDesc("");
    setCreateRuleScope("baseline");
    setCreateRuleEvaluationGroup("5m");
    // Seleciona primeira pasta de cliente se existir
    const firstClient = foldersList.find((f) => f.uid.toLowerCase() !== "global" && f.title.toLowerCase() !== "global");
    setCreateRuleTargetClientUid(firstClient ? firstClient.uid : "");
    const firstTech = technologies.find((t) => t.enabled) ?? null;
    setCreateRuleTechnology(firstTech ? firstTech.slug : "");
    setCreateRuleLogQL(buildTechnologyQuery(firstTech));
    setCreateRuleSeverity("high");
    setCreateRuleTactic("Credential Access");
    setCreateRuleTechnique("T1110");
    logqlAssist.reset();
    setCreateRuleError(null);
    setCreateRuleSuccess(null);
    setReplicateBaselineModalOpen(false);
    setCreateModalOpen(true);
  };

  // Validação (Linting) sintática e semântica
  const handleLintLogQL = async () => {
    if (!createRuleLogQL.trim()) {
      setCreateRuleError("Informe a query LogQL para validação.");
      return;
    }
    setCreateRuleError(null);
    const outcome = await logqlAssist.lint(createRuleLogQL);
    if (!outcome.data) {
      setCreateRuleError(`Erro no linting: ${outcome.error ?? "falha desconhecida"}`);
      return;
    }
    // Mantém o radio box coerente com a tecnologia real do matcher rule_groups.
    if (outcome.data.technologies.length === 1) {
      setCreateRuleTechnology(outcome.data.technologies[0]);
    }
  };

  // Execução da query no Grafana com notificação de timeout
  const handleExecuteQuery = async () => {
    if (!createRuleLogQL.trim()) {
      setCreateRuleError("Informe a query LogQL para execução.");
      return;
    }
    if (createRuleScope === "client" && !createRuleTargetClientUid) {
      setCreateRuleError("Selecione um cliente (grafana_folder) de destino para consultar os logs.");
      return;
    }
    setCreateRuleError(null);
    const outcome = await logqlAssist.run(createRuleLogQL, {
      scope: createRuleScope,
      client_uid: createRuleScope === "client" ? createRuleTargetClientUid : undefined,
    });
    if (!outcome.data && outcome.error) {
      setCreateRuleError(`Erro ao consultar query: ${outcome.error}`);
    }
  };

  // Persiste a regra no backend (com ou sem replicação automática para clientes no caso de baseline)
  const executeCreateRule = async (replicateToClients: boolean, resolvedTechSlug?: string) => {
    const techSlug = resolvedTechSlug ?? createRuleTechnology;
    setCreatingRule(true);
    setCreateRuleError(null);
    setCreateRuleSuccess(null);

    try {
      const res = await api.createRule({
        name: createRuleName.trim(),
        description: createRuleDesc.trim() || undefined,
        scope: createRuleScope,
        target_client_uid: createRuleScope === "client" ? createRuleTargetClientUid : undefined,
        logql_query: createRuleLogQL.trim(),
        severity: createRuleSeverity,
        mitre_tactic: createRuleTactic.trim(),
        mitre_technique: createRuleTechnique.trim(),
        evaluation_group: createRuleEvaluationGroup.trim() || undefined,
        technology: techSlug || undefined,
        replicate_to_clients: createRuleScope === "baseline" ? replicateToClients : false,
      });

      setReplicateBaselineModalOpen(false);
      setCreateRuleSuccess(res.message);
      await loadData();
      setTimeout(() => {
        setCreateModalOpen(false);
      }, 1500);
    } catch (err: unknown) {
      setReplicateBaselineModalOpen(false);
      if (err instanceof Error) {
        setCreateRuleError(err.message);
      } else {
        setCreateRuleError("Erro ao criar regra de detecção.");
      }
    } finally {
      setCreatingRule(false);
    }
  };

  // Criação final da regra de detecção (valida e, se for baseline, exibe pop-up de replicação)
  const handleCreateRuleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // REGRA DE NEGÓCIO: NUNCA poderá ser criada sem que a query seja devidamente validada
    const gate = await logqlAssist.assertValid(createRuleLogQL);
    if (!gate.ok) {
      setCreateRuleError(gate.error);
      return;
    }
    const currentLint = gate.lint;
    let resolvedTech = createRuleTechnology;
    if (currentLint && currentLint.technologies.length === 1) {
      resolvedTech = currentLint.technologies[0];
      setCreateRuleTechnology(resolvedTech);
    }

    if (createRuleScope === "client" && !createRuleTargetClientUid) {
      setCreateRuleError("Selecione um cliente (grafana_folder) de destino.");
      return;
    }

    if (!resolvedTech) {
      setCreateRuleError(
        "Selecione a tecnologia (data source) que a regra irá observar no radio box."
      );
      return;
    }

    setCreateRuleError(null);

    if (createRuleScope === "baseline") {
      setReplicateBaselineModalOpen(true);
      return;
    }

    await executeCreateRule(false, resolvedTech);
  };

  return (
    <div className="flex flex-col w-full pb-12">
      {/* Breadcrumb and Top View Info */}
      <div className="flex flex-col gap-4 pb-4">
        {/* Breadcrumb path */}
        <div className="flex items-center gap-2 font-code-sm text-code-sm tracking-wide text-outline">
          <span className="hover:text-on-surface cursor-pointer">DANTE</span>
          <span>/</span>
          <span className="hover:text-on-surface cursor-pointer">ENGENHARIA DE DETECÇÃO</span>
          <span>/</span>
          <span className="text-on-surface font-semibold">REGRAS DE DETECÇÃO</span>
        </div>

        {/* Header Actions Toolbar */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight flex items-center gap-3">
              Regras de Detecção
              <span className="px-2 py-0.5 rounded-full font-code-sm text-code-sm bg-tertiary-container/30 text-tertiary font-semibold flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-tertiary animate-pulse"></span>
                Loki Ruler Sync Ativo
              </span>
            </h1>
            <p className="font-body-md text-body-md text-outline">
              Catálogo central de detecções, replicação multi-tenant para clientes e validação sintética de consultas LogQL.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center flex-wrap gap-2.5">
            {/* Bulk Actions Menu */}
            <div className="relative" ref={actionsMenuRef}>
              <button
                type="button"
                onClick={() => setActionsDropdownOpen((prev) => !prev)}
                className={`px-3 py-1.5 rounded-lg bg-surface-container-low text-on-surface hover:bg-surface-container-high font-body-sm text-body-sm flex items-center gap-1.5 transition-colors shadow-sm ${
                  selectedRuleUids.size > 0 ? "border border-primary-container text-primary font-semibold" : ""
                }`}
              >
                <span className="material-symbols-outlined text-[16px] text-outline">checklist</span>
                <span>Ações em Massa {selectedRuleUids.size > 0 ? `(${selectedRuleUids.size})` : ""}</span>
                <span className="material-symbols-outlined text-[16px] text-outline">expand_more</span>
              </button>

              {actionsDropdownOpen && (
                <div className="absolute right-0 top-full mt-1.5 min-w-[220px] bg-surface-container-low border border-outline-variant/30 rounded-lg shadow-xl p-1.5 z-50 flex flex-col gap-1">
                  <div className="font-label-uppercase text-label-uppercase text-outline px-2 py-1 uppercase tracking-wider">
                    Ações em Lote {selectedRuleUids.size > 0 ? `(${selectedRuleUids.size})` : ""}
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRequestBatchPause(true)}
                    disabled={selectedRuleUids.size === 0 || batchProcessing}
                    className="flex items-center gap-2 px-2.5 py-1.5 rounded text-left font-body-sm text-body-sm text-error hover:bg-surface-container-high transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <span className="material-symbols-outlined text-[16px]">pause_circle</span>
                    <span>Pausar selecionadas</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleRequestBatchPause(false)}
                    disabled={selectedRuleUids.size === 0 || batchProcessing}
                    className="flex items-center gap-2 px-2.5 py-1.5 rounded text-left font-body-sm text-body-sm text-tertiary hover:bg-surface-container-high transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <span className="material-symbols-outlined text-[16px]">play_circle</span>
                    <span>Reativar selecionadas</span>
                  </button>
                  <div className="h-px bg-surface-variant my-1" />
                  <button
                    type="button"
                    onClick={() => {
                      handleToggleSelectAll();
                      setActionsDropdownOpen(false);
                    }}
                    className="flex items-center gap-2 px-2.5 py-1.5 rounded text-left font-body-sm text-body-sm text-on-surface hover:bg-surface-container-high transition-colors"
                  >
                    <span className="material-symbols-outlined text-[16px] text-outline">done_all</span>
                    <span>
                      {isAllFilteredSelected
                        ? "Desmarcar visíveis"
                        : `Selecionar todas visíveis (${filteredRules.length})`}
                    </span>
                  </button>
                  {selectedRuleUids.size > 0 && (
                    <button
                      type="button"
                      onClick={() => {
                        handleDeselectAll();
                        setActionsDropdownOpen(false);
                      }}
                      className="flex items-center gap-2 px-2.5 py-1.5 rounded text-left font-body-sm text-body-sm text-outline hover:bg-surface-container-high transition-colors"
                    >
                      <span className="material-symbols-outlined text-[16px]">remove_done</span>
                      <span>Desmarcar todas</span>
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Refresh */}
            <button
              onClick={loadData}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-surface-container-low text-on-surface hover:bg-surface-container-high font-body-sm text-body-sm flex items-center gap-1.5 transition-colors shadow-sm"
              title="Recarregar catálogo"
              type="button"
            >
              <span className={`material-symbols-outlined text-[16px] text-outline ${loading ? "animate-spin" : ""}`}>
                sync
              </span>
              <span>Atualizar</span>
            </button>

            {/* Import Modal Trigger */}
            <button
              onClick={() => setImportModalOpen(true)}
              className="px-3.5 py-1.5 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-bright font-body-sm text-body-sm font-medium flex items-center gap-1.5 transition-colors shadow-sm"
              type="button"
            >
              <span className="material-symbols-outlined text-[18px] text-secondary">file_download</span>
              <span>Importar Regras</span>
            </button>

            {/* New Rule Primary CTA */}
            <button
              onClick={handleOpenCreateModal}
              className="px-4 py-1.5 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 font-body-sm text-body-sm font-semibold flex items-center gap-1.5 shadow-[0_0_16px_rgba(225,29,72,0.35)] transition-all"
              type="button"
            >
              <span className="material-symbols-outlined text-[18px]">add</span>
              <span>Nova Regra</span>
            </button>
          </div>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-space-md rounded-xl bg-error-container/20 border border-error-container text-error font-body-sm">
          {error}
        </div>
      )}

      {/* Alerta de Feedback de Ações em Lote */}
      {batchFeedback && (
        <div
          className={`mb-4 p-space-md rounded-xl border flex items-center justify-between font-body-sm ${
            batchFeedback.type === "success"
              ? "bg-tertiary-container/20 border-tertiary/40 text-tertiary"
              : "bg-error-container/20 border-error-container text-error"
          }`}
        >
          <span>{batchFeedback.message}</span>
          <button
            onClick={() => setBatchFeedback(null)}
            className="hover:opacity-75 transition-opacity"
            title="Fechar"
            type="button"
          >
            <span className="material-symbols-outlined text-[16px]">close</span>
          </button>
        </div>
      )}

      {/* Filter & Search Command Bar */}
      <div className="p-3 mb-4 rounded-xl bg-surface-container-low shadow-sm flex flex-col xl:flex-row items-stretch xl:items-center justify-between gap-3">
        {/* Left Filters Group */}
        <div className="flex flex-wrap items-center gap-2.5 flex-1 min-w-0">
          {/* Search Input */}
          <div className="relative flex-1 min-w-[220px]">
            <span className="material-symbols-outlined absolute left-2.5 top-2 text-outline text-[18px]">search</span>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full h-8 pl-8 pr-8 rounded-lg bg-surface-container-lowest text-on-surface placeholder:text-outline font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-secondary transition-all"
              placeholder="Filtrar por nome, label ou MITRE Tactic..."
              type="text"
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                className="absolute right-2.5 top-2 text-outline hover:text-on-surface"
                type="button"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
              </button>
            )}
          </div>

          {/* Filter: Clientes */}
          <div className="relative">
            <select
              value={selectedFolder}
              onChange={(e) => {
                setSelectedFolder(e.target.value);
                setSearchParams(e.target.value === "all" ? {} : { folder: e.target.value });
              }}
              className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-secondary cursor-pointer"
            >
              <option value="all">Todos os Clientes</option>
              {folders.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-1.5 top-1.5 text-outline text-[18px]">
              arrow_drop_down
            </span>
          </div>

          {/* Filter: Tecnologias */}
          <div className="relative">
            <select
              value={selectedTechnology}
              onChange={(e) => setSelectedTechnology(e.target.value)}
              className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-secondary cursor-pointer"
            >
              <option value="all">Todas as Tecnologias</option>
              {technologies.map((t) => (
                <option key={t.slug} value={t.slug}>
                  {t.name}
                </option>
              ))}
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-1.5 top-1.5 text-outline text-[18px]">
              arrow_drop_down
            </span>
          </div>

          {/* Filter: Estados */}
          <div className="relative">
            <select
              value={selectedState}
              onChange={(e) => setSelectedState(e.target.value)}
              className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-secondary cursor-pointer"
            >
              <option value="all">Todos os Estados</option>
              <option value="normal">Normal (Silenciosa)</option>
              <option value="firing">Firing (Em Alerta)</option>
              <option value="pending">Pending (Avaliando)</option>
              <option value="paused">Desativada / Pausada</option>
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-1.5 top-1.5 text-outline text-[18px]">
              arrow_drop_down
            </span>
          </div>

          {/* Filter: Estágios de Deploy */}
          <div className="relative">
            <select
              value={selectedDeployStatus}
              onChange={(e) => setSelectedDeployStatus(e.target.value)}
              className="appearance-none h-8 pl-2.5 pr-7 rounded-lg bg-surface-container-lowest text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-secondary cursor-pointer"
            >
              <option value="all">Todos os Estágios de Deploy</option>
              <option value="homolog">Homologação (dev/stg)</option>
              <option value="active">Produção (Live Alerting)</option>
              <option value="paused">Pausadas</option>
              <option value="unassigned">Sem Contact Point</option>
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-1.5 top-1.5 text-outline text-[18px]">
              arrow_drop_down
            </span>
          </div>
        </div>

        {/* Right Quick Info & Counters */}
        <div className="flex items-center gap-3 self-end xl:self-auto shrink-0">
          <div className="flex items-center gap-2">
            <span className="font-code-sm text-code-sm text-outline">Contador:</span>
            <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface font-semibold">
              {filteredRules.length} de {rules.length} regras
            </span>
          </div>
        </div>
      </div>

      {/* Main Detection Rules SIEM Table Container */}
      <div className="w-full overflow-hidden rounded-xl bg-surface-container-lowest shadow-md mb-4">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-low text-outline font-label-uppercase text-label-uppercase uppercase tracking-wider">
                <th className="py-2.5 pl-4 pr-2 w-10">
                  <input
                    type="checkbox"
                    checked={isAllFilteredSelected}
                    ref={(el) => {
                      if (el) el.indeterminate = isIndeterminate;
                    }}
                    onChange={handleToggleSelectAll}
                    aria-label="Selecionar todas as regras visíveis"
                    className="w-3.5 h-3.5 rounded bg-surface-container text-primary-container accent-primary-container cursor-pointer"
                  />
                </th>
                <th className="py-2.5 px-3 w-28">Estado</th>
                <th className="py-2.5 px-4 min-w-[320px]">Nome da Regra &amp; LogQL Scope</th>
                <th className="py-2.5 px-3 w-32">Cliente SIEM</th>
                <th className="py-2.5 px-3 w-28">Tier</th>
                <th className="py-2.5 px-4 min-w-[380px]">Labels / Tags Telemetria</th>
                <th className="py-2.5 px-3 w-36">Status</th>
                <th className="py-2.5 pr-4 pl-2 text-right w-40">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container/30 text-on-surface font-body-sm text-body-sm">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-outline font-body-sm">
                    Carregando catálogo de regras de detecção...
                  </td>
                </tr>
              ) : filteredRules.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-outline font-body-sm">
                    Nenhuma regra de detecção encontrada com os filtros selecionados.
                  </td>
                </tr>
              ) : (
                filteredRules.map((rule) => {
                  const isSelected = selectedRuleUids.has(rule.uid);
                  const isFromGlobal =
                    rule.folder_uid.toLowerCase() === "global" ||
                    rule.folder_title.toLowerCase() === "global";
                  const isFiring = rule.state?.toLowerCase() === "firing" || rule.state?.toLowerCase() === "alerting";
                  const silencedCount =
                    ruleSilencedCountMap.get(rule.uid) ??
                    ruleSilencedCountMap.get(rule.title) ??
                    rule.silenced_instances ??
                    0;

                  return (
                    <tr
                      key={rule.uid}
                      className={`hover:bg-surface-container-low/70 transition-colors group ${
                        isSelected ? "bg-surface-container-low/50" : ""
                      }`}
                    >
                      <td className="py-3.5 pl-4 pr-2 align-top" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={(e) => handleToggleSelectRule(rule.uid, e.target.checked)}
                          aria-label={`Selecionar regra ${rule.title}`}
                          className="w-3.5 h-3.5 rounded bg-surface-container text-primary-container accent-primary-container cursor-pointer mt-1"
                        />
                      </td>

                      <td className="py-3.5 px-3 align-top">
                        {rule.is_paused ? (
                          <div className="flex flex-col gap-1 items-start">
                            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-highest text-outline font-medium">
                              <span className="w-1.5 h-1.5 rounded-full bg-outline"></span>
                              <span>Pausada</span>
                            </div>
                            <button
                              onClick={() => handleOpenDetail(rule.uid)}
                              className="inline-flex items-center gap-1 text-[11px] font-code-sm text-tertiary hover:text-tertiary-fixed underline transition-colors"
                              title="Ver análise da IA e parecer técnico com telemetria real do cliente"
                              type="button"
                            >
                              <span className="material-symbols-outlined text-[12px]">auto_awesome</span>
                              <span>Parecer IA</span>
                            </button>
                          </div>
                        ) : isFiring ? (
                          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-code-sm text-code-sm bg-error-container text-on-error-container font-semibold">
                            <span className="relative flex h-2 w-2">
                              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-container opacity-75"></span>
                              <span className="relative inline-flex rounded-full h-2 w-2 bg-primary-container"></span>
                            </span>
                            <span>Firing</span>
                          </div>
                        ) : (
                          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-code-sm text-code-sm bg-tertiary-container/20 text-tertiary font-medium">
                            <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
                            <span>Normal</span>
                          </div>
                        )}
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-col gap-0.5">
                          <button
                            type="button"
                            onClick={() => handleOpenDetail(rule.uid)}
                            className="text-left font-headline-md text-headline-md text-on-surface font-semibold group-hover:text-secondary transition-colors cursor-pointer"
                          >
                            {rule.title}
                          </button>
                          <div className="flex items-center gap-2 font-code-sm text-code-sm text-outline flex-wrap">
                            {rule.for_duration && (
                              <span className="flex items-center gap-1">
                                <span className="material-symbols-outlined text-[13px]">timer</span>
                                Janela: {rule.for_duration}
                              </span>
                            )}
                            {rule.rule_group && <span>• Grupo: {rule.rule_group}</span>}
                            {rule.labels.severity && (
                              <span className="text-error font-medium">• Sev: {rule.labels.severity}</span>
                            )}
                          </div>
                          {isFiring && (
                            <div className="flex items-center gap-1.5 font-code-sm text-code-sm mt-0.5">
                              <span
                                className={`material-symbols-outlined text-[14px] ${
                                  silencedCount > 0 ? "text-tertiary" : "text-outline"
                                }`}
                              >
                                {silencedCount > 0 ? "notifications_paused" : "notifications_off"}
                              </span>
                              <span
                                className={
                                  silencedCount > 0 ? "text-tertiary font-medium" : "text-outline"
                                }
                              >
                                Alertas silenciados:{" "}
                                <strong
                                  className={
                                    silencedCount > 0
                                      ? "text-tertiary font-semibold"
                                      : "text-outline font-semibold"
                                  }
                                >
                                  {silencedCount}
                                </strong>
                              </span>
                            </div>
                          )}
                        </div>
                      </td>

                      <td className="py-3.5 px-3 align-top">
                        <span className="font-body-md text-body-md text-on-surface font-medium">
                          {rule.folder_title}
                        </span>
                      </td>

                      <td className="py-3.5 px-3 align-top">
                        {isFromGlobal ? (
                          <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-secondary-container/20 text-secondary font-semibold">
                            Global
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-tertiary-container/30 text-tertiary font-semibold">
                            Cliente
                          </span>
                        )}
                      </td>

                      <td className="py-3.5 px-4 align-top">
                        <div className="flex flex-wrap gap-1 font-code-sm text-code-sm">
                          {Object.entries(rule.labels).map(([k, v]) => {
                            let style = "bg-surface-container-high text-on-surface-variant";
                            if (k === "severity" && (v === "critical" || v === "high")) {
                              style = "bg-error-container/40 text-error font-semibold";
                            } else if (k === "mitre_technique" || k === "mitre_tactic") {
                              style = "bg-secondary/10 text-secondary";
                            } else if (k === "source") {
                              style = v === "grafana" ? "bg-amber-500/20 text-amber-300 font-semibold border border-amber-500/30" : "bg-primary/10 text-primary font-semibold";
                            } else if (k === "technology" || k === "technology_name") {
                              style = "bg-primary/10 text-primary";
                            } else if (k === "scope" || k === "siem_tier" || k === "tier") {
                              style = "bg-tertiary/10 text-tertiary";
                            }
                            return (
                              <span key={k} className={`px-1.5 py-0.5 rounded ${style}`}>
                                <span className="text-outline">{k}=</span>{v}
                              </span>
                            );
                          })}
                        </div>
                      </td>

                      <td className="py-3.5 px-3 align-top">
                        <div className="flex flex-col gap-0.5">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold w-max ${
                              rule.deploy_status === "active"
                                ? "bg-tertiary-container/30 text-tertiary"
                                : rule.deploy_status === "homolog"
                                ? "bg-primary/10 text-primary"
                                : "bg-surface-container-highest text-outline"
                            }`}
                          >
                            {rule.deploy_status === "active"
                              ? "Produção"
                              : rule.deploy_status === "homolog"
                              ? "Homologação"
                              : "Pausada"}
                          </span>
                          {rule.contact_point && (
                            <span className="font-code-sm text-code-sm text-outline">
                              CP: {rule.contact_point}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-3.5 pr-4 pl-2 align-top text-right">
                        <div className="inline-flex items-center gap-1.5">
                          {rule.is_paused && (
                            <button
                              onClick={() => handleOpenDetail(rule.uid)}
                              className="px-2.5 py-1 rounded bg-tertiary-container/20 text-tertiary hover:bg-tertiary-container/30 border border-tertiary/30 font-body-sm text-body-sm transition-colors inline-flex items-center gap-1"
                              type="button"
                              title="Análise e Parecer Técnico da IA com telemetria nas faixas temporais"
                            >
                              <span className="material-symbols-outlined text-[14px]">auto_awesome</span>
                              <span>Parecer IA</span>
                            </button>
                          )}
                          <button
                            onClick={() => handleOpenDetail(rule.uid)}
                            className="px-2.5 py-1 rounded bg-surface-container-high hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors"
                            type="button"
                          >
                            Detalhes
                          </button>
                          <button
                            onClick={() => handleTogglePause(rule.uid, rule.is_paused)}
                            disabled={togglingUid === rule.uid}
                            className={`px-2.5 py-1 rounded font-body-sm text-body-sm transition-colors ${
                              rule.is_paused
                                ? "bg-primary-container text-on-primary-container"
                                : "bg-surface-container-high hover:bg-surface-bright text-on-surface"
                            }`}
                            type="button"
                          >
                            {togglingUid === rule.uid ? "..." : rule.is_paused ? "Ativar" : "Pausar"}
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
      </div>

      {/* Modal 1: Detalhes da Regra - Layout Amplo com Blocos Grafana (A, B, C) e Parecer da IA */}
      <Modal
        isOpen={detailModalOpen}
        onClose={() => {
          setDetailModalOpen(false);
          setSelectedRule(null);
        }}
        title={
          selectedRule ? (
            <div className="flex items-center gap-2.5">
              <span className="material-symbols-outlined text-primary text-[22px]">
                security
              </span>
              <span className="font-semibold text-white tracking-tight text-base sm:text-lg">
                {selectedRule.title}
              </span>
            </div>
          ) : (
            "Detalhes da Regra"
          )
        }
        maxWidth="1560px"
        width="96vw"
      >
        {loadingDetail || !selectedRule ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
            <span className="material-symbols-outlined text-[32px] animate-spin text-primary">
              progress_activity
            </span>
            <p className="text-sm m-0">Carregando dados da regra de detecção...</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
            {/* Lado Esquerdo: Detalhes da Regra (Blocos A, B e C e Metadados Grafana) */}
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 pb-1.5 border-b border-slate-700/60">
                <span className="material-symbols-outlined text-[18px] text-blue-400">
                  dashboard_customize
                </span>
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 m-0">
                  Estrutura da Regra no Grafana Alerting (Blocos A, B e C)
                </h3>
              </div>
              <RuleGrafanaBlocks rule={selectedRule} />
            </div>

            {/* Lado Direito: Parecer Técnico da IA */}
            <div className="flex flex-col gap-3">
              <div className="flex items-center gap-2 pb-1.5 border-b border-purple-500/30">
                <span className="material-symbols-outlined text-[18px] text-purple-400">
                  auto_awesome
                </span>
                <h3 className="text-xs font-bold uppercase tracking-wider text-purple-200 m-0">
                  Parecer Técnico e Oportunidades de Melhoria por IA
                </h3>
              </div>
              <RuleAIEvaluationPanel
                evaluation={aiEvaluation}
                loading={loadingAiEvaluation}
                onRefresh={() => fetchAiEvaluation(selectedRule.uid, true)}
                onImplement={() => setConfirmImplementAiModalOpen(true)}
                feedback={implementAiFeedback}
              />
            </div>
          </div>
        )}
      </Modal>

      {/* Modal CRIAR NOVA REGRA DE DETECÇÃO */}
      <Modal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        title="Criar Nova Regra de Detecção"
        maxWidth="860px"
      >
        <div className="flex flex-col gap-5 text-on-surface">
          {/* Header informativo com padrão de identidade do D.A.N.T.E. */}
          <div className="flex items-center justify-between p-3.5 rounded-xl bg-surface-container-low border border-outline-variant/30">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-primary-container/20 border border-primary-container/40 flex items-center justify-center text-primary-fixed-dim">
                <span className="material-symbols-outlined text-[22px]">add_alert</span>
              </div>
              <div>
                <h4 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                  Nova Regra no Grafana Loki
                </h4>
                <p className="font-body-sm text-body-sm text-on-surface-variant">
                  Provisionamento com linting LogQL, segregação de tecnologia por <code>rule_groups</code> e estágio dev.
                </p>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-full font-code-sm text-xs bg-surface-container text-primary border border-primary/20 font-semibold shrink-0">
              LogQL v2 / Ruler
            </span>
          </div>

          {createRuleError && (
            <div className="p-3 rounded-lg bg-error-container/30 border border-error/40 text-error font-body-sm text-body-sm flex items-start gap-2">
              <span className="material-symbols-outlined text-[18px] shrink-0 mt-0.5">error</span>
              <div>{createRuleError}</div>
            </div>
          )}

          {createRuleSuccess && (
            <div className="p-3 rounded-lg bg-tertiary-container/30 border border-tertiary/40 text-tertiary font-body-sm text-body-sm flex items-start gap-2">
              <span className="material-symbols-outlined text-[18px] shrink-0 mt-0.5">check_circle</span>
              <div>{createRuleSuccess}</div>
            </div>
          )}

          {/* Notificação especial de Timeout */}
          {queryTimeoutNotification && <LogQLTimeoutNotice message={queryTimeoutNotification} />}

          <form onSubmit={handleCreateRuleSubmit} className="space-y-4">
            {/* 1. Nome da Regra */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                Nome da Regra <span className="text-error font-bold ml-0.5">*</span>
              </label>
              <input
                type="text"
                className="w-full h-10 px-3.5 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm placeholder:text-outline/50 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
                value={createRuleName}
                onChange={(e) => setCreateRuleName(e.target.value)}
                placeholder="Ex: SSH - Detecção de Força Bruta"
                required
              />
            </div>

            {/* 2. Descrição (opcional) */}
            <div className="space-y-1.5">
              <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                Descrição <span className="text-outline/60 lowercase font-normal">(opcional)</span>
              </label>
              <textarea
                className="w-full p-3 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm placeholder:text-outline/50 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all resize-y min-h-[64px]"
                value={createRuleDesc}
                onChange={(e) => setCreateRuleDesc(e.target.value)}
                placeholder="Contexto da ameaça, impacto operacional e plano de resposta..."
              />
            </div>

            {/* 3 e 4. Abrangência e Tecnologia / Data Source em grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* 3. Abrangência: Baseline ou Cliente */}
              <div className="space-y-1.5">
                <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                  Abrangência <span className="text-error font-bold ml-0.5">*</span>
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setCreateRuleScope("baseline");
                      setCreateRuleEvaluationGroup("5m");
                    }}
                    className={`flex items-center gap-2.5 p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                      createRuleScope === "baseline"
                        ? "bg-primary-container/20 border-primary text-primary-fixed-dim shadow-sm"
                        : "bg-surface-container-lowest border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:border-outline-variant/60"
                    }`}
                  >
                    <span className="material-symbols-outlined text-[20px]">public</span>
                    <div>
                      <div className="text-xs font-semibold">Baseline Global</div>
                      <div className="text-[11px] text-outline">Todos os clientes</div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => {
                      setCreateRuleScope("client");
                      let targetUid = createRuleTargetClientUid;
                      if (!targetUid) {
                        const first = clientFolders[0];
                        if (first) {
                          targetUid = first.uid;
                          setCreateRuleTargetClientUid(first.uid);
                        }
                      }
                      const t = tenantsList.find((ten) => ten.uid === targetUid);
                      setCreateRuleEvaluationGroup(t?.evaluation_group || "5m");
                    }}
                    className={`flex items-center gap-2.5 p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                      createRuleScope === "client"
                        ? "bg-primary-container/20 border-primary text-primary-fixed-dim shadow-sm"
                        : "bg-surface-container-lowest border-outline-variant/30 text-on-surface-variant hover:text-on-surface hover:border-outline-variant/60"
                    }`}
                  >
                    <span className="material-symbols-outlined text-[20px]">domain</span>
                    <div>
                      <div className="text-xs font-semibold">Cliente Específico</div>
                      <div className="text-[11px] text-outline">Pasta isolada</div>
                    </div>
                  </button>
                </div>

                {createRuleScope === "client" && (
                  <div className="pt-1.5 space-y-1">
                    <label className="block text-[11px] font-semibold text-outline uppercase tracking-wider">
                      Cliente (grafana_folder) de Destino:
                    </label>
                    <select
                      className="w-full h-10 px-3 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all cursor-pointer"
                      value={createRuleTargetClientUid}
                      onChange={(e) => {
                        const uid = e.target.value;
                        setCreateRuleTargetClientUid(uid);
                        const t = tenantsList.find((ten) => ten.uid === uid);
                        setCreateRuleEvaluationGroup(t?.evaluation_group || "5m");
                      }}
                    >
                      {clientFolders.map((f) => (
                        <option key={f.uid} value={f.uid}>
                          {f.title} ({f.uid})
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              </div>

              {/* 4. Tecnologia / Data Source */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                    Tecnologia / Data Source <span className="text-error font-bold ml-0.5">*</span>
                  </label>
                  <button
                    type="button"
                    onClick={() => {
                      setTechError(null);
                      setTechFormOpen(false);
                      setTechManagerOpen(true);
                    }}
                    className="text-xs text-primary hover:underline flex items-center gap-1 cursor-pointer font-medium"
                  >
                    <span className="material-symbols-outlined text-[14px]">settings</span>
                    Gerenciar Tecnologias
                  </button>
                </div>

                {technologies.filter((t) => t.enabled).length === 0 ? (
                  <div className="p-2.5 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-xs text-outline">
                    Nenhuma tecnologia cadastrada. Use "Gerenciar Tecnologias" para incluir o mapeamento.
                  </div>
                ) : (
                  <select
                    className="w-full h-10 px-3.5 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all cursor-pointer"
                    value={createRuleTechnology}
                    onChange={(e) => handleSelectTechnology(e.target.value)}
                  >
                    <option value="" disabled>
                      Selecione uma tecnologia...
                    </option>
                    {technologies
                      .filter((t) => t.enabled)
                      .map((tech) => (
                        <option key={tech.slug} value={tech.slug}>
                          {tech.name} ({tech.logql_selector})
                        </option>
                      ))}
                  </select>
                )}
                <span className="text-[11px] text-outline leading-tight block">
                  <code>rule_groups</code> é a tecnologia no Wazuh; selecionar a tecnologia reescreve a query para <code>{`{job="wazuh", rule_groups=~"..."}`}</code>.
                </span>
              </div>
            </div>

            {/* 5, 6, 7 e 8: Severidade, MITRE ATT&CK e Grupo de Avaliação */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-1">
              <div className="space-y-1">
                <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                  Severidade <span className="text-error font-bold ml-0.5">*</span>
                </label>
                <select
                  className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all cursor-pointer"
                  value={createRuleSeverity}
                  onChange={(e) => setCreateRuleSeverity(e.target.value as RuleSeverity)}
                >
                  <option value="low">Baixa</option>
                  <option value="medium">Média</option>
                  <option value="high">Alta</option>
                  <option value="critical">Crítica</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                  Tática MITRE <span className="text-error font-bold ml-0.5">*</span>
                </label>
                <input
                  type="text"
                  className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm placeholder:text-outline/50 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all"
                  value={createRuleTactic}
                  onChange={(e) => setCreateRuleTactic(e.target.value)}
                  placeholder="Ex: Credential Access"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                  Técnica MITRE <span className="text-error font-bold ml-0.5">*</span>
                </label>
                <input
                  type="text"
                  className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm placeholder:text-outline/50 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all font-mono"
                  value={createRuleTechnique}
                  onChange={(e) => setCreateRuleTechnique(e.target.value)}
                  placeholder="Ex: T1110"
                  required
                />
              </div>

              <div className="space-y-1">
                <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                  Grupo Avaliação
                </label>
                <input
                  type="text"
                  list="evaluation-groups-datalist"
                  className="w-full h-9 px-3 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-on-surface font-body-sm text-body-sm placeholder:text-outline/50 focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary transition-all font-mono"
                  value={createRuleEvaluationGroup}
                  onChange={(e) => setCreateRuleEvaluationGroup(e.target.value)}
                  placeholder="5m"
                  title="Grupo de avaliação (evaluation group) no Grafana Alerting. Padrão: 5m."
                />
                <datalist id="evaluation-groups-datalist">
                  {availableEvaluationGroups.map((g) => (
                    <option key={g} value={g}>
                      {g}
                    </option>
                  ))}
                </datalist>
              </div>
            </div>

            {/* 9. Query em LogQL */}
            <div className="space-y-1.5 pt-1">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <label className="block text-xs font-semibold text-outline uppercase tracking-wider">
                    Query em LogQL <span className="text-error font-bold ml-0.5">*</span>
                  </label>
                  <span className="text-xs text-outline">
                    (Data source: <span className="text-primary font-medium">{createRuleScope === "baseline" ? "Loki" : (selectedClient ? `${selectedClient.title} e sandbox-${selectedClient.title}` : "Cliente e sandbox-<cliente>")}</span>)
                  </span>
                </div>
                <LogQLActionButtons
                  linting={linting}
                  executing={executingQuery}
                  onLint={handleLintLogQL}
                  onRun={handleExecuteQuery}
                />
              </div>

              <LogQLEditor
                value={createRuleLogQL}
                onChange={(val) => setCreateRuleLogQL(val)}
                placeholder={`count_over_time(\n    {job="wazuh", rule_groups=~".*<tecnologia>.*"}\n    | json\n    [5m]\n)`}
                height="120px"
                required
              />

              <span className="text-[11px] text-outline leading-tight block">
                <strong>Regras obrigatórias:</strong> O seletor <code>{`{}`}</code> deve conter as labels <code>job</code> e <code>rule_groups</code>, e possuir ao menos uma função (ex: <code>| json</code>).
              </span>
            </div>

            {/* Painéis de Linting e Resultado da Query */}
            {lintResult && <LogQLLintPanel lintResult={lintResult} />}
            {queryExecutionResult && <LogQLQueryResultPanel queryResult={queryExecutionResult} />}

            {/* Footer do formulário */}
            <div className="flex items-center justify-end gap-3 pt-4 border-t border-outline-variant/30">
              <button
                type="button"
                onClick={() => setCreateModalOpen(false)}
                className="px-4 py-2 rounded-lg border border-outline-variant/40 text-on-surface hover:bg-surface-container-high font-body-sm text-body-sm font-medium transition-colors cursor-pointer"
              >
                Cancelar
              </button>
              <button
                type="submit"
                disabled={creatingRule}
                className="flex items-center gap-2 px-5 py-2 rounded-lg bg-primary text-on-primary font-body-sm text-body-sm font-semibold hover:brightness-110 shadow-lg shadow-primary/20 transition-all disabled:opacity-50 cursor-pointer"
              >
                {creatingRule ? (
                  <>
                    <span className="material-symbols-outlined text-[16px] animate-spin">progress_activity</span>
                    <span>Criando Regra...</span>
                  </>
                ) : (
                  <>
                    <span className="material-symbols-outlined text-[18px]">add_task</span>
                    <span>Criar Regra de Detecção</span>
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      </Modal>

      {/* Pop-up de confirmação de replicação automática ao criar regra no Baseline */}
      <Modal
        isOpen={replicateBaselineModalOpen}
        onClose={() => {
          if (!creatingRule) {
            setReplicateBaselineModalOpen(false);
          }
        }}
        title="Replicar Regra de Baseline"
      >
        <div>
          <div
            style={{
              backgroundColor: "rgba(225, 29, 72, 0.1)",
              border: "1px solid rgba(225, 29, 72, 0.25)",
              padding: "14px 16px",
              borderRadius: "8px",
              color: "var(--text-main)",
              fontSize: "0.9rem",
              marginBottom: "16px",
              lineHeight: 1.5,
            }}
          >
            <p style={{ margin: "0 0 8px 0", fontWeight: 600, color: "#f43f5e" }}>
              Deseja replicar esta regra de detecção para todos os clientes que possuem esta tecnologia?
            </p>
            <p style={{ margin: 0, fontSize: "0.82rem", color: "var(--text-muted)" }}>
              Tecnologia selecionada:{" "}
              <strong>
                {technologies.find((t) => t.slug === createRuleTechnology)?.name ||
                  createRuleTechnology}
              </strong>
              . Ao clicar em <strong>Sim</strong>, a regra será criada no Baseline Global (data source{" "}
              <code>Loki</code>) e replicada automaticamente para todos os clientes que possuem esta
              tecnologia (apontando para o data source Loki de cada cliente, em estágio{" "}
              <code>dev</code>). Ao clicar em <strong>Não</strong>, a regra será criada apenas no
              Baseline Global.
            </p>
          </div>

          <div className="modal-footer" style={{ padding: "12px 0 0 0", marginTop: "16px" }}>
            <button
              type="button"
              onClick={() => executeCreateRule(false)}
              className="btn btn-secondary"
              disabled={creatingRule}
            >
              {creatingRule ? "Processando..." : "Não"}
            </button>
            <button
              type="button"
              onClick={() => executeCreateRule(true)}
              className="btn btn-primary"
              disabled={creatingRule}
            >
              {creatingRule ? "Criando e Replicando..." : "Sim"}
            </button>
          </div>
        </div>
      </Modal>

      {/* Confirmação de Ação em Lote (Pausar / Reativar Regras) */}
      <ConfirmModal
        isOpen={confirmBatchModalOpen}
        onClose={() => {
          if (!batchProcessing) {
            setConfirmBatchModalOpen(false);
            setPendingBatchPause(null);
          }
        }}
        onConfirm={() => {
          if (pendingBatchPause !== null) {
            handleBatchPause(pendingBatchPause);
          }
        }}
        isLoading={batchProcessing}
        title={pendingBatchPause ? "Confirmar Pausa Massiva de Regras" : "Confirmar Reativação de Regras"}
        confirmLabel={
          pendingBatchPause
            ? `Pausar ${selectedRuleUids.size} regra(s)`
            : `Reativar ${selectedRuleUids.size} regra(s)`
        }
        variant={pendingBatchPause ? "danger" : "primary"}
        message={
          <div>
            <p style={{ margin: "0 0 8px 0" }}>
              Você está prestes a <strong>{pendingBatchPause ? "pausar" : "reativar"}</strong> a avaliação contínua de{" "}
              <strong>{selectedRuleUids.size} regra(s) de detecção</strong> selecionada(s).
            </p>
            {pendingBatchPause ? (
              <p style={{ margin: 0, fontSize: "0.8rem", opacity: 0.9 }}>
                Durante o período em que as regras estiverem pausadas, nenhum novo incidente ou alerta de segurança será disparado por elas no Grafana.
              </p>
            ) : (
              <p style={{ margin: 0, fontSize: "0.8rem", opacity: 0.9 }}>
                As regras voltarão a ser avaliadas periodicamente contra o datasource Loki.
              </p>
            )}
          </div>
        }
      />

      {/* Gerência do catálogo de Tecnologias (rule_groups -> data source) */}
      <Modal
        isOpen={techManagerOpen}
        onClose={() => {
          if (!techSaving) {
            setTechManagerOpen(false);
            setTechFormOpen(false);
            setTechError(null);
          }
        }}
        title="Catálogo de Tecnologias / Data Sources"
      >
        {techError && <div className="alert-box">{techError}</div>}

        <p style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: 0, lineHeight: 1.5 }}>
          Cada tecnologia associa um nome de negócio a um recorte regex da label{" "}
          <code>rule_groups</code> (espelho de <code>rule.groups</code> do Wazuh). O tenant continua
          sendo o <code>grafana_folder</code>. O seletor gerado é usado no radio box de criação de
          regras.
        </p>

        {technologies.length === 0 && (
          <p style={{ fontSize: "0.82rem", color: "var(--text-subtle)" }}>
            Nenhuma tecnologia cadastrada.
          </p>
        )}

        {technologies.map((tech) => (
          <div
            key={tech.slug}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "flex-start",
              gap: "12px",
              padding: "8px 10px",
              border: "1px solid var(--border-color)",
              borderRadius: "8px",
              marginBottom: "6px",
              backgroundColor: "var(--bg-input)",
            }}
          >
            <div style={{ display: "flex", flexDirection: "column", gap: "2px", minWidth: 0 }}>
              <span style={{ fontSize: "0.85rem", color: "var(--text-main)" }}>
                <strong>{tech.name}</strong>{" "}
                <code style={{ fontSize: "0.7rem", color: "var(--text-subtle)" }}>{tech.slug}</code>
              </span>
              <code style={{ fontSize: "0.72rem", color: "#f43f5e" }}>{tech.logql_selector}</code>
              {tech.description && (
                <span style={{ fontSize: "0.72rem", color: "var(--text-subtle)" }}>
                  {tech.description}
                </span>
              )}
            </div>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setTechToDelete(tech)}
              disabled={techSaving}
              title={`Remover ${tech.name} do catálogo`}
            >
              Excluir
            </button>
          </div>
        ))}

        {!techFormOpen ? (
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => {
              setTechError(null);
              setTechFormOpen(true);
            }}
            style={{ marginTop: "8px" }}
          >
            + Nova Tecnologia
          </button>
        ) : (
          <form
            onSubmit={handleCreateTechnology}
            style={{
              marginTop: "10px",
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "10px",
              borderTop: "1px solid var(--border-color)",
              paddingTop: "10px",
            }}
          >
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Nome da Tecnologia *</label>
              <input
                type="text"
                className="input"
                value={techForm.name}
                onChange={(e) => setTechForm({ ...techForm, name: e.target.value })}
                placeholder="Ex: Palo Alto"
                required
              />
            </div>
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Slug (label technology) *</label>
              <input
                type="text"
                className="input"
                value={techForm.slug}
                onChange={(e) => setTechForm({ ...techForm, slug: e.target.value })}
                placeholder="Ex: palo_alto"
                pattern="[a-z0-9_]{2,32}"
                title="2 a 32 caracteres: letras minúsculas, números e underscore"
                required
              />
            </div>
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Recorte de rule_groups (regex) *</label>
              <input
                type="text"
                className="input"
                value={techForm.rule_groups_regex}
                onChange={(e) => setTechForm({ ...techForm, rule_groups_regex: e.target.value })}
                placeholder='Ex: .*paloalto.*'
                required
              />
            </div>
            <div className="form-group" style={{ margin: 0 }}>
              <label className="form-label">Label job</label>
              <input
                type="text"
                className="input"
                value={techForm.job}
                onChange={(e) => setTechForm({ ...techForm, job: e.target.value })}
                placeholder="wazuh"
              />
            </div>
            <div className="form-group" style={{ margin: 0, gridColumn: "1 / -1" }}>
              <label className="form-label">Descrição</label>
              <input
                type="text"
                className="input"
                value={techForm.description}
                onChange={(e) => setTechForm({ ...techForm, description: e.target.value })}
                placeholder="Fontes de log cobertas por esta tecnologia..."
              />
            </div>
            <div
              style={{
                gridColumn: "1 / -1",
                display: "flex",
                justifyContent: "flex-end",
                gap: "8px",
              }}
            >
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => setTechFormOpen(false)}
                disabled={techSaving}
              >
                Cancelar
              </button>
              <button type="submit" className="btn btn-primary btn-sm" disabled={techSaving}>
                {techSaving ? "Salvando..." : "Cadastrar Tecnologia"}
              </button>
            </div>
          </form>
        )}

        <div className="modal-footer" style={{ marginTop: "14px" }}>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setTechManagerOpen(false)}
            disabled={techSaving}
          >
            Fechar
          </button>
        </div>
      </Modal>

      {/* Modal Importar Regras (Loki Ruler) */}
      <RuleImportModal
        isOpen={importModalOpen}
        onClose={() => setImportModalOpen(false)}
        onSuccess={loadData}
      />

      {/* Confirmação de implementação de melhorias da IA na regra */}
      <ConfirmModal
        isOpen={confirmImplementAiModalOpen}
        onClose={() => {
          if (!implementingAi) setConfirmImplementAiModalOpen(false);
        }}
        onConfirm={handleApplyAiSuggestions}
        isLoading={implementingAi}
        title="Implementar Sugestões da IA na Regra"
        confirmLabel="Implementar Sugestões"
        variant="primary"
        message={
          <div>
            <p style={{ margin: "0 0 8px 0" }}>
              Você está prestes a aplicar as melhorias sugeridas pela IA na regra{" "}
              <strong>{selectedRule?.title}</strong> (<code>{selectedRule?.uid}</code>).
            </p>
            {aiEvaluation?.suggested_logql_query && (
              <div style={{ marginBottom: "10px" }}>
                <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", display: "block", marginBottom: "4px" }}>
                  Nova Expressão LogQL Validada:
                </span>
                <pre style={{ margin: 0, padding: "8px", backgroundColor: "var(--bg-input)", borderRadius: "4px", fontSize: "0.75rem", fontFamily: "var(--font-mono)", color: "var(--primary)", overflowX: "auto" }}>
                  {aiEvaluation.suggested_logql_query}
                </pre>
              </div>
            )}
            {aiEvaluation?.suggested_labels && Object.keys(aiEvaluation.suggested_labels).length > 0 && (
              <div style={{ marginBottom: "8px", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                <span style={{ fontWeight: 600, display: "block", marginBottom: "4px" }}>Tags e Metadados Enriquecidos:</span>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                  {Object.entries(aiEvaluation.suggested_labels).map(([k, v]) => (
                    <span key={k} style={{ padding: "2px 6px", borderRadius: "4px", backgroundColor: "rgba(168, 85, 247, 0.15)", border: "1px solid rgba(168, 85, 247, 0.3)", fontSize: "0.75rem", color: "rgb(216, 180, 254)" }}>
                      {k}={v}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {aiEvaluation?.diff_summary && aiEvaluation.diff_summary.length > 0 && (
              <ul style={{ margin: "0 0 8px", paddingLeft: "16px", fontSize: "0.8rem", color: "var(--text-muted)" }}>
                {aiEvaluation.diff_summary.map((d, i) => (
                  <li key={i}>{d}</li>
                ))}
              </ul>
            )}
            <p style={{ margin: 0, fontSize: "0.8rem", opacity: 0.9 }}>
              A regra será atualizada diretamente no Grafana Alerting e reavaliada pelo pipeline de detecção.
            </p>
          </div>
        }
      />

      {/* Confirmação de remoção de tecnologia do catálogo */}
      <ConfirmModal
        isOpen={techToDelete !== null}
        onClose={() => {
          if (!techSaving) setTechToDelete(null);
        }}
        onConfirm={handleDeleteTechnology}
        isLoading={techSaving}
        title="Remover Tecnologia do Catálogo"
        confirmLabel="Remover Tecnologia"
        variant="danger"
        message={
          <div>
            <p style={{ margin: "0 0 8px 0" }}>
              Você está prestes a remover{" "}
              <strong>{techToDelete?.name}</strong>{" "}
              (<code>{techToDelete?.rule_groups_regex}</code>) do catálogo de tecnologias.
            </p>
            <p style={{ margin: 0, fontSize: "0.8rem", opacity: 0.9 }}>
              A tecnologia deixa de estar disponível no radio box de criação de regras. Regras já
              criadas no Grafana mantêm suas labels <code>technology</code> e continuam avaliando
              normalmente.
            </p>
          </div>
        }
      />
    </div>
  );
};
