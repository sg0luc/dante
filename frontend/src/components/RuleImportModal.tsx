import React, { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { Modal } from "./Modal";
import { api } from "../api";
import {
  AISettingsPublicResponse,
  LokiDatasourceItem,
  RuleImportItemValidation,
  RuleImportPreviewResponse,
  TechnologyPayload,
} from "../types";

interface RuleImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

interface UploadedFileInfo {
  filename: string;
  content: string;
  size: number;
}

export const RuleImportModal: React.FC<RuleImportModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFileInfo[]>([]);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [readingFiles, setReadingFiles] = useState<boolean>(false);
  const [jsonContent, setJsonContent] = useState<string>("");
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [isImporting, setIsImporting] = useState<boolean>(false);
  const [previewResult, setPreviewResult] = useState<RuleImportPreviewResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [showManualEditor, setShowManualEditor] = useState<boolean>(false);

  // Filtros e Visualização de Parecer
  const [filterTab, setFilterTab] = useState<"all" | "qualified" | "high" | "incompatible">("all");
  const [expandedIndices, setExpandedIndices] = useState<Set<number>>(new Set());
  const [importOnlyQualified, setImportOnlyQualified] = useState<boolean>(true);

  // Provedor e Configurações de IA
  const [aiSettings, setAISettings] = useState<AISettingsPublicResponse | null>(null);
  const [generatingAIIndices, setGeneratingAIIndices] = useState<Set<number>>(new Set());

  // Data source Loki de destino
  const [datasources, setDatasources] = useState<LokiDatasourceItem[]>([]);
  const [selectedDatasourceUid, setSelectedDatasourceUid] = useState<string>("loki");
  const [datasourcesLoading, setDatasourcesLoading] = useState<boolean>(false);

  // Grupo de avaliação padrão é 5m
  const [evaluationGroups, setEvaluationGroups] = useState<string[]>(["5m"]);
  const [selectedEvaluationGroup, setSelectedEvaluationGroup] = useState<string>("5m");
  const [evalGroupsLoading, setEvalGroupsLoading] = useState<boolean>(false);

  // Modal de criação de tecnologia para regras OK sem tecnologia
  const [isCreateTechOpen, setIsCreateTechOpen] = useState<boolean>(false);
  const [techForm, setTechForm] = useState<TechnologyPayload>({
    slug: "",
    name: "",
    rule_groups_regex: "",
    job: "wazuh",
    description: "",
    confirm_without_logs: true,
  });
  const [savingTech, setSavingTech] = useState<boolean>(false);
  const [techError, setTechError] = useState<string | null>(null);
  const [techSuccessMsg, setTechSuccessMsg] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const isRuleImportAIEnabled = Boolean(
    aiSettings?.enabled && aiSettings?.rule_import_ai_enabled
  );

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const resetState = () => {
    setUploadedFiles([]);
    setIsDragging(false);
    setReadingFiles(false);
    setJsonContent("");
    setIsValidating(false);
    setIsImporting(false);
    setPreviewResult(null);
    setErrorMsg(null);
    setSuccessMsg(null);
    setShowManualEditor(false);
    setIsCreateTechOpen(false);
    setTechError(null);
    setTechSuccessMsg(null);
    setFilterTab("all");
    setExpandedIndices(new Set());
    setGeneratingAIIndices(new Set());
    setImportOnlyQualified(true);
    setSelectedEvaluationGroup("5m");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  const handleClose = () => {
    resetState();
    onClose();
  };

  const loadInitialData = useCallback(async () => {
    setDatasourcesLoading(true);
    setEvalGroupsLoading(true);
    try {
      const [dsRes, groupsRes, aiRes] = await Promise.allSettled([
        api.getLokiDatasources(),
        api.getEvaluationGroups(),
        api.getAISettings(),
      ]);

      if (dsRes.status === "fulfilled") {
        setDatasources(dsRes.value);
        const defaultDs =
          dsRes.value.find((d) => d.is_internal && d.is_default) ||
          dsRes.value.find((d) => d.is_internal) ||
          dsRes.value[0];
        if (defaultDs) {
          setSelectedDatasourceUid(defaultDs.uid);
        }
      }

      if (groupsRes.status === "fulfilled" && groupsRes.value.length > 0) {
        const uniqueGroups = Array.from(new Set(["5m", ...groupsRes.value]));
        setEvaluationGroups(uniqueGroups);
        setSelectedEvaluationGroup("5m");
      }

      if (aiRes.status === "fulfilled") {
        setAISettings(aiRes.value);
      }
    } catch (err: unknown) {
      console.warn("Falha ao carregar dados iniciais de importação:", err);
    } finally {
      setDatasourcesLoading(false);
      setEvalGroupsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadInitialData();
    } else {
      resetState();
    }
  }, [isOpen, loadInitialData]);

  const toggleExpand = (index: number) => {
    setExpandedIndices((prev) => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const expandAll = (items: RuleImportItemValidation[]) => {
    setExpandedIndices(new Set(items.map((it) => it.index)));
  };

  const collapseAll = () => {
    setExpandedIndices(new Set());
  };

  const getCompatibilityMeta = (item: RuleImportItemValidation) => {
    const compat = item.field_compatibility_pct ?? 100;
    if (compat >= 95) {
      return {
        label: `${compat.toFixed(1)}% Alta Compatibilidade`,
        shortLabel: "Excelente (≥ 95%)",
        bg: "bg-emerald-950/40",
        color: "text-emerald-400",
        border: "border-emerald-500/40",
        icon: "verified",
      };
    }
    if (compat >= 80) {
      return {
        label: `${compat.toFixed(1)}% Boa Compatibilidade`,
        shortLabel: "Qualificada (80%-94%)",
        bg: "bg-sky-950/40",
        color: "text-sky-400",
        border: "border-sky-500/40",
        icon: "check_circle",
      };
    }
    return {
      label: `${compat.toFixed(1)}% Incompatível`,
      shortLabel: "Incompatível (< 80%)",
      bg: "bg-rose-950/40",
      color: "text-rose-400",
      border: "border-rose-500/40",
      icon: "warning",
    };
  };

  const handleOpenCreateTech = (item: RuleImportItemValidation) => {
    setTechForm({
      slug: item.suggested_technology_slug || "",
      name: item.suggested_technology_name || "",
      rule_groups_regex: item.suggested_rule_groups_regex || "",
      job: "wazuh",
      description: `Tecnologia gerada a partir da importação da regra '${item.title}'`,
      confirm_without_logs: true,
    });
    setTechError(null);
    setTechSuccessMsg(null);
    setIsCreateTechOpen(true);
  };

  const handleSaveTechnology = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!techForm.slug || !techForm.name || !techForm.rule_groups_regex) {
      setTechError("Preencha todos os campos obrigatórios da tecnologia.");
      return;
    }
    setSavingTech(true);
    setTechError(null);
    try {
      await api.createTechnology(techForm);
      setTechSuccessMsg(`Tecnologia '${techForm.name}' cadastrada com sucesso!`);
      setTimeout(async () => {
        setIsCreateTechOpen(false);
        setTechSuccessMsg(null);
        if (uploadedFiles.length > 0) {
          await runValidationForFiles(uploadedFiles);
        } else if (jsonContent.trim()) {
          await runValidationForManualText();
        }
      }, 900);
    } catch (err: unknown) {
      setTechError(err instanceof Error ? err.message : "Erro ao cadastrar tecnologia.");
    } finally {
      setSavingTech(false);
    }
  };

  const processFiles = (files: File[]) => {
    const supportedFiles = files.filter(
      (f) =>
        f.name.endsWith(".json") ||
        f.name.endsWith(".yaml") ||
        f.name.endsWith(".yml") ||
        f.type === "application/json" ||
        f.type === "text/yaml" ||
        f.type === "text/x-yaml"
    );

    if (supportedFiles.length === 0) {
      setErrorMsg("Apenas arquivos JSON ou YAML (.json, .yaml, .yml) são suportados.");
      return;
    }

    setReadingFiles(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    setPreviewResult(null);

    try {
      const readPromises = supportedFiles.map(
        (file) =>
          new Promise<UploadedFileInfo>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (event) => {
              resolve({
                filename: file.name,
                content: (event.target?.result as string) || "",
                size: file.size,
              });
            };
            reader.onerror = () => reject(new Error(`Falha ao ler o arquivo ${file.name}`));
            reader.readAsText(file);
          })
      );

      Promise.all(readPromises)
        .then((loaded) => {
          setUploadedFiles((prev) => {
            const existingNames = new Set(prev.map((p) => p.filename));
            const newOnes = loaded.filter((l) => !existingNames.has(l.filename));
            const updated = [...prev, ...newOnes];
            runValidationForFiles(updated);
            return updated;
          });
        })
        .catch((err) => {
          setErrorMsg(err.message || "Erro ao carregar arquivos.");
        })
        .finally(() => {
          setReadingFiles(false);
        });
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Erro no processamento de arquivos.");
      setReadingFiles(false);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFiles(Array.from(e.target.files));
    }
  };

  const handleRemoveFile = (filename: string) => {
    const remaining = uploadedFiles.filter((f) => f.filename !== filename);
    setUploadedFiles(remaining);
    if (remaining.length > 0) {
      runValidationForFiles(remaining);
    } else {
      setPreviewResult(null);
      setErrorMsg(null);
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    const droppedFiles = Array.from(e.dataTransfer.files);
    if (droppedFiles.length === 0) return;
    processFiles(droppedFiles);
  };

  const runValidationForFiles = async (filesToValidate: UploadedFileInfo[]) => {
    setIsValidating(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await api.previewImportRules({
        files: filesToValidate.map((f) => ({ filename: f.filename, content: f.content })),
      });
      setPreviewResult(res);
      if (res.general_error) {
        setErrorMsg(res.general_error);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Falha ao validar os arquivos de regras.");
      setPreviewResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  const runValidationForManualText = async (contentToValidate?: string) => {
    const text = contentToValidate ?? jsonContent;
    if (!text.trim()) {
      setErrorMsg("Insira o conteúdo YAML ou JSON das regras para validação.");
      return;
    }

    setIsValidating(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await api.previewImportRules(text);
      setPreviewResult(res);
      if (res.general_error) {
        setErrorMsg(res.general_error);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Falha ao validar o conteúdo de regras.");
      setPreviewResult(null);
    } finally {
      setIsValidating(false);
    }
  };

  // Parecer Técnico por IA emitido sob demanda exclusivamente ao clicar nas 3 estrelinhas
  const handleGenerateAIOpinion = async (item: RuleImportItemValidation, e: React.MouseEvent) => {
    e.stopPropagation();

    if (!isRuleImportAIEnabled) {
      setErrorMsg(
        "A análise e parecer por IA na importação de regras está desativada nas configurações de API Keys."
      );
      return;
    }

    setGeneratingAIIndices((prev) => new Set(prev).add(item.index));
    setErrorMsg(null);

    try {
      const res = await api.generateRuleImportAIOpinion({
        rule: item,
        technology: item.technology,
      });

      setPreviewResult((prev) => {
        if (!prev) return prev;
        const updatedItems = prev.items.map((it) => {
          if (it.index === item.index) {
            return {
              ...it,
              ai_rationale: res.ai_rationale,
              ai_model: res.ai_model,
              curation_engine: res.curation_engine || "ai",
              classification: res.classification ?? it.classification,
              classification_reason: res.classification_reason ?? it.classification_reason,
              qualification_factors:
                res.qualification_factors && res.qualification_factors.length > 0
                  ? res.qualification_factors
                  : it.qualification_factors,
            };
          }
          return it;
        });
        return { ...prev, items: updatedItems };
      });

      // Expande automaticamente a linha para visualização imediata do parecer emitido
      setExpandedIndices((prev) => new Set(prev).add(item.index));
    } catch (err: unknown) {
      setErrorMsg(
        err instanceof Error ? err.message : "Falha ao gerar parecer técnico por IA para a regra."
      );
    } finally {
      setGeneratingAIIndices((prev) => {
        const next = new Set(prev);
        next.delete(item.index);
        return next;
      });
    }
  };

  // Regras válidas e qualificadas
  const validRules = useMemo(() => {
    if (!previewResult) return [];
    return previewResult.items.filter(
      (item) => item.valid && item.errors.length === 0 && !item.technology_missing
    );
  }, [previewResult]);

  const qualifiedRules = useMemo(() => {
    return validRules.filter((item) => (item.field_compatibility_pct ?? 100) >= 80);
  }, [validRules]);

  const highCompatRules = useMemo(() => {
    return validRules.filter((item) => (item.field_compatibility_pct ?? 100) >= 95);
  }, [validRules]);

  const incompatibleRules = useMemo(() => {
    if (!previewResult) return [];
    return previewResult.items.filter(
      (item) => (item.field_compatibility_pct ?? 100) < 80 || item.errors.length > 0
    );
  }, [previewResult]);

  const filteredItems = useMemo(() => {
    if (!previewResult) return [];
    return previewResult.items.filter((item) => {
      const compat = item.field_compatibility_pct ?? 100;
      if (filterTab === "qualified") {
        return item.valid && !item.technology_missing && compat >= 80;
      }
      if (filterTab === "high") {
        return item.valid && !item.technology_missing && compat >= 95;
      }
      if (filterTab === "incompatible") {
        return compat < 80 || item.errors.length > 0;
      }
      return true;
    });
  }, [previewResult, filterTab]);

  const rulesToImport = useMemo(() => {
    if (importOnlyQualified && qualifiedRules.length > 0) {
      return qualifiedRules;
    }
    return validRules;
  }, [importOnlyQualified, qualifiedRules, validRules]);

  const handleImport = async () => {
    if (!previewResult || previewResult.valid_count === 0) return;
    if (rulesToImport.length === 0) {
      setErrorMsg("Nenhuma regra válida selecionada para importação.");
      return;
    }

    setIsImporting(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await api.executeImportRules(
        rulesToImport,
        selectedDatasourceUid,
        selectedEvaluationGroup.trim() || "5m"
      );
      if (res.failed_count > 0 && res.imported_count === 0) {
        const detail = res.failed?.[0]?.error ? `: ${res.failed[0].error}` : "";
        setErrorMsg(`${res.message}${detail}`);
      } else if (res.failed_count > 0) {
        const detail = res.failed?.[0]?.error ? ` (Detalhe: ${res.failed[0].error})` : "";
        setSuccessMsg(`${res.message}${detail}`);
        setTimeout(() => {
          onSuccess();
          handleClose();
        }, 3000);
      } else {
        setSuccessMsg(res.message);
        setTimeout(() => {
          onSuccess();
          handleClose();
        }, 1500);
      }
    } catch (err: unknown) {
      setErrorMsg(err instanceof Error ? err.message : "Falha ao importar regras.");
    } finally {
      setIsImporting(false);
    }
  };

  const modalTitle = (
    <div className="flex items-center gap-3">
      <div className="w-10 h-10 rounded-xl bg-sky-500/10 border border-sky-500/20 flex items-center justify-center text-sky-400">
        <span className="material-symbols-outlined text-[22px]">cloud_upload</span>
      </div>
      <div>
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
          Importar Regras de Detecção
          <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
            Loki Ruler
          </span>
        </h2>
        <p className="text-xs text-slate-400">
          Curadoria estática de campos, compatibilidade com telemetria Wazuh e parecer técnico por IA sob demanda
        </p>
      </div>
    </div>
  );

  return (
    <>
      <Modal
        isOpen={isOpen}
        onClose={handleClose}
        title={modalTitle}
        maxWidth="1180px"
      >
        <div className="space-y-5 text-slate-200">
          {/* Banner de Invariantes e Diretriz de Governança */}
          <div className="rounded-xl border border-sky-500/20 bg-sky-950/20 p-3.5 flex items-start gap-3">
            <span className="material-symbols-outlined text-sky-400 text-xl mt-0.5 shrink-0">
              shield
            </span>
            <div className="text-xs leading-relaxed text-slate-300">
              <span className="text-sky-300 font-semibold block mb-0.5">
                Diretrizes de Governança, Curadoria e Segurança
              </span>
              Regras importadas são direcionadas para a pasta <strong>Global (Baseline)</strong> no estágio de <strong>Homologação (Contact Point &apos;stg&apos;)</strong>.
              A avaliação inicial valida a sintaxe LogQL e mapeia a compatibilidade dos campos. O <strong>parecer técnico por IA</strong> é acionado sob demanda exclusivamente no botão com 3 estrelinhas (
              <span className="inline-flex items-center gap-0.5 font-semibold text-purple-300 mx-1">
                <span className="material-symbols-outlined text-[13px]">auto_awesome</span> Parecer IA
              </span>
              ) na linha de cada regra.
            </div>
          </div>

          {/* Configuração de Destino: Data Source Loki e Grupo de Avaliação */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-900/60 p-4 rounded-xl border border-slate-800">
            {/* Seletor de Data Source Loki */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-2">
                <span>Data Source Loki de Destino *</span>
                {datasourcesLoading && (
                  <span className="text-[11px] text-slate-500 font-normal">
                    (carregando...)
                  </span>
                )}
              </label>
              <select
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 transition-colors"
                value={selectedDatasourceUid}
                onChange={(e) => setSelectedDatasourceUid(e.target.value)}
                disabled={datasourcesLoading || isImporting}
              >
                {datasources.map((ds) => (
                  <option key={ds.uid} value={ds.uid}>
                    {ds.name} {ds.is_internal ? "(Interno)" : "(Cliente)"}{" "}
                    {ds.is_default ? "★ Padrão" : ""}
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-slate-400 mt-1">
                Data source interno onde as expressões LogQL serão executadas no Grafana.
              </p>
            </div>

            {/* Grupo de Avaliação (Evaluation Group) - Padrão 5m */}
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-2">
                <span>Grupo de Avaliação (ruleGroup) *</span>
                {evalGroupsLoading && (
                  <span className="text-[11px] text-slate-500 font-normal">
                    (carregando...)
                  </span>
                )}
              </label>
              <input
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-mono transition-colors"
                list="evaluation-groups-datalist"
                value={selectedEvaluationGroup}
                onChange={(e) => setSelectedEvaluationGroup(e.target.value)}
                placeholder="5m"
                disabled={isImporting}
              />
              <datalist id="evaluation-groups-datalist">
                {evaluationGroups.map((g) => (
                  <option key={g} value={g} />
                ))}
              </datalist>
              <p className="text-[11px] text-slate-400 mt-1">
                Intervalo de avaliação no Grafana Alerting. Padrão canônico: <strong className="text-sky-300">5m</strong>.
              </p>
            </div>
          </div>

          {/* Zona de Upload / Arrastar e Soltar (Dropzone) */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`rounded-2xl border-2 border-dashed p-6 text-center cursor-pointer transition-all ${
              isDragging
                ? "border-sky-500 bg-sky-950/30 shadow-lg shadow-sky-500/10"
                : "border-slate-700/80 bg-slate-900/40 hover:border-slate-600 hover:bg-slate-900/70"
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".json,.yaml,.yml,application/json,text/yaml,text/x-yaml"
              onChange={handleFileInputChange}
              className="hidden"
            />
            <div className="w-12 h-12 mx-auto mb-2 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-sky-400">
              <span className="material-symbols-outlined text-[28px]">
                {readingFiles ? "progress_activity" : "upload_file"}
              </span>
            </div>
            <p className="text-sm font-semibold text-slate-200 mb-1">
              Arraste e solte arquivos YAML/JSON ou clique para selecionar
            </p>
            <p className="text-xs text-slate-400 mb-3">
              Suporta múltiplos arquivos simultâneos (.yaml, .yml, .json) ou múltiplos documentos separados por &apos;---&apos;
            </p>
            <div className="flex items-center justify-center gap-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                .yaml
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                .yml
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                .json
              </span>
            </div>
          </div>

          {/* Lista de Arquivos Carregados */}
          {uploadedFiles.length > 0 && (
            <div className="space-y-2 max-h-36 overflow-y-auto p-1">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                <span>Arquivos Selecionados ({uploadedFiles.length})</span>
                <button
                  type="button"
                  onClick={() => {
                    setUploadedFiles([]);
                    setPreviewResult(null);
                    setErrorMsg(null);
                  }}
                  className="text-xs text-rose-400 hover:text-rose-300 transition-colors"
                >
                  Limpar todos
                </button>
              </div>
              <div className="flex flex-wrap gap-2">
                {uploadedFiles.map((f) => (
                  <div
                    key={f.filename}
                    className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-slate-200"
                  >
                    <span className="material-symbols-outlined text-sm text-sky-400">
                      description
                    </span>
                    <span className="font-medium max-w-[220px] truncate">{f.filename}</span>
                    <span className="text-slate-400 text-[11px]">({formatFileSize(f.size)})</span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleRemoveFile(f.filename);
                      }}
                      className="text-slate-400 hover:text-rose-400 transition-colors"
                      title="Remover arquivo"
                    >
                      <span className="material-symbols-outlined text-sm">close</span>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Toggle para entrada manual de texto */}
          <div>
            <button
              type="button"
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400 hover:text-sky-400 transition-colors"
              onClick={() => setShowManualEditor(!showManualEditor)}
            >
              <span className="material-symbols-outlined text-base">
                {showManualEditor ? "expand_less" : "expand_more"}
              </span>
              <span>{showManualEditor ? "Ocultar Editor Manual" : "Colar Conteúdo YAML/JSON Manualmente"}</span>
            </button>
          </div>

          {showManualEditor && (
            <div className="space-y-2 bg-slate-900/80 p-3 rounded-xl border border-slate-800">
              <textarea
                className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                rows={6}
                value={jsonContent}
                onChange={(e) => setJsonContent(e.target.value)}
                placeholder={`groups:
  - name: windows_security_alerts
    rules:
      - alert: "AD/Windows - Escalonamento de Privilegio"
        expr: 'sum(count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json | win_system_eventID=~"4728" [5m])) > 0'
        for: "0s"
        labels:
          severity: "critical"
          mitre_tactic: "persistence"
          mitre_technique: "T1098"
        annotations:
          summary: "Membro adicionado a grupo privilegiado"
          description: "Detecta modificação de grupos sensíveis no Active Directory."`}
              />
              <div className="flex justify-end">
                <button
                  type="button"
                  className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
                  onClick={() => runValidationForManualText()}
                  disabled={isValidating || isImporting || !jsonContent.trim()}
                >
                  {isValidating ? "Validando..." : "Validar Conteúdo Manual"}
                </button>
              </div>
            </div>
          )}

          {/* Mensagens de Feedback Global */}
          {errorMsg && (
            <div className="p-3.5 rounded-xl border border-rose-500/40 bg-rose-950/30 text-rose-300 text-xs flex items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-base shrink-0">error</span>
                <span>{errorMsg}</span>
              </div>
              <button
                type="button"
                onClick={() => setErrorMsg(null)}
                className="text-rose-400 hover:text-rose-200"
              >
                <span className="material-symbols-outlined text-sm">close</span>
              </button>
            </div>
          )}

          {successMsg && (
            <div className="p-3.5 rounded-xl border border-emerald-500/40 bg-emerald-950/30 text-emerald-300 text-xs flex items-center gap-2">
              <span className="material-symbols-outlined text-base shrink-0">check_circle</span>
              <span>{successMsg}</span>
            </div>
          )}

          {/* Status de Validação */}
          {isValidating && (
            <div className="py-8 text-center text-slate-400">
              <span className="material-symbols-outlined animate-spin text-2xl text-sky-400">
                progress_activity
              </span>
              <p className="mt-2 text-xs font-medium">
                Validando estrutura LogQL e compatibilidade de campos nos clientes...
              </p>
            </div>
          )}

          {/* Painel de Resultados do Preview */}
          {previewResult && !isValidating && (
            <div className="space-y-4 pt-2">
              {/* Cards de Métricas de Curadoria e Compatibilidade */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Total Regras
                  </span>
                  <div className="text-xl font-bold text-slate-100 mt-1">
                    {previewResult.total_rules}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-500/30 flex flex-col justify-between">
                  <span className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider">
                    Válidas
                  </span>
                  <div className="text-xl font-bold text-emerald-300 mt-1">
                    {previewResult.valid_count}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-sky-950/20 border border-sky-500/30 flex flex-col justify-between">
                  <span className="text-[11px] font-semibold text-sky-400 uppercase tracking-wider">
                    Alta Compatibilidade
                  </span>
                  <div className="text-xl font-bold text-sky-300 mt-1">
                    {previewResult.high_compatibility_count ?? highCompatRules.length}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-rose-950/20 border border-rose-500/30 flex flex-col justify-between">
                  <span className="text-[11px] font-semibold text-rose-400 uppercase tracking-wider">
                    Incompatíveis
                  </span>
                  <div className="text-xl font-bold text-rose-300 mt-1">
                    {previewResult.discarded_count ?? incompatibleRules.length}
                  </div>
                </div>
              </div>

              {/* Filtros e Ações em Lote */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => setFilterTab("all")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      filterTab === "all"
                        ? "bg-slate-700 text-white"
                        : "bg-slate-900 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Todas ({previewResult.items.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilterTab("qualified")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      filterTab === "qualified"
                        ? "bg-sky-600 text-white"
                        : "bg-slate-900 text-slate-400 hover:text-sky-300"
                    }`}
                  >
                    Qualificadas ≥80% ({qualifiedRules.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilterTab("high")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      filterTab === "high"
                        ? "bg-emerald-600 text-white"
                        : "bg-slate-900 text-slate-400 hover:text-emerald-300"
                    }`}
                  >
                    Alta Compatibilidade ≥95% ({highCompatRules.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilterTab("incompatible")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                      filterTab === "incompatible"
                        ? "bg-rose-600 text-white"
                        : "bg-slate-900 text-slate-400 hover:text-rose-300"
                    }`}
                  >
                    Ajuste Necessário ({incompatibleRules.length})
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => expandAll(filteredItems)}
                    className="text-xs text-slate-400 hover:text-slate-200"
                  >
                    Expandir Todas
                  </button>
                  <span className="text-slate-600">•</span>
                  <button
                    type="button"
                    onClick={collapseAll}
                    className="text-xs text-slate-400 hover:text-slate-200"
                  >
                    Recolher Todas
                  </button>
                </div>
              </div>

              {/* Lista de Regras Avaliadas */}
              <div className="space-y-3 max-h-[480px] overflow-y-auto pr-1">
                {filteredItems.length === 0 ? (
                  <div className="text-center py-12 text-slate-400 text-xs">
                    Nenhuma regra encontrada para o filtro selecionado ({filterTab}).
                  </div>
                ) : (
                  filteredItems.map((item: RuleImportItemValidation) => {
                    const isItemInvalid = item.errors.length > 0;
                    const isItemTechMissing = item.technology_missing;
                    const compatMeta = getCompatibilityMeta(item);
                    const isExpanded = expandedIndices.has(item.index);
                    const isGeneratingAI = generatingAIIndices.has(item.index);
                    const hasAIOpinion = Boolean(item.ai_rationale);

                    return (
                      <div
                        key={item.index}
                        className={`rounded-xl border p-4 transition-all ${
                          isItemInvalid
                            ? "border-rose-500/50 bg-rose-950/10"
                            : isItemTechMissing
                            ? "border-amber-500/50 bg-amber-950/10"
                            : `${compatMeta.border} bg-slate-900/40`
                        }`}
                      >
                        {/* Linha Principal do Card */}
                        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className="font-semibold text-sm text-slate-100">
                                {item.title}
                              </span>
                              {/* Badge de Compatibilidade Dinâmica */}
                              <span
                                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${compatMeta.bg} ${compatMeta.color} ${compatMeta.border}`}
                              >
                                <span className="material-symbols-outlined text-[13px]">
                                  {compatMeta.icon}
                                </span>
                                <span>{compatMeta.label}</span>
                              </span>
                            </div>

                            {item.description && (
                              <p className="text-xs text-slate-400 line-clamp-2 mb-2">
                                {item.description}
                              </p>
                            )}

                            {/* Tags de Metadados: Tecnologia, Tática, Severidade */}
                            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                              {item.filename && (
                                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">
                                  {item.filename}
                                </span>
                              )}
                              {item.technology_name && (
                                <span className="px-2 py-0.5 rounded bg-sky-950/40 text-sky-300 border border-sky-500/30">
                                  {item.technology_name}
                                </span>
                              )}
                              {item.mitre_tactic && (
                                <span className="px-2 py-0.5 rounded bg-purple-950/40 text-purple-300 border border-purple-500/30">
                                  {item.mitre_tactic} ({item.mitre_technique || "T1059"})
                                </span>
                              )}
                              <span
                                className={`px-2 py-0.5 rounded font-semibold uppercase ${
                                  item.severity === "critical"
                                    ? "bg-rose-950/40 text-rose-300 border border-rose-500/30"
                                    : item.severity === "high"
                                    ? "bg-amber-950/40 text-amber-300 border border-amber-500/30"
                                    : "bg-slate-800 text-slate-300 border border-slate-700"
                                }`}
                              >
                                {item.severity}
                              </span>
                            </div>
                          </div>

                          {/* Botões de Ação na Linha */}
                          <div className="flex items-center gap-2 shrink-0">
                            {isItemTechMissing && (
                              <button
                                type="button"
                                className="px-2.5 py-1 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-medium inline-flex items-center gap-1 transition-colors"
                                onClick={() => handleOpenCreateTech(item)}
                                title="Cadastrar tecnologia para liberar a regra"
                              >
                                <span className="material-symbols-outlined text-[14px]">add</span>
                                <span>Criar Tecnologia</span>
                              </button>
                            )}

                            {/* Botão de 3 Estrelinhas de IA (auto_awesome) para Parecer Técnico Sob Demanda */}
                            <button
                              type="button"
                              onClick={(e) => handleGenerateAIOpinion(item, e)}
                              disabled={isGeneratingAI || !isRuleImportAIEnabled}
                              className={`px-2.5 py-1 rounded-lg text-xs font-medium inline-flex items-center gap-1.5 transition-all shadow-sm ${
                                !isRuleImportAIEnabled
                                  ? "bg-slate-800/40 border border-slate-800 text-slate-500 cursor-not-allowed opacity-60"
                                  : hasAIOpinion
                                  ? "bg-purple-950/60 border border-purple-500/50 text-purple-300 hover:bg-purple-900/60"
                                  : "bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 hover:text-white"
                              }`}
                              title={
                                !isRuleImportAIEnabled
                                  ? "A análise por IA para regras importadas está desativada nas configurações de API Keys"
                                  : hasAIOpinion
                                  ? "Parecer por IA gerado com sucesso. Clique para regenerar."
                                  : "Gerar parecer técnico por IA sob demanda (Contexto de Ameaça, Aderência de Campos e Diretrizes SOC)"
                              }
                            >
                              <span
                                className={`material-symbols-outlined text-[15px] ${
                                  isGeneratingAI ? "animate-spin text-purple-400" : hasAIOpinion ? "text-purple-300" : "text-sky-400"
                                }`}
                              >
                                {isGeneratingAI ? "progress_activity" : "auto_awesome"}
                              </span>
                              <span>
                                {isGeneratingAI
                                  ? "Gerando Parecer..."
                                  : hasAIOpinion
                                  ? "Parecer IA ✓"
                                  : "Parecer IA"}
                              </span>
                            </button>

                            {/* Botão de Expandir / Recolher Detalhes */}
                            <button
                              type="button"
                              onClick={() => toggleExpand(item.index)}
                              className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-white text-xs font-medium inline-flex items-center gap-1 transition-colors"
                            >
                              <span className="material-symbols-outlined text-[16px]">
                                {isExpanded ? "expand_less" : "expand_more"}
                              </span>
                              <span>{isExpanded ? "Recolher" : "Detalhes"}</span>
                            </button>
                          </div>
                        </div>

                        {/* Painel Expandido: Parecer Técnico de IA, Compatibilidade e Query */}
                        {isExpanded && (
                          <div className="mt-3 pt-3 border-t border-slate-800 space-y-3 text-xs">
                            {/* Bloco 1: Parecer Técnico da IA */}
                            {item.ai_rationale ? (
                              <div className="rounded-xl border border-purple-500/30 bg-purple-950/20 p-3.5 space-y-2">
                                <div className="flex items-center justify-between">
                                  <div className="flex items-center gap-1.5 text-purple-300 font-semibold uppercase tracking-wider text-[11px]">
                                    <span className="material-symbols-outlined text-[15px]">
                                      auto_awesome
                                    </span>
                                    <span>Parecer Técnico por IA (D.A.N.T.E. Cognitive Engine)</span>
                                  </div>
                                  {item.ai_model && (
                                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-900/40 text-purple-200 border border-purple-500/30">
                                      {item.ai_model}
                                    </span>
                                  )}
                                </div>
                                <div className="text-slate-200 leading-relaxed whitespace-pre-line text-xs font-sans">
                                  {item.ai_rationale}
                                </div>
                              </div>
                            ) : (
                              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3 flex items-center justify-between text-slate-400">
                                <div className="flex items-center gap-2">
                                  <span className="material-symbols-outlined text-slate-500 text-base">
                                    psychology
                                  </span>
                                  <span>
                                    Parecer técnico por IA ainda não gerado para esta regra.
                                  </span>
                                </div>
                                {isRuleImportAIEnabled && (
                                  <button
                                    type="button"
                                    onClick={(e) => handleGenerateAIOpinion(item, e)}
                                    disabled={isGeneratingAI}
                                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs transition-colors"
                                  >
                                    <span className="material-symbols-outlined text-[14px]">
                                      auto_awesome
                                    </span>
                                    <span>Gerar Parecer Agora</span>
                                  </button>
                                )}
                              </div>
                            )}

                            {/* Bloco 2: Aderência de Campos e Schema Wazuh */}
                            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 space-y-2">
                              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                                Mapeamento e Aderência dos Campos (Schema Wazuh / Loki)
                              </span>
                              {item.mapped_fields && item.mapped_fields.length > 0 ? (
                                <div className="flex flex-wrap gap-1.5">
                                  {item.mapped_fields.map((mf, mfIdx) => (
                                    <span
                                      key={mfIdx}
                                      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono border ${
                                        mf.compatible
                                          ? "bg-emerald-950/30 text-emerald-300 border-emerald-500/30"
                                          : "bg-rose-950/30 text-rose-300 border-rose-500/30"
                                      }`}
                                    >
                                      <span>{mf.compatible ? "✓" : "✕"}</span>
                                      <span>{mf.logql_field || mf.original_field}</span>
                                    </span>
                                  ))}
                                </div>
                              ) : (
                                <p className="text-slate-400 text-xs">
                                  Telemetria padrão baseada no fluxo do Wazuh (| json).
                                </p>
                              )}

                              {item.client_evaluations && item.client_evaluations.length > 0 && (
                                <div className="pt-2 border-t border-slate-800/80">
                                  <span className="text-[11px] font-medium text-slate-400 block mb-1">
                                    Presença de Telemetria nos Ambientes de Clientes:
                                  </span>
                                  <div className="flex flex-wrap gap-1.5">
                                    {item.client_evaluations.map((ce, ceIdx) => (
                                      <span
                                        key={ceIdx}
                                        className={`px-2 py-0.5 rounded text-[11px] border ${
                                          ce.classification === "excellent"
                                            ? "bg-emerald-950/30 text-emerald-300 border-emerald-500/30"
                                            : ce.classification === "good"
                                            ? "bg-sky-950/30 text-sky-300 border-sky-500/30"
                                            : "bg-rose-950/30 text-rose-300 border-rose-500/30"
                                        }`}
                                      >
                                        {ce.client_name}: {(ce.field_compatibility_pct ?? 100).toFixed(0)}%
                                      </span>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </div>

                            {/* Bloco 3: Consulta LogQL e Comparador */}
                            <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-3 font-mono text-[11px] text-slate-300 overflow-x-auto">
                              <div className="text-[10px] uppercase tracking-wider text-slate-400 font-sans font-semibold mb-1 flex items-center justify-between">
                                <span>Expressão LogQL</span>
                                <span>
                                  Threshold: {item.threshold_operator} {item.threshold_value} | for: {item.for_duration}
                                </span>
                              </div>
                              <code className="text-sky-300">{item.query}</code>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* Rodapé e Ações Finais */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-slate-800">
            <div className="text-xs text-slate-400">
              {previewResult && previewResult.valid_count > 0 && (
                <span>
                  Serão importadas <strong>{rulesToImport.length}</strong> regra(s) no baseline global.
                </span>
              )}
            </div>

            <div className="flex items-center gap-3">
              <button
                type="button"
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-semibold transition-colors"
                onClick={handleClose}
                disabled={isImporting}
              >
                Cancelar
              </button>
              <button
                type="button"
                className="px-5 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
                onClick={handleImport}
                disabled={
                  isImporting ||
                  isValidating ||
                  !previewResult ||
                  rulesToImport.length === 0
                }
              >
                {isImporting
                  ? "Importando Regras..."
                  : `Importar ${rulesToImport.length} Regra(s) no Baseline`}
              </button>
            </div>
          </div>
        </div>
      </Modal>

      {/* Modal de Criação Rápida de Tecnologia para regras sem tecnologia cadastrada */}
      <Modal
        isOpen={isCreateTechOpen}
        onClose={() => setIsCreateTechOpen(false)}
        title="Cadastrar Nova Tecnologia"
        maxWidth="640px"
      >
        <form onSubmit={handleSaveTechnology} className="space-y-4 text-slate-200">
          {techError && (
            <div className="p-3 rounded-lg border border-rose-500/40 bg-rose-950/30 text-rose-300 text-xs flex items-center gap-2">
              <span className="material-symbols-outlined text-sm">error</span>
              <span>{techError}</span>
            </div>
          )}
          {techSuccessMsg && (
            <div className="p-3 rounded-lg border border-emerald-500/40 bg-emerald-950/30 text-emerald-300 text-xs flex items-center gap-2">
              <span className="material-symbols-outlined text-sm">check_circle</span>
              <span>{techSuccessMsg}</span>
            </div>
          )}

          <p className="text-xs text-slate-400 leading-relaxed">
            Cadastre a tecnologia correspondente ao seletor da regra. Após salvar, o validador reavaliará as regras automaticamente.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Nome da Tecnologia *
              </label>
              <input
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                value={techForm.name}
                onChange={(e) => setTechForm({ ...techForm, name: e.target.value })}
                placeholder="Ex.: Crowdstrike Falcon"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Slug *
              </label>
              <input
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                value={techForm.slug}
                onChange={(e) => setTechForm({ ...techForm, slug: e.target.value })}
                placeholder="ex.: crowdstrike_falcon"
                required
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Grupo de Regras Wazuh (rule_groups regex) *
              </label>
              <input
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                value={techForm.rule_groups_regex}
                onChange={(e) => setTechForm({ ...techForm, rule_groups_regex: e.target.value })}
                placeholder="ex.: .*crowdstrike.*"
                required
              />
            </div>
            <div>
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
                Label job
              </label>
              <input
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                value={techForm.job || "wazuh"}
                onChange={(e) => setTechForm({ ...techForm, job: e.target.value })}
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
              Descrição
            </label>
            <textarea
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
              rows={2}
              value={techForm.description || ""}
              onChange={(e) => setTechForm({ ...techForm, description: e.target.value })}
              placeholder="Descrição ou fontes de telemetria desta tecnologia."
            />
          </div>

          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
            <input
              type="checkbox"
              checked={techForm.confirm_without_logs ?? true}
              onChange={(e) => setTechForm({ ...techForm, confirm_without_logs: e.target.checked })}
              className="rounded bg-slate-900 border-slate-700 text-sky-600 focus:ring-sky-500"
            />
            Confirmar cadastro mesmo que ainda não existam logs no Loki para esta tecnologia
          </label>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              onClick={() => setIsCreateTechOpen(false)}
              disabled={savingTech}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
              disabled={savingTech || !techForm.slug || !techForm.name || !techForm.rule_groups_regex}
            >
              {savingTech ? "Salvando..." : "Salvar Tecnologia e Revalidar"}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
};
