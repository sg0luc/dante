import React, { useState, useRef, useEffect, useCallback, useMemo } from "react";
import { Modal } from "./Modal";
import { api } from "../api";
import {
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

  // Filtros de Curadoria e Visualização de Parecer
  const [filterTab, setFilterTab] = useState<"all" | "qualified" | "high" | "incompatible">("all");
  const [expandedIndices, setExpandedIndices] = useState<Set<number>>(new Set());
  const [importOnlyQualified, setImportOnlyQualified] = useState<boolean>(true);

  // Data source Loki de destino
  const [datasources, setDatasources] = useState<LokiDatasourceItem[]>([]);
  const [selectedDatasourceUid, setSelectedDatasourceUid] = useState<string>("loki");
  const [datasourcesLoading, setDatasourcesLoading] = useState<boolean>(false);

  // Grupo de avaliação (Evaluation Group / ruleGroup)
  const [evaluationGroups, setEvaluationGroups] = useState<string[]>(["global-detections"]);
  const [selectedEvaluationGroup, setSelectedEvaluationGroup] = useState<string>("global-detections");
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
    setImportOnlyQualified(true);
    setSelectedEvaluationGroup("global-detections");
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
      const [dsRes, groupsRes] = await Promise.allSettled([
        api.getLokiDatasources(),
        api.getEvaluationGroups(),
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
        setEvaluationGroups(groupsRes.value);
      }
    } catch (err: any) {
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
        bg: "rgba(16, 185, 129, 0.16)",
        color: "#34d399",
        border: "1px solid rgba(16, 185, 129, 0.45)",
        icon: "verified",
      };
    }
    if (compat >= 80) {
      return {
        label: `${compat.toFixed(1)}% Boa Candidata (≥ 80%)`,
        shortLabel: "Qualificada (80%-94%)",
        bg: "rgba(14, 165, 233, 0.16)",
        color: "#38bdf8",
        border: "1px solid rgba(14, 165, 233, 0.45)",
        icon: "check_circle",
      };
    }
    return {
      label: `${compat.toFixed(1)}% Incompatível (< 80%)`,
      shortLabel: "Incompatível (< 80%)",
      bg: "rgba(244, 63, 94, 0.16)",
      color: "#fb7185",
      border: "1px solid rgba(244, 63, 94, 0.45)",
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
    } catch (err: any) {
      setTechError(err.message || "Erro ao cadastrar tecnologia.");
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
    } catch (err: any) {
      setErrorMsg(err.message || "Erro no processamento de arquivos.");
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
    } catch (err: any) {
      setErrorMsg(err.message || "Falha ao validar os arquivos de regras.");
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
    } catch (err: any) {
      setErrorMsg(err.message || "Falha ao validar o conteúdo de regras.");
      setPreviewResult(null);
    } finally {
      setIsValidating(false);
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
        selectedEvaluationGroup.trim() || undefined
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
    } catch (err: any) {
      setErrorMsg(err.message || "Erro ao executar importação de regras.");
    } finally {
      setIsImporting(false);
    }
  };

  return (
    <>
      <Modal
        isOpen={isOpen}
        onClose={handleClose}
        title="Importar Regras de Detecção (Loki Ruler)"
        maxWidth="1000px"
      >
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Banner de Invariantes e Diretriz de Segurança */}
          <div
            style={{
              backgroundColor: "rgba(30, 41, 59, 0.7)",
              border: "1px solid var(--border-color)",
              borderRadius: "6px",
              padding: "12px 14px",
              fontSize: "0.85rem",
              color: "var(--text-muted)",
              lineHeight: "1.4",
            }}
          >
            <div style={{ fontWeight: 600, color: "var(--text-main)", marginBottom: "4px" }}>
              Diretrizes de Governança, Curadoria e Segurança:
            </div>
            <div>
              1. Formatos suportados: especificação <strong>Loki Ruler</strong> (YAML ou JSON) com suporte a múltiplos arquivos e múltiplos documentos.
            </div>
            <div>
              2. <strong>Padrão de Curadoria &amp; Parecer Técnico por IA</strong>: cada regra importada é avaliada quanto à compatibilidade de campos do schema Wazuh e telemetria ativa nos clientes.
            </div>
            <div>
              3. Todas as regras importadas são salvas na pasta <strong>Global (Baseline)</strong> no estágio de <strong>Homologação (Contact Point &apos;stg&apos;)</strong>.
            </div>
            <div>
              4. Regras com erros ou sem tecnologia cadastrada ficam bloqueadas ou com chip amarelo até a tecnologia ser cadastrada.
            </div>
          </div>

          {/* Destino das Regras: Data Source e Grupo de Avaliação */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
              gap: "12px",
              backgroundColor: "var(--bg-input)",
              padding: "12px",
              borderRadius: "6px",
              border: "1px solid var(--border-color)",
            }}
          >
            {/* Seletor de Data Source Loki */}
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label
                className="form-label"
                style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "6px" }}
              >
                <span>Data Source Loki de Destino *</span>
                {datasourcesLoading && (
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    (carregando...)
                  </span>
                )}
              </label>
              <select
                className="input"
                value={selectedDatasourceUid}
                onChange={(e) => setSelectedDatasourceUid(e.target.value)}
                disabled={datasourcesLoading || isImporting}
                style={{ fontSize: "0.85rem" }}
              >
                {datasources.map((ds) => (
                  <option key={ds.uid} value={ds.uid}>
                    {ds.name} {ds.is_internal ? "(Interno)" : "(Cliente)"}{" "}
                    {ds.is_default ? "★ Padrão" : ""}
                  </option>
                ))}
              </select>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "4px" }}>
                Data source Loki onde as consultas da regra serão executadas no Grafana.
              </div>
            </div>

            {/* Grupo de Avaliação (Evaluation Group) */}
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label
                className="form-label"
                style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "6px" }}
              >
                <span>Grupo de Avaliação (ruleGroup)</span>
                {evalGroupsLoading && (
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    (carregando...)
                  </span>
                )}
              </label>
              <input
                className="input"
                list="evaluation-groups-datalist"
                value={selectedEvaluationGroup}
                onChange={(e) => setSelectedEvaluationGroup(e.target.value)}
                placeholder="global-detections"
                disabled={isImporting}
                style={{ fontSize: "0.85rem" }}
              />
              <datalist id="evaluation-groups-datalist">
                {evaluationGroups.map((g) => (
                  <option key={g} value={g} />
                ))}
              </datalist>
              <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "4px" }}>
                Grupo do Grafana Alerting. Padrão canônico: <strong>global-detections</strong>.
              </div>
            </div>
          </div>

          {/* Zona de Upload / Arrastar e Soltar */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            style={{
              border: `2px dashed ${isDragging ? "var(--primary-color)" : "var(--border-color)"}`,
              borderRadius: "8px",
              padding: "24px 16px",
              textAlign: "center",
              cursor: "pointer",
              backgroundColor: isDragging
                ? "rgba(99, 102, 241, 0.08)"
                : "rgba(15, 23, 42, 0.4)",
              transition: "all 0.2s ease",
            }}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".json,.yaml,.yml,application/json,text/yaml,text/x-yaml"
              onChange={handleFileInputChange}
              style={{ display: "none" }}
            />
            <div style={{ fontSize: "2rem", marginBottom: "6px" }}>📁</div>
            <div style={{ fontWeight: 600, color: "var(--text-main)", marginBottom: "4px" }}>
              Arraste e solte arquivos YAML/JSON ou clique para selecionar
            </div>
            <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>
              Suporta múltiplos arquivos simultâneos (.yaml, .yml, .json) ou múltiplos documentos separados por &apos;---&apos;
            </div>
          </div>

          {/* Lista de Arquivos Carregados */}
          {uploadedFiles.length > 0 && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: "6px",
                maxHeight: "150px",
                overflowY: "auto",
              }}
            >
              <div
                style={{
                  fontSize: "0.8rem",
                  fontWeight: 600,
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                }}
              >
                Arquivos Selecionados ({uploadedFiles.length})
              </div>
              {uploadedFiles.map((f) => (
                <div
                  key={f.filename}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "6px 10px",
                    backgroundColor: "var(--bg-input)",
                    borderRadius: "4px",
                    fontSize: "0.85rem",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                    <span>📄</span>
                    <span style={{ fontWeight: 500, color: "var(--text-main)" }}>{f.filename}</span>
                    <span style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>
                      ({formatFileSize(f.size)})
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRemoveFile(f.filename);
                    }}
                    style={{
                      background: "none",
                      border: "none",
                      color: "var(--status-firing)",
                      cursor: "pointer",
                      fontSize: "0.85rem",
                      padding: "2px 6px",
                    }}
                    title="Remover arquivo"
                  >
                    ✕
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Toggle para entrada manual de texto */}
          <div>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() => setShowManualEditor(!showManualEditor)}
              style={{ fontSize: "0.8rem" }}
            >
              {showManualEditor ? "▾ Ocultar Editor Manual" : "▸ Colar Conteúdo YAML/JSON Manualmente"}
            </button>
          </div>

          {showManualEditor && (
            <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
              <textarea
                className="textarea"
                rows={7}
                value={jsonContent}
                onChange={(e) => setJsonContent(e.target.value)}
                placeholder={`Cole aqui o conteúdo YAML ou JSON das regras Loki Ruler. Exemplo:

groups:
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
                style={{ fontFamily: "var(--font-mono)", fontSize: "0.82rem" }}
              />
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
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
            <div
              className="alert-box"
              style={{
                backgroundColor: "rgba(239, 68, 68, 0.15)",
                color: "var(--status-firing)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                borderRadius: "6px",
                padding: "10px 12px",
                fontSize: "0.85rem",
              }}
            >
              <strong>Erro:</strong> {errorMsg}
            </div>
          )}

          {successMsg && (
            <div
              className="alert-box"
              style={{
                backgroundColor: "rgba(34, 197, 94, 0.15)",
                color: "var(--status-normal)",
                border: "1px solid rgba(34, 197, 94, 0.3)",
                borderRadius: "6px",
                padding: "10px 12px",
                fontSize: "0.85rem",
              }}
            >
              <strong>Sucesso:</strong> {successMsg}
            </div>
          )}

          {/* Estado de Carregamento / Validação */}
          {isValidating && (
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                padding: "24px 16px",
                backgroundColor: "rgba(15, 23, 42, 0.5)",
                borderRadius: "8px",
                border: "1px solid var(--border-color)",
                gap: "10px",
              }}
            >
              <div
                style={{
                  width: "28px",
                  height: "28px",
                  border: "3px solid rgba(99, 102, 241, 0.2)",
                  borderTopColor: "var(--primary-color)",
                  borderRadius: "50%",
                  animation: "spin 0.8s linear infinite",
                }}
              />
              <div style={{ fontWeight: 600, fontSize: "0.9rem", color: "var(--text-main)" }}>
                Executando Análise de Curadoria e Parecer Técnico com IA...
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", textAlign: "center", maxWidth: "480px" }}>
                Validando sintaxe LogQL, mapeando campos para o schema Wazuh (| json), aferindo telemetria no Loki dos clientes e sintetizando parecer técnico SOC.
              </div>
            </div>
          )}

          {/* Painel Completo de Resultados de Curadoria */}
          {previewResult && !previewResult.general_error && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {/* Dashboard de Métricas da Curadoria */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: "10px",
                }}
              >
                {/* Total Analisadas */}
                <div
                  style={{
                    backgroundColor: "rgba(30, 41, 59, 0.6)",
                    border: "1px solid var(--border-color)",
                    borderRadius: "6px",
                    padding: "10px 12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "2px",
                  }}
                >
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", textTransform: "uppercase" }}>
                    Total Analisadas
                  </span>
                  <span style={{ fontSize: "1.3rem", fontWeight: 700, color: "var(--text-main)" }}>
                    {previewResult.total_rules}
                  </span>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    {uploadedFiles.length > 0 ? `${uploadedFiles.length} arquivo(s)` : "Entrada manual"}
                  </span>
                </div>

                {/* Qualificadas (>= 80%) */}
                <div
                  style={{
                    backgroundColor: "rgba(14, 165, 233, 0.08)",
                    border: "1px solid rgba(14, 165, 233, 0.3)",
                    borderRadius: "6px",
                    padding: "10px 12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "2px",
                  }}
                >
                  <span style={{ fontSize: "0.75rem", color: "#38bdf8", textTransform: "uppercase", fontWeight: 600 }}>
                    Aptas ao SIEM (≥ 80%)
                  </span>
                  <span style={{ fontSize: "1.3rem", fontWeight: 700, color: "#38bdf8" }}>
                    {previewResult.qualified_count ?? qualifiedRules.length}
                  </span>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Aderência comprovada
                  </span>
                </div>

                {/* Alta Compatibilidade (>= 95%) */}
                <div
                  style={{
                    backgroundColor: "rgba(16, 185, 129, 0.08)",
                    border: "1px solid rgba(16, 185, 129, 0.3)",
                    borderRadius: "6px",
                    padding: "10px 12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "2px",
                  }}
                >
                  <span style={{ fontSize: "0.75rem", color: "#34d399", textTransform: "uppercase", fontWeight: 600 }}>
                    Alta Compatibilidade (≥ 95%)
                  </span>
                  <span style={{ fontSize: "1.3rem", fontWeight: 700, color: "#34d399" }}>
                    {previewResult.high_compatibility_count ?? highCompatRules.length}
                  </span>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Telemetria plena
                  </span>
                </div>

                {/* Incompatíveis (< 80%) ou Inválidas */}
                <div
                  style={{
                    backgroundColor: "rgba(244, 63, 94, 0.08)",
                    border: "1px solid rgba(244, 63, 94, 0.3)",
                    borderRadius: "6px",
                    padding: "10px 12px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "2px",
                  }}
                >
                  <span style={{ fontSize: "0.75rem", color: "#fb7185", textTransform: "uppercase", fontWeight: 600 }}>
                    Incompatíveis (&lt; 80%)
                  </span>
                  <span style={{ fontSize: "1.3rem", fontWeight: 700, color: "#fb7185" }}>
                    {previewResult.discarded_count ?? incompatibleRules.length}
                  </span>
                  <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                    Telemetria ou schema ausente
                  </span>
                </div>
              </div>

              {/* Barra de Filtros e Controles de Expansão */}
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: "8px",
                  padding: "6px 10px",
                  backgroundColor: "var(--bg-input)",
                  borderRadius: "6px",
                }}
              >
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  <button
                    type="button"
                    onClick={() => setFilterTab("all")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      border: "none",
                      fontSize: "0.78rem",
                      fontWeight: 600,
                      cursor: "pointer",
                      backgroundColor: filterTab === "all" ? "var(--primary-color)" : "transparent",
                      color: filterTab === "all" ? "#fff" : "var(--text-muted)",
                    }}
                  >
                    Todas ({previewResult.total_rules})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilterTab("qualified")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      border: "none",
                      fontSize: "0.78rem",
                      fontWeight: 600,
                      cursor: "pointer",
                      backgroundColor: filterTab === "qualified" ? "rgba(14, 165, 233, 0.25)" : "transparent",
                      color: filterTab === "qualified" ? "#38bdf8" : "var(--text-muted)",
                    }}
                  >
                    Qualificadas ({previewResult.qualified_count ?? qualifiedRules.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilterTab("high")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      border: "none",
                      fontSize: "0.78rem",
                      fontWeight: 600,
                      cursor: "pointer",
                      backgroundColor: filterTab === "high" ? "rgba(16, 185, 129, 0.25)" : "transparent",
                      color: filterTab === "high" ? "#34d399" : "var(--text-muted)",
                    }}
                  >
                    Alta Compatibilidade ({previewResult.high_compatibility_count ?? highCompatRules.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilterTab("incompatible")}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "4px",
                      border: "none",
                      fontSize: "0.78rem",
                      fontWeight: 600,
                      cursor: "pointer",
                      backgroundColor: filterTab === "incompatible" ? "rgba(244, 63, 94, 0.25)" : "transparent",
                      color: filterTab === "incompatible" ? "#fb7185" : "var(--text-muted)",
                    }}
                  >
                    Incompatíveis ({previewResult.discarded_count ?? incompatibleRules.length})
                  </button>
                </div>

                <div style={{ display: "flex", gap: "6px" }}>
                  <button
                    type="button"
                    onClick={() => expandAll(previewResult.items)}
                    style={{
                      background: "none",
                      border: "1px solid var(--border-color)",
                      color: "var(--text-muted)",
                      borderRadius: "4px",
                      padding: "2px 8px",
                      fontSize: "0.74rem",
                      cursor: "pointer",
                    }}
                  >
                    Expandir Todos
                  </button>
                  <button
                    type="button"
                    onClick={collapseAll}
                    style={{
                      background: "none",
                      border: "1px solid var(--border-color)",
                      color: "var(--text-muted)",
                      borderRadius: "4px",
                      padding: "2px 8px",
                      fontSize: "0.74rem",
                      cursor: "pointer",
                    }}
                  >
                    Recolher
                  </button>
                </div>
              </div>

              {/* Lista de Regras com Parecer Técnico e Compatibilidade de Campos */}
              <div
                id="rules-preview-list-container"
                data-testid="rules-preview-list"
                style={{
                  maxHeight: "440px",
                  overflowY: "auto",
                  display: "flex",
                  flexDirection: "column",
                  gap: "12px",
                  paddingRight: "4px",
                }}
              >
                {filteredItems.length === 0 ? (
                  <div
                    style={{
                      textAlign: "center",
                      padding: "24px",
                      color: "var(--text-muted)",
                      fontSize: "0.85rem",
                    }}
                  >
                    Nenhuma regra corresponde ao filtro selecionado ({filterTab}).
                  </div>
                ) : (
                  filteredItems.map((item: RuleImportItemValidation) => {
                    const isItemInvalid = item.errors.length > 0;
                    const isItemTechMissing = item.technology_missing;
                    const compatMeta = getCompatibilityMeta(item);
                    const isExpanded = expandedIndices.has(item.index);
                    const hasCuration = Boolean(item.ai_rationale || (item.mapped_fields && item.mapped_fields.length > 0));

                    return (
                      <div
                        key={item.index}
                        style={{
                          border: `1px solid ${
                            isItemInvalid
                              ? "rgba(239, 68, 68, 0.6)"
                              : isItemTechMissing
                              ? "rgba(234, 179, 8, 0.6)"
                              : compatMeta.border
                          }`,
                          borderRadius: "8px",
                          padding: "12px 14px",
                          backgroundColor: isItemInvalid
                            ? "rgba(239, 68, 68, 0.05)"
                            : isItemTechMissing
                            ? "rgba(234, 179, 8, 0.05)"
                            : "rgba(15, 23, 42, 0.4)",
                          display: "flex",
                          flexDirection: "column",
                          gap: "8px",
                        }}
                      >
                        {/* Linha Superior: Título, Badges e Botão de Ação */}
                        <div
                          style={{
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "flex-start",
                            gap: "10px",
                          }}
                        >
                          <div style={{ flex: 1 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                              <span style={{ fontWeight: 600, fontSize: "0.94rem", color: "var(--text-main)" }}>
                                {item.title}
                              </span>
                              {/* Badge de Compatibilidade Dinâmica */}
                              <span
                                style={{
                                  backgroundColor: compatMeta.bg,
                                  color: compatMeta.color,
                                  border: compatMeta.border,
                                  borderRadius: "4px",
                                  padding: "2px 8px",
                                  fontSize: "0.75rem",
                                  fontWeight: 600,
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "4px",
                                }}
                              >
                                <span>{compatMeta.icon === "verified" ? "★" : compatMeta.icon === "check_circle" ? "✓" : "⚠"}</span>
                                <span>{compatMeta.label}</span>
                              </span>
                            </div>

                            {item.description && (
                              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "4px" }}>
                                {item.description}
                              </div>
                            )}
                          </div>

                          {/* Ações e Status */}
                          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
                            {isItemTechMissing && (
                              <button
                                type="button"
                                className="btn btn-sm btn-secondary"
                                onClick={() => handleOpenCreateTech(item)}
                                style={{
                                  fontSize: "0.78rem",
                                  padding: "3px 8px",
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "4px",
                                  backgroundColor: "rgba(234, 179, 8, 0.15)",
                                  borderColor: "rgba(234, 179, 8, 0.4)",
                                  color: "#fbbf24",
                                }}
                                title="Cadastrar esta tecnologia no catálogo para liberar a importação"
                              >
                                <span>➕ Criar Tecnologia</span>
                              </button>
                            )}

                            <span
                              className="badge"
                              style={{
                                backgroundColor: isItemInvalid
                                  ? "rgba(239, 68, 68, 0.2)"
                                  : isItemTechMissing
                                  ? "rgba(234, 179, 8, 0.2)"
                                  : "rgba(34, 197, 94, 0.2)",
                                color: isItemInvalid
                                  ? "#ef4444"
                                  : isItemTechMissing
                                  ? "#fbbf24"
                                  : "#22c55e",
                                borderColor: isItemInvalid
                                  ? "rgba(239, 68, 68, 0.4)"
                                  : isItemTechMissing
                                  ? "rgba(234, 179, 8, 0.4)"
                                  : "rgba(34, 197, 94, 0.4)",
                                fontWeight: 600,
                              }}
                            >
                              {isItemInvalid
                                ? "✕ Inválida"
                                : isItemTechMissing
                                ? "⚠ Sem Tecnologia"
                                : "✓ Válida"}
                            </span>

                            {hasCuration && (
                              <button
                                type="button"
                                onClick={() => toggleExpand(item.index)}
                                style={{
                                  backgroundColor: isExpanded ? "rgba(99, 102, 241, 0.25)" : "rgba(30, 41, 59, 0.8)",
                                  border: "1px solid rgba(99, 102, 241, 0.4)",
                                  color: isExpanded ? "#a5b4fc" : "#c7d2fe",
                                  borderRadius: "4px",
                                  padding: "3px 9px",
                                  fontSize: "0.76rem",
                                  cursor: "pointer",
                                  display: "inline-flex",
                                  alignItems: "center",
                                  gap: "4px",
                                  fontWeight: 500,
                                }}
                              >
                                <span>✦</span>
                                <span>{isExpanded ? "Recolher Parecer" : "Ver Parecer & Compatibilidade"}</span>
                              </button>
                            )}
                          </div>
                        </div>

                        {/* Badges de Metadados Principais */}
                        <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                          {item.filename && (
                            <span
                              className="badge badge-tag"
                              style={{
                                backgroundColor: "rgba(99, 102, 241, 0.15)",
                                color: "#a5b4fc",
                                borderColor: "rgba(99, 102, 241, 0.3)",
                              }}
                            >
                              📄 {item.filename}
                            </span>
                          )}
                          {item.technology_name && (
                            <span className="badge badge-tag">
                              Tecnologia: {item.technology_name}
                            </span>
                          )}
                          {item.severity && (
                            <span className="badge badge-tag">
                              Severidade: {item.severity.toUpperCase()}
                            </span>
                          )}
                          {item.mitre_tactic && (
                            <span className="badge badge-tag">
                              Tática: {item.mitre_tactic}
                            </span>
                          )}
                          {item.mitre_technique && (
                            <span className="badge badge-tag">
                              Técnica: {item.mitre_technique}
                            </span>
                          )}
                          {item.already_exists && (
                            <span
                              className="badge"
                              style={{
                                backgroundColor: "rgba(234, 179, 8, 0.2)",
                                color: "#eab308",
                                borderColor: "rgba(234, 179, 8, 0.4)",
                              }}
                            >
                              Já no Baseline
                            </span>
                          )}
                        </div>

                        {/* Aviso: Tecnologia Ausente */}
                        {isItemTechMissing && (
                          <div
                            style={{
                              backgroundColor: "rgba(234, 179, 8, 0.1)",
                              border: "1px solid rgba(234, 179, 8, 0.25)",
                              borderRadius: "4px",
                              padding: "6px 10px",
                              fontSize: "0.82rem",
                              color: "#fbbf24",
                              lineHeight: "1.4",
                            }}
                          >
                            A regra está correta, mas a tecnologia{" "}
                            <strong>{item.suggested_technology_name || item.suggested_technology_slug}</strong>{" "}
                            ({item.suggested_technology_slug}) ainda não existe no catálogo. Clique em &quot;Criar Tecnologia&quot; ao lado para cadastrá-la.
                          </div>
                        )}

                        {/* Alerta de Incompatibilidade de Telemetria */}
                        {!isItemInvalid && (item.field_compatibility_pct ?? 100) < 80 && (
                          <div
                            style={{
                              backgroundColor: "rgba(244, 63, 94, 0.12)",
                              border: "1px solid rgba(244, 63, 94, 0.3)",
                              borderRadius: "4px",
                              padding: "8px 10px",
                              fontSize: "0.82rem",
                              color: "#fca5a5",
                              lineHeight: "1.4",
                            }}
                          >
                            <strong>Alerta de Incompatibilidade ({item.field_compatibility_pct?.toFixed(0)}% &lt; 80%):</strong>{" "}
                            {item.classification_reason || "Esta regra não atingiu o limiar de 80% de aderência de campos ou telemetria necessária nos clientes avaliados."}
                          </div>
                        )}

                        {/* Exibição de Erros Impeditivos */}
                        {item.errors.length > 0 && (
                          <div
                            style={{
                              backgroundColor: "rgba(239, 68, 68, 0.15)",
                              border: "1px solid rgba(239, 68, 68, 0.3)",
                              borderRadius: "4px",
                              padding: "8px 10px",
                              fontSize: "0.82rem",
                              color: "#fca5a5",
                            }}
                          >
                            <div style={{ fontWeight: 600, marginBottom: "2px" }}>
                              Erros impeditivos de importação:
                            </div>
                            <ul style={{ margin: 0, paddingLeft: "18px" }}>
                              {item.errors.map((err, errIdx) => (
                                <li key={errIdx}>{err}</li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Painel Expandido de Curadoria, Parecer IA e Campos Mapeados */}
                        {isExpanded && (
                          <div
                            style={{
                              marginTop: "6px",
                              padding: "12px",
                              backgroundColor: "rgba(10, 15, 30, 0.8)",
                              borderRadius: "6px",
                              border: "1px solid rgba(99, 102, 241, 0.25)",
                              display: "flex",
                              flexDirection: "column",
                              gap: "12px",
                            }}
                          >
                            {/* Bloco 1: Parecer Técnico da IA */}
                            {item.ai_rationale && (
                              <div
                                style={{
                                  backgroundColor: "rgba(88, 28, 135, 0.18)",
                                  border: "1px solid rgba(168, 85, 247, 0.35)",
                                  borderRadius: "6px",
                                  padding: "10px 12px",
                                }}
                              >
                                <div
                                  style={{
                                    display: "flex",
                                    alignItems: "center",
                                    gap: "6px",
                                    color: "#d8b4fe",
                                    fontSize: "0.78rem",
                                    fontWeight: 700,
                                    textTransform: "uppercase",
                                    letterSpacing: "0.5px",
                                    marginBottom: "6px",
                                  }}
                                >
                                  <span>✦</span>
                                  <span>
                                    Parecer Técnico da IA — Contexto de Ameaça e Diretrizes SOC{" "}
                                    {item.ai_model ? `(${item.ai_model})` : ""}
                                  </span>
                                </div>
                                <div
                                  style={{
                                    fontSize: "0.82rem",
                                    color: "#f3e8ff",
                                    lineHeight: "1.55",
                                    whiteSpace: "pre-line",
                                  }}
                                >
                                  {item.ai_rationale}
                                </div>
                              </div>
                            )}

                            {/* Bloco 2: Composição Dinâmica dos 3 Eixos */}
                            <div
                              style={{
                                backgroundColor: "rgba(15, 23, 42, 0.6)",
                                border: "1px solid var(--border-color)",
                                borderRadius: "6px",
                                padding: "10px",
                              }}
                            >
                              <div
                                style={{
                                  fontSize: "0.76rem",
                                  color: "var(--text-muted)",
                                  fontWeight: 700,
                                  textTransform: "uppercase",
                                  marginBottom: "8px",
                                }}
                              >
                                Composição dos 3 Eixos da Compatibilidade Dinâmica (Base 80.0%)
                              </div>
                              <div
                                style={{
                                  display: "grid",
                                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                                  gap: "8px",
                                  fontSize: "0.78rem",
                                }}
                              >
                                {/* Eixo 1 */}
                                <div
                                  style={{
                                    backgroundColor: "rgba(2, 132, 199, 0.08)",
                                    border: "1px solid rgba(2, 132, 199, 0.25)",
                                    borderRadius: "4px",
                                    padding: "6px 8px",
                                  }}
                                >
                                  <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600, color: "#38bdf8" }}>
                                    <span>1. Presença de Logs</span>
                                    <span>+{(item.log_presence_score ?? 0).toFixed(1)} pts</span>
                                  </div>
                                  <div style={{ color: "var(--text-muted)", fontSize: "0.73rem", marginTop: "2px" }}>
                                    Volume de telemetria ({item.total_tech_logs_seen ?? 0} logs observados) nas janelas progressivas.
                                  </div>
                                </div>

                                {/* Eixo 2 */}
                                <div
                                  style={{
                                    backgroundColor: "rgba(245, 158, 11, 0.08)",
                                    border: "1px solid rgba(245, 158, 11, 0.25)",
                                    borderRadius: "4px",
                                    padding: "6px 8px",
                                  }}
                                >
                                  <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600, color: "#fbbf24" }}>
                                    <span>2. Contexto de Ameaça</span>
                                    <span>+{(item.threat_context_score ?? 0).toFixed(1)} pts</span>
                                  </div>
                                  <div style={{ color: "var(--text-muted)", fontSize: "0.73rem", marginTop: "2px" }}>
                                    Severidade {item.severity.toUpperCase()} e técnica {item.mitre_technique || "—"} no MITRE ATT&amp;CK.
                                  </div>
                                </div>

                                {/* Eixo 3 */}
                                <div
                                  style={{
                                    backgroundColor: "rgba(16, 185, 129, 0.08)",
                                    border: "1px solid rgba(16, 185, 129, 0.25)",
                                    borderRadius: "4px",
                                    padding: "6px 8px",
                                  }}
                                >
                                  <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 600, color: "#34d399" }}>
                                    <span>3. Correspondência Cenário</span>
                                    <span>+{(item.scenario_match_score ?? 0).toFixed(1)} pts</span>
                                  </div>
                                  <div style={{ color: "var(--text-muted)", fontSize: "0.73rem", marginTop: "2px" }}>
                                    {(item.observed_field_compatibility_pct ?? 100).toFixed(0)}% dos campos encontrados no schema Wazuh.
                                  </div>
                                </div>
                              </div>
                            </div>

                            {/* Bloco 3: Aderência dos Campos Mapeados (Schema Wazuh / Clientes) */}
                            {item.mapped_fields && item.mapped_fields.length > 0 && (
                              <div>
                                <div
                                  style={{
                                    fontSize: "0.76rem",
                                    color: "var(--text-muted)",
                                    fontWeight: 700,
                                    textTransform: "uppercase",
                                    marginBottom: "6px",
                                  }}
                                >
                                  Campos Mapeados para o Schema Wazuh (| json) ({item.mapped_fields.length})
                                </div>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                                  {item.mapped_fields.map((mf, mfIdx) => {
                                    const isObs = item.observed_fields_in_logs?.includes(mf.logql_field);
                                    return (
                                      <div
                                        key={mfIdx}
                                        style={{
                                          display: "inline-flex",
                                          alignItems: "center",
                                          gap: "6px",
                                          backgroundColor: "rgba(15, 23, 42, 0.7)",
                                          border: `1px solid ${
                                            !mf.compatible
                                              ? "rgba(239, 68, 68, 0.4)"
                                              : isObs
                                              ? "rgba(16, 185, 129, 0.4)"
                                              : "rgba(14, 165, 233, 0.3)"
                                          }`,
                                          borderRadius: "4px",
                                          padding: "3px 8px",
                                          fontSize: "0.76rem",
                                          fontFamily: "var(--font-mono)",
                                        }}
                                      >
                                        <span style={{ color: "var(--text-muted)" }}>{mf.original_field} →</span>
                                        <span style={{ color: mf.compatible ? "#38bdf8" : "#fca5a5", fontWeight: 600 }}>
                                          {mf.logql_field}
                                        </span>
                                        <span
                                          style={{
                                            fontSize: "0.68rem",
                                            padding: "1px 4px",
                                            borderRadius: "3px",
                                            backgroundColor: mf.compatible
                                              ? isObs
                                                ? "rgba(16, 185, 129, 0.2)"
                                                : "rgba(14, 165, 233, 0.2)"
                                              : "rgba(239, 68, 68, 0.2)",
                                            color: mf.compatible
                                              ? isObs
                                                ? "#34d399"
                                                : "#7dd3fc"
                                              : "#f87171",
                                          }}
                                        >
                                          {!mf.compatible
                                            ? "Incompatível"
                                            : isObs
                                            ? "Confirmado em logs"
                                            : "Schema OK"}
                                        </span>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}

                            {/* Bloco 4: Avaliação por Ambiente de Cliente */}
                            {item.client_evaluations && item.client_evaluations.length > 0 && (
                              <div>
                                <div
                                  style={{
                                    fontSize: "0.76rem",
                                    color: "var(--text-muted)",
                                    fontWeight: 700,
                                    textTransform: "uppercase",
                                    marginBottom: "6px",
                                  }}
                                >
                                  Avaliação nos Ambientes de Clientes ({item.client_evaluations.length})
                                </div>
                                <div
                                  style={{
                                    display: "flex",
                                    flexDirection: "column",
                                    gap: "4px",
                                    maxHeight: "120px",
                                    overflowY: "auto",
                                  }}
                                >
                                  {item.client_evaluations.map((ev) => {
                                    const evCompat = ev.field_compatibility_pct ?? 100;
                                    const isEvGood = evCompat >= 80;
                                    return (
                                      <div
                                        key={ev.client_uid}
                                        style={{
                                          display: "flex",
                                          justifyContent: "space-between",
                                          alignItems: "center",
                                          backgroundColor: "rgba(15, 23, 42, 0.5)",
                                          border: "1px solid var(--border-color)",
                                          borderRadius: "4px",
                                          padding: "4px 8px",
                                          fontSize: "0.78rem",
                                        }}
                                      >
                                        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                                          <span style={{ fontWeight: 600, color: "var(--text-main)" }}>
                                            {ev.client_name}
                                          </span>
                                          <span style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>
                                            ({ev.tech_logs_count} logs da tecnologia)
                                          </span>
                                        </div>
                                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                          <span style={{ color: "var(--text-muted)", fontSize: "0.72rem" }}>
                                            {ev.reason}
                                          </span>
                                          <span
                                            style={{
                                              color: isEvGood ? "#34d399" : "#fb7185",
                                              fontWeight: 700,
                                              fontSize: "0.76rem",
                                            }}
                                          >
                                            {evCompat.toFixed(1)}%
                                          </span>
                                        </div>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}

                            {/* Bloco 5: Expressão LogQL Completa */}
                            {item.query && (
                              <div>
                                <div
                                  style={{
                                    fontSize: "0.74rem",
                                    color: "var(--text-muted)",
                                    fontWeight: 700,
                                    textTransform: "uppercase",
                                    marginBottom: "4px",
                                  }}
                                >
                                  Expressão LogQL
                                </div>
                                <div
                                  style={{
                                    fontSize: "0.76rem",
                                    fontFamily: "var(--font-mono)",
                                    backgroundColor: "rgba(2, 6, 23, 0.8)",
                                    border: "1px solid var(--border-color)",
                                    padding: "6px 8px",
                                    borderRadius: "4px",
                                    color: "var(--text-main)",
                                    wordBreak: "break-all",
                                  }}
                                >
                                  {item.query}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {/* Rodapé do Modal */}
          <div
            className="modal-footer"
            style={{
              padding: "14px 0 0 0",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "10px",
            }}
          >
            {/* Opção de Importar Apenas Qualificadas */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              {Boolean(previewResult && previewResult.discarded_count && previewResult.discarded_count > 0 && qualifiedRules.length > 0) && (
                <label
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    fontSize: "0.82rem",
                    color: "#38bdf8",
                    cursor: "pointer",
                  }}
                >
                  <input
                    type="checkbox"
                    checked={importOnlyQualified}
                    onChange={(e) => setImportOnlyQualified(e.target.checked)}
                  />
                  <span>Importar apenas regras qualificadas (≥ 80%)</span>
                </label>
              )}
            </div>

            <div style={{ display: "flex", gap: "10px" }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={handleClose}
                disabled={isImporting}
              >
                Cancelar
              </button>

              <button
                type="button"
                className="btn btn-primary"
                onClick={handleImport}
                disabled={
                  isImporting ||
                  isValidating ||
                  readingFiles ||
                  !previewResult ||
                  rulesToImport.length === 0
                }
              >
                {isImporting
                  ? "Importando regras..."
                  : isValidating
                  ? "Validando..."
                  : readingFiles
                  ? "Lendo arquivos..."
                  : previewResult && rulesToImport.length > 0
                  ? `Importar ${rulesToImport.length} Regra(s) ${
                      importOnlyQualified && qualifiedRules.length > 0 && qualifiedRules.length < validRules.length
                        ? "Qualificada(s)"
                        : "Válida(s)"
                    }`
                  : "Importar Regras"}
              </button>
            </div>
          </div>
        </div>
      </Modal>

      {/* Sub-Modal: Criação de Tecnologia para regras pendentes */}
      <Modal
        isOpen={isCreateTechOpen}
        onClose={() => setIsCreateTechOpen(false)}
        title="Criar Tecnologia a partir da Regra"
        maxWidth="580px"
      >
        <form onSubmit={handleSaveTechnology}>
          {techError && (
            <div className="alert-box" style={{ marginBottom: "12px" }}>
              {techError}
            </div>
          )}
          {techSuccessMsg && (
            <div
              className="alert-box"
              style={{
                marginBottom: "12px",
                backgroundColor: "rgba(34, 197, 94, 0.15)",
                color: "var(--status-normal)",
                borderColor: "rgba(34, 197, 94, 0.3)",
              }}
            >
              {techSuccessMsg}
            </div>
          )}

          <div
            style={{
              backgroundColor: "rgba(15, 23, 42, 0.5)",
              border: "1px solid var(--border-color)",
              borderRadius: "6px",
              padding: "10px 12px",
              fontSize: "0.83rem",
              color: "var(--text-muted)",
              marginBottom: "14px",
              lineHeight: "1.4",
            }}
          >
            Cadastre a tecnologia correspondente ao seletor da regra. Após salvar, o validador reavaliará as regras automaticamente.
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", marginBottom: "12px" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label" style={{ fontSize: "0.85rem" }}>
                Nome da Tecnologia *
              </label>
              <input
                className="input"
                value={techForm.name}
                onChange={(e) => setTechForm({ ...techForm, name: e.target.value })}
                placeholder="Ex.: Crowdstrike Falcon, PfSense"
                required
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label" style={{ fontSize: "0.85rem" }}>
                Slug *
              </label>
              <input
                className="input"
                value={techForm.slug}
                onChange={(e) => setTechForm({ ...techForm, slug: e.target.value })}
                placeholder="ex.: crowdstrike_falcon"
                required
              />
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "12px", marginBottom: "12px" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label" style={{ fontSize: "0.85rem" }}>
                Grupo de Regras Wazuh (rule_groups regex) *
              </label>
              <input
                className="input"
                value={techForm.rule_groups_regex}
                onChange={(e) => setTechForm({ ...techForm, rule_groups_regex: e.target.value })}
                placeholder="ex.: .*crowdstrike.*"
                required
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label" style={{ fontSize: "0.85rem" }}>
                Label job
              </label>
              <input
                className="input"
                value={techForm.job || "wazuh"}
                onChange={(e) => setTechForm({ ...techForm, job: e.target.value })}
                required
              />
            </div>
          </div>

          <div className="form-group" style={{ marginBottom: "14px" }}>
            <label className="form-label" style={{ fontSize: "0.85rem" }}>
              Descrição
            </label>
            <textarea
              className="textarea"
              rows={2}
              value={techForm.description || ""}
              onChange={(e) => setTechForm({ ...techForm, description: e.target.value })}
              placeholder="Descrição ou fontes de telemetria desta tecnologia."
            />
          </div>

          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontSize: "0.82rem",
              color: "var(--text-muted)",
              marginBottom: 16,
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={techForm.confirm_without_logs ?? true}
              onChange={(e) => setTechForm({ ...techForm, confirm_without_logs: e.target.checked })}
            />
            Confirmar cadastro mesmo que ainda não existam logs no Loki para esta tecnologia
          </label>

          <div
            className="modal-footer"
            style={{
              padding: "10px 0 0 0",
              display: "flex",
              justifyContent: "flex-end",
              gap: "10px",
            }}
          >
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setIsCreateTechOpen(false)}
              disabled={savingTech}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="btn btn-primary"
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
