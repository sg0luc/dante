import React, { useState, useRef, useEffect, useCallback } from "react";
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
    }
  }, [isOpen, loadInitialData]);

  const handleOpenCreateTech = (item: RuleImportItemValidation) => {
    const slug = (item.suggested_technology_slug || "").trim();
    const name =
      (item.suggested_technology_name || "").trim() ||
      slug.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()) ||
      "Nova Tecnologia";
    const regex = (item.suggested_rule_groups_regex || item.suggested_rule_groups_regex || "").trim() || `.*${slug}.*`;

    setTechForm({
      slug,
      name,
      rule_groups_regex: regex,
      job: "wazuh",
      description: item.description || `Tecnologia importada para regra de detecção: ${item.title}`,
      confirm_without_logs: true,
    });
    setTechError(null);
    setTechSuccessMsg(null);
    setIsCreateTechOpen(true);
  };

  const handleSaveTechnology = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!techForm.slug || !techForm.name || !techForm.rule_groups_regex) {
      setTechError("Preencha todos os campos obrigatórios (Nome, Slug e Recorte).");
      return;
    }

    setSavingTech(true);
    setTechError(null);
    setTechSuccessMsg(null);

    try {
      await api.createTechnology(techForm);
      setTechSuccessMsg(`Tecnologia "${techForm.name}" cadastrada com sucesso! Revalidando regras...`);

      setTimeout(async () => {
        setIsCreateTechOpen(false);
        setTechSuccessMsg(null);

        // Revalidação automática imediata para transformar regras amarelas em verdes
        if (uploadedFiles.length > 0) {
          await runValidationForFiles(uploadedFiles);
        } else if (jsonContent.trim()) {
          await runValidationForManualText(jsonContent);
        }
      }, 700);
    } catch (err: any) {
      setTechError(err.message || "Erro ao criar tecnologia no catálogo.");
    } finally {
      setSavingTech(false);
    }
  };

  const processFiles = async (files: File[]) => {
    const supportedFiles = files.filter((f) => {
      const lower = f.name.toLowerCase();
      return lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".json");
    });

    if (supportedFiles.length === 0) {
      setErrorMsg("Nenhum arquivo válido (.yaml, .yml ou .json) foi selecionado.");
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
            reader.onerror = () => {
              reject(new Error(`Falha ao ler o arquivo ${file.name}`));
            };
            reader.readAsText(file);
          })
      );

      const loaded = await Promise.all(readPromises);
      setUploadedFiles(loaded);

      if (loaded.length === 1) {
        setJsonContent(loaded[0].content);
      } else {
        setJsonContent("");
      }

      // Validação automática executada imediatamente após a leitura dos arquivos
      await runValidationForFiles(loaded);
    } catch (err: any) {
      setErrorMsg(err.message || "Erro ao ler os arquivos selecionados.");
    } finally {
      setReadingFiles(false);
    }
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (files.length === 0) return;
    processFiles(files);
  };

  const handleDragEnter = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget.contains(e.relatedTarget as Node)) return;
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
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

  const handleImport = async () => {
    if (!previewResult || previewResult.valid_count === 0) return;

    // Filtra estritamente as regras válidas, sem erros e que não estejam com tecnologia pendente
    const validRules = previewResult.items.filter(
      (item) => item.valid && item.errors.length === 0 && !item.technology_missing
    );
    if (validRules.length === 0) {
      setErrorMsg("Nenhuma regra válida para importação.");
      return;
    }

    setIsImporting(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await api.executeImportRules(
        validRules,
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
      maxWidth="860px"
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
            Diretrizes de Governança e Segurança:
          </div>
          <div>
            1. Formatos suportados: especificação <strong>Loki Ruler</strong> (YAML ou JSON) com suporte a múltiplos arquivos e múltiplos documentos.
          </div>
          <div>
            2. Todas as regras importadas são salvas na pasta <strong>Global (Baseline)</strong> apontadas para o <strong>data source Loki interno selecionado</strong>.
          </div>
          <div>
            3. Toda regra importada nasce no estágio de <strong>Homologação (Contact Point &apos;stg&apos;)</strong>.
          </div>
          <div>
            4. Regras com erros são bloqueadas. Regras sem tecnologia cadastrada ficam com aviso amarelo e podem ter sua tecnologia criada diretamente neste modal.
          </div>
        </div>

        {/* Destino das Regras: Data Source e Grupo de Avaliação */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "12px",
          }}
        >
          {/* Seletor de Data Source Loki de Destino */}
          <div
            style={{
              backgroundColor: "rgba(15, 23, 42, 0.6)",
              border: "1px solid var(--border-color)",
              borderRadius: "6px",
              padding: "12px 14px",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <label
                htmlFor="rule-import-datasource-select"
                style={{ fontWeight: 600, fontSize: "0.85rem", color: "var(--text-main)" }}
              >
                Data Source Loki de Destino:
              </label>
              <span
                className="badge badge-normal"
                style={{ fontSize: "0.72rem" }}
              >
                Apenas Internos
              </span>
            </div>

            <select
              id="rule-import-datasource-select"
              className="input"
              value={selectedDatasourceUid}
              onChange={(e) => setSelectedDatasourceUid(e.target.value)}
              disabled={isValidating || isImporting || datasourcesLoading}
              style={{ width: "100%", fontSize: "0.85rem" }}
            >
              {datasourcesLoading && <option value="">Carregando data sources...</option>}
              {!datasourcesLoading &&
                datasources.map((ds) => {
                  const isClient = !ds.is_internal;
                  return (
                    <option
                      key={ds.uid}
                      value={ds.uid}
                      disabled={isClient}
                      style={{
                        color: isClient ? "var(--text-muted)" : "inherit",
                      }}
                    >
                      {ds.name} ({ds.uid}) {ds.is_internal ? "— [Interno]" : "— [Cliente: Bloqueado]"}
                      {ds.is_default ? " ★ Padrão" : ""}
                    </option>
                  );
                })}
            </select>

            <div style={{ fontSize: "0.76rem", color: "var(--text-muted)" }}>
              Regras globais não podem apontar para clientes.
            </div>
          </div>

          {/* Seletor de Grupo de Avaliação (Evaluation Group / ruleGroup) */}
          <div
            style={{
              backgroundColor: "rgba(15, 23, 42, 0.6)",
              border: "1px solid var(--border-color)",
              borderRadius: "6px",
              padding: "12px 14px",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <label
                htmlFor="rule-import-eval-group-input"
                style={{ fontWeight: 600, fontSize: "0.85rem", color: "var(--text-main)" }}
              >
                Grupo de Avaliação (Evaluation Group):
              </label>
              <span
                className="badge badge-normal"
                style={{ fontSize: "0.72rem" }}
              >
                ruleGroup
              </span>
            </div>

            <input
              id="rule-import-eval-group-input"
              type="text"
              list="rule-import-eval-groups-datalist"
              className="input"
              value={selectedEvaluationGroup}
              onChange={(e) => setSelectedEvaluationGroup(e.target.value)}
              disabled={isValidating || isImporting || evalGroupsLoading}
              placeholder="global-detections"
              style={{ width: "100%", fontSize: "0.85rem" }}
              title="Grupo de avaliação (ruleGroup) no Grafana Alerting. Selecione ou digite um novo."
            />
            <datalist id="rule-import-eval-groups-datalist">
              {evaluationGroups.map((g) => (
                <option key={g} value={g} />
              ))}
            </datalist>

            <div style={{ fontSize: "0.76rem", color: "var(--text-muted)" }}>
              Padrão: <code>global-detections</code>. Selecione da lista ou digite.
            </div>
          </div>
        </div>

        {/* Mensagens de Feedback */}
        {errorMsg && <div className="alert-box">{errorMsg}</div>}
        {successMsg && (
          <div
            className="alert-box"
            style={{
              backgroundColor: "rgba(34, 197, 94, 0.15)",
              color: "var(--status-normal)",
              borderColor: "rgba(34, 197, 94, 0.3)",
            }}
          >
            {successMsg}
          </div>
        )}

        {/* Caixa de Upload com Drag and Drop para Múltiplos Arquivos */}
        <div
          onDragEnter={handleDragEnter}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          style={{
            border: isDragging
              ? "2px dashed var(--primary)"
              : "2px dashed var(--border-color)",
            borderRadius: "8px",
            padding: "24px 20px",
            textAlign: "center",
            backgroundColor: isDragging
              ? "rgba(59, 130, 246, 0.12)"
              : "rgba(15, 23, 42, 0.4)",
            transition: "all 0.2s ease-in-out",
          }}
        >
          <input
            type="file"
            accept=".json,.yaml,.yml,application/json,text/yaml,text/x-yaml"
            ref={fileInputRef}
            onChange={handleFileInputChange}
            multiple
            style={{ display: "none" }}
          />

          <div style={{ marginBottom: "12px" }}>
            <svg
              width="44"
              height="44"
              viewBox="0 0 24 24"
              fill="none"
              stroke={isDragging ? "var(--primary)" : "var(--text-muted)"}
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ margin: "0 auto", display: "block" }}
            >
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="17 8 12 3 7 8" />
              <line x1="12" y1="3" x2="12" y2="15" />
            </svg>
          </div>

          <div
            style={{
              fontSize: "0.95rem",
              fontWeight: 600,
              color: isDragging ? "var(--primary)" : "var(--text-main)",
              marginBottom: "4px",
            }}
          >
            {isDragging
              ? "Solte os arquivos YAML ou JSON aqui para leitura automática"
              : "Arraste e solte múltiplos arquivos YAML ou JSON aqui"}
          </div>

          <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginBottom: "14px" }}>
            A leitura e validação das regras ocorrem de forma automática assim que os arquivos são soltos
          </div>

          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => fileInputRef.current?.click()}
            disabled={isValidating || isImporting || readingFiles}
          >
            {uploadedFiles.length > 0
              ? "Adicionar / Trocar Arquivos (.yaml, .json)"
              : "Selecionar Arquivos do Computador"}
          </button>

          {/* Indicador de Leitura de Arquivos */}
          {readingFiles && (
            <div style={{ marginTop: "12px", fontSize: "0.85rem", color: "var(--primary)" }}>
              Lendo arquivos de forma automática...
            </div>
          )}

          {/* Lista de Arquivos Carregados */}
          {uploadedFiles.length > 0 && !readingFiles && (
            <div
              style={{
                marginTop: "16px",
                paddingTop: "14px",
                borderTop: "1px solid rgba(255, 255, 255, 0.08)",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: "8px",
              }}
            >
              <div
                style={{
                  fontSize: "0.82rem",
                  color: "var(--text-muted)",
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                }}
              >
                <span>
                  <strong>{uploadedFiles.length}</strong> arquivo(s) carregado(s):
                </span>
                <button
                  type="button"
                  className="btn btn-sm btn-secondary"
                  onClick={resetState}
                  style={{ fontSize: "0.75rem", padding: "1px 8px" }}
                  title="Remover todos os arquivos"
                >
                  Limpar lista
                </button>
              </div>

              <div
                style={{
                  display: "flex",
                  flexWrap: "wrap",
                  gap: "6px",
                  justifyContent: "center",
                  maxWidth: "100%",
                }}
              >
                {uploadedFiles.map((f, idx) => (
                  <span
                    key={idx}
                    className="badge badge-tag"
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "5px",
                      padding: "4px 8px",
                      fontSize: "0.78rem",
                      backgroundColor: "rgba(30, 41, 59, 0.85)",
                    }}
                  >
                    <span>📄 {f.filename}</span>
                    <span style={{ opacity: 0.6 }}>({formatFileSize(f.size)})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          <div style={{ marginTop: "14px" }}>
            <button
              type="button"
              className="btn btn-sm btn-secondary"
              onClick={() => setShowManualEditor(!showManualEditor)}
              style={{ fontSize: "0.8rem" }}
            >
              {showManualEditor ? "Ocultar editor manual" : "Colar ou editar YAML/JSON manualmente"}
            </button>
          </div>
        </div>

        {/* Editor manual de YAML / JSON */}
        {showManualEditor && (
          <div className="form-group" style={{ marginBottom: "0" }}>
            <label className="form-label" style={{ fontSize: "0.85rem" }}>
              Conteúdo YAML ou JSON da regra ou grupo de regras:
            </label>
            <textarea
              className="input"
              rows={8}
              value={jsonContent}
              onChange={(e) => {
                setJsonContent(e.target.value);
                setPreviewResult(null);
              }}
              placeholder={`groups:\n  - name: windows_baseline\n    rules:\n      - alert: AD_Privilege_Escalation\n        expr: sum(count_over_time({job="wazuh", rule_groups=~".*windows.*"} [5m])) > 0\n        labels:\n          severity: critical\n          mitre_tactic: persistence\n          mitre_technique: T1098`}
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: "0.82rem",
                width: "100%",
                resize: "vertical",
              }}
            />
            <div style={{ marginTop: "8px", display: "flex", justifyContent: "flex-end" }}>
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

        {/* Resumo da Validação */}
        {previewResult && !previewResult.general_error && (
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {/* Barra de Contagem */}
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "8px 12px",
                backgroundColor: "var(--bg-input)",
                borderRadius: "6px",
              }}
            >
              <span style={{ fontSize: "0.9rem", fontWeight: 600 }}>
                Resultado da Validação: {previewResult.total_rules} regra(s) encontrada(s)
                {uploadedFiles.length > 1 ? ` em ${uploadedFiles.length} arquivos` : ""}
              </span>
              <div style={{ display: "flex", gap: "8px" }}>
                <span className="badge badge-normal" style={{ fontSize: "0.8rem", padding: "4px 8px" }}>
                  Válidas: {previewResult.valid_count}
                </span>
                {Boolean(previewResult.missing_tech_count && previewResult.missing_tech_count > 0) && (
                  <span
                    className="badge"
                    style={{
                      fontSize: "0.8rem",
                      padding: "4px 8px",
                      backgroundColor: "rgba(234, 179, 8, 0.2)",
                      color: "#fbbf24",
                      border: "1px solid rgba(234, 179, 8, 0.4)",
                      fontWeight: 600,
                    }}
                  >
                    Sem Tecnologia: {previewResult.missing_tech_count}
                  </span>
                )}
                {previewResult.invalid_count > 0 && (
                  <span className="badge badge-firing" style={{ fontSize: "0.8rem", padding: "4px 8px" }}>
                    Inválidas: {previewResult.invalid_count}
                  </span>
                )}
              </div>
            </div>

            {previewResult.invalid_count > 0 && (
              <div
                style={{
                  fontSize: "0.83rem",
                  color: "var(--status-firing)",
                  padding: "4px 8px",
                }}
              >
                Atenção: Regras com erros estão destacadas em vermelho e <strong>não serão importadas</strong>.
              </div>
            )}

            {/* Lista de Regras Analisadas */}
            <div
              id="rules-preview-list-container"
              data-testid="rules-preview-list"
              style={{
                maxHeight: "360px",
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: "10px",
                paddingRight: "4px",
              }}
            >
              {previewResult.items.map((item: RuleImportItemValidation) => {
                const isItemInvalid = item.errors.length > 0;
                const isItemTechMissing = item.technology_missing;

                return (
                  <div
                    key={item.index}
                    style={{
                      border: `1px solid ${
                        isItemInvalid
                          ? "rgba(239, 68, 68, 0.6)"
                          : isItemTechMissing
                          ? "rgba(234, 179, 8, 0.6)"
                          : "rgba(34, 197, 94, 0.4)"
                      }`,
                      borderRadius: "6px",
                      padding: "10px 12px",
                      backgroundColor: isItemInvalid
                        ? "rgba(239, 68, 68, 0.06)"
                        : isItemTechMissing
                        ? "rgba(234, 179, 8, 0.06)"
                        : "rgba(34, 197, 94, 0.04)",
                    }}
                  >
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "flex-start",
                        gap: "10px",
                        marginBottom: "6px",
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: "0.92rem", color: "var(--text-main)" }}>
                          {item.title}
                        </div>
                        {item.description && (
                          <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "2px" }}>
                            {item.description}
                          </div>
                        )}
                      </div>

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
                            <span>➕</span>
                            <span>Criar Tecnologia</span>
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
                      </div>
                    </div>

                    {/* Badges de Metadados */}
                    <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginBottom: "6px" }}>
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
                          Severidade: {item.severity}
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

                    {/* Aviso Amarelo: Tecnologia não cadastrada */}
                    {isItemTechMissing && (
                      <div
                        style={{
                          backgroundColor: "rgba(234, 179, 8, 0.1)",
                          border: "1px solid rgba(234, 179, 8, 0.25)",
                          borderRadius: "4px",
                          padding: "6px 10px",
                          marginTop: "6px",
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

                    {/* Exibição de Erros */}
                    {item.errors.length > 0 && (
                      <div
                        style={{
                          backgroundColor: "rgba(239, 68, 68, 0.15)",
                          border: "1px solid rgba(239, 68, 68, 0.3)",
                          borderRadius: "4px",
                          padding: "8px 10px",
                          marginTop: "6px",
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

                    {/* Exibição da Query */}
                    {item.query && (
                      <div
                        style={{
                          marginTop: "6px",
                          fontSize: "0.78rem",
                          fontFamily: "var(--font-mono)",
                          backgroundColor: "var(--bg-input)",
                          padding: "4px 8px",
                          borderRadius: "4px",
                          color: "var(--text-muted)",
                          wordBreak: "break-all",
                        }}
                      >
                        LogQL: {item.query}
                      </div>
                    )}
                  </div>
                );
              })}
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
          }}
        >
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
              previewResult.valid_count === 0
            }
          >
            {isImporting
              ? "Importando regras..."
              : isValidating
              ? "Validando..."
              : readingFiles
              ? "Lendo arquivos..."
              : previewResult && previewResult.valid_count > 0
              ? `Importar ${previewResult.valid_count} Regra(s) Válida(s)`
              : "Importar Regras"}
          </button>
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
