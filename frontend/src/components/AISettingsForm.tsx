import React, { useEffect, useState } from "react";
import { api } from "../api";
import { AIProvider, AISettingsPublicResponse } from "../types";

export interface AISettingsFormProps {
  onSaved?: () => void;
  onCancel?: () => void;
}

export const AISettingsForm: React.FC<AISettingsFormProps> = ({
  onSaved,
  onCancel,
}) => {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [clearingCache, setClearingCache] = useState(false);
  const [settings, setSettings] = useState<AISettingsPublicResponse | null>(null);

  // Form fields
  const [selectedProvider, setSelectedProvider] = useState<AIProvider>("deepseek");
  const [selectedModel, setSelectedModel] = useState<string>("deepseek-chat");
  const [apiKeyInput, setApiKeyInput] = useState<string>("");
  const [baseUrlInput, setBaseUrlInput] = useState<string>("");
  const [analysisEnabled, setAnalysisEnabled] = useState<boolean>(true);
  const [curationEnabled, setCurationEnabled] = useState<boolean>(true);
  const [ruleImportAIEnabled, setRuleImportAIEnabled] = useState<boolean>(true);
  const [cacheEnabled, setCacheEnabled] = useState<boolean>(true);
  const [showKey, setShowKey] = useState<boolean>(false);

  // Feedback status
  const [feedback, setFeedback] = useState<{
    type: "success" | "error" | "info";
    message: string;
    latencyMs?: number;
  } | null>(null);

  const fetchSettings = async () => {
    setLoading(true);
    setFeedback(null);
    try {
      const data = await api.getAISettings();
      setSettings(data);
      setSelectedProvider(data.provider);
      setSelectedModel(data.model);
      setBaseUrlInput(data.api_base_url || "");
      setAnalysisEnabled(data.ai_analysis_enabled !== undefined ? data.ai_analysis_enabled : true);
      setCurationEnabled(data.curation_enabled !== undefined ? data.curation_enabled : data.enabled);
      setRuleImportAIEnabled(data.rule_import_ai_enabled !== undefined ? data.rule_import_ai_enabled : true);
      setCacheEnabled(data.cache_enabled);
      setApiKeyInput(""); // Preserva chave salva no servidor
    } catch (err: unknown) {
      setFeedback({
        type: "error",
        message:
          err instanceof Error
            ? err.message
            : "Falha ao carregar configurações de IA.",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const currentProviderInfo = settings?.available_providers.find(
    (p) => p.id === selectedProvider
  );

  const handleProviderChange = (providerId: AIProvider) => {
    setSelectedProvider(providerId);
    const prov = settings?.available_providers.find((p) => p.id === providerId);
    if (prov) {
      setSelectedModel(prov.default_model);
      if (providerId === "ollama") {
        setBaseUrlInput(prov.default_base_url || "http://host.docker.internal:11434/v1");
      } else {
        setBaseUrlInput("");
      }
    }
    setFeedback(null);
  };

  const handleTestConnection = async () => {
    setTesting(true);
    setFeedback(null);
    try {
      const res = await api.testAIConnection({
        provider: selectedProvider,
        model: selectedModel,
        api_key: apiKeyInput.trim() || undefined,
        api_base_url: baseUrlInput.trim() || undefined,
      });

      if (res.success) {
        setFeedback({
          type: "success",
          message: res.message,
          latencyMs: res.latency_ms,
        });
      } else {
        setFeedback({
          type: "error",
          message: res.message,
          latencyMs: res.latency_ms,
        });
      }
    } catch (err: unknown) {
      setFeedback({
        type: "error",
        message:
          err instanceof Error
            ? err.message
            : "Falha ao testar conexão com o modelo.",
      });
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setFeedback(null);

    try {
      const updated = await api.updateAISettings({
        provider: selectedProvider,
        model: selectedModel,
        api_key: apiKeyInput.trim() ? apiKeyInput.trim() : null,
        api_base_url: baseUrlInput.trim() ? baseUrlInput.trim() : null,
        temperature: 0.1,
        enabled: curationEnabled,
        ai_analysis_enabled: analysisEnabled,
        curation_enabled: curationEnabled,
        rule_import_ai_enabled: ruleImportAIEnabled,
        cache_enabled: cacheEnabled,
      });

      setSettings(updated);
      setApiKeyInput("");
      setFeedback({
        type: "success",
        message: "Configurações de IA e chaves de API salvas com sucesso!",
      });
      if (onSaved) onSaved();
    } catch (err: unknown) {
      setFeedback({
        type: "error",
        message:
          err instanceof Error
            ? err.message
            : "Erro ao salvar configurações de IA.",
      });
    } finally {
      setSaving(false);
    }
  };

  const handleClearCache = async () => {
    if (!window.confirm("Deseja realmente limpar o cache de regras de IA? Novas execuções farão requisições à API.")) {
      return;
    }
    setClearingCache(true);
    try {
      const res = await api.clearAICache();
      if (settings) {
        setSettings({ ...settings, cached_rules_count: 0 });
      }
      setFeedback({
        type: "info",
        message: res.message,
      });
    } catch (err: unknown) {
      setFeedback({
        type: "error",
        message: err instanceof Error ? err.message : "Erro ao limpar cache.",
      });
    } finally {
      setClearingCache(false);
    }
  };

  if (loading) {
    return (
      <div className="py-16 text-center text-slate-400">
        <span className="material-symbols-outlined animate-spin text-3xl text-sky-400">
          progress_activity
        </span>
        <p className="mt-2 text-sm font-body-sm">Carregando configurações de IA...</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSave} className="space-y-6 text-slate-200">
      {/* Banner de Garantia de Privacidade */}
      <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/20 p-4 flex items-start gap-3">
        <span className="material-symbols-outlined text-emerald-400 text-xl mt-0.5 shrink-0">
          verified_user
        </span>
        <div className="text-xs leading-relaxed text-emerald-200/90">
          <strong className="text-emerald-300 font-semibold block mb-0.5">
            Garantia Absoluta de Privacidade e Segurança
          </strong>
          Sob nenhuma hipótese os dados confidenciais ou logs de clientes no Loki são enviados para a IA.
          O modelo recebe apenas a especificação técnica da regra (Sigma/SPL/LogQL) e o catálogo de campos técnicos sanitizados.
        </div>
      </div>

      {/* Feedback de Status */}
      {feedback && (
        <div
          className={`rounded-xl p-3.5 text-xs flex items-center justify-between border ${
            feedback.type === "success"
              ? "bg-emerald-900/20 border-emerald-500/40 text-emerald-300"
              : feedback.type === "error"
              ? "bg-rose-900/20 border-rose-500/40 text-rose-300"
              : "bg-cyan-900/20 border-cyan-500/40 text-cyan-300"
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-sm">
              {feedback.type === "success" ? "check_circle" : feedback.type === "error" ? "error" : "info"}
            </span>
            <span>{feedback.message}</span>
          </div>
          {feedback.latencyMs !== undefined && (
            <span className="font-mono text-[11px] opacity-80 ml-2">
              Latência: {feedback.latencyMs}ms
            </span>
          )}
        </div>
      )}

      {/* Seleção de Provedor */}
      <div>
        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2.5">
          Provedor de Inteligência Artificial
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {(settings?.available_providers || []).map((p) => {
            const isSelected = selectedProvider === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => handleProviderChange(p.id)}
                className={`text-left p-3.5 rounded-xl border transition-all ${
                  isSelected
                    ? "border-sky-500 bg-sky-950/30 text-white shadow-sm ring-1 ring-sky-500/50"
                    : "border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700 hover:bg-slate-900"
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-semibold text-sm">{p.name}</span>
                  {p.badge && (
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                        p.id === "deepseek"
                          ? "bg-sky-500/20 text-sky-300 border border-sky-500/30"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {p.badge}
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 leading-tight line-clamp-2">
                  {p.description}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Modelo e URL Base (Alinhados na mesma linha) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-start">
        {/* Div Modelo */}
        <div>
          <div className="h-5 flex items-center mb-1.5">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Modelo
            </label>
          </div>
          {currentProviderInfo && currentProviderInfo.models.length > 0 ? (
            <select
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="w-full h-10 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
            >
              {currentProviderInfo.models.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.name}
                </option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              placeholder="Nome do modelo (ex: deepseek-chat)"
              className="w-full h-10 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-sky-500"
            />
          )}
          {currentProviderInfo?.models.find((m) => m.id === selectedModel)?.description && (
            <p
              className="text-[11px] text-slate-400 mt-1 truncate"
              title={currentProviderInfo.models.find((m) => m.id === selectedModel)?.description}
            >
              {currentProviderInfo.models.find((m) => m.id === selectedModel)?.description}
            </p>
          )}
        </div>

        {/* Div URL Base com truncamento para alinhar perfeitamente */}
        <div>
          <div className="h-5 flex items-center justify-between gap-2 mb-1.5 min-w-0">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-400 shrink-0">
              URL Base
            </label>
            {currentProviderInfo?.default_base_url && (
              <span
                className="text-[10px] text-slate-500 font-mono truncate max-w-[150px] sm:max-w-[180px]"
                title={`Padrão: ${currentProviderInfo.default_base_url}`}
              >
                Padrão: {currentProviderInfo.default_base_url}
              </span>
            )}
          </div>
          <input
            type="text"
            value={baseUrlInput}
            onChange={(e) => setBaseUrlInput(e.target.value)}
            placeholder={currentProviderInfo?.default_base_url || "https://api.deepseek.com"}
            className="w-full h-10 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono focus:outline-none focus:border-sky-500"
          />
        </div>
      </div>

      {/* Chave de API (BYOK) */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Chave de API ({currentProviderInfo?.name || selectedProvider})
          </label>
          {currentProviderInfo?.help_url && (
            <a
              href={currentProviderInfo.help_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1"
            >
              Obter chave no {currentProviderInfo.name}
              <span className="material-symbols-outlined text-[13px]">open_in_new</span>
            </a>
          )}
        </div>

        <div className="relative">
          <input
            type={showKey ? "text" : "password"}
            value={apiKeyInput}
            onChange={(e) => setApiKeyInput(e.target.value)}
            placeholder={
              settings?.is_configured && settings.provider === selectedProvider
                ? `Chave configurada: ${settings.masked_key} (digite para alterar)`
                : currentProviderInfo?.api_key_placeholder || "sk-..."
            }
            className="w-full h-10 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-200 font-mono pr-10 focus:outline-none focus:border-sky-500"
          />
          <button
            type="button"
            onClick={() => setShowKey(!showKey)}
            className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-200 text-sm"
            title={showKey ? "Ocultar" : "Mostrar"}
          >
            <span className="material-symbols-outlined text-lg">
              {showKey ? "visibility_off" : "visibility"}
            </span>
          </button>
        </div>
        {settings?.is_configured && settings.provider === selectedProvider && !apiKeyInput && (
          <p className="text-[11px] text-emerald-400/90 mt-1.5 flex items-center gap-1">
            <span className="material-symbols-outlined text-sm">lock</span>
            Chave persistida no servidor: <span className="font-mono">{settings.masked_key}</span>. Digite uma nova apenas se desejar substituir.
          </p>
        )}
      </div>

      {/* Opções de Ativação por Switches Liga/Desliga e Cache */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 space-y-4">
        {/* Switch 1: Análises e Recomendações por IA */}
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <span className="text-sm font-medium text-slate-200 block">
              Análises e Recomendações por IA
            </span>
            <p className="text-xs text-slate-400 mt-0.5">
              Gera pareceres técnicos automatizados, diagnósticos de telemetria em regras pausadas e recomendações preditivas de calibração via IA.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={analysisEnabled}
            onClick={() => setAnalysisEnabled(!analysisEnabled)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-sky-500/50 ${
              analysisEnabled ? "bg-sky-600" : "bg-slate-700"
            }`}
          >
            <span
              aria-hidden="true"
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                analysisEnabled ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>

        {/* Switch 2: Curadoria com IA */}
        <div className="border-t border-slate-800 pt-3.5 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <span className="text-sm font-medium text-slate-200 block">
              Curadoria com IA
            </span>
            <p className="text-xs text-slate-400 mt-0.5">
              Traduz regras Sigma/SPL e qualifica detecções cognitivamente utilizando o modelo de IA selecionado. Se desativado, utiliza o motor heurístico.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={curationEnabled}
            onClick={() => setCurationEnabled(!curationEnabled)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-sky-500/50 ${
              curationEnabled ? "bg-sky-600" : "bg-slate-700"
            }`}
          >
            <span
              aria-hidden="true"
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                curationEnabled ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>

        {/* Switch: Análise e Parecer por IA na Importação de Regras */}
        <div className="border-t border-slate-800 pt-3.5 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <span className="text-sm font-medium text-slate-200 block">
              Análise e Parecer por IA na Importação de Regras
            </span>
            <p className="text-xs text-slate-400 mt-0.5">
              Habilita a geração sob demanda do parecer técnico, contexto de ameaças e diretrizes SOC via IA no modal de importação de regras (botão com 3 estrelinhas).
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={ruleImportAIEnabled}
            onClick={() => setRuleImportAIEnabled(!ruleImportAIEnabled)}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-sky-500/50 ${
              ruleImportAIEnabled ? "bg-sky-600" : "bg-slate-700"
            }`}
          >
            <span
              aria-hidden="true"
              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                ruleImportAIEnabled ? "translate-x-5" : "translate-x-0"
              }`}
            />
          </button>
        </div>

        {/* Switch 3: Cache de Regras Traduzidas */}
        <div className="border-t border-slate-800 pt-3.5 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <span className="text-sm font-medium text-slate-200 block">
              Cache de Regras Traduzidas
            </span>
            <p className="text-xs text-slate-400 mt-0.5">
              Evita gastar tokens com regras já processadas anteriormente ({settings?.cached_rules_count || 0} regras em cache).
            </p>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={handleClearCache}
              disabled={clearingCache || (settings?.cached_rules_count || 0) === 0}
              className="text-xs text-rose-400 hover:text-rose-300 disabled:opacity-40 disabled:hover:text-rose-400 transition-colors"
            >
              {clearingCache ? "Limpando..." : "Limpar Cache"}
            </button>
            <button
              type="button"
              role="switch"
              aria-checked={cacheEnabled}
              onClick={() => setCacheEnabled(!cacheEnabled)}
              className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-sky-500/50 ${
                cacheEnabled ? "bg-sky-600" : "bg-slate-700"
              }`}
            >
              <span
                aria-hidden="true"
                className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                  cacheEnabled ? "translate-x-5" : "translate-x-0"
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Botões de Ação */}
      <div className="flex items-center justify-between pt-3 border-t border-slate-800">
        <button
          type="button"
          onClick={handleTestConnection}
          disabled={testing || saving}
          className="px-4 py-2 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-750 text-slate-200 text-xs font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
        >
          <span className={`material-symbols-outlined text-sm ${testing ? "animate-spin" : ""}`}>
            {testing ? "progress_activity" : "network_check"}
          </span>
          {testing ? "Testando Conexão..." : "Testar Conexão"}
        </button>

        <div className="flex items-center gap-2.5">
          {onCancel && (
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2 rounded-xl border border-slate-750 text-slate-300 hover:bg-slate-800 text-xs font-medium transition-colors"
            >
              Cancelar
            </button>
          )}
          <button
            type="submit"
            disabled={saving}
            className="px-5 py-2 rounded-xl bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold flex items-center gap-2 transition-colors disabled:opacity-50 shadow-sm"
          >
            <span className={`material-symbols-outlined text-sm ${saving ? "animate-spin" : ""}`}>
              {saving ? "progress_activity" : "save"}
            </span>
            {saving ? "Salvando..." : "Salvar Configuração"}
          </button>
        </div>
      </div>
    </form>
  );
};

