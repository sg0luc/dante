import React, { useEffect, useState, useRef } from "react";
import { api } from "../api";
import { BaselinePrefixSettings } from "../types";

export const BaselinePrefixPage: React.FC = () => {
  const [settings, setSettings] = useState<BaselinePrefixSettings>({
    enabled: true,
    template: "Baseline - ",
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [saveSuccess, setSaveSuccess] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Estados de simulação / preview
  const [sampleTitle, setSampleTitle] = useState<string>(
    "Tentativa de Força Bruta contra RDP"
  );
  const [sampleTechName, setSampleTechName] = useState<string>("AD/Windows");
  const [sampleTactic, setSampleTactic] = useState<string>("credential_access");
  const [sampleSeverity, setSampleSeverity] = useState<string>("high");
  const [sampleTenant, setSampleTenant] = useState<string>("Financeiro");

  const [previewBaseline, setPreviewBaseline] = useState<string>("");
  const [previewClient, setPreviewClient] = useState<string>("");

  const inputRef = useRef<HTMLInputElement>(null);

  // Carrega configurações persistidas
  useEffect(() => {
    let mounted = true;
    api
      .getBaselinePrefixSettings()
      .then((data) => {
        if (mounted) {
          setSettings(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (mounted) {
          setErrorMessage(
            err instanceof Error ? err.message : "Erro ao carregar configurações de prefixo."
          );
          setLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  // Atualiza previews em tempo real
  useEffect(() => {
    if (!settings.enabled) {
      setPreviewBaseline(sampleTitle);
      setPreviewClient(sampleTitle);
      return;
    }

    const template = settings.template || "";

    // Preview no Baseline Global
    api
      .previewBaselinePrefix({
        template,
        title: sampleTitle,
        technology: sampleTechName,
        technology_name: sampleTechName,
        tactic: sampleTactic,
        severity: sampleSeverity,
        tenant: null, // Global Baseline
      })
      .then((res) => setPreviewBaseline(res.preview_title))
      .catch(() => {});

    // Preview no Tenant do Cliente
    // Se o template contiver {{tenant}}, renderiza com o nome do cliente.
    // Caso contrário, salva exatamente como ela está (sem prefixo do cliente)
    if (template.toLowerCase().includes("{{tenant}}") || template.toLowerCase().includes("{tenant}")) {
      api
        .previewBaselinePrefix({
          template,
          title: sampleTitle,
          technology: sampleTechName,
          technology_name: sampleTechName,
          tactic: sampleTactic,
          severity: sampleSeverity,
          tenant: sampleTenant,
        })
        .then((res) => setPreviewClient(res.preview_title))
        .catch(() => {});
    } else {
      setPreviewClient(sampleTitle);
    }
  }, [settings, sampleTitle, sampleTechName, sampleTactic, sampleSeverity, sampleTenant]);

  const handleSave = async () => {
    setSaving(true);
    setErrorMessage(null);
    setSaveSuccess(false);

    try {
      const updated = await api.setBaselinePrefixSettings(settings);
      setSettings(updated);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3500);
    } catch (err) {
      setErrorMessage(
        err instanceof Error ? err.message : "Erro ao salvar configurações de prefixo."
      );
    } finally {
      setSaving(false);
    }
  };

  const insertVariable = (variable: string) => {
    const input = inputRef.current;
    if (!input) {
      setSettings((prev) => ({ ...prev, template: prev.template + variable }));
      return;
    }

    const start = input.selectionStart || 0;
    const end = input.selectionEnd || 0;
    const current = settings.template;
    const nextVal = current.substring(0, start) + variable + current.substring(end);

    setSettings((prev) => ({ ...prev, template: nextVal }));

    setTimeout(() => {
      input.focus();
      const pos = start + variable.length;
      input.setSelectionRange(pos, pos);
    }, 50);
  };

  const applyPreset = (presetTemplate: string) => {
    setSettings((prev) => ({ ...prev, template: presetTemplate }));
    if (inputRef.current) {
      inputRef.current.focus();
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center p-16 space-y-4">
        <span className="material-symbols-outlined animate-spin text-[36px] text-primary">
          progress_activity
        </span>
        <span className="font-body-sm text-body-sm text-on-surface-variant">
          Carregando configurações de prefixo...
        </span>
      </div>
    );
  }

  return (
    <div className="flex flex-col w-full space-y-6 pb-16">
      {/* Header com padrão tático D.A.N.T.E. */}
      <header className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 bg-surface-container-low p-6 rounded-2xl border border-outline-variant/30 shadow-sm">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary-container/20 border border-primary/40 flex items-center justify-center text-primary">
              <span className="material-symbols-outlined text-[22px]">title</span>
            </div>
            <h1 className="font-headline-xl text-headline-xl text-on-surface font-semibold tracking-tight">
              Prefixo Baseline
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-surface-container text-primary text-code-sm font-code-sm tracking-wide border border-primary/30">
              <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse"></span>
              Governança de Nomenclatura • SIEM
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant max-w-3xl leading-relaxed">
            Configure o padrão de prefixo a ser utilizado nos títulos das regras de detecção instaladas no Baseline Global.
            Suporta variáveis dinâmicas (como tecnologia, tenant, tática e severidade) com capitalização automática. Regras replicadas para clientes são salvas exatamente como estão, sem o prefixo rígido de cliente.
          </p>
        </div>

        <button
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-primary text-on-primary font-body-sm text-body-sm font-medium hover:bg-primary/90 transition-all shadow-md active:scale-95 disabled:opacity-50"
        >
          {saving ? (
            <>
              <span className="material-symbols-outlined animate-spin text-[18px]">
                progress_activity
              </span>
              <span>Salvando...</span>
            </>
          ) : (
            <>
              <span className="material-symbols-outlined text-[18px]">save</span>
              <span>Salvar Configurações</span>
            </>
          )}
        </button>
      </header>

      {/* Alertas de Sucesso / Erro */}
      {saveSuccess && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-body-sm text-body-sm animate-fadeIn">
          <span className="material-symbols-outlined text-[20px]">check_circle</span>
          <span>Configurações de prefixo salvas com sucesso! As novas regras seguirão o padrão configurado.</span>
        </div>
      )}

      {errorMessage && (
        <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-error/10 border border-error/30 text-error font-body-sm text-body-sm">
          <span className="material-symbols-outlined text-[20px]">error</span>
          <span>{errorMessage}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Painel de Configuração (7 colunas) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-surface-container-low/70 rounded-2xl border border-outline-variant/30 p-6 space-y-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-outline-variant/20 pb-4">
              <div>
                <h2 className="font-title-md text-title-md text-on-surface font-medium">
                  Estrutura do Prefixo
                </h2>
                <p className="font-body-xs text-body-xs text-on-surface-variant">
                  Defina o texto estático e as variáveis dinâmicas que antecederão o nome de cada regra.
                </p>
              </div>

              {/* Toggle Habilitar/Desabilitar */}
              <label className="flex items-center gap-3 cursor-pointer">
                <span className="font-body-xs text-body-xs text-on-surface-variant font-medium">
                  {settings.enabled ? "Prefixo Ativo" : "Desativado"}
                </span>
                <input
                  type="checkbox"
                  checked={settings.enabled}
                  onChange={(e) =>
                    setSettings((prev) => ({ ...prev, enabled: e.target.checked }))
                  }
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-surface-container-highest peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
              </label>
            </div>

            {/* Input do Template */}
            <div className="space-y-3">
              <label className="block font-body-sm text-body-sm font-medium text-on-surface">
                Template do Prefixo
              </label>
              <div className="relative">
                <input
                  ref={inputRef}
                  type="text"
                  disabled={!settings.enabled}
                  value={settings.template}
                  onChange={(e) =>
                    setSettings((prev) => ({ ...prev, template: e.target.value }))
                  }
                  placeholder="Ex: Baseline -  ou [{{tenant}}] [{{technology_name}}] - "
                  className="w-full px-4 py-3 bg-surface-container-highest/60 border border-outline-variant/40 rounded-xl font-mono text-code-md text-on-surface placeholder:text-on-surface-variant/40 focus:outline-none focus:border-primary/60 focus:ring-1 focus:ring-primary/40 disabled:opacity-50 transition-all"
                />
              </div>
              <p className="font-body-xs text-body-xs text-on-surface-variant">
                Dica: adicione um espaço ou traço no final caso queira separação visual do título da regra (ex.: <code className="text-primary font-mono font-medium">"Baseline - "</code>).
              </p>
            </div>

            {/* Variáveis Dinâmicas */}
            <div className="space-y-2.5">
              <span className="block font-body-xs text-body-xs font-semibold text-on-surface-variant uppercase tracking-wider">
                Variáveis Dinâmicas Disponíveis (Clique para Inserir)
              </span>
              <div className="flex flex-wrap gap-2">
                {[
                  { tag: "{{tenant}}", label: "Nome do Tenant / Baseline", icon: "domain" },
                  { tag: "{{technology_name}}", label: "Nome da Tecnologia", icon: "memory" },
                  { tag: "{{tactic}}", label: "Tática MITRE", icon: "radar" },
                  { tag: "{{severity}}", label: "Severidade", icon: "warning" },
                ].map(({ tag, label, icon }) => (
                  <button
                    key={tag}
                    type="button"
                    disabled={!settings.enabled}
                    onClick={() => insertVariable(tag)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-primary border border-primary/20 hover:border-primary/50 text-code-xs font-mono font-medium transition-all active:scale-95 disabled:opacity-50"
                    title={`Inserir ${tag} - ${label}`}
                  >
                    <span className="material-symbols-outlined text-[14px]">{icon}</span>
                    <span>{tag}</span>
                    <span className="text-[11px] text-on-surface-variant font-sans font-normal ml-1">
                      ({label})
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Presets Rápidos */}
            <div className="space-y-2.5 pt-2 border-t border-outline-variant/20">
              <span className="block font-body-xs text-body-xs font-semibold text-on-surface-variant uppercase tracking-wider">
                Modelos Sugeridos (Presets Rápidos)
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                {[
                  {
                    name: "Padrão Simples",
                    preset: "Baseline - ",
                    desc: "Simples e direto para o baseline",
                  },
                  {
                    name: "Contexto Completo",
                    preset: "[{{tenant}}] [{{technology_name}}] - ",
                    desc: "Tenant e Tecnologia destacados",
                  },
                  {
                    name: "Tag de Tenant",
                    preset: "[{{tenant}}] ",
                    desc: "Prefixo com tag de escopo",
                  },
                  {
                    name: "Hierarquia SOC",
                    preset: "{{tenant}} | {{tactic}} | ",
                    desc: "Segmentado por tática de ataque",
                  },
                  {
                    name: "Tecnológico",
                    preset: "[{{technology_name}}] ",
                    desc: "Foco no produto/tecnologia",
                  },
                  {
                    name: "Sem Prefixo",
                    preset: "",
                    desc: "Salva os títulos originais",
                  },
                ].map((item) => (
                  <button
                    key={item.name}
                    type="button"
                    disabled={!settings.enabled}
                    onClick={() => applyPreset(item.preset)}
                    className={`flex flex-col text-left p-3 rounded-xl border transition-all ${
                      settings.template === item.preset
                        ? "bg-primary/10 border-primary text-on-surface"
                        : "bg-surface-container-highest/40 hover:bg-surface-container-highest border-outline-variant/30 text-on-surface-variant"
                    } disabled:opacity-50`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="font-body-sm text-body-sm font-medium text-on-surface">
                        {item.name}
                      </span>
                      {settings.template === item.preset && (
                        <span className="material-symbols-outlined text-[16px] text-primary">
                          check_circle
                        </span>
                      )}
                    </div>
                    <code className="text-code-xs font-mono text-primary mt-1">
                      {item.preset ? item.preset : "(vazio)"}
                    </code>
                    <span className="text-[11px] text-on-surface-variant/80 mt-0.5">
                      {item.desc}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Painel de Preview e Regras de Negócio (5 colunas) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Card de Simulação em Tempo Real */}
          <div className="bg-surface-container-low/70 rounded-2xl border border-outline-variant/30 p-6 space-y-5 shadow-sm">
            <div className="flex items-center gap-2.5 border-b border-outline-variant/20 pb-3">
              <span className="material-symbols-outlined text-[20px] text-primary">
                visibility
              </span>
              <h2 className="font-title-md text-title-md text-on-surface font-medium">
                Simulação em Tempo Real
              </h2>
            </div>

            {/* Controles de Simulação */}
            <div className="space-y-3 text-body-xs text-on-surface-variant">
              <div>
                <label className="block text-[11px] font-medium text-on-surface-variant uppercase mb-1">
                  Título Base da Regra de Detecção
                </label>
                <input
                  type="text"
                  value={sampleTitle}
                  onChange={(e) => setSampleTitle(e.target.value)}
                  className="w-full px-3 py-1.5 bg-surface-container-highest/50 border border-outline-variant/30 rounded-lg text-body-sm text-on-surface focus:outline-none focus:border-primary/50 font-sans"
                />
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[11px] font-medium text-on-surface-variant uppercase mb-1">
                    Nome da Tecnologia (technology_name)
                  </label>
                  <input
                    type="text"
                    value={sampleTechName}
                    onChange={(e) => setSampleTechName(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-container-highest/50 border border-outline-variant/30 rounded-lg font-mono text-code-xs text-on-surface focus:outline-none focus:border-primary/50"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-on-surface-variant uppercase mb-1">
                    Tenant de Teste
                  </label>
                  <input
                    type="text"
                    value={sampleTenant}
                    onChange={(e) => setSampleTenant(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-container-highest/50 border border-outline-variant/30 rounded-lg font-mono text-code-xs text-on-surface focus:outline-none focus:border-primary/50"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="block text-[11px] font-medium text-on-surface-variant uppercase mb-1">
                    Tática MITRE
                  </label>
                  <input
                    type="text"
                    value={sampleTactic}
                    onChange={(e) => setSampleTactic(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-container-highest/50 border border-outline-variant/30 rounded-lg font-mono text-code-xs text-on-surface focus:outline-none focus:border-primary/50"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-on-surface-variant uppercase mb-1">
                    Severidade
                  </label>
                  <input
                    type="text"
                    value={sampleSeverity}
                    onChange={(e) => setSampleSeverity(e.target.value)}
                    className="w-full px-3 py-1.5 bg-surface-container-highest/50 border border-outline-variant/30 rounded-lg font-mono text-code-xs text-on-surface focus:outline-none focus:border-primary/50"
                  />
                </div>
              </div>
            </div>

            {/* Resultado 1: No Baseline Global */}
            <div className="space-y-2 pt-2 border-t border-outline-variant/20">
              <div className="flex items-center justify-between">
                <span className="font-body-xs text-body-xs font-semibold text-primary uppercase tracking-wide flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[16px]">public</span>
                  No Baseline Global
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-primary/10 text-primary font-mono border border-primary/20">
                  {"{{tenant}}"} = Baseline
                </span>
              </div>
              <div className="p-3.5 rounded-xl bg-surface-container-highest/60 border border-outline-variant/40 space-y-1">
                <span className="block font-body-sm text-body-sm font-semibold text-on-surface break-words">
                  {previewBaseline || sampleTitle}
                </span>
                <span className="block text-[11px] text-on-surface-variant font-mono">
                  Pasta: global / baseline-detections
                </span>
              </div>
            </div>

            {/* Resultado 2: No Ambiente de Cliente */}
            <div className="space-y-2 pt-2 border-t border-outline-variant/20">
              <div className="flex items-center justify-between">
                <span className="font-body-xs text-body-xs font-semibold text-secondary uppercase tracking-wide flex items-center gap-1.5">
                  <span className="material-symbols-outlined text-[16px]">domain</span>
                  No Cliente ({sampleTenant})
                </span>
                <span className="text-[11px] px-2 py-0.5 rounded bg-surface-container text-on-surface-variant font-mono border border-outline-variant/30">
                  {settings.template.toLowerCase().includes("tenant")
                    ? "Substitui dinamicamente"
                    : "Sem prefixo [cliente]"}
                </span>
              </div>
              <div className="p-3.5 rounded-xl bg-surface-container-highest/60 border border-outline-variant/40 space-y-1">
                <span className="block font-body-sm text-body-sm font-semibold text-on-surface break-words">
                  {previewClient || sampleTitle}
                </span>
                <span className="block text-[11px] text-on-surface-variant font-mono">
                  Pasta: {sampleTenant} / 5m
                </span>
              </div>
            </div>
          </div>

          {/* Card de Regras de Governança e Boas Práticas */}
          <div className="bg-surface-container-low/70 rounded-2xl border border-outline-variant/30 p-6 space-y-4 shadow-sm">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-amber-400">
                info
              </span>
              <h3 className="font-title-sm text-title-sm text-on-surface font-medium">
                Regras de Negócio e Convenções
              </h3>
            </div>

            <ul className="space-y-3 font-body-xs text-body-xs text-on-surface-variant leading-relaxed">
              <li className="flex items-start gap-2">
                <span className="material-symbols-outlined text-[16px] text-emerald-400 mt-0.5 shrink-0">
                  check
                </span>
                <span>
                  <strong className="text-on-surface font-medium">Fim do prefixo rígido:</strong> As regras replicadas para os clientes não recebem mais obrigatoriamente <code className="text-amber-300 font-mono">"[nomedocliente]"</code>. Elas são salvas exatamente como estão, salvo se o template utilizar a tag <code className="text-primary font-mono font-medium">{"{{tenant}}"}</code>.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="material-symbols-outlined text-[16px] text-emerald-400 mt-0.5 shrink-0">
                  check
                </span>
                <span>
                  <strong className="text-on-surface font-medium">Primeira Letra Capitalizada:</strong> Todas as variáveis dinâmicas inseridas têm sua primeira letra convertida automaticamente em maiúscula (Title Case).
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="material-symbols-outlined text-[16px] text-emerald-400 mt-0.5 shrink-0">
                  check
                </span>
                <span>
                  <strong className="text-on-surface font-medium">Identificador do Baseline:</strong> No repositório Baseline Global, a variável <code className="text-primary font-mono font-medium">{"{{tenant}}"}</code> assume estritamente o valor fixo <strong className="text-on-surface font-medium">"Baseline"</strong>.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <span className="material-symbols-outlined text-[16px] text-emerald-400 mt-0.5 shrink-0">
                  check
                </span>
                <span>
                  <strong className="text-on-surface font-medium">Idempotência garantida:</strong> Ao reimportar ou atualizar uma regra que já comece com o prefixo avaliado, o sistema não o duplica.
                </span>
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
