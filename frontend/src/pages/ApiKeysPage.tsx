import React from "react";
import { AISettingsForm } from "../components/AISettingsForm";

export const ApiKeysPage: React.FC = () => {
  return (
    <div className="flex flex-col w-full space-y-6 pb-12">
      {/* Header com padrão tático D.A.N.T.E. */}
      <header className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 bg-surface-container-low p-6 rounded-2xl border border-outline-variant/30 shadow-sm">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-tertiary-container/20 border border-tertiary/40 flex items-center justify-center text-tertiary">
              <span className="material-symbols-outlined text-[22px]">auto_awesome</span>
            </div>
            <h1 className="font-headline-xl text-headline-xl text-on-surface font-semibold tracking-tight">
              API Keys
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-surface-container text-tertiary text-code-sm font-code-sm tracking-wide border border-tertiary/30">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
              Gateway de IA • BYOK
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant max-w-2xl leading-relaxed">
            Gerenciamento centralizado de provedores de Inteligência Artificial (DeepSeek, OpenAI, Google Gemini, Anthropic, Ollama), chaves de API criptografadas e ativação seletiva de módulos cognitivos no SIEM.
          </p>
        </div>
      </header>

      {/* Formulário Principal */}
      <div className="bg-surface-container-low/60 rounded-2xl border border-outline-variant/30 p-6 sm:p-8 shadow-sm">
        <AISettingsForm />
      </div>
    </div>
  );
};

