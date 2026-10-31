import React, { useEffect, useState } from "react";
import { api } from "../api";

export const SystemUpdatesPage: React.FC = () => {
  const [versionInfo, setVersionInfo] = useState<any>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadVersion = async (force = false) => {
    try {
      setChecking(true);
      setError(null);
      const res = await api.getVersion(force);
      setVersionInfo(res);
    } catch (e: any) {
      setError(e.message || "Erro ao consultar versão do sistema.");
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    loadVersion(false);
  }, []);

  return (
    <div className="flex flex-col w-full space-y-6 pb-12">
      {/* Header */}
      <header className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 bg-surface-container-low p-6 rounded-xl border border-outline-variant/30 shadow-sm">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="font-headline-xl text-headline-xl text-on-surface">
              Sistema &amp; Updates
            </h1>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-surface-container text-secondary text-code-sm font-code-sm tracking-wide border border-secondary/30">
              <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
              Release Channel: Stable
            </span>
          </div>
          <p className="font-body-sm text-body-sm text-on-surface-variant max-w-2xl">
            Gerenciamento de versão, atualizações automáticas via GitHub Container Registry e integridade dos serviços D.A.N.T.E.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <a
            href="https://github.com/sg0luc/dante/releases"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-body-sm text-body-sm transition-all shadow-sm border border-outline-variant/30"
          >
            <span className="material-symbols-outlined text-[18px] text-outline">history_edu</span>
            <span>Ver Release Notes ↗</span>
          </a>
          <button
            onClick={() => loadVersion(true)}
            disabled={checking}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary-container hover:bg-inverse-primary text-on-primary-container font-body-sm text-body-sm font-semibold shadow-[0_0_12px_rgba(225,29,72,0.3)] transition-all active:scale-95 disabled:opacity-50"
          >
            <span
              className={`material-symbols-outlined text-[18px] ${
                checking ? "animate-spin" : ""
              }`}
            >
              sync
            </span>
            <span>{checking ? "Checando..." : "Checar Atualizações"}</span>
          </button>
        </div>
      </header>

      {error && (
        <div className="p-4 rounded-xl bg-error-container/20 border border-error-container text-error font-body-sm">
          {error}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-space-sm">
        <div className="p-space-md rounded-xl bg-surface-container-low border border-outline-variant/30 flex flex-col justify-between">
          <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
            Versão Instalada
          </span>
          <div className="my-space-sm">
            <span className="font-metric-display text-metric-display text-on-surface">
              {versionInfo?.current_version || "v1.0.0"}
            </span>
          </div>
          <span className="font-code-sm text-code-sm text-tertiary">
            Build de Produção Oficial
          </span>
        </div>

        <div className="p-space-md rounded-xl bg-surface-container-low border border-outline-variant/30 flex flex-col justify-between">
          <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
            Última Release Oficial
          </span>
          <div className="my-space-sm">
            <span className="font-metric-display text-metric-display text-secondary">
              {versionInfo?.latest_version || versionInfo?.current_version || "v1.0.0"}
            </span>
          </div>
          <span className="font-code-sm text-code-sm text-outline">
            {versionInfo?.update_available
              ? "Nova versão disponível no repositório"
              : "Sistema na versão estável mais recente"}
          </span>
        </div>

        <div className="p-space-md rounded-xl bg-surface-container-low border border-outline-variant/30 flex flex-col justify-between">
          <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
            Status do Workflow
          </span>
          <div className="my-space-sm">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-tertiary"></span>
              <span className="font-headline-md text-headline-md text-on-surface">
                CI/CD Release Ativo
              </span>
            </div>
          </div>
          <span className="font-code-sm text-code-sm text-outline">
            Zero etapas manuais pós-merge
          </span>
        </div>
      </div>

      {/* Architecture & Pipeline Card */}
      <div className="p-6 rounded-xl bg-surface-container-low border border-outline-variant/30 space-y-4">
        <div className="flex items-center justify-between border-b border-outline-variant/30 pb-3">
          <h2 className="font-headline-lg text-headline-lg text-on-surface">
            Arquitetura de Atualizações e Versionamento Semântico
          </h2>
          <span className="font-code-sm text-code-sm text-outline">
            docker-compose / GHCR
          </span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-body-sm text-on-surface-variant">
          <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/20 space-y-2">
            <div className="flex items-center gap-2 text-on-surface font-semibold">
              <span className="material-symbols-outlined text-secondary text-[20px]">
                deployed_code_update
              </span>
              <span>Ciclo de Release Automatizado</span>
            </div>
            <p>
              Toda nova funcionalidade ou correção segue o versionamento semântico canônico
              em <code className="font-mono text-secondary">VERSION</code> e{" "}
              <code className="font-mono text-secondary">backend/app/__init__.py</code>.
              Ao realizar o merge na branch <code className="font-mono text-secondary">main</code>,
              o GitHub Actions gera a tag oficial, compila as imagens dos containers e publica no GHCR.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-surface-container-lowest border border-outline-variant/20 space-y-2">
            <div className="flex items-center gap-2 text-on-surface font-semibold">
              <span className="material-symbols-outlined text-tertiary text-[20px]">
                verified
              </span>
              <span>Integridade dos Tenants &amp; Baseline</span>
            </div>
            <p>
              Atualizações de código preservam a integridade dos tenants no Grafana e pastas
              de baseline institucional. Grupos de avaliação canônicos (<code className="font-mono text-tertiary">5m</code>)
              e datasources Loki associados são idempotentemente mantidos.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

