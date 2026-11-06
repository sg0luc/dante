import React, { useEffect, useState, useRef } from "react";
import { api } from "../api";
import { AppVersionInfo, UpgradeTriggerResponse } from "../types";

interface SystemUpdateModalProps {
  isOpen: boolean;
  onClose: () => void;
  onVersionUpdated?: (newVersion: string) => void;
}

type ModalStep = "overview" | "confirm" | "upgrading" | "success" | "error";

export const SystemUpdateModal: React.FC<SystemUpdateModalProps> = ({
  isOpen,
  onClose,
  onVersionUpdated,
}) => {
  const [step, setStep] = useState<ModalStep>("overview");
  const [versionInfo, setVersionInfo] = useState<AppVersionInfo | null>(null);
  const [checking, setChecking] = useState(false);
  const [upgradeError, setUpgradeError] = useState<string | null>(null);
  const [upgradeMessage, setUpgradeMessage] = useState<string | null>(null);
  const [manualCommandRequired, setManualCommandRequired] = useState(false);
  const [countdown, setCountdown] = useState(3);
  const pollTimerRef = useRef<number | null>(null);
  const countdownTimerRef = useRef<number | null>(null);

  const loadVersion = async (force = false) => {
    try {
      setChecking(true);
      const res = await api.getVersion(force);
      setVersionInfo(res);
    } catch (e: any) {
      setVersionInfo((prev) =>
        prev
          ? { ...prev, error: e.message || "Erro ao consultar versão." }
          : {
              current_version: "v1.1.0",
              update_available: false,
              error: e.message || "Erro ao consultar versão do sistema.",
            }
      );
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      setStep("overview");
      setUpgradeError(null);
      setUpgradeMessage(null);
      setManualCommandRequired(false);
      loadVersion(false);
    } else {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);
    }
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);
    };
  }, [isOpen]);

  const handleStartUpgrade = async () => {
    try {
      setStep("upgrading");
      setUpgradeError(null);
      const target = versionInfo?.latest_version || undefined;
      const res: UpgradeTriggerResponse = await api.triggerUpgrade(target);

      if (res.status === "manual_action_required") {
        setManualCommandRequired(true);
        setUpgradeMessage(res.message);
        return;
      }

      if (res.status === "error") {
        setStep("error");
        setUpgradeError(res.message || "Falha ao iniciar atualização.");
        return;
      }

      setUpgradeMessage(res.message || "Atualização iniciada. Aguardando a aplicação abaixar...");
      startPollingForReconnection(target || versionInfo?.latest_version || "");
    } catch (e: any) {
      // Se a conexão falhou imediatamente, significa que a aplicação já começou a cair
      setUpgradeMessage("Containers reiniciando... Aguardando reconexão da stack.");
      startPollingForReconnection(versionInfo?.latest_version || "");
    }
  };

  const startPollingForReconnection = (expectedVersion: string) => {
    let attempts = 0;
    const maxAttempts = 100; // até 200s
    let hasGoneDown = false;
    let offlineCount = 0;
    const initialVersion = versionInfo?.current_version || "1.1.0";
    const cleanInitial = initialVersion.replace(/^[vV]/, "").trim();
    const cleanExpected = expectedVersion ? expectedVersion.replace(/^[vV]/, "").trim() : "";

    const triggerSuccessRedirect = (targetVersion: string) => {
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
        pollTimerRef.current = null;
      }
      if (onVersionUpdated) onVersionUpdated(targetVersion);
      setVersionInfo((prev) => (prev ? { ...prev, current_version: targetVersion, update_available: false } : null));
      setStep("success");

      let cnt = 3;
      setCountdown(cnt);
      if (countdownTimerRef.current) clearInterval(countdownTimerRef.current);
      countdownTimerRef.current = window.setInterval(() => {
        cnt -= 1;
        setCountdown(cnt);
        if (cnt <= 0) {
          if (countdownTimerRef.current) {
            clearInterval(countdownTimerRef.current);
            countdownTimerRef.current = null;
          }
          window.location.href = "/login";
        }
      }, 1000);
    };

    setUpgradeMessage("Disparando comando de atualização. Baixando imagens oficiais no GHCR...");

    pollTimerRef.current = window.setInterval(async () => {
      attempts++;
      try {
        const health = await api.getHealth();
        const cleanCurrent = (health.version || "").replace(/^[vV]/, "").trim();

        // 1. Se a versão já mudou em relação à inicial ou bate com a esperada, a atualização já está concluída!
        if (cleanCurrent && (cleanCurrent !== cleanInitial || (cleanExpected && cleanCurrent === cleanExpected))) {
          triggerSuccessRedirect(health.version || expectedVersion);
          return;
        }

        // 2. Se a aplicação AINDA NÃO caiu (continua online na versão anterior):
        if (!hasGoneDown) {
          if (attempts >= 45) {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            setStep("error");
            setUpgradeError(
              `A aplicação não foi reiniciada após 90 segundos. O serviço de atualização não conseguiu baixar uma nova versão ou as imagens da release ainda não foram publicadas no GHCR (a versão permanece ${health.version || initialVersion}). Verifique se o GitHub Token possui a permissão 'read:packages' ou execute no terminal: docker compose pull && docker compose up -d`
            );
            return;
          }
          setUpgradeMessage(
            `Baixando imagens oficiais no GHCR e preparando recriação da stack... (${attempts * 2}s)`
          );
          return;
        }

        // 3. Se a aplicação EFETIVAMENTE CAIU (hasGoneDown = true) E AGORA SUBIU NOVAMENTE:
        triggerSuccessRedirect(health.version || expectedVersion || "1.2.1");
      } catch (err: any) {
        // Se a requisição retornou 401 Unauthorized ou 403 Forbidden, significa que o novo container backend
        // já subiu e o servidor HTTP respondeu (a sessão anterior foi limpa na reinicialização)
        if (err?.status === 401 || err?.status === 403 || err?.message?.includes("401") || err?.message?.includes("403")) {
          triggerSuccessRedirect(expectedVersion || "1.2.1");
          return;
        }

        // Requisição falhou por rede ou gateway (502/503): significa que a aplicação EFETIVAMENTE ABAIXOU!
        offlineCount++;
        hasGoneDown = true;
        setUpgradeMessage(
          `⚡ A aplicação abaixou! Os containers estão sendo recriados com a nova versão... (${offlineCount * 2}s)`
        );

        if (attempts >= maxAttempts) {
          if (pollTimerRef.current) clearInterval(pollTimerRef.current);
          setStep("error");
          setUpgradeError(
            "Tempo limite de espera excedido. Verifique o status dos containers via terminal: docker compose ps"
          );
        }
      }
    }, 2000);
  };

  if (!isOpen) return null;

  // Renderizador simples e seguro de Markdown para notas de release
  const renderMarkdown = (content: string) => {
    const lines = content.split("\n");
    return lines.map((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith("### ")) {
        return (
          <h4 key={idx} className="font-headline-sm text-headline-sm text-secondary mt-3 mb-1 font-semibold">
            {trimmed.replace(/^###\s+/, "")}
          </h4>
        );
      }
      if (trimmed.startsWith("## ")) {
        return (
          <h3 key={idx} className="font-headline-md text-headline-md text-on-surface mt-4 mb-2 font-bold border-b border-outline-variant/30 pb-1">
            {trimmed.replace(/^##\s+/, "")}
          </h3>
        );
      }
      if (trimmed.startsWith("# ")) {
        return (
          <h2 key={idx} className="font-headline-lg text-headline-lg text-on-surface mt-5 mb-2 font-bold">
            {trimmed.replace(/^#\s+/, "")}
          </h2>
        );
      }
      if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
        return (
          <li key={idx} className="ml-5 list-disc text-body-sm text-on-surface-variant my-0.5">
            {trimmed.replace(/^[-*]\s+/, "")}
          </li>
        );
      }
      if (!trimmed) {
        return <div key={idx} className="h-2" />;
      }
      return (
        <p key={idx} className="text-body-sm text-on-surface-variant my-1 leading-relaxed">
          {trimmed}
        </p>
      );
    });
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-fade-in"
      role="dialog"
      aria-modal="true"
    >
      <div className="bg-surface-container-low border border-outline-variant/30 rounded-2xl shadow-2xl w-full max-w-2xl flex flex-col overflow-hidden max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-outline-variant/30 bg-surface-container/40">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-primary-container/20 border border-primary-container/40 flex items-center justify-center shadow-sm">
              <span className="material-symbols-outlined text-primary-fixed-dim text-[24px]">
                deployed_code_update
              </span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-headline-md text-headline-md font-bold text-on-surface">
                  Atualização do Sistema
                </h2>
                <span className="px-2 py-0.5 rounded-full text-code-sm bg-surface-container text-tertiary border border-tertiary/30 font-semibold">
                  Oficial GHCR
                </span>
              </div>
              <p className="font-body-sm text-body-sm text-on-surface-variant">
                Gerenciamento in-app de releases e integridade da stack D.A.N.T.E.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={step === "upgrading"}
            className="p-1.5 text-outline hover:text-on-surface hover:bg-surface-container-high rounded-lg transition-colors disabled:opacity-40"
            title="Fechar"
          >
            <span className="material-symbols-outlined text-[20px]">close</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {step === "overview" && (
            <>
              {/* Version Comparison Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-4 rounded-xl bg-surface-container-lowest border border-outline-variant/20 flex flex-col justify-between">
                  <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
                    Versão Atual Instalada
                  </span>
                  <div className="my-2">
                    <span className="font-headline-xl text-headline-xl font-bold text-on-surface font-mono">
                      {versionInfo?.current_version || "1.2.0"}
                    </span>
                  </div>
                  <span className="font-code-sm text-code-sm text-tertiary flex items-center gap-1">
                    <span className="w-2 h-2 rounded-full bg-tertiary"></span>
                    Em execução
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-surface-container-lowest border border-outline-variant/20 flex flex-col justify-between">
                  <span className="font-label-uppercase text-label-uppercase text-outline uppercase tracking-wider">
                    Última Release no Repositório
                  </span>
                  <div className="my-2">
                    <span className="font-headline-xl text-headline-xl font-bold text-secondary font-mono">
                      {versionInfo?.latest_version || versionInfo?.current_version || "1.2.0"}
                    </span>
                  </div>
                  <span className="font-code-sm text-code-sm text-outline flex items-center gap-1">
                    {versionInfo?.update_available ? (
                      <span className="text-primary-fixed-dim font-semibold flex items-center gap-1">
                        <span className="material-symbols-outlined text-[15px]">arrow_circle_up</span>
                        Nova versão disponível
                      </span>
                    ) : (
                      <span className="text-tertiary flex items-center gap-1">
                        <span className="material-symbols-outlined text-[15px]">verified</span>
                        Sistema atualizado
                      </span>
                    )}
                  </span>
                </div>
              </div>

              {/* Erro ou aviso de Repositório Privado / Token */}
              {versionInfo?.error && (
                <div className="p-4 rounded-xl bg-error-container/15 border border-error-container/40 text-on-surface flex items-start gap-3">
                  <span className="material-symbols-outlined text-error text-[22px] shrink-0 mt-0.5">
                    warning
                  </span>
                  <div className="space-y-1.5 text-body-sm">
                    <div className="font-semibold text-error">
                      Atenção na verificação do repositório
                    </div>
                    <p className="text-on-surface-variant">{versionInfo.error}</p>
                    <div className="p-2.5 rounded-lg bg-surface-container-lowest border border-outline-variant/30 text-code-sm font-mono text-outline">
                      GITHUB_REPO=sg0luc/dante<br />
                      <span className="text-on-surface-variant text-[11px]"># GITHUB_TOKEN é opcional (repositório público)</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Aviso Preventivo de Escopo de Packages do GHCR */}
              {versionInfo?.ghcr_status === "missing_packages_scope" && (
                <div className="p-4 rounded-xl bg-amber-500/15 border border-amber-500/40 text-on-surface flex items-start gap-3">
                  <span className="material-symbols-outlined text-amber-400 text-[24px] shrink-0 mt-0.5">
                    shield_lock
                  </span>
                  <div className="space-y-2 text-body-sm">
                    <div className="font-semibold text-amber-300">
                      Permissão 'read:packages' necessária no GitHub
                    </div>
                    <p className="text-on-surface-variant">
                      O seu <strong>GITHUB_TOKEN</strong> tem permissão para ler as Releases, mas <strong>não possui o escopo para baixar imagens do GHCR</strong>.
                    </p>
                    <p className="text-on-surface-variant text-code-sm">
                      Para que a atualização in-app funcione de verdade: acesse <strong>GitHub &gt; Settings &gt; Developer Settings &gt; Personal access tokens (classic)</strong> e gere um token marcando <strong>repo</strong> e <strong>read:packages</strong>. Em seguida, atualize seu arquivo <code className="font-mono text-secondary">.env</code>.
                    </p>
                  </div>
                </div>
              )}

              {/* Release Notes */}
              <div className="rounded-xl bg-surface-container-lowest border border-outline-variant/30 overflow-hidden">
                <div className="px-4 py-2.5 border-b border-outline-variant/20 bg-surface-container/50 flex items-center justify-between">
                  <span className="font-body-sm font-semibold text-on-surface flex items-center gap-2">
                    <span className="material-symbols-outlined text-secondary text-[18px]">
                      description
                    </span>
                    Release Notes {versionInfo?.latest_version ? `(${versionInfo.latest_version})` : ""}
                  </span>
                  {versionInfo?.release_url && (
                    <a
                      href={versionInfo.release_url}
                      target="_blank"
                      rel="noreferrer"
                      className="font-code-sm text-secondary hover:underline flex items-center gap-1"
                    >
                      Abrir no GitHub ↗
                    </a>
                  )}
                </div>
                <div className="p-4 max-h-56 overflow-y-auto">
                  {versionInfo?.release_notes ? (
                    renderMarkdown(versionInfo.release_notes)
                  ) : (
                    <div className="text-body-sm text-outline italic py-4 text-center">
                      {versionInfo?.update_available
                        ? "Nenhuma descrição fornecida na release oficial."
                        : "O sistema já está na versão estável mais recente. Nenhuma atualização pendente."}
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {step === "confirm" && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-primary-container/10 border border-primary-container/30 flex items-start gap-3">
                <span className="material-symbols-outlined text-primary-fixed-dim text-[26px] shrink-0 mt-0.5">
                  security_update_good
                </span>
                <div className="space-y-2 text-body-sm">
                  <div className="font-semibold text-primary-fixed-dim text-headline-sm">
                    Validação de Segurança e Confirmação de Upgrade
                  </div>
                  <p className="text-on-surface-variant">
                    Você está prestes a atualizar o D.A.N.T.E. para a versão{" "}
                    <strong className="text-on-surface font-mono">
                      {versionInfo?.latest_version || "mais recente"}
                    </strong>
                    .
                  </p>
                  <ul className="list-disc list-inside space-y-1 text-on-surface-variant text-code-sm pt-1">
                    <li>
                      <strong>Indisponibilidade Transitória:</strong> A aplicação abaixará e ficará fora do ar por aproximadamente 10 a 20 segundos enquanto os containers são recriados.
                    </li>
                    <li>
                      <strong>Retorno Automático:</strong> Após a stack subir novamente, você será redirecionado automaticamente já para a página de login.
                    </li>
                    <li>
                      <strong>Integridade Garantida:</strong> Tenants, regras de detecção e logs persistidos em volumes Docker não sofrem alterações.
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {step === "upgrading" && (
            <div className="py-6 flex flex-col items-center justify-center text-center space-y-5">
              {!manualCommandRequired ? (
                <>
                  <div className="relative">
                    <div className="w-16 h-16 rounded-full border-4 border-outline-variant/30 border-b-primary-container flex items-center justify-center"></div>
                    <span className="absolute inset-0 flex items-center justify-center"><span className="material-symbols-outlined text-[24px] text-primary-fixed-dim animate-spin">
                      sync
                    </span></span>
                  </div>
                  <div className="space-y-1.5 max-w-md">
                    <h3 className="font-headline-md font-bold text-on-surface">
                      Atualizando a Stack do D.A.N.T.E.
                    </h3>
                    <p className="text-body-sm text-on-surface-variant">
                      {upgradeMessage || "Baixando imagens oficiais do GHCR e reiniciando containers..."}
                    </p>
                    <p className="text-code-sm text-outline italic">
                      Aguardando a aplicação abaixar e subir novamente. Não feche esta janela.
                    </p>
                  </div>
                </>
              ) : (
                <div className="space-y-4 text-left w-full">
                  <div className="p-4 rounded-xl bg-surface-container-high border border-outline-variant/40 space-y-3">
                    <div className="flex items-center gap-2 text-secondary font-semibold text-body-sm">
                      <span className="material-symbols-outlined text-[20px]">terminal</span>
                      <span>Atualização Manual Necessária no Servidor</span>
                    </div>
                    <p className="text-body-sm text-on-surface-variant">
                      {upgradeMessage}
                    </p>
                    <div className="p-3 rounded-lg bg-surface-container-lowest font-mono text-code-sm text-on-surface flex items-center justify-between border border-outline-variant/30">
                      <code>docker compose pull &amp;&amp; docker compose up -d</code>
                      <button
                        onClick={() => navigator.clipboard.writeText("docker compose pull && docker compose up -d")}
                        className="p-1 text-outline hover:text-on-surface hover:bg-surface-container-high rounded transition-colors"
                        title="Copiar comando"
                      >
                        <span className="material-symbols-outlined text-[16px]">content_copy</span>
                      </button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {step === "success" && (
            <div className="py-6 flex flex-col items-center justify-center text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-tertiary-container/30 border border-tertiary/40 flex items-center justify-center shadow-lg">
                <span className="material-symbols-outlined text-[36px] text-tertiary">
                  check_circle
                </span>
              </div>
              <div className="space-y-1 max-w-md">
                <h3 className="font-headline-md font-bold text-on-surface">
                  Atualização Concluída com Sucesso!
                </h3>
                <p className="text-body-sm text-on-surface-variant">
                  A stack do D.A.N.T.E. abaixou, foi atualizada e subiu com sucesso na versão{" "}
                  <strong className="text-secondary font-mono">
                    {versionInfo?.current_version || "mais recente"}
                  </strong>
                  .
                </p>
                <p className="text-code-sm text-outline">
                  Redirecionando para a página de login em {countdown} segundos...
                </p>
              </div>
            </div>
          )}

          {step === "error" && (
            <div className="py-6 flex flex-col items-center justify-center text-center space-y-4">
              <div className="w-16 h-16 rounded-full bg-error-container/20 border border-error-container/40 flex items-center justify-center shadow-lg">
                <span className="material-symbols-outlined text-[36px] text-error">
                  error
                </span>
              </div>
              <div className="space-y-1 max-w-md">
                <h3 className="font-headline-md font-bold text-error">
                  Não Foi Possível Concluir a Atualização
                </h3>
                <p className="text-body-sm text-on-surface-variant">
                  {upgradeError || "Ocorreu um erro durante a atualização."}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 border-t border-outline-variant/30 bg-surface-container/30 flex items-center justify-between">
          {step === "overview" && (
            <>
              <button
                onClick={() => loadVersion(true)}
                disabled={checking}
                className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-on-surface font-body-sm text-body-sm transition-all disabled:opacity-50"
              >
                <span className={`material-symbols-outlined text-[18px] ${checking ? "animate-spin" : ""}`}>
                  sync
                </span>
                <span>{checking ? "Checando..." : "Checar Atualizações"}</span>
              </button>

              <div className="flex items-center gap-3">
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg text-outline hover:text-on-surface font-body-sm text-body-sm transition-colors"
                >
                  Fechar
                </button>
                <button
                  onClick={() => setStep("confirm")}
                  className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-body-sm text-body-sm font-semibold transition-all shadow-md active:scale-95 ${
                    versionInfo?.update_available
                      ? "bg-primary-container hover:bg-inverse-primary text-on-primary-container shadow-[0_0_12px_rgba(225,29,72,0.35)]"
                      : "bg-surface-container-high hover:bg-surface-container-highest text-on-surface"
                  }`}
                >
                  <span className="material-symbols-outlined text-[18px]">
                    {versionInfo?.update_available ? "rocket_launch" : "update"}
                  </span>
                  <span>
                    {versionInfo?.update_available
                      ? `Atualizar Agora (${versionInfo.latest_version || "Nova Versão"})`
                      : "Reinstalar / Forçar Atualização"}
                  </span>
                </button>
              </div>
            </>
          )}

          {step === "confirm" && (
            <div className="flex items-center justify-end gap-3 w-full">
              <button
                onClick={() => setStep("overview")}
                className="px-4 py-2 rounded-lg text-outline hover:text-on-surface font-body-sm text-body-sm transition-colors"
              >
                Voltar
              </button>
              <button
                onClick={handleStartUpgrade}
                className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-primary-container hover:bg-inverse-primary text-on-primary-container font-body-sm text-body-sm font-semibold shadow-[0_0_14px_rgba(225,29,72,0.4)] transition-all active:scale-95"
              >
                <span className="material-symbols-outlined text-[18px]">rocket_launch</span>
                <span>Confirmar e Iniciar Atualização</span>
              </button>
            </div>
          )}

          {step === "upgrading" && (
            <div className="flex justify-end w-full">
              {manualCommandRequired && (
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-lg bg-surface-container-high text-on-surface font-body-sm text-body-sm hover:bg-surface-container-highest"
                >
                  Entendi, vou rodar no terminal
                </button>
              )}
            </div>
          )}

          {step === "success" && (
            <div className="flex justify-end w-full">
              <button
                onClick={() => {
                  window.location.href = "/login";
                }}
                className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-tertiary-container text-on-tertiary-container font-body-sm text-body-sm font-semibold transition-all hover:brightness-110"
              >
                <span className="material-symbols-outlined text-[18px]">login</span>
                <span>Ir para a Página de Login Agora</span>
              </button>
            </div>
          )}

          {step === "error" && (
            <div className="flex justify-end gap-3 w-full">
              <button
                onClick={() => setStep("overview")}
                className="px-4 py-2 rounded-lg text-outline hover:text-on-surface font-body-sm text-body-sm"
              >
                Voltar
              </button>
              <button
                onClick={() => {
                  window.location.href = "/login";
                }}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-surface-container-highest hover:bg-secondary-container hover:text-on-secondary-container text-on-surface font-body-sm text-body-sm transition-all"
              >
                <span className="material-symbols-outlined text-[16px]">login</span>
                <span>Ir para Login</span>
              </button>
              <button
                onClick={onClose}
                className="px-4 py-2 rounded-lg bg-surface-container-high text-on-surface font-body-sm text-body-sm hover:bg-surface-container-highest"
              >
                Fechar
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
