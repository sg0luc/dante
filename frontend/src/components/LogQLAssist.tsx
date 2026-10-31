import React from "react";
import { ExecuteQueryResult, LogQLLintResult } from "../types";

/**
 * Componentes compartilhados de assistência LogQL.
 *
 * Usados no modal de criação de regra (página "Regras") e no modal de
 * implementação de regra baseline em um cliente (página "Controle de
 * Baseline"), garantindo paridade funcional entre os dois fluxos.
 */

interface LogQLActionButtonsProps {
  linting: boolean;
  executing: boolean;
  onLint: () => void;
  onRun: () => void;
}

/** Par de botões "Validar (Linting)" + "Consultar Logs (Run)". */
export const LogQLActionButtons: React.FC<LogQLActionButtonsProps> = ({
  linting,
  executing,
  onLint,
  onRun,
}) => (
  <div style={{ display: "flex", gap: "8px" }}>
    <button
      type="button"
      onClick={onLint}
      disabled={linting}
      className="btn btn-secondary btn-sm"
      style={{ fontSize: "0.75rem", padding: "2px 8px" }}
    >
      {linting ? "Validando..." : "Validar (Linting)"}
    </button>
    <button
      type="button"
      onClick={onRun}
      disabled={executing}
      className="btn btn-secondary btn-sm"
      style={{ fontSize: "0.75rem", padding: "2px 8px" }}
    >
      {executing ? "Validando Logs..." : "Validar Logs (Run)"}
    </button>
  </div>
);

interface LogQLLintPanelProps {
  lintResult: LogQLLintResult;
}

/** Painel de resultado do linting sintático e semântico. */
export const LogQLLintPanel: React.FC<LogQLLintPanelProps> = ({ lintResult }) => (
  <div
    style={{
      backgroundColor: lintResult.is_valid ? "rgba(34, 197, 94, 0.08)" : "rgba(239, 68, 68, 0.08)",
      border: lintResult.is_valid ? "1px solid rgba(34, 197, 94, 0.3)" : "1px solid rgba(239, 68, 68, 0.3)",
      padding: "10px 14px",
      borderRadius: "6px",
      marginBottom: "14px",
      fontSize: "0.85rem",
    }}
  >
    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
      <span
        style={{
          color: lintResult.is_valid ? "var(--status-normal)" : "var(--status-firing)",
          fontWeight: 700,
        }}
      >
        {lintResult.is_valid ? "LINTING: VÁLIDO" : "LINTING: ERROS ENCONTRADOS"}
      </span>
      <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{lintResult.message}</span>
    </div>

    {lintResult.issues.length > 0 && (
      <ul style={{ margin: "6px 0 0 16px", padding: 0, fontSize: "0.8rem" }}>
        {lintResult.issues.map((iss, idx) => (
          <li
            key={idx}
            style={{
              color:
                iss.level === "error"
                  ? "var(--status-firing)"
                  : iss.level === "warning"
                  ? "var(--status-pending)"
                  : "var(--text-muted)",
            }}
          >
            <strong>[{iss.level.toUpperCase()}]:</strong> {iss.message}
          </li>
        ))}
      </ul>
    )}

    {lintResult.is_valid && lintResult.pipeline_stages.length > 0 && (
      <div style={{ marginTop: "6px", fontSize: "0.75rem", color: "var(--text-subtle)" }}>
        Estágios do Pipeline detectados: {lintResult.pipeline_stages.join(" ➔ ")}
      </div>
    )}
  </div>
);

interface LogQLQueryResultPanelProps {
  queryResult: ExecuteQueryResult;
}

interface RenderLogLinesProps {
  lines: Array<{ timestamp: string; line: string; labels?: Record<string, string> }>;
  accentColor?: string;
}

const RenderLogLines: React.FC<RenderLogLinesProps> = ({ lines, accentColor = "#ffffff" }) => (
  <div
    style={{
      maxHeight: "150px",
      overflowY: "auto",
      fontFamily: "var(--font-mono)",
      fontSize: "0.75rem",
      display: "flex",
      flexDirection: "column",
      gap: "6px",
    }}
  >
    {lines.map((l, idx) => (
      <div
        key={idx}
        style={{
          padding: "6px 8px",
          backgroundColor: "var(--bg-surface)",
          borderRadius: "6px",
          border: "1px solid var(--border-color-subtle)",
          borderLeft: `2px solid ${accentColor}`,
          wordBreak: "break-all",
          lineHeight: "1.4",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "2px" }}>
          <span style={{ color: "var(--text-subtle)", fontWeight: 500 }}>
            {new Date(l.timestamp).toLocaleTimeString("pt-BR")}.
            {new Date(l.timestamp).getMilliseconds().toString().padStart(3, "0")}
          </span>
          {l.labels && Object.keys(l.labels).length > 0 && (
            <div style={{ display: "inline-flex", gap: "4px", flexWrap: "wrap" }}>
              {Object.entries(l.labels).slice(0, 4).map(([k, v]) => (
                <span
                  key={k}
                  style={{
                    fontSize: "0.68rem",
                    backgroundColor: "rgba(255, 255, 255, 0.04)",
                    padding: "1px 5px",
                    borderRadius: "4px",
                    color: "var(--text-muted)",
                  }}
                >
                  {k}={String(v)}
                </span>
              ))}
            </div>
          )}
        </div>
        <span style={{ color: "var(--text-main)" }}>{l.line}</span>
      </div>
    ))}
  </div>
);

/** Painel com as linhas retornadas pela execução real da query no Loki com segregação Sandbox vs Produção. */
export const LogQLQueryResultPanel: React.FC<LogQLQueryResultPanelProps> = ({ queryResult }) => {
  const hasEnvironments = Array.isArray(queryResult.environments) && queryResult.environments.length > 0;
  const sandboxEnv = hasEnvironments ? queryResult.environments!.find((e) => e.environment === "sandbox") : null;
  const prodEnv = hasEnvironments ? queryResult.environments!.find((e) => e.environment === "production") : null;

  const [activeTab, setActiveTab] = React.useState<"sandbox" | "production" | "both">("sandbox");

  if (!hasEnvironments) {
    return (
      <div
        style={{
          backgroundColor: "var(--bg-input)",
          border: "1px solid var(--border-color)",
          padding: "12px 14px",
          borderRadius: "8px",
          marginBottom: "16px",
          fontSize: "0.82rem",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
          <span style={{ fontWeight: 600, color: "var(--text-main)", display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
            <span>Resultados da Consulta ({queryResult.total_lines} linha(s) em {queryResult.duration_ms}ms)</span>
            {queryResult.datasource_name && (
              <span style={{ fontSize: "0.75rem", color: "var(--text-subtle)", fontWeight: 400 }}>
                • Data source: <code style={{ color: "#ffffff", backgroundColor: "rgba(255, 255, 255, 0.08)", padding: "1px 5px", borderRadius: "3px" }}>{queryResult.datasource_name}</code>
              </span>
            )}
          </span>
          <span
            className="badge"
            style={{
              backgroundColor: queryResult.success ? "var(--status-normal-bg)" : "var(--status-firing-bg)",
              color: queryResult.success ? "var(--status-normal)" : "var(--status-firing)",
              border: `1px solid ${queryResult.success ? "var(--status-normal-border)" : "var(--status-firing-border)"}`,
            }}
          >
            {queryResult.success ? "Concluída" : "Falhou"}
          </span>
        </div>

        {!queryResult.success && queryResult.error && (
          <div style={{ fontSize: "0.8rem", color: "var(--status-firing)", marginBottom: "6px" }}>
            {queryResult.error}
          </div>
        )}

        {queryResult.lines.length === 0 ? (
          <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>
            Nenhuma linha retornada para o período consultado.
          </span>
        ) : (
          <RenderLogLines lines={queryResult.lines} accentColor="#ffffff" />
        )}
      </div>
    );
  }

  return (
    <div
      style={{
        backgroundColor: "var(--bg-input)",
        border: "1px solid var(--border-color)",
        padding: "12px 14px",
        borderRadius: "8px",
        marginBottom: "16px",
        fontSize: "0.82rem",
      }}
    >
      {/* Header com resumo geral e status */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px", flexWrap: "wrap", gap: "8px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ fontWeight: 700, color: "var(--text-main)", fontSize: "0.85rem" }}>
            Resultados da Consulta por Ambiente
          </span>
          <span style={{ fontSize: "0.75rem", color: "var(--text-subtle)" }}>
            ({queryResult.total_lines} total de linhas em {queryResult.duration_ms}ms)
          </span>
        </div>
        <span
          className="badge"
          style={{
            backgroundColor: queryResult.success ? "var(--status-normal-bg)" : "var(--status-firing-bg)",
            color: queryResult.success ? "var(--status-normal)" : "var(--status-firing)",
            border: `1px solid ${queryResult.success ? "var(--status-normal-border)" : "var(--status-firing-border)"}`,
          }}
        >
          {queryResult.success ? "Concluída" : "Falhou"}
        </span>
      </div>

      {/* Tabs de navegação entre os ambientes */}
      <div style={{ display: "flex", gap: "6px", marginBottom: "12px", borderBottom: "1px solid var(--border-color-subtle)", paddingBottom: "8px" }}>
        <button
          type="button"
          onClick={() => setActiveTab("sandbox")}
          style={{
            padding: "4px 10px",
            borderRadius: "6px",
            fontSize: "0.75rem",
            fontWeight: 600,
            cursor: "pointer",
            border: activeTab === "sandbox" ? "1px solid rgba(56, 189, 248, 0.5)" : "1px solid transparent",
            backgroundColor: activeTab === "sandbox" ? "rgba(56, 189, 248, 0.15)" : "rgba(255, 255, 255, 0.04)",
            color: activeTab === "sandbox" ? "#38bdf8" : "var(--text-muted)",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <span>🧪 Ambiente Sandbox</span>
          <span
            style={{
              padding: "1px 6px",
              borderRadius: "10px",
              fontSize: "0.7rem",
              backgroundColor: activeTab === "sandbox" ? "#38bdf8" : "rgba(255, 255, 255, 0.08)",
              color: activeTab === "sandbox" ? "#0f172a" : "var(--text-muted)",
              fontWeight: 700,
            }}
          >
            {sandboxEnv?.total_lines ?? 0}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("production")}
          style={{
            padding: "4px 10px",
            borderRadius: "6px",
            fontSize: "0.75rem",
            fontWeight: 600,
            cursor: "pointer",
            border: activeTab === "production" ? "1px solid rgba(52, 211, 153, 0.5)" : "1px solid transparent",
            backgroundColor: activeTab === "production" ? "rgba(52, 211, 153, 0.15)" : "rgba(255, 255, 255, 0.04)",
            color: activeTab === "production" ? "#34d399" : "var(--text-muted)",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <span>🏢 Ambiente de Produção</span>
          <span
            style={{
              padding: "1px 6px",
              borderRadius: "10px",
              fontSize: "0.7rem",
              backgroundColor: activeTab === "production" ? "#34d399" : "rgba(255, 255, 255, 0.08)",
              color: activeTab === "production" ? "#0f172a" : "var(--text-muted)",
              fontWeight: 700,
            }}
          >
            {prodEnv?.total_lines ?? 0}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab("both")}
          style={{
            padding: "4px 10px",
            borderRadius: "6px",
            fontSize: "0.75rem",
            fontWeight: 600,
            cursor: "pointer",
            border: activeTab === "both" ? "1px solid rgba(168, 85, 247, 0.5)" : "1px solid transparent",
            backgroundColor: activeTab === "both" ? "rgba(168, 85, 247, 0.15)" : "rgba(255, 255, 255, 0.04)",
            color: activeTab === "both" ? "#c084fc" : "var(--text-muted)",
          }}
        >
          📋 Ambos os Ambientes
        </button>
      </div>

      {/* Visão Ambiente Sandbox */}
      {(activeTab === "sandbox" || activeTab === "both") && (
        <div
          style={{
            padding: "10px",
            borderRadius: "8px",
            border: "1px solid rgba(56, 189, 248, 0.25)",
            backgroundColor: "rgba(56, 189, 248, 0.03)",
            marginBottom: activeTab === "both" ? "12px" : "0",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
              <span style={{ fontWeight: 700, color: "#38bdf8", fontSize: "0.8rem" }}>
                Ambiente Sandbox (Logs Sintéticos Injetados)
              </span>
              <span style={{ fontSize: "0.72rem", color: "var(--text-subtle)" }}>
                • Data source: <code style={{ color: "#38bdf8", backgroundColor: "rgba(56, 189, 248, 0.1)", padding: "1px 5px", borderRadius: "3px" }}>{sandboxEnv?.datasource_name || "sandbox"}</code>
              </span>
              {sandboxEnv && (
                <span style={{ fontSize: "0.72rem", color: "var(--text-subtle)" }}>
                  • {sandboxEnv.duration_ms}ms
                </span>
              )}
            </div>
            <span
              style={{
                fontSize: "0.7rem",
                padding: "1px 6px",
                borderRadius: "4px",
                fontWeight: 600,
                backgroundColor: sandboxEnv?.success ? "rgba(34, 197, 94, 0.15)" : "rgba(239, 68, 68, 0.15)",
                color: sandboxEnv?.success ? "#4ade80" : "#f87171",
              }}
            >
              {sandboxEnv?.success ? `${sandboxEnv.total_lines} linha(s)` : "Falhou"}
            </span>
          </div>

          {!sandboxEnv?.success && sandboxEnv?.error && (
            <div style={{ fontSize: "0.75rem", color: "var(--status-firing)", marginBottom: "6px" }}>
              {sandboxEnv.error}
            </div>
          )}

          {(!sandboxEnv?.lines || sandboxEnv.lines.length === 0) ? (
            <div style={{ padding: "8px", fontSize: "0.75rem", color: "var(--text-muted)", backgroundColor: "rgba(0,0,0,0.15)", borderRadius: "6px" }}>
              Nenhum log sintético encontrado no data source de sandbox para o período consultado.
            </div>
          ) : (
            <RenderLogLines lines={sandboxEnv.lines} accentColor="#38bdf8" />
          )}
        </div>
      )}

      {/* Visão Ambiente de Produção */}
      {(activeTab === "production" || activeTab === "both") && (
        <div
          style={{
            padding: "10px",
            borderRadius: "8px",
            border: "1px solid rgba(52, 211, 153, 0.25)",
            backgroundColor: "rgba(52, 211, 153, 0.03)",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap" }}>
              <span style={{ fontWeight: 700, color: "#34d399", fontSize: "0.8rem" }}>
                Ambiente de Produção (Telemetria do Cliente)
              </span>
              <span style={{ fontSize: "0.72rem", color: "var(--text-subtle)" }}>
                • Data source: <code style={{ color: "#34d399", backgroundColor: "rgba(52, 211, 153, 0.1)", padding: "1px 5px", borderRadius: "3px" }}>{prodEnv?.datasource_name || "produção"}</code>
              </span>
              {prodEnv && (
                <span style={{ fontSize: "0.72rem", color: "var(--text-subtle)" }}>
                  • {prodEnv.duration_ms}ms
                </span>
              )}
            </div>
            <span
              style={{
                fontSize: "0.7rem",
                padding: "1px 6px",
                borderRadius: "4px",
                fontWeight: 600,
                backgroundColor: prodEnv?.success ? "rgba(34, 197, 94, 0.15)" : "rgba(239, 68, 68, 0.15)",
                color: prodEnv?.success ? "#4ade80" : "#f87171",
              }}
            >
              {prodEnv?.success ? `${prodEnv.total_lines} linha(s)` : "Falhou"}
            </span>
          </div>

          {!prodEnv?.success && prodEnv?.error && (
            <div style={{ fontSize: "0.75rem", color: "var(--status-firing)", marginBottom: "6px" }}>
              {prodEnv.error}
            </div>
          )}

          {(!prodEnv?.lines || prodEnv.lines.length === 0) ? (
            <div style={{ padding: "8px", fontSize: "0.75rem", color: "var(--text-muted)", backgroundColor: "rgba(0,0,0,0.15)", borderRadius: "6px" }}>
              Nenhuma linha retornada para o período consultado no data source de produção.
            </div>
          ) : (
            <RenderLogLines lines={prodEnv.lines} accentColor="#34d399" />
          )}
        </div>
      )}
    </div>
  );
};

interface LogQLTimeoutNoticeProps {
  message: string;
}

/** Aviso de timeout/erro na consulta real do Loki. */
export const LogQLTimeoutNotice: React.FC<LogQLTimeoutNoticeProps> = ({ message }) => (
  <div
    style={{
      backgroundColor: "rgba(234, 179, 8, 0.1)",
      border: "1px solid rgba(234, 179, 8, 0.4)",
      color: "var(--status-pending)",
      padding: "8px 12px",
      borderRadius: "6px",
      fontSize: "0.8rem",
      marginBottom: "12px",
    }}
  >
    {message}
  </div>
);

export { LogQLEditor } from "./LogQLEditor";
