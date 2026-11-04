import React, { useState } from "react";
import { RuleDetail } from "../types";
import { StatusBadge } from "./StatusBadge";
import { DeployStatusBadge } from "./DeployStatusBadge";

interface RuleGrafanaBlocksProps {
  rule: RuleDetail;
}

export const RuleGrafanaBlocks: React.FC<RuleGrafanaBlocksProps> = ({ rule }) => {
  const [copiedQuery, setCopiedQuery] = useState(false);
  const [copiedUid, setCopiedUid] = useState(false);

  // Mapeia queries para os blocos Grafana (A, B, C)
  const queryA = rule.queries.find((q) => q.ref_id === "A") || rule.queries[0];
  const queryB = rule.queries.find((q) => q.ref_id === "B");
  const queryC = rule.queries.find((q) => q.ref_id === "C");
  const extraQueries = rule.queries.filter(
    (q) => !["A", "B", "C"].includes(q.ref_id)
  );

  // Extrai LogQL do Bloco A
  const logqlExpr =
    (queryA?.model?.expr as string) ||
    rule.annotations?.logql_query ||
    "";

  // Extrai detalhes do Bloco B (Reduce / Math)
  const bModel = queryB?.model || {};
  const bType = (bModel.type as string) || "reduce";
  const bInput = (bModel.expression as string) || "A";
  const bReducer = (bModel.reducer as string) || "last";

  // Extrai detalhes do Bloco C (Threshold Condition)
  const cModel = queryC?.model || {};
  const cConditions = (cModel.conditions as Array<{
    evaluator?: { params?: number[]; type?: string };
  }>) || [];
  const cEvaluatorType = cConditions[0]?.evaluator?.type || "gt";
  const cEvaluatorParam = cConditions[0]?.evaluator?.params?.[0] ?? 0;
  const isConditionC = rule.condition === "C" || !rule.condition;

  const handleCopyLogql = () => {
    if (logqlExpr) {
      navigator.clipboard.writeText(logqlExpr);
      setCopiedQuery(true);
      setTimeout(() => setCopiedQuery(false), 2000);
    }
  };

  const handleCopyUid = () => {
    navigator.clipboard.writeText(rule.uid);
    setCopiedUid(true);
    setTimeout(() => setCopiedUid(false), 2000);
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Barra de Metadados Rápidos do Grafana */}
      <div className="p-3.5 bg-slate-900/60 rounded-xl border border-slate-700/60 flex flex-wrap items-center justify-between gap-3 shadow-sm">
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge state={rule.state} type="rule" />
          <DeployStatusBadge status={rule.deploy_status} />
          {rule.is_paused && (
            <span className="px-2 py-0.5 rounded text-[11px] font-bold uppercase tracking-wide bg-rose-500/20 text-rose-300 border border-rose-500/30">
              Pausada
            </span>
          )}
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800/80 text-slate-300 text-xs border border-slate-700">
            <span className="material-symbols-outlined text-[14px] text-slate-400">folder</span>
            <strong>{rule.folder_title}</strong>
          </span>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800/80 text-slate-300 text-xs border border-slate-700">
            <span className="material-symbols-outlined text-[14px] text-slate-400">schedule</span>
            Grupo: <strong>{rule.rule_group || "5m"}</strong>
          </span>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            type="button"
            onClick={handleCopyUid}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            title="Copiar UID da regra"
          >
            <span className="material-symbols-outlined text-[13px] text-slate-400">
              {copiedUid ? "check" : "fingerprint"}
            </span>
            <code className="text-[11px] text-slate-300">{rule.uid}</code>
            {copiedUid && <span className="text-[10px] text-emerald-400 font-medium">Copiado</span>}
          </button>
          <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
            <span className="material-symbols-outlined text-[13px] text-slate-400">notifications</span>
            Receiver: <strong className="text-primary font-mono">{rule.contact_point || "dev"}</strong>
          </span>
        </div>
      </div>

      {/* BLOCO A: Query LogQL (Telemetria) */}
      <div className="rounded-xl border border-blue-500/30 bg-slate-900/50 overflow-hidden shadow-sm">
        {/* Header Bloco A estilo Grafana Alerting */}
        <div className="px-4 py-2.5 bg-blue-950/40 border-b border-blue-500/20 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <span className="w-6 h-6 rounded flex items-center justify-center font-black text-xs bg-[#1F60C4] text-white shadow-sm border border-[#3871dc]">
              A
            </span>
            <span className="text-sm font-semibold text-slate-100 flex items-center gap-1.5">
              Query (Telemetria)
            </span>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-blue-900/40 text-blue-300 border border-blue-700/50">
              <span className="material-symbols-outlined text-[12px]">storage</span>
              {rule.folder_title ? `${rule.folder_title} (Telemetria)` : "Engine de Telemetria"}
            </span>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] bg-slate-800/80 text-slate-300 border border-slate-700">
              <span className="material-symbols-outlined text-[12px] text-slate-400">timelapse</span>
              Range: 5m
            </span>
            <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-slate-800 text-slate-400 border border-slate-700">
              Range Query
            </span>
          </div>
        </div>

        {/* Editor Code LogQL estilo Grafana */}
        <div className="p-3.5 flex flex-col gap-2">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="flex items-center gap-1 font-mono text-[11px] text-blue-300/80">
              <span className="material-symbols-outlined text-[13px]">terminal</span>
              Expressão LogQL
            </span>
            <button
              type="button"
              onClick={handleCopyLogql}
              disabled={!logqlExpr}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors text-[11px]"
              title="Copiar expressão LogQL"
            >
              <span className="material-symbols-outlined text-[13px] text-blue-400">
                {copiedQuery ? "check" : "content_copy"}
              </span>
              {copiedQuery ? "Copiado!" : "Copiar LogQL"}
            </button>
          </div>

          <div className="p-3.5 bg-[#090D16] rounded-lg border border-slate-800/80 font-mono text-xs text-emerald-400 leading-relaxed overflow-x-auto shadow-inner selection:bg-blue-600/30">
            {logqlExpr || "// Nenhuma expressão LogQL encontrada na query A"}
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-slate-400">
            <span>
              Editor Mode: <code className="text-slate-300">code</code>
            </span>
            <span>•</span>
            <span>
              Max Data Points: <code className="text-slate-300">43200</code>
            </span>
            <span>•</span>
            <span>
              Interval: <code className="text-slate-300">1000ms</code>
            </span>
          </div>
        </div>
      </div>

      {/* BLOCO B: Expressão de Transformação (Reduce / Math) */}
      <div className="rounded-xl border border-amber-500/30 bg-slate-900/50 overflow-hidden shadow-sm">
        {/* Header Bloco B estilo Grafana Alerting */}
        <div className="px-4 py-2.5 bg-amber-950/30 border-b border-amber-500/20 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <span className="w-6 h-6 rounded flex items-center justify-center font-black text-xs bg-[#F2994A] text-slate-950 shadow-sm border border-[#F2C94C]">
              B
            </span>
            <span className="text-sm font-semibold text-slate-100 flex items-center gap-1.5">
              Expressão ({bType === "reduce" ? "Reduce" : "Math"})
            </span>
          </div>

          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium bg-amber-900/30 text-amber-300 border border-amber-700/40">
            <span className="material-symbols-outlined text-[12px]">functions</span>
            Pipeline de Expressões (__expr__)
          </span>
        </div>

        {/* Pipeline Visual de Processamento Grafana */}
        <div className="p-3.5 flex flex-col gap-3">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 items-center">
            {/* Entrada */}
            <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center gap-2.5">
              <span className="w-5 h-5 rounded flex items-center justify-center font-bold text-[10px] bg-[#1F60C4] text-white">
                {bInput}
              </span>
              <div className="flex flex-col text-[11px]">
                <span className="text-slate-400">Entrada</span>
                <span className="font-semibold text-slate-200">Query [{bInput}]</span>
              </div>
            </div>

            {/* Operação */}
            <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center gap-2.5">
              <span className="material-symbols-outlined text-amber-400 text-[18px]">
                tune
              </span>
              <div className="flex flex-col text-[11px]">
                <span className="text-slate-400">Operação / Função</span>
                <span className="font-semibold text-amber-300 uppercase tracking-wide">
                  {bType}: {bReducer}
                </span>
              </div>
            </div>

            {/* Saída */}
            <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800 flex items-center gap-2.5">
              <span className="w-5 h-5 rounded flex items-center justify-center font-bold text-[10px] bg-[#F2994A] text-slate-950">
                B
              </span>
              <div className="flex flex-col text-[11px]">
                <span className="text-slate-400">Saída Gerada</span>
                <span className="font-semibold text-slate-200">Valor Escalar [B]</span>
              </div>
            </div>
          </div>

          <p className="text-[11px] text-slate-400 leading-normal">
            Agrega a série temporal de eventos da <strong>Query [{bInput}]</strong> extraindo o último
            valor instantâneo (<code>{bReducer}</code>) em modo estrito para avaliação de limiar.
          </p>
        </div>
      </div>

      {/* BLOCO C: Condição de Disparo (Alert Condition / Threshold) */}
      <div className="rounded-xl border border-rose-500/30 bg-slate-900/50 overflow-hidden shadow-sm">
        {/* Header Bloco C estilo Grafana Alerting */}
        <div className="px-4 py-2.5 bg-rose-950/30 border-b border-rose-500/20 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2.5">
            <span className="w-6 h-6 rounded flex items-center justify-center font-black text-xs bg-[#EB5757] text-white shadow-sm border border-[#FF6B6B]">
              C
            </span>
            <span className="text-sm font-semibold text-slate-100 flex items-center gap-1.5">
              Condição de Disparo (Threshold)
            </span>
            {isConditionC && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/40">
                <span className="material-symbols-outlined text-[12px]">notifications_active</span>
                Condição Ativa
              </span>
            )}
          </div>

          <span className="text-[11px] text-slate-400">
            Disparo quando: <strong className="text-rose-300 font-mono">B {cEvaluatorType === "gt" ? ">" : cEvaluatorType} {cEvaluatorParam}</strong>
          </span>
        </div>

        {/* Avaliação de Limiar e Opções da Regra */}
        <div className="p-3.5 flex flex-col gap-3.5">
          {/* Card de Threshold */}
          <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span className="w-5 h-5 rounded flex items-center justify-center font-bold text-[10px] bg-[#F2994A] text-slate-950">
                B
              </span>
              <span className="text-xs text-slate-300 font-medium">Entrada avaliada</span>
              <span className="material-symbols-outlined text-[14px] text-slate-500">arrow_forward</span>
              <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950 text-rose-300 border border-rose-800/80">
                IS ABOVE (MAIOR QUE) {cEvaluatorParam}
              </span>
            </div>

            <div className="text-[11px] text-slate-400">
              Estado: <span className="text-emerald-400 font-semibold">Firing se B &gt; {cEvaluatorParam}</span>
            </div>
          </div>

          {/* Configurações Operacionais do Grafana */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-800/80 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase tracking-wide">Avaliar a cada</span>
              <span className="font-semibold text-slate-200 mt-0.5">{rule.rule_group || "5m"}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-800/80 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase tracking-wide">Tempo de Espera (For)</span>
              <span className="font-semibold text-slate-200 mt-0.5">{rule.for_duration || "0s"}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-800/80 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase tracking-wide">Sem Dados (No Data)</span>
              <span className="font-semibold text-slate-200 mt-0.5">{rule.no_data_state || "OK"}</span>
            </div>
            <div className="p-2.5 bg-slate-950/40 rounded-lg border border-slate-800/80 flex flex-col">
              <span className="text-[10px] text-slate-400 uppercase tracking-wide">Erro de Execução</span>
              <span className="font-semibold text-slate-200 mt-0.5">{rule.exec_err_state || "Error"}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Outras Queries (se houver) */}
      {extraQueries.map((q) => (
        <div key={q.ref_id} className="rounded-xl border border-slate-700 bg-slate-900/50 p-3 text-xs font-mono">
          <div className="font-bold text-slate-300 mb-1">Query [{q.ref_id}]</div>
          <pre className="text-[11px] text-slate-400 overflow-x-auto">
            {JSON.stringify(q.model, null, 2)}
          </pre>
        </div>
      ))}

      {/* Anotações da Regra */}
      {rule.annotations && Object.keys(rule.annotations).length > 0 && (
        <div className="p-3.5 bg-slate-900/50 rounded-xl border border-slate-700/60 flex flex-col gap-2.5">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <span className="material-symbols-outlined text-[15px] text-slate-400">notes</span>
            Anotações da Regra
          </h4>
          <div className="flex flex-col gap-2 text-xs">
            {rule.annotations.summary && (
              <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">Resumo (summary)</span>
                <span className="text-slate-200 font-medium">{rule.annotations.summary}</span>
              </div>
            )}
            {rule.annotations.description && (
              <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800">
                <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">Descrição (description)</span>
                <span className="text-slate-300 leading-relaxed">{rule.annotations.description}</span>
              </div>
            )}
            {Object.entries(rule.annotations)
              .filter(([k]) => !["summary", "description", "logql_query"].includes(k))
              .map(([k, v]) => (
                <div key={k} className="p-2 bg-slate-950/40 rounded border border-slate-800/80 flex items-start gap-2">
                  <span className="font-semibold text-slate-400 font-mono text-[11px]">{k}:</span>
                  <span className="text-slate-300 break-all">{v}</span>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Labels / Tags da Regra (Grafana Tags) */}
      <div className="p-3.5 bg-slate-900/50 rounded-xl border border-slate-700/60 flex flex-col gap-2.5">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <span className="material-symbols-outlined text-[15px] text-slate-400">label</span>
          Labels & Classificação
        </h4>
        <div className="flex flex-wrap gap-1.5">
          {Object.entries(rule.labels || {}).map(([k, v]) => {
            const isMitre = k.startsWith("mitre_");
            const isSeverity = k === "severity";
            const isTech = k.startsWith("technology");

            let valColor = "bg-slate-900 text-slate-300 border-slate-700";
            if (isSeverity) {
              if (v === "critical") valColor = "bg-rose-950 text-rose-300 border-rose-800 font-bold";
              else if (v === "high") valColor = "bg-amber-950 text-amber-300 border-amber-800 font-bold";
              else if (v === "medium") valColor = "bg-yellow-950 text-yellow-300 border-yellow-800";
              else valColor = "bg-blue-950 text-blue-300 border-blue-800";
            } else if (isMitre) {
              valColor = "bg-purple-950/80 text-purple-200 border-purple-800/80";
            } else if (isTech) {
              valColor = "bg-cyan-950/80 text-cyan-200 border-cyan-800/80";
            }

            return (
              <div key={k} className="inline-flex text-[11px] shadow-sm">
                <span className="px-2 py-0.5 rounded-l bg-slate-800 text-slate-400 font-mono border-y border-l border-slate-700">
                  {k}
                </span>
                <span className={`px-2 py-0.5 rounded-r font-mono border-y border-r ${valColor}`}>
                  {v}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Alerta de Erro de Avaliação (se houver) */}
      {rule.last_error && (
        <div className="p-3 bg-rose-950/40 rounded-xl border border-rose-500/40 text-rose-200 text-xs flex items-start gap-2.5">
          <span className="material-symbols-outlined text-rose-400 text-[18px] shrink-0 mt-0.5">
            error
          </span>
          <div>
            <strong className="block text-rose-300 font-semibold mb-0.5">Último erro de avaliação na engine:</strong>
            <p className="font-mono text-[11px] leading-relaxed text-rose-200/90 m-0 break-all">
              {rule.last_error}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
