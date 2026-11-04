import React, { useState } from "react";
import { RuleImprovementEvaluation } from "../types";

interface RuleAIEvaluationPanelProps {
  evaluation: RuleImprovementEvaluation | null;
  loading: boolean;
  onRefresh: () => void;
  onImplement: () => void;
  feedback?: { type: "success" | "error"; message: string } | null;
}

export const RuleAIEvaluationPanel: React.FC<RuleAIEvaluationPanelProps> = ({
  evaluation,
  loading,
  onRefresh,
  onImplement,
  feedback,
}) => {
  const [copiedQuery, setCopiedQuery] = useState(false);

  const handleCopySuggested = () => {
    if (evaluation?.suggested_logql_query) {
      navigator.clipboard.writeText(evaluation.suggested_logql_query);
      setCopiedQuery(true);
      setTimeout(() => setCopiedQuery(false), 2000);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Header do Painel de Parecer da IA */}
      <div className="p-3.5 bg-gradient-to-r from-purple-950/40 via-indigo-950/30 to-slate-900/60 rounded-xl border border-purple-500/30 flex items-center justify-between gap-3 shadow-sm">
        <div className="flex items-center gap-2.5">
          <span className="material-symbols-outlined text-purple-400 text-[24px]">
            auto_awesome
          </span>
          <div>
            <h4 className="text-sm font-semibold text-slate-100 m-0 flex items-center gap-1.5">
              Parecer Técnico da IA
            </h4>
            <p className="text-[11px] text-slate-400 m-0">
              Análise profunda de telemetria, detecção e redução de ruído
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs shadow transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          title="Executar análise da regra com IA"
        >
          <span
            className={`material-symbols-outlined text-[16px] ${
              loading ? "animate-spin" : ""
            }`}
          >
            {loading ? "progress_activity" : "auto_awesome"}
          </span>
          {loading ? "Analisando..." : "Analisar"}
        </button>
      </div>

      {/* Feedback de implementação */}
      {feedback && (
        <div
          className={`p-3 rounded-xl border text-xs flex items-center gap-2 ${
            feedback.type === "success"
              ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-300"
              : "bg-rose-950/40 border-rose-500/40 text-rose-300"
          }`}
        >
          <span className="material-symbols-outlined text-[18px]">
            {feedback.type === "success" ? "check_circle" : "error"}
          </span>
          <span>{feedback.message}</span>
        </div>
      )}

      {/* Estado: Carregando análise */}
      {loading ? (
        <div className="p-6 bg-slate-900/50 rounded-xl border border-slate-800 text-center flex flex-col items-center justify-center gap-3">
          <div className="relative w-12 h-12 flex items-center justify-center">
            <span className="material-symbols-outlined text-[36px] text-purple-400 animate-spin">
              progress_activity
            </span>
            <span className="material-symbols-outlined text-[18px] text-indigo-300 absolute">
              auto_awesome
            </span>
          </div>
          <div className="flex flex-col gap-1 max-w-sm">
            <strong className="text-sm text-slate-200">
              Analisando regra com Inteligência Artificial
            </strong>
            <p className="text-xs text-slate-400 m-0 leading-relaxed">
              Executando faixas temporais progressivas na telemetria (15m → 1h → 6h → 24h → 3d), aferindo aderência de campos do schema Wazuh e gerando parecer técnico...
            </p>
          </div>
        </div>
      ) : evaluation ? (
        <div className="flex flex-col gap-4">
          {/* Bloco 1: Telemetria Real no Cliente (Janelas Progressivas) */}
          {evaluation.telemetry_evaluated && (
            <div className="p-4 bg-indigo-950/20 rounded-xl border border-indigo-500/30 flex flex-col gap-3 shadow-sm">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-indigo-400 text-[18px]">
                    query_stats
                  </span>
                  <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">
                    Telemetria Real no Cliente {evaluation.client_name ? `(${evaluation.client_name})` : ""}
                  </span>
                </div>
                {evaluation.is_paused_rule && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    REGRA PAUSADA
                  </span>
                )}
              </div>

              {/* Badges das 5 Janelas Progressivas */}
              <div className="flex flex-col gap-1.5">
                <span className="text-[11px] text-slate-400">
                  Janelas temporais avaliadas progressivamente:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {["15 minutos", "1 hora", "6 horas", "24 horas", "3 dias"].map((win) => {
                    const isMatched = evaluation.matched_window === win;
                    const isEvaluated = (evaluation.windows_evaluated || []).includes(win);

                    return (
                      <span
                        key={win}
                        className={`px-2.5 py-1 rounded text-xs transition-colors ${
                          isMatched
                            ? "bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/50 shadow-sm"
                            : isEvaluated
                            ? "bg-slate-800 text-slate-300 border border-slate-700"
                            : "bg-slate-900/60 text-slate-500 border border-slate-800/80"
                        }`}
                      >
                        {win} {isMatched ? `✓ (${evaluation.matched_events_count} logs)` : ""}
                      </span>
                    );
                  })}
                </div>
              </div>

              {/* Métricas de retorno e conformidade */}
              <div className="pt-2.5 border-t border-indigo-500/20 flex flex-wrap items-center justify-between gap-2 text-xs">
                <span className="text-slate-300">
                  Eventos retornados: <strong className="text-white">{evaluation.matched_events_count || 0}</strong>
                  {evaluation.matched_window ? ` na janela de ${evaluation.matched_window}` : " (0 eventos nas janelas analisadas)"}
                </span>
                {evaluation.field_compatibility_pct !== undefined && evaluation.field_compatibility_pct !== null && (
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-indigo-900/40 text-indigo-200 border border-indigo-700/50">
                    Aderência de Campos: <strong className="text-white">{evaluation.field_compatibility_pct.toFixed(0)}%</strong>
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Bloco 2: Veredito e Motor */}
          <div className="p-3.5 bg-slate-900/60 rounded-xl border border-slate-700/60 flex items-center justify-between gap-3 shadow-sm">
            <div className="flex items-center gap-2.5">
              <span
                className={`material-symbols-outlined text-[22px] ${
                  evaluation.verdict_level === "warning" ? "text-amber-400" : "text-emerald-400"
                }`}
              >
                {evaluation.verdict_level === "warning" ? "warning" : "verified"}
              </span>
              <div>
                <span className="text-[10px] uppercase font-bold text-slate-400 block">Veredito do Engenheiro</span>
                <span
                  className={`text-sm font-semibold ${
                    evaluation.verdict_level === "warning" ? "text-amber-300" : "text-emerald-300"
                  }`}
                >
                  {evaluation.verdict}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {evaluation.is_cached && (
                <span
                  className="px-2 py-0.5 rounded bg-purple-950/40 text-purple-300 border border-purple-500/30 text-[10px] font-mono flex items-center gap-1"
                  title="Parecer técnico preservado do cache da regra"
                >
                  <span className="material-symbols-outlined text-[12px]">inventory_2</span>
                  Em Cache
                </span>
              )}
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[11px] font-mono border border-slate-700">
                {evaluation.engine === "ai"
                  ? `IA: ${evaluation.model || "Universal LLM"}`
                  : "Motor Heurístico D.A.N.T.E."}
              </span>
            </div>
          </div>

          {/* Bloco 3: Cenário e Contexto de Ameaça */}
          {evaluation.threat_context && (
            <div className="p-3.5 bg-cyan-950/20 rounded-xl border border-cyan-500/30 flex flex-col gap-1.5 shadow-sm">
              <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-cyan-300">
                <span className="material-symbols-outlined text-[16px]">security</span>
                Cenário e Contexto de Ameaça
              </div>
              <p className="text-xs text-slate-200 leading-relaxed m-0">
                {evaluation.threat_context}
              </p>
            </div>
          )}

          {/* Bloco 4: Oportunidades de Melhoria & Ações Anti-Ruído */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Oportunidades de Melhoria */}
            <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-700/60 flex flex-col gap-2">
              <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wide text-purple-300">
                <span className="material-symbols-outlined text-[16px]">tune</span>
                Oportunidades de Melhoria
              </div>
              <ul className="m-0 pl-4 text-xs text-slate-300 space-y-1">
                {(evaluation.improvements || []).map((imp, idx) => (
                  <li key={idx} className="leading-normal">{imp}</li>
                ))}
              </ul>
            </div>

            {/* Ações Anti-Ruído */}
            <div className="p-3 bg-slate-900/50 rounded-xl border border-slate-700/60 flex flex-col gap-2">
              <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wide text-amber-300">
                <span className="material-symbols-outlined text-[16px]">noise_control_off</span>
                Ações Anti-Ruído
              </div>
              <ul className="m-0 pl-4 text-xs text-slate-300 space-y-1">
                {(evaluation.noise_reduction_actions || []).map((act, idx) => (
                  <li key={idx} className="leading-normal">{act}</li>
                ))}
              </ul>
            </div>
          </div>

          {/* Bloco 5: Expressão LogQL Sugerida */}
          {evaluation.suggested_logql_query && (
            <div className="p-4 bg-gradient-to-br from-purple-950/20 via-slate-900/60 to-indigo-950/20 rounded-xl border border-purple-500/30 flex flex-col gap-3 shadow-sm">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-purple-400 text-[20px]">
                    bolt
                  </span>
                  <div>
                    <h5 className="text-xs font-bold uppercase tracking-wider text-purple-300 m-0">
                      Expressão LogQL Otimizada Sugerida
                    </h5>
                    <span className="text-[11px] text-slate-400">
                      Validação sintática e de compliance aplicada
                    </span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleCopySuggested}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition-colors"
                >
                  <span className="material-symbols-outlined text-[14px] text-slate-400">
                    {copiedQuery ? "check" : "content_copy"}
                  </span>
                  {copiedQuery ? "Copiado!" : "Copiar"}
                </button>
              </div>

              {/* Caixa com o código sugerido */}
              <div className="p-3 bg-[#090D16] rounded-lg border border-slate-800 font-mono text-xs text-purple-300 leading-relaxed overflow-x-auto shadow-inner">
                {evaluation.suggested_logql_query}
              </div>
            </div>
          )}

          {/* Resumo das melhorias e ajustes prontos para aplicação */}
          {evaluation.diff_summary && evaluation.diff_summary.length > 0 && (
            <div className="p-3.5 bg-slate-900/50 rounded-xl border border-slate-700/60 flex flex-col gap-2 shadow-sm">
              <span className="text-xs font-bold uppercase tracking-wide text-slate-300 flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px] text-purple-400">playlist_add_check</span>
                Benefícios e Ajustes Recomendados:
              </span>
              <ul className="m-0 pl-4 text-xs text-slate-300 space-y-1">
                {evaluation.diff_summary.map((d, i) => (
                  <li key={i} className="leading-normal">{d}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Bloco 6: Botão de Implementar Sugestões sob a análise */}
          <div className="p-4 bg-gradient-to-r from-purple-950/40 via-indigo-950/30 to-slate-900/60 rounded-xl border border-purple-500/40 flex items-center justify-between gap-3 shadow-md">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300">
                <span className="material-symbols-outlined text-[20px]">
                  auto_awesome
                </span>
              </div>
              <div>
                <span className="text-xs font-bold text-slate-100 block">
                  Implementação de Recomendações Técnicas
                </span>
                <span className="text-[11px] text-slate-400">
                  Aplica as otimizações recomendadas pela IA diretamente na engine de alertas
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={onImplement}
              disabled={loading}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white font-semibold text-xs shadow-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              <span className="material-symbols-outlined text-[16px]">
                auto_awesome
              </span>
              Implementar Sugestões
            </button>
          </div>
        </div>
      ) : (
        <div className="p-6 bg-slate-900/40 rounded-xl border border-slate-800 text-center flex flex-col items-center justify-center gap-3">
          <span className="material-symbols-outlined text-[32px] text-slate-500">
            analytics
          </span>
          <div className="flex flex-col gap-1 max-w-sm">
            <strong className="text-sm text-slate-200">
              Nenhuma avaliação gerada ainda
            </strong>
            <p className="text-xs text-slate-400 m-0">
              Clique em "Reavaliar com IA" para consultar a telemetria do cliente e gerar o parecer técnico completo.
            </p>
          </div>
          <button
            type="button"
            onClick={onRefresh}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-medium text-xs transition-colors"
          >
            <span className="material-symbols-outlined text-[16px]">auto_awesome</span>
            Gerar Parecer com IA
          </button>
        </div>
      )}
    </div>
  );
};

