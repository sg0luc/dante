import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { ExecuteQueryResult, LogQLLintResult } from "../types";

/**
 * Resultado padronizado das operações de assistência LogQL.
 * `data` nulo indica falha e `error` traz a mensagem para o operador.
 */
export interface AssistOutcome<T> {
  data: T | null;
  error: string | null;
}

/** Gate de submissão: garante que a query só é persistida se o linting aprovar. */
export interface LintGate {
  ok: boolean;
  lint: LogQLLintResult | null;
  error: string | null;
}

/** Opções de execução da query LogQL (escopo baseline/cliente e janela temporal). */
export interface RunQueryOptions {
  scope?: "baseline" | "client";
  client_uid?: string;
  time_range_from?: string;
  time_range_to?: string;
  limit?: number;
}

const NETWORK_LINT_ERROR = "Erro ao validar sintaxe LogQL.";
const EMPTY_QUERY_ERROR = "Informe a query LogQL.";

function toMessage(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

/**
 * Hook compartilhado de edição de LogQL: linting sintático/semântico e
 * execução real da query contra o datasource do Grafana.
 *
 * Usado tanto pelo modal de criação de regra (página "Regras") quanto pelo
 * modal de implementação de uma regra baseline em um cliente
 * (página "Mapa de Adesão"), para que os dois fluxos tenham exatamente
 * o mesmo poder de validação antes de persistir a regra.
 *
 * Qualquer alteração em `query` invalida o linting anterior (cache local),
 * forçando re-validação antes de um novo submit.
 */
export function useLogQLAssist(query: string) {
  const [lintResult, setLintResult] = useState<LogQLLintResult | null>(null);
  const [linting, setLinting] = useState(false);
  const [queryResult, setQueryResult] = useState<ExecuteQueryResult | null>(null);
  const [executing, setExecuting] = useState(false);
  const [timeoutNotification, setTimeoutNotification] = useState<string | null>(null);

  // A query mudou: o resultado de linting deixa de valer para o novo texto.
  useEffect(() => {
    setLintResult(null);
  }, [query]);

  /** Limpa todos os resultados (usado ao abrir/fechar o modal). */
  const reset = useCallback(() => {
    setLintResult(null);
    setQueryResult(null);
    setTimeoutNotification(null);
  }, []);

  const lint = useCallback(async (rawQuery: string): Promise<AssistOutcome<LogQLLintResult>> => {
    const trimmed = rawQuery.trim();
    if (!trimmed) return { data: null, error: EMPTY_QUERY_ERROR };
    setLinting(true);
    try {
      const res = await api.lintLogQL(trimmed);
      setLintResult(res);
      return { data: res, error: null };
    } catch (err: unknown) {
      return { data: null, error: toMessage(err, NETWORK_LINT_ERROR) };
    } finally {
      setLinting(false);
    }
  }, []);


  const run = useCallback(
    async (
      rawQuery: string,
      options?: RunQueryOptions
    ): Promise<AssistOutcome<ExecuteQueryResult>> => {
      const trimmed = rawQuery.trim();
      if (!trimmed) return { data: null, error: EMPTY_QUERY_ERROR };
      setExecuting(true);
      setTimeoutNotification(null);
      try {
        const res = await api.executeQuery(
          trimmed,
          options?.time_range_from ?? "now-1h",
          options?.time_range_to ?? "now",
          options?.limit ?? 25,
          {
            scope: options?.scope,
            client_uid: options?.client_uid,
          }
        );
        setQueryResult(res);
        if (res.is_timeout) {
          setTimeoutNotification(
            "ATENÇÃO: A consulta LogQL atingiu o tempo limite (Timeout) no Grafana. Verifique o volume de dados ou restrinja o seletor de stream."
          );
        } else if (!res.success && res.error) {
          setTimeoutNotification(`Erro ao consultar query: ${res.error}`);
        }
        return { data: res, error: res.success ? null : (res.error ?? "Falha na consulta") };
      } catch (err: unknown) {
        const msg = toMessage(err, "Erro ao consultar query.");
        setTimeoutNotification(`Erro ao consultar query: ${msg}`);
        return { data: null, error: msg };
      } finally {
        setExecuting(false);
      }
    },
    []
  );

  /**
   * Reaproveita o linting já feito para a mesma query ou dispara um novo e
   * decide se a submissão pode prosseguir. Regra de negócio: nunca persistir
   * uma regra cuja query LogQL não foi aprovada pelo linter.
   */
  const assertValid = useCallback(
    async (rawQuery: string): Promise<LintGate> => {
      const trimmed = rawQuery.trim();
      if (!trimmed) return { ok: false, lint: null, error: EMPTY_QUERY_ERROR };

      let current = lintResult?.query === trimmed ? lintResult : null;
      if (!current) {
        const outcome = await lint(trimmed);
        if (!outcome.data) {
          return { ok: false, lint: null, error: outcome.error ?? NETWORK_LINT_ERROR };
        }
        current = outcome.data;
      }

      if (!current.is_valid) {
        const errorMsgs = current.issues.filter((i) => i.level === "error").map((i) => i.message);
        return {
          ok: false,
          lint: current,
          error: `A query LogQL possui erros que impedem sua execução: ${
            errorMsgs.join("; ") || current.message
          }`,
        };
      }

      return { ok: true, lint: current, error: null };
    },
    [lint, lintResult]
  );

  return {
    lintResult,
    linting,
    queryResult,
    executing,
    timeoutNotification,
    reset,
    lint,
    run,
    assertValid,
  };
}
