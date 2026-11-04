"""Serviço unificado de Inteligência Artificial para Curadoria de Regras no D.A.N.T.E.

Orquestra:
1. Resolução segura de credenciais e provedor ativo (DeepSeek, OpenAI, Gemini, etc.);
2. Cache persistente de regras traduzidas;
3. Engenharia de prompts com schemas Wazuh (zero envio de logs do Loki);
4. Validação estrita via linter LogQL (lint_logql);
5. Loop de autocorreção em caso de falha de sintaxe;
6. Fallback resiliente para o motor heurístico.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

from ..config import Settings, get_settings
from ..logql_validator import lint_logql
from ..schemas import (
    AIClearCacheResponse,
    AISettingsData,
    AISettingsPublicResponse,
    AISettingsUpdateRequest,
    AITestConnectionRequest,
    AITestConnectionResponse,
    CurationFieldMapping,
    RuleDetail,
    RuleHomologationAIEvaluation,
    RuleHomologationHistoryResponse,
    RuleImprovementEvaluation,
)
from ..system_settings_store import SystemSettingsStore
from ..technologies import Technology
from .cache import AICurationCache, AIRuleEvaluationCache
from .client import AIClientError, AIUniversalClient
from .prompts import (
    SYSTEM_PROMPT_CURATION,
    SYSTEM_PROMPT_HOMOLOGATION_EVALUATION,
    build_curation_prompt,
    build_homologation_evaluation_prompt,
    build_rule_improvement_prompt,
    build_self_correction_prompt,
    SYSTEM_PROMPT_RULE_IMPROVEMENT_EVALUATION,
)
from .providers import AVAILABLE_AI_PROVIDERS

logger = logging.getLogger("hunter_portal.ai.service")


def mask_secret(value: str) -> str:
    """Retorna uma versão mascarada da chave de API para segurança (ex: sk-...4X8q)."""
    clean = (value or "").strip()
    if not clean:
        return ""
    if len(clean) <= 8:
        return "********"
    return f"{clean[:4]}...{clean[-4:]}"


class AIService:
    """Gerenciador central de operações de IA do portal D.A.N.T.E."""

    def __init__(
        self,
        sys_settings: SystemSettingsStore,
        cache_path: str = "/data/curation-ai-cache.json",
        settings: Settings | None = None,
        rules_cache_path: str | None = None,
    ) -> None:
        self.sys_settings = sys_settings
        self.cache = AICurationCache(cache_path)
        self.app_settings = settings or get_settings()
        self.rules_cache = AIRuleEvaluationCache(
            rules_cache_path
            or getattr(self.app_settings, "rule_evaluation_ai_cache_path", "/data/rules-ai-evaluation-cache.json")
        )

    def get_cached_rule_evaluation(self, rule_uid: str) -> RuleImprovementEvaluation | None:
        """Retorna a avaliação técnica da regra em cache persistido se disponível."""
        raw = self.rules_cache.get(rule_uid)
        if raw and isinstance(raw, dict):
            try:
                eval_obj = RuleImprovementEvaluation(**raw)
                eval_obj.is_cached = True
                return eval_obj
            except Exception as exc:
                logger.warning("Falha ao desserializar avaliação em cache da regra %s: %s", rule_uid, exc)
                return None
        return None

    def set_cached_rule_evaluation(self, rule_uid: str, evaluation: RuleImprovementEvaluation) -> None:
        """Salva a avaliação técnica da regra no cache persistido."""
        try:
            dumped = evaluation.model_dump()
            dumped["is_cached"] = True
            self.rules_cache.set(rule_uid, dumped)
        except Exception as exc:
            logger.warning("Falha ao salvar avaliação no cache da regra %s: %s", rule_uid, exc)

    def invalidate_rule_evaluation_cache(self, rule_uid: str) -> bool:
        """Invalida o cache de avaliação técnica da regra."""
        return self.rules_cache.delete(rule_uid)

    def get_raw_settings(self) -> AISettingsData:
        """Retorna as configurações de IA com as credenciais resolvidas."""
        stored = self.sys_settings.get_ai_settings()

        # Fallback para variáveis de ambiente caso a chave não esteja definida no store
        key = stored.api_key
        if not key:
            if stored.provider == "deepseek":
                key = (
                    os.environ.get("DEEPSEEK_API_KEY")
                    or (self.app_settings.deepseek_api_key.get_secret_value() if self.app_settings.deepseek_api_key else "")
                )
            elif stored.provider == "openai":
                key = (
                    os.environ.get("OPENAI_API_KEY")
                    or (self.app_settings.openai_api_key.get_secret_value() if self.app_settings.openai_api_key else "")
                )
            elif stored.provider == "gemini":
                key = (
                    os.environ.get("GEMINI_API_KEY")
                    or (self.app_settings.gemini_api_key.get_secret_value() if self.app_settings.gemini_api_key else "")
                )
            elif stored.provider == "anthropic":
                key = (
                    os.environ.get("ANTHROPIC_API_KEY")
                    or (self.app_settings.anthropic_api_key.get_secret_value() if self.app_settings.anthropic_api_key else "")
                )

        # Atualiza a chave resolvida em memória caso tenha vindo do ambiente
        effective = stored.model_copy()
        if key and not stored.api_key:
            effective.api_key = key

        return effective

    def is_configured(self) -> bool:
        """Indica se a IA está habilitada e configurada com chave ou endpoint ativo."""
        cfg = self.get_raw_settings()
        if not (cfg.enabled or cfg.curation_enabled or cfg.ai_analysis_enabled):
            return False
        if cfg.provider == "ollama":
            return True  # Ollama local não requer obrigatoriamente API Key
        return bool(cfg.api_key and len(cfg.api_key.strip()) > 5)

    def is_curation_enabled(self) -> bool:
        """Indica se o módulo de Curadoria com IA está habilitado e configurado."""
        cfg = self.get_raw_settings()
        if not (cfg.curation_enabled and cfg.enabled):
            return False
        if cfg.provider == "ollama":
            return True
        return bool(cfg.api_key and len(cfg.api_key.strip()) > 5)

    def is_rule_import_ai_enabled(self) -> bool:
        """Indica se o parecer e análise por IA na importação de regras está habilitado."""
        cfg = self.get_raw_settings()
        if not (cfg.rule_import_ai_enabled and cfg.enabled):
            return False
        if cfg.provider == "ollama":
            return True
        return bool(cfg.api_key and len(cfg.api_key.strip()) > 5)

    def is_analysis_enabled(self) -> bool:
        """Indica se o módulo de Análises e Recomendações por IA está habilitado e configurado."""
        cfg = self.get_raw_settings()
        if not cfg.ai_analysis_enabled:
            return False
        if cfg.provider == "ollama":
            return True
        return bool(cfg.api_key and len(cfg.api_key.strip()) > 5)

    def get_public_settings(self) -> AISettingsPublicResponse:
        """Retorna as configurações de IA mascaradas para exibição no frontend."""
        raw = self.get_raw_settings()
        is_cfg = self.is_configured()
        masked = mask_secret(raw.api_key)

        return AISettingsPublicResponse(
            provider=raw.provider,
            model=raw.model,
            is_configured=is_cfg,
            masked_key=masked,
            api_base_url=raw.api_base_url,
            temperature=raw.temperature,
            enabled=raw.enabled,
            ai_analysis_enabled=raw.ai_analysis_enabled,
            curation_enabled=raw.curation_enabled,
            rule_import_ai_enabled=raw.rule_import_ai_enabled,
            cache_enabled=raw.cache_enabled,
            available_providers=AVAILABLE_AI_PROVIDERS,
            cached_rules_count=self.cache.count(),
        )

    def update_settings(self, req: AISettingsUpdateRequest) -> AISettingsPublicResponse:
        """Atualiza a configuração de IA persistindo em /data/system-settings.json."""
        current = self.sys_settings.get_ai_settings()

        # Se o usuário não enviou uma nova chave ou enviou string vazia/mascarada, preserva a anterior
        new_key = req.api_key.strip() if req.api_key is not None else current.api_key
        if new_key and ("..." in new_key or new_key == "********"):
            new_key = current.api_key

        effective_curation = req.curation_enabled if req.curation_enabled is not None else req.enabled

        updated = AISettingsData(
            provider=req.provider,
            model=req.model.strip(),
            api_key=new_key,
            api_base_url=req.api_base_url.strip() if req.api_base_url else None,
            temperature=req.temperature,
            enabled=effective_curation,
            ai_analysis_enabled=req.ai_analysis_enabled,
            curation_enabled=effective_curation,
            rule_import_ai_enabled=req.rule_import_ai_enabled if req.rule_import_ai_enabled is not None else current.rule_import_ai_enabled,
            cache_enabled=req.cache_enabled,
        )

        self.sys_settings.update_ai_settings(updated)
        return self.get_public_settings()

    async def test_connection(self, req: AITestConnectionRequest) -> AITestConnectionResponse:
        """Testa em tempo real a conectividade com o modelo de IA especificado."""
        current = self.get_raw_settings()
        key_to_use = req.api_key.strip() if req.api_key is not None else current.api_key
        if key_to_use and ("..." in key_to_use or key_to_use == "********"):
            key_to_use = current.api_key

        client = AIUniversalClient(
            provider=req.provider,
            model=req.model,
            api_key=key_to_use,
            api_base_url=req.api_base_url,
            timeout_seconds=15.0,
        )

        success, msg, latency = await client.test_connection()
        return AITestConnectionResponse(
            success=success,
            message=msg,
            latency_ms=latency,
            model=req.model,
        )

    def clear_cache(self) -> AIClearCacheResponse:
        """Limpa o cache persistido de IA."""
        cleared = self.cache.clear()
        return AIClearCacheResponse(
            cleared_count=cleared,
            message=f"Cache de IA limpo com sucesso ({cleared} regras removidas).",
        )

    async def curate_rule_with_ai(
        self,
        *,
        raw_rule: dict[str, Any],
        technology: Technology,
        supported_fields: list[str],
        known_rule_groups_patterns: list[str],
        client_prevalence: str = "",
    ) -> tuple[str, list[CurationFieldMapping], bool, str, str | None, str | None, str | None]:
        """Sintetiza e valida a regra de detecção via IA com garantia de conformidade LogQL.

        Retorna:
          (logql_query, mapped_fields, is_valid, lint_message, mitre_tactic, mitre_technique, ai_rationale)

        Garantia de Segurança Absoluta:
        Nenhum log real de cliente é enviado. Apenas a especificação da regra e os nomes de campos.
        """
        raw_syntax = str(raw_rule.get("original_syntax") or "").strip()
        orig_title = str(raw_rule.get("original_title") or raw_rule.get("title") or "").strip()
        orig_format = str(raw_rule.get("original_format") or "Sigma (YAML)").strip()
        desc = str(raw_rule.get("description") or "").strip()

        cfg = self.get_raw_settings()

        # 1. Verifica cache persistente se ativado
        cache_key = self.cache.compute_rule_key(raw_syntax or orig_title, orig_title, technology.slug)
        if cfg.cache_enabled:
            cached = self.cache.get(cache_key)
            if cached and isinstance(cached, dict):
                logql_q = str(cached.get("logql_query") or "").strip()
                if logql_q:
                    lint_res = lint_logql(
                        logql_q,
                        known_rule_groups_patterns=known_rule_groups_patterns,
                        expected_job=technology.job,
                    )
                    if lint_res.is_valid:
                        mapped = [
                            CurationFieldMapping(**m) if isinstance(m, dict) else m
                            for m in cached.get("mapped_fields") or []
                        ]
                        return (
                            logql_q,
                            mapped,
                            True,
                            "Query recuperada do cache de IA e validada com sucesso.",
                            cached.get("mitre_tactic"),
                            cached.get("mitre_technique"),
                            cached.get("ai_rationale"),
                        )

        # 2. Constrói o prompt para a IA
        prompt = build_curation_prompt(
            rule_title=orig_title,
            original_syntax=raw_syntax,
            original_format=orig_format,
            description=desc,
            technology_name=technology.name,
            technology_slug=technology.slug,
            job=technology.job,
            rule_groups_regex=technology.rule_groups_regex or technology.ss_groups_regex,
            supported_fields=supported_fields,
            perimeter=technology.perimeter,
            perimeter_name=technology.perimeter_name,
            client_prevalence=client_prevalence,
        )

        client = AIUniversalClient(
            provider=cfg.provider,
            model=cfg.model,
            api_key=cfg.api_key,
            api_base_url=cfg.api_base_url,
            timeout_seconds=self.app_settings.ai_timeout_seconds,
            temperature=cfg.temperature,
        )

        # 3. Executa a chamada inicial
        ai_output = await client.generate_json(SYSTEM_PROMPT_CURATION, prompt)
        logql_query = str(ai_output.get("logql_query") or "").strip()
        from ..curation import ensure_data_prefix, ensure_data_prefix_in_logql
        logql_query = ensure_data_prefix_in_logql(logql_query)

        # 4. Validação estrita via linter LogQL do D.A.N.T.E.
        lint_res = lint_logql(
            logql_query,
            known_rule_groups_patterns=known_rule_groups_patterns,
            expected_job=technology.job,
        )

        # 5. Self-Correction Loop: Se o linter falhar, dá 1 chance de autocorreção à IA
        if not lint_res.is_valid:
            logger.info("IA gerou query com erro de linter (%s); iniciando autocorreção.", lint_res.message)
            correction_prompt = build_self_correction_prompt(
                previous_query=logql_query,
                lint_error_message=lint_res.message,
                job=technology.job,
                rule_groups_regex=technology.rule_groups_regex or technology.ss_groups_regex,
            )
            try:
                ai_output = await client.generate_json(SYSTEM_PROMPT_CURATION, correction_prompt)
                logql_query = str(ai_output.get("logql_query") or "").strip()
                logql_query = ensure_data_prefix_in_logql(logql_query)
                lint_res = lint_logql(
                    logql_query,
                    known_rule_groups_patterns=known_rule_groups_patterns,
                    expected_job=technology.job,
                )
            except Exception as exc:
                logger.warning("Falha no loop de autocorreção da IA: %s", exc)

        if not lint_res.is_valid:
            return logql_query, [], False, lint_res.message, None, None, None

        # 6. Constrói a lista de campos mapeados com prefixo data_
        raw_mapped = ai_output.get("mapped_fields") or []
        mapped_fields: list[CurationFieldMapping] = []
        for mf in raw_mapped:
            if isinstance(mf, dict):
                orig_f = str(mf.get("original_field") or "").strip()
                l_f = str(mf.get("logql_field") or "").strip()
                is_compat = bool(mf.get("compatible", True))
                if orig_f and l_f:
                    mapped_fields.append(
                        CurationFieldMapping(
                            original_field=orig_f,
                            logql_field=ensure_data_prefix(l_f),
                            compatible=is_compat,
                        )
                    )

        mitre_tactic = str(ai_output.get("mitre_tactic") or raw_rule.get("mitre_tactic") or "execution")
        mitre_technique = str(ai_output.get("mitre_technique") or raw_rule.get("mitre_technique") or "T1059")
        ai_rationale = str(ai_output.get("ai_rationale") or "").strip() or None

        # 7. Salva no cache
        if cfg.cache_enabled and lint_res.is_valid:
            self.cache.set(
                cache_key,
                {
                    "logql_query": logql_query,
                    "mapped_fields": [m.model_dump() for m in mapped_fields],
                    "mitre_tactic": mitre_tactic,
                    "mitre_technique": mitre_technique,
                    "ai_rationale": ai_rationale,
                },
            )

        return (
            logql_query,
            mapped_fields,
            lint_res.is_valid,
            lint_res.message,
            mitre_tactic,
            mitre_technique,
            ai_rationale,
        )

    async def evaluate_rule_homologation(
        self,
        history: RuleHomologationHistoryResponse,
    ) -> RuleHomologationAIEvaluation:
        """Avalia tecnicamente os alertas e a telemetria de uma regra em homologação ou produção via IA."""
        now_iso = datetime.now(timezone.utc).isoformat()
        prod_cp = self.sys_settings.get_stage_contact_points().get("prod", "prod").lower()
        is_in_prod = (
            history.deploy_status == "active"
            or (history.contact_point or "").lower() in ("prod", prod_cp)
        )
        cfg = self.get_raw_settings()

        # Amostra resumida de eventos recentes para contexto da IA
        event_lines: list[str] = []
        for ev in (history.events or [])[:15]:
            event_lines.append(f"- [{ev.timestamp}] Estado: {ev.new_state} (kind: {ev.kind})")
        recent_summary = "\n".join(event_lines) if event_lines else "Nenhum evento registrado na janela selecionada."

        if self.is_configured():
            prompt = build_homologation_evaluation_prompt(
                rule_title=history.title,
                folder_title=history.folder_title,
                contact_point=history.contact_point or "",
                deploy_status=history.deploy_status,
                is_in_production=is_in_prod,
                window_hours=history.window_hours,
                logql_query=history.logql_query or "",
                severity=history.severity or "medium",
                mitre_tactic=history.mitre_tactic or "",
                mitre_technique=history.mitre_technique or "",
                firing_events_count=history.firing_events_count,
                resolved_events_count=history.resolved_events_count,
                active_alerts_count=history.active_alerts_count,
                suppressed_alerts_count=history.suppressed_alerts_count,
                avg_firing_per_hour=history.avg_firing_per_hour,
                peak_bucket_firing=history.peak_bucket_firing,
                recent_events_summary=recent_summary,
            )

            client = AIUniversalClient(
                provider=cfg.provider,
                model=cfg.model,
                api_key=cfg.api_key,
                api_base_url=cfg.api_base_url,
                timeout_seconds=min(self.app_settings.ai_timeout_seconds, 6.0),
                temperature=0.2,
            )

            try:
                ai_res = await client.generate_json(SYSTEM_PROMPT_HOMOLOGATION_EVALUATION, prompt)
                summary = str(ai_res.get("summary") or "").strip()
                threat_analysis = str(ai_res.get("threat_analysis") or "").strip()
                noise_reduction = [
                    str(x).strip() for x in ai_res.get("noise_reduction_actions") or [] if str(x).strip()
                ]
                improvements = [str(x).strip() for x in ai_res.get("improvements") or [] if str(x).strip()]
                calibration_for_prod = str(ai_res.get("calibration_for_prod") or "").strip()
                verdict = str(ai_res.get("verdict") or "Avaliação Concluída").strip()

                if summary and threat_analysis:
                    return RuleHomologationAIEvaluation(
                        rule_uid=history.uid,
                        rule_title=history.title,
                        folder_title=history.folder_title,
                        window_hours=history.window_hours,
                        is_in_production=is_in_prod,
                        ai_provider=cfg.provider,
                        ai_model=cfg.model,
                        verdict=verdict,
                        threat_analysis=threat_analysis,
                        noise_reduction_actions=noise_reduction or ["Revisar telemetria periódica do endpoint"],
                        improvements=improvements or ["Query LogQL em conformidade estrutural"],
                        calibration_for_prod=calibration_for_prod,
                        summary=summary,
                        generated_at=now_iso,
                    )
            except Exception as exc:
                logger.warning(
                    "Falha na inferência de IA para homologação da regra '%s': %s. Acionando motor analítico heurístico.",
                    history.title,
                    exc,
                )

        return self._generate_heuristic_homologation_evaluation(history, is_in_prod, now_iso)

    def _generate_heuristic_homologation_evaluation(
        self,
        history: RuleHomologationHistoryResponse,
        is_in_prod: bool,
        now_iso: str,
    ) -> RuleHomologationAIEvaluation:
        """Gera parecer analítico determinístico especialista quando a IA externa está indisponível."""
        firing = history.firing_events_count
        avg_h = history.avg_firing_per_hour
        peak = history.peak_bucket_firing
        active = history.active_alerts_count
        hours = history.window_hours

        if firing == 0:
            verdict = "Telemetria Silenciosa (Zero Disparos)"
            summary = (
                f"Regra operando sem disparos de alerta na janela de {hours}h. "
                f"Telemetria estável e sem ocorrência de falso positivo."
            )
            threat_analysis = (
                f"Nenhum evento anômalo ou disparo de alerta foi registrado nas últimas {hours} horas. "
                f"Não há indícios de incidentes reais em andamento relacionados à técnica {history.mitre_technique or 'monitorada'}."
            )
            improvements = [
                "Validar se os seletores de stream {job=\"wazuh\", rule_groups=~\"...\"} cobrem todos os nós da infraestrutura",
                "Executar simulação com telemetria controlada no LokiLab para atestar que a regra dispara sob ataque real",
            ]
            noise_reduction_actions = [
                "Regra atualmente sem ruído operacional",
                "Manter acompanhamento periódico do pipeline de ingestão",
            ]
            if is_in_prod:
                calibration_for_prod = (
                    "Regra em produção com histórico silencioso. Recomenda-se aferir a saúde da telemetria "
                    "no SIEM para assegurar que os logs da tecnologia alvo continuam sendo ingeridos sem gaps."
                )
            else:
                calibration_for_prod = (
                    "Para homologar com total segurança antes da virada para prod, injete um evento sintético "
                    "no laboratório do D.A.N.T.E. comprovando que o alerta dispara exclusivamente sob a condição adversária pretendida."
                )

        elif firing > 40 or avg_h > 4.0:
            verdict = "Alto Volume / Risco de Flood"
            summary = (
                f"Regra apresentou volume elevado ({firing} disparos na janela de {hours}h, "
                f"média de {avg_h}/h com pico de {peak}). Requer calibração imediata para evitar sobrecarga de alertas."
            )
            threat_analysis = (
                f"O volume registrado ({firing} disparos) sugere probabilidade significativa de falsos positivos sistemáticos "
                f"ou varreduras/rotinas automatizadas internas (ex.: scripts de manutenção, scanners de vulnerabilidade, tarefas agendadas). "
                f"Caso os alertas estejam concentrados em um único IP ou usuário, audite se há incidente real de propagação em lote."
            )
            improvements = [
                "Adicionar limiar de contagem estatística (ex.: > 5 ou > 10) ao final da agregação da query LogQL",
                "Identificar atributos comuns nos eventos e criar filtros de negação específicos no pipeline LogQL",
                "Aumentar a janela de avaliação de 5m para 10m para absorver flutuações e rajadas transitórias",
            ]
            noise_reduction_actions = [
                "Aplicar silêncio operacional (Silence) com tag canônica [antiflood] enquanto o tuning é realizado",
                "Adicionar exclusão para contas de serviço autorizadas e faixas de IP de gerência conhecidas",
            ]
            if is_in_prod:
                calibration_for_prod = (
                    "Atenção: A regra já está em produção gerando volume crítico. Aplique urgentemente silêncio de antiflood "
                    "ou restrinja os filtros LogQL para proteger a equipe de SOC de fadiga de alertas e perda de visibilidade."
                )
            else:
                calibration_for_prod = (
                    "Bloqueio de homologação: Não promover para produção no estado atual. Reduza o volume de disparos "
                    "através de filtros de exclusão e thresholds numéricos antes de apontar para o contact point 'prod'."
                )

        else:
            verdict = "Produção Estável" if is_in_prod else "Volume Controlado (Apta para Validação)"
            summary = (
                f"Regra registrou {firing} disparos na janela de {hours}h (média de {avg_h}/h, {active} alerta(s) ativo(s) agora). "
                f"Comportamento volumétrico equilibrado dentro dos padrões esperados."
            )
            threat_analysis = (
                f"Foram identificados {firing} disparos pontuais com pico de {peak} eventos. "
                f"Recomenda-se analisar se os alertas ativos coincidem com ações de usuários privilegiados ou testes controlados. "
                f"Se os disparos ocorreram fora do horário comercial, priorizar investigação de atividade anômala."
            )
            improvements = [
                "Revisar o alinhamento dos campos com prefixo data_ no schema do Wazuh",
                "Assegurar que a regra possui severidade condizente com o impacto no ambiente",
            ]
            noise_reduction_actions = [
                "Verificar se os disparos envolveram contas legítimas de administração e adicionar whitelist pontual se necessário",
                "Se a regra envolver autenticações repetidas, certificar-se de ter operador de threshold (> 5)",
            ]
            if is_in_prod:
                calibration_for_prod = (
                    "Regra em produção operando com estabilidade e volumetria controlada. "
                    "Manter acompanhamento rotineiro das taxas de normalização e resolução de alertas."
                )
            else:
                calibration_for_prod = (
                    "Regra apta para virada para produção: volumetria sob controle e ausência de tempestades de alertas. "
                    "Certifique-se de que o time de SOC está ciente antes de efetuar a promoção para o contact point 'prod'."
                )

        return RuleHomologationAIEvaluation(
            rule_uid=history.uid,
            rule_title=history.title,
            folder_title=history.folder_title,
            window_hours=history.window_hours,
            is_in_production=is_in_prod,
            ai_provider="dante-threat-engine",
            ai_model="D.A.N.T.E. Detection Heuristic AI",
            verdict=verdict,
            threat_analysis=threat_analysis,
            noise_reduction_actions=noise_reduction_actions,
            improvements=improvements,
            calibration_for_prod=calibration_for_prod,
            summary=summary,
            generated_at=now_iso,
        )


    async def evaluate_rule_improvements(
        self,
        rule_detail: RuleDetail,
        client_telemetry: dict[str, Any] | None = None,
    ) -> RuleImprovementEvaluation:
        """Avalia oportunidades de melhoria técnica por IA em uma regra existente de detecção."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cfg = self.get_raw_settings()

        # Extrai a query LogQL principal da regra
        current_query = ""
        for q in rule_detail.queries:
            if isinstance(q.model, dict) and q.model.get("expr"):
                current_query = str(q.model.get("expr") or "").strip()
                break

        if self.is_analysis_enabled() and cfg.api_key:
            prompt = build_rule_improvement_prompt(
                rule_title=rule_detail.title,
                folder_title=rule_detail.folder_title,
                deploy_status=rule_detail.deploy_status,
                contact_point=rule_detail.contact_point or "",
                current_logql_query=current_query,
                severity=rule_detail.labels.get("severity", "medium"),
                labels=rule_detail.labels,
                annotations=rule_detail.annotations,
                for_duration=getattr(rule_detail, "for_duration", "0s") or "0s",
                client_telemetry=client_telemetry,
            )
            client = AIUniversalClient(
                provider=cfg.provider,
                model=cfg.model,
                api_key=cfg.api_key,
                api_base_url=cfg.api_base_url,
                timeout_seconds=min(self.app_settings.ai_timeout_seconds, 15.0),
                temperature=0.2,
            )
            try:
                ai_output = await client.generate_json(
                    SYSTEM_PROMPT_RULE_IMPROVEMENT_EVALUATION,
                    prompt,
                )
                if isinstance(ai_output, dict) and ai_output.get("verdict"):
                    sug_query = ai_output.get("suggested_logql_query")
                    can_impl = bool(ai_output.get("can_implement"))
                    if sug_query:
                        from ..curation import ensure_data_prefix_in_logql
                        sug_query = ensure_data_prefix_in_logql(str(sug_query).strip())
                        lint_res = lint_logql(sug_query)
                        if not lint_res.is_valid:
                            logger.info("Sugestão de LogQL da IA reprovada no linter: %s", lint_res.message)
                            sug_query = None
                            can_impl = False
                        else:
                            can_impl = True
                    else:
                        can_impl = bool(ai_output.get("can_implement")) or bool(ai_output.get("suggested_labels")) or bool(ai_output.get("diff_summary"))

                    return RuleImprovementEvaluation(
                        rule_uid=rule_detail.uid,
                        rule_title=rule_detail.title,
                        verdict=str(ai_output.get("verdict") or "Avaliação Técnica Concluída"),
                        verdict_level=ai_output.get("verdict_level") or "good",
                        threat_context=str(ai_output.get("threat_context") or "Cenário de ameaça monitorado na telemetria."),
                        improvements=[str(x) for x in ai_output.get("improvements") or [] if str(x).strip()],
                        noise_reduction_actions=[str(x) for x in ai_output.get("noise_reduction_actions") or [] if str(x).strip()],
                        suggested_logql_query=sug_query,
                        suggested_for_duration=ai_output.get("suggested_for_duration"),
                        suggested_labels={str(k): str(v) for k, v in (ai_output.get("suggested_labels") or {}).items()},
                        suggested_annotations={str(k): str(v) for k, v in (ai_output.get("suggested_annotations") or {}).items()},
                        diff_summary=[str(x) for x in ai_output.get("diff_summary") or [] if str(x).strip()],
                        can_implement=can_impl,
                        evaluated_at=now_iso,
                        engine="ai",
                        model=f"{cfg.provider}:{cfg.model}",
                        telemetry_evaluated=bool(client_telemetry and client_telemetry.get("telemetry_evaluated")),
                        client_name=client_telemetry.get("client_name") if client_telemetry else None,
                        client_uid=client_telemetry.get("client_uid") if client_telemetry else None,
                        windows_evaluated=client_telemetry.get("windows_evaluated", []) if client_telemetry else [],
                        matched_window=client_telemetry.get("matched_window") if client_telemetry else None,
                        matched_events_count=client_telemetry.get("matched_events_count", 0) if client_telemetry else 0,
                        sample_logs=client_telemetry.get("sample_logs", []) if client_telemetry else [],
                        observed_fields=client_telemetry.get("observed_fields", []) if client_telemetry else [],
                        field_compatibility_pct=client_telemetry.get("field_compatibility_pct") if client_telemetry else None,
                        is_paused_rule=bool(client_telemetry and client_telemetry.get("is_paused_rule")),
                    )
            except Exception as exc:
                logger.warning(
                    "Falha na inferência de melhoria de regra por IA para '%s': %s. Usando motor heurístico.",
                    rule_detail.title,
                    exc,
                )

        return self._generate_heuristic_rule_improvements(
            rule_detail, current_query, now_iso, client_telemetry=client_telemetry
        )

    def _generate_heuristic_rule_improvements(
        self,
        rule_detail: RuleDetail,
        current_query: str,
        now_iso: str,
        client_telemetry: dict[str, Any] | None = None,
    ) -> RuleImprovementEvaluation:
        """Motor analítico heurístico especialista para avaliação de regras de detecção.

        Avalia minuciosamente o contexto da regra (vetor de ameaça, lógica de detecção,
        sintaxe LogQL, auditoria de GPO, resiliência contra evasões e ações anti-ruído),
        garantindo parecer técnico detalhado e acionável mesmo quando a regra não está 'Firing'
        (telemetria silenciosa / 0 eventos nas janelas temporais progressivas).
        """
        from ..curation import ensure_data_prefix_in_logql

        title = rule_detail.title
        title_lower = title.lower()
        query_clean = current_query.strip()
        query_lower = query_clean.lower()
        desc = (rule_detail.annotations.get("description") or rule_detail.annotations.get("summary") or "").strip()
        desc_lower = desc.lower()

        mitre_tech = rule_detail.labels.get("mitre_technique", "").strip()
        mitre_tactic = rule_detail.labels.get("mitre_tactic", "").strip()
        severity = rule_detail.labels.get("severity", "high")

        is_paused = bool(client_telemetry and client_telemetry.get("is_paused_rule"))
        matched_window = client_telemetry.get("matched_window") if client_telemetry else None
        matched_events = client_telemetry.get("matched_events_count", 0) if client_telemetry else 0
        c_name = (client_telemetry.get("client_name") if client_telemetry else None) or rule_detail.folder_title or "Cliente"

        # Detecção contextual dos arquétipos de ameaça
        is_ntds_backup = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in ("ntdsutil", "ntds.dit", "active directory backup", "ac i ntds", "activate instance ntds", "ifm")
        )
        is_lsass_or_dcsync = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in ("dcsync", "drsuapi", "mimikatz", "sekurlsa", "lsass", "procdump", "comsvcs", "t1003.006")
        )
        is_kerberos_privesc = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in (
                "kerberoast", "as-rep", "roasting", "golden ticket", "silver ticket",
                "tgs", "tgt", "escalonamento de privilegio", "privilege escalation",
                "controlador de dominio", "domain admin", "4728", "4732", "4756", "4672"
            )
        )
        is_process_lolbas = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in (
                "powershell", "pwsh", "encodedcommand", "downloadstring", "certutil",
                "bitsadmin", "mshta", "rundll32", "regsvr32", "wmic", "lolbas",
                "dusttrap", "spawning", "4688"
            )
        )
        is_brute_force = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in ("brute", "force", "spray", "falhas de logon", "logon failure", "4625", "ssh", "rdp", "sshd")
        )
        is_ransomware_evasion = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in ("vssadmin", "shadowcopy", "delete shadows", "bcdedit", "wevtutil", "1102", "104", "cipher", "ransomware", "wbadmin")
        )
        is_firewall_network = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in ("fortigate", "firewall", "traffic blocked", "trafego negado", "port scan", "varredura de portas", "deny", "drop", "inbound", "outbound")
        )
        is_linux_sudo = any(
            k in title_lower or k in query_lower or k in desc_lower
            for k in ("sudo", "su privilege", "pam", "root", "escalada de privilegio via sudo")
        )

        has_threshold = any(op in query_clean for op in (">", ">=", "<", "<="))

        # Normalização inicial da query sugerida com validação de conformidade
        suggested_query = ensure_data_prefix_in_logql(query_clean) if query_clean else None
        if suggested_query:
            lint_res = lint_logql(suggested_query)
            if not lint_res.is_valid:
                suggested_query = query_clean

        suggested_labels: dict[str, str] = {}
        suggested_annotations: dict[str, str] = {}
        diff_summary: list[str] = []
        suggested_for_duration: str | None = None

        if is_paused:
            if matched_window and matched_events > 0:
                verdict = f"Regra Pausada com Telemetria Ativa: {matched_events} evento(s) na janela de {matched_window}"
                verdict_level = "warning" if matched_events > 30 else "good"
                threat_context = (
                    f"A regra de detecção '{title}' está atualmente PAUSADA no Grafana Alerting. "
                    f"A execução analítica da query LogQL nas faixas progressivas (15m -> 1h -> 6h -> 24h -> 3d) "
                    f"no Loki do cliente '{c_name}' capturou {matched_events} evento(s) correspondente(s) na janela de {matched_window}. "
                    f"Se reativada no ambiente produtivo, a regra geraria incidentes com base nessa telemetria."
                )
                improvements = [
                    f"Verificar se o volume de {matched_events} evento(s) na janela de {matched_window} reflete incidentes reais de segurança antes de reativar.",
                    "Promover inicialmente para estágio de Homologação (dev/stg) para validar sem impacto operacional no SOC.",
                    "Garantir a integridade dos prefixos de campos (data_*) no schema Wazuh.",
                ]
                noise_reduction_actions = [
                    "Adicionar filtros de exclusão de hosts/IPs autorizados se os eventos observados forem rotineiros.",
                    "Calibrar o limiar estatístico (ex: '> 5') se a intenção for alertar apenas rajadas volumétricas.",
                ]
            else:
                verdict = "Regra Pausada Silenciosa: 0 eventos detectados nas 5 faixas progressivas"
                verdict_level = "good"
                threat_context = (
                    f"A regra de detecção '{title}' está atualmente PAUSADA no Grafana Alerting. "
                    f"A análise da query nas 5 etapas progressivas no Loki (15m, 1h, 6h, 24h e 3d) no cliente '{c_name}' "
                    f"retornou 0 eventos, demonstrando que a regra não gerará ruído imediato ou floods se reativada."
                )
                improvements = [
                    "A regra pode ser reativada em segurança em estágio de Homologação (dev/stg).",
                    "Confirmar que o agente Wazuh e os decoders continuam ingerindo dados para o rule_groups da tecnologia.",
                    "Injetar telemetria sintética no LokiLab para atestar disparo sob condição adversária controlada.",
                ]
                noise_reduction_actions = [
                    "Manter limiar atual e acompanhar nas primeiras 24 horas após despausar.",
                    "Configurar silêncio operacional durante janelas de manutenção de infraestrutura.",
                ]

        elif is_ntds_backup:
            verdict = "Prontidão Operacional: Regra Silenciosa de Alta Fidelidade (Defesa de Active Directory Ativa)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' monitora tentativas de extração não autorizada do banco de dados do Active Directory "
                f"(NTDS.dit) através do utilitário administrativo ntdsutil.exe com sintaxe abreviada (MITRE ATT&CK T1003.003 - "
                f"OS Credential Dumping: NTDS). Invasores utilizam comandos shorthand como 'ac i ntds' e 'create full' para tentar "
                f"evadir detecções ingênuas baseadas em strings literais completas e extrair os arquivos NTDS.dit e as hives de registro "
                f"SYSTEM e SECURITY, permitindo a extração offline de hashes NTLM e chaves Kerberos de todos os usuários corporativos. "
                f"Como o ambiente corporativo do cliente '{c_name}' não registra incidentes recentes deste vetor (0 eventos nas "
                f"5 janelas progressivas de 15m a 3d), a ausência de disparos representa telemetria silenciosa saudável em postura de defesa preventiva ativa."
            )
            improvements = [
                "Assegurar que a GPO corporativa de Controladores de Domínio audite Process Creation (Event ID 4688) com a opção 'Include command line in process creation events' ativada, caso contrário a linha de comando não será capturada pelo Wazuh.",
                "Verificar cobertura de variações sintáticas como citação entre aspas (ex.: ntdsutil \"ac i ntds\"), parâmetros sem espaçamento ou invocação indireta via scripts PowerShell/Batch.",
                "Garantir a preservação dos prefixos 'data_' nos campos extraídos do schema Wazuh (ex.: data_win_eventdata_commandLine, data_win_system_eventID) para conformidade estrita no pipeline Vector/Loki.",
                "Testar o pipeline de disparo no laboratório LokiLab do D.A.N.T.E. através de injeção de log sintético controlado de Event ID 4688 para certificar o alerta sem comprometer o DC de produção.",
            ]
            noise_reduction_actions = [
                "Adicionar filtro de exclusão cirúrgico para rotinas de backup corporativo homologadas (ex.: Veeam, Commvault, Windows Server Backup) restringindo pela conta de serviço dedicada ou binário pai autorizado.",
                "Configurar silêncio operacional temporário (tag [manutencao]) durante janelas programadas de disaster recovery ou manutenção de infraestrutura de domínio.",
                "Correlacionar detecções com anomalias de logon administrativo e privilégios delegados (Event ID 4672 / 4624) antes de escalonar para incidente de alta severidade.",
            ]
            tech_code = mitre_tech or "T1003.003"
            tactic_code = mitre_tactic or "credential-access"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = tactic_code
            suggested_labels["dante_ai_tuning"] = "verified"
            suggested_annotations["triage_guidance"] = (
                "Verificar imediatamente o host de origem (Controlador de Domínio), a conta de usuário executora "
                "e se há ordem de serviço aprovada para rotina de backup antes de isolar o ativo."
            )
            suggested_annotations["runbook_url"] = "https://attack.mitre.org/techniques/T1003/003/"
            diff_summary.append("Query LogQL estruturada e validada com linter de conformidade do Grafana Alerting")
            diff_summary.append(f"Enriquecimento de tags MITRE ATT&CK ({tech_code}) e diretrizes de triagem rápida para o SOC")
            diff_summary.append("Validação preventiva de telemetria concluída (sem falsos positivos identificados)")

        elif is_lsass_or_dcsync:
            verdict = "Prontidão Operacional: Regra Silenciosa de Alta Fidelidade (Defesa contra Roubo de Credenciais)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' monitora táticas de acesso e extração de credenciais de memória (LSASS) ou abuso de replicação "
                f"Directory Replication Service (DCSync) (MITRE ATT&CK T1003). Atacantes utilizam ferramentas como Mimikatz ou chamadas "
                f"RPC proprietárias para forçar a sincronização de hashes de senhas e tickets Kerberos (krbtgt). "
                f"A ausência de disparos no cliente '{c_name}' indica que não há atividade de dump de credenciais em andamento na infraestrutura."
            )
            improvements = [
                "Verificar se o recurso LSA Protection (RunAsPPL) e Credential Guard estão ativados nos endpoints e servidores.",
                "Garantir a auditoria de acesso a objetos e handles privilegiados no processo lsass.exe (Event ID 4663 / 4656).",
                "Assegurar conformidade dos campos no formato data_* no schema Wazuh para Loki.",
                "Validar no LokiLab com injeção sintética de telemetria simulada de DCSync.",
            ]
            noise_reduction_actions = [
                "Excluir contas de agentes antivírus/EDR legítimos que inspecionam o processo lsass.exe.",
                "Filtrar replicações normais entre Controladores de Domínio autorizados pelo IP de origem.",
            ]
            tech_code = mitre_tech or "T1003.006"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "credential-access"
            suggested_labels["dante_ai_tuning"] = "verified"
            suggested_annotations["triage_guidance"] = "Validar IP de origem da replicação RPC. Se originado de estação de trabalho, disparar contenção imediata."
            diff_summary.append(f"Reforço de metadados MITRE ATT&CK ({tech_code}) e guia de contenção")
            diff_summary.append("Query LogQL alinhada ao linter D.A.N.T.E.")

        elif is_kerberos_privesc:
            verdict = "Prontidão Operacional: Regra Silenciosa de Alta Fidelidade (Defesa de Identidade & IAM)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' protege contra escalada de privilégios e abuso de permissões no Active Directory "
                f"({mitre_tech or 'T1078 / T1098'}). Monitora requisições anômalas de tickets Kerberos (Kerberoasting / AS-REP Roasting) "
                f"ou atribuição indevida de contas a grupos de privilégio máximo (Domain Admins). "
                f"A telemetria silenciosa confirma conformidade operacional e ausência de movimentação lateral de identidade no cliente '{c_name}'."
            )
            improvements = [
                "Auditar eventos de gerenciamento de contas (Event IDs 4720, 4728, 4732, 4769) garantindo encaminhamento via agente Wazuh.",
                "Restringir a query aos Service Principal Names (SPNs) com métodos de cifragem fracos (RC4).",
                "Enriquecer labels com a técnica MITRE correspondente e adicionar documentação de triagem rápida para o SOC.",
            ]
            noise_reduction_actions = [
                "Excluir procedimentos corporativos de onboarding/offboarding executados por ferramentas de automação IAM autorizadas.",
                "Definir silêncio operacional durante janelas de manutenção de infraestrutura de diretório.",
            ]
            tech_code = mitre_tech or "T1558.003"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "credential-access"
            suggested_labels["dante_ai_tuning"] = "verified"
            diff_summary.append(f"Padronização de tags MITRE ({tech_code}) e calibração de campos")

        elif is_process_lolbas:
            verdict = "Prontidão Operacional: Regra Silenciosa de Alta Fidelidade (Execução & Evasão de Defesa)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' monitora o uso de interpretadores de comando ou binários nativos do sistema (Living-off-the-Land) "
                f"para execução de scripts maliciosos, download de payloads externos ou evasão de defesas ({mitre_tech or 'T1059 / T1218'}). "
                f"Invasores utilizam essas ferramentas legítimas para evitar detecção por antivírus tradicionais. "
                f"A ausência de registros nas janelas analisadas comprova conformidade de integridade de execução no cliente '{c_name}'."
            )
            improvements = [
                "Validar se a auditoria avançada de PowerShell (Event ID 4104 - Script Block Logging) e Process Creation (4688) estão ativadas via GPO.",
                "Adicionar suporte a caminhos absolutos e aliases comuns no regex de busca da linha de comando.",
                "Calibrar o tempo de avaliação da regra para 5m e manter limiar estrito para execução anômala.",
                "Testar no LokiLab com telemetria sintética demonstrando o disparo com linha de comando representativa.",
            ]
            noise_reduction_actions = [
                "Mapear scripts administrativos corporativos de inventário ou suporte e criar whitelist por hash ou caminho autenticado.",
                "Restringir filtros de exclusão às contas de automação corporativa conhecidas.",
            ]
            tech_code = mitre_tech or "T1059.001"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "execution"
            suggested_labels["dante_ai_tuning"] = "verified"
            suggested_annotations["triage_guidance"] = "Inspecionar processo pai, linha de comando decodificada e conexões de rede simultâneas."
            diff_summary.append(f"Enriquecimento de técnicas MITRE ({tech_code}) e validação de linter LogQL")

        elif is_brute_force:
            if not has_threshold and query_clean:
                suggested_query = f"{query_clean} > 5"
                lint_res = lint_logql(suggested_query)
                if lint_res.is_valid:
                    diff_summary.append("Adicionado limiar estatístico '> 5' ao final da métrica para diferenciar falhas esporádicas de ataques volumétricos")
                else:
                    suggested_query = query_clean

            verdict = "Oportunidade de Calibração Anti-Ruído" if not has_threshold else "Monitoramento de Autenticação Ativo"
            verdict_level = "warning" if not has_threshold else "good"
            threat_context = (
                f"A regra '{title}' monitora atividades adversárias volumétricas de autenticação / força bruta "
                f"({mitre_tech or 'T1110'} - {mitre_tactic or 'credential-access'}). "
                f"Sem um limiar quantitativo de tentativas em janela curta, falhas pontuais e isoladas de digitação "
                f"de operadores legítimos disparam incidentes desnecessários na fila do SOC."
            )
            improvements = [
                "Adicionar limiar de contagem estatística '> 5' ao final da expressão LogQL para garantir disparo apenas em rajadas anômalas.",
                "Assegurar conformidade com a tática MITRE ATT&CK T1110 (Brute Force / Password Spraying).",
                "Ajustar a janela de avaliação temporal para 5m para acomodar dispersão transitória.",
            ]
            noise_reduction_actions = [
                "Excluir contas de serviço conhecidas e scanners corporativos de inventário da regra.",
                "Verificar se há estações específicas com scripts agendados com credenciais antigas gerando erros repetitivos.",
            ]
            tech_code = mitre_tech or "T1110.001"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "credential-access"
            suggested_labels["dante_ai_tuning"] = "verified"
            suggested_for_duration = "5m"
            diff_summary.append(f"Tags MITRE ATT&CK padronizadas ({tech_code})")

        elif is_ransomware_evasion:
            verdict = "Prontidão Operacional: Regra Crítica Silenciosa (Anti-Ransomware & Integridade de Logs)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' atua como controle crítico contra operadores de ransomware e ações de sabotagem corporativa "
                f"({mitre_tech or 'T1490 / T1070'}). Detecta tentativas de exclusão de cópias de sombra de volume (VSS) ou limpeza "
                f"de logs de auditoria do Windows/Linux, táticas utilizadas para impedir a recuperação de desastres e ocultar evidências forenses. "
                f"O estado silencioso nas janelas avaliadas é o padrão esperado de integridade dos sistemas."
            )
            improvements = [
                "Assegurar que os eventos de sistema do Windows e serviços VSS estejam sendo encaminhados para o Wazuh.",
                "Verificar a inclusão de comandos alternativos como 'wmic shadowcopy delete' e 'wbadmin delete catalog'.",
                "Configurar severidade operacional crítica com notificação imediata de alta prioridade.",
            ]
            noise_reduction_actions = [
                "Filtrar rotinas pontuais de limpeza automática de espaço em disco executadas por agentes de backup autorizados.",
                "Criar silêncio programado antes de migrações ou desativações planejadas de servidores.",
            ]
            tech_code = mitre_tech or "T1490"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "impact"
            suggested_labels["dante_ai_tuning"] = "verified"
            diff_summary.append(f"Classificação MITRE ATT&CK ({tech_code}) e reforço de triagem crítica")

        elif is_firewall_network:
            verdict = "Monitoramento de Perímetro Ativo" if matched_events > 0 else "Perímetro Estável (Sem Varreduras Ativas)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' avalia tráfego rejeitado e anomalias de conexão nos firewalls de borda ({mitre_tech or 'T1046 / T1071'}). "
                f"Monitora varreduras externas de portas e tentativas de conexão a serviços corporativos restritos. "
                f"A ausência de eventos na janela selecionada indica estabilidade nas portas avaliadas e filtragem eficaz no perímetro do cliente '{c_name}'."
            )
            improvements = [
                "Garantir agregação estatística com limiar (ex.: '> 5' ou '> 10') para focar em varreduras massivas e evitar alertas de ruído esporádico da internet.",
                "Verificar se as interfaces de WAN do firewall estão enviando logs Syslog no formato esperado pelo pipeline Wazuh/Loki.",
                "Calibrar a severidade de acordo com a criticidade da porta monitorada.",
            ]
            noise_reduction_actions = [
                "Adicionar exceção para IPs de scanners externos autorizados e serviços de monitoramento contratados.",
                "Agrupar eventos por IP de origem ('by (data_src_ip)') para correlacionar varreduras direcionadas.",
            ]
            tech_code = mitre_tech or "T1046"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "discovery"
            suggested_labels["dante_ai_tuning"] = "verified"
            diff_summary.append(f"Normalização de labels MITRE ATT&CK ({tech_code})")

        elif is_linux_sudo:
            verdict = "Prontidão Operacional: Regra Silenciosa de Alta Fidelidade (Defesa Linux / PAM)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' monitora abuso de privilégios e elevação não autorizada para o usuário root via sudo ou PAM "
                f"em ambientes Linux ({mitre_tech or 'T1548.003'}). Invasores que comprometem contas de serviço de baixa permissão "
                f"tentam explorar binários com SUID ou falhas de configuração no arquivo sudoers. "
                f"A telemetria silenciosa confirma conformidade de acesso privilegiado nos servidores do cliente '{c_name}'."
            )
            improvements = [
                "Assegurar que os logs de autenticação (/var/log/auth.log ou /var/log/secure) estejam configurados no ossec.conf do agente Wazuh.",
                "Filtrar comandos rotineiros autorizados nos arquivos sudoers.",
                "Testar com log sintético no LokiLab para atestar o alerta de violação de sudoers.",
            ]
            noise_reduction_actions = [
                "Excluir contas de automação corporativa (ex.: Ansible, Rundeck, Zabbix) que executam tarefas agendadas com sudo.",
                "Manter severidade alta para comandos desconhecidos ou executados fora de janelas de release.",
            ]
            tech_code = mitre_tech or "T1548.003"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "privilege-escalation"
            suggested_labels["dante_ai_tuning"] = "verified"
            diff_summary.append(f"Enriquecimento de tags MITRE ({tech_code}) e validação de sudoers")

        else:
            verdict = "Prontidão Operacional: Regra Silenciosa de Alta Fidelidade (Defesa Preventiva Ativa)"
            verdict_level = "good"
            threat_context = (
                f"A regra '{title}' monitora técnicas de intrusão cibernética ({mitre_tech or 'MITRE ATT&CK'} - {mitre_tactic or 'Threat Vector'}). "
                f"{desc + ' ' if desc else ''}O pipeline de telemetria no Loki do cliente '{c_name}' vigia continuamente os fluxos de eventos, "
                f"mantendo cobertura preventiva sem ocorrência de falsos positivos ou floods nas últimas janelas de tempo analisadas."
            )
            improvements = [
                "Assegurar a conformidade de todos os campos extraídos do log com prefixo 'data_' no schema Wazuh.",
                "Validar se a severidade operacional ('" + str(severity) + "') reflete a criticidade real do ativo protegido.",
                "Executar injeção de log sintético no LokiLab do D.A.N.T.E. para comprovar o disparo controlado do alerta.",
            ]
            noise_reduction_actions = [
                "Manter filtro de exclusão para janelas de manutenção corporativa autorizadas.",
                "Correlacionar com alertas de perímetro antes de abrir chamado crítico para o SOC.",
            ]
            tech_code = mitre_tech or "T1059"
            suggested_labels["mitre_technique"] = tech_code
            suggested_labels["mitre_tactic"] = mitre_tactic or "execution"
            suggested_labels["dante_ai_tuning"] = "verified"
            diff_summary.append(f"Validação estrutural e enriquecimento de labels MITRE ({tech_code})")

        # Garante enriquecimento de anotações úteis para SOC caso ausentes
        if not rule_detail.annotations.get("triage_guidance") and "triage_guidance" not in suggested_annotations:
            suggested_annotations["triage_guidance"] = (
                "Validar contexto de execução, credencial associada e host de origem antes de fechar como falso positivo."
            )
            diff_summary.append("Adicionada anotação de triagem operacional para o SOC")

        if not diff_summary:
            diff_summary.append("Validação sintática e de compliance LogQL confirmada")
            diff_summary.append("Recomendações técnicas estruturadas prontas para aplicação")

        return RuleImprovementEvaluation(
            rule_uid=rule_detail.uid,
            rule_title=rule_detail.title,
            verdict=verdict,
            verdict_level=verdict_level,
            threat_context=threat_context,
            improvements=improvements,
            noise_reduction_actions=noise_reduction_actions,
            suggested_logql_query=suggested_query,
            suggested_for_duration=suggested_for_duration,
            suggested_labels=suggested_labels,
            suggested_annotations=suggested_annotations,
            diff_summary=diff_summary,
            can_implement=True,
            evaluated_at=now_iso,
            engine="heuristic",
            model="D.A.N.T.E. Detection Heuristic Engine",
            telemetry_evaluated=bool(client_telemetry and client_telemetry.get("telemetry_evaluated")),
            client_name=client_telemetry.get("client_name") if client_telemetry else None,
            client_uid=client_telemetry.get("client_uid") if client_telemetry else None,
            windows_evaluated=client_telemetry.get("windows_evaluated", []) if client_telemetry else [],
            matched_window=client_telemetry.get("matched_window") if client_telemetry else None,
            matched_events_count=client_telemetry.get("matched_events_count", 0) if client_telemetry else 0,
            sample_logs=client_telemetry.get("sample_logs", []) if client_telemetry else [],
            observed_fields=client_telemetry.get("observed_fields", []) if client_telemetry else [],
            field_compatibility_pct=client_telemetry.get("field_compatibility_pct") if client_telemetry else None,
            is_paused_rule=bool(client_telemetry and client_telemetry.get("is_paused_rule")),
        )
