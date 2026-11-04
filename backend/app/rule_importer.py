"""Validador, curador e compilador de regras importadas (Loki Ruler / Detection-as-Code).

Garante que toda regra importada:
1. Seja validada ponta a ponta: sintaxe JSON/YAML, campos obrigatórios, sintaxe LogQL via lint_logql;
2. Tenha seletor 'ss_groups' casado com uma tecnologia do catálogo;
3. Tenha severidade válida e labels MITRE ATT&CK (mitre_tactic, mitre_technique);
4. Passe pelo mesmo padrão rigoroso de análise, curadoria e parecer técnico por IA da Curadoria;
5. Tenha compatibilidade garantida com os campos existentes e mapeados nos ambientes dos clientes;
6. Seja compilada para a pasta Baseline ('global'), data source 'Loki' e Contact Point 'stg';
7. Não permita que regras inválidas ou com erro sejam salvas sob hipótese alguma.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import re
import uuid
from typing import Any, Literal

import yaml

from .ai import AIService
from .config import get_settings
from .contact_points import apply_contact_point
from .curation import (
    FIELD_TRANSLATION_MAP,
    PERIMETER_DEFAULT_FIELDS,
    PERIMETER_FIELD_TRANSLATION_MAP,
    SUPPORTED_WAZUH_LOKI_FIELDS,
    compute_dynamic_compatibility,
    ensure_data_prefix,
    evaluate_rule_across_clients,
    _evaluate_client_telemetry_readiness,
    _expand_observed_field_aliases,
)
from .grafana_client import GrafanaClient, GrafanaError
from .logql_validator import lint_logql
from .rule_prefix import format_rule_title
from .schemas import (
    BaselinePrefixSettings,
    CurationCandidateQuality,
    CurationClientEvaluation,
    CurationFieldMapping,
    CurationQualificationFactor,
    RuleImportExecuteResponse,
    RuleImportFileInput,
    RuleImportItemValidation,
    RuleImportPreviewResponse,
    RuleSeverity,
)
from .sigma_converter import convert_sigma_to_logql
from .system_settings_store import SystemSettingsStore
from .technologies import (
    Technology,
    TechnologyNotFound,
    TechnologyStore,
    extract_rule_groups_values,
    extract_ss_groups_values,
    selector_matches_technology,
)
from .technology_insights import is_client_folder
from .technology_store import get_tenant_scan_store, get_tenant_technology_store
from .tenants import BASELINE_RULE_GROUP

logger = logging.getLogger("dante.rule_importer")

# Padrão regex para separar expressão métrica de comparadores de threshold em queries de Loki Ruler
# Ex: 'sum(count_over_time(...)) > 0' -> ('sum(count_over_time(...))', '>', '0')
_THRESHOLD_PATTERN = re.compile(
    r"^(.*?)\s*(==|!=|>=|<=|>|<)\s*([0-9]+(?:\.[0-9]+)?)\s*$",
    re.DOTALL,
)

VALID_SEVERITIES: set[str] = {"low", "medium", "high", "critical"}


def parse_query_and_threshold(raw_expr: str) -> tuple[str, str, float]:
    """Separa a expressão LogQL pura do operador/valor de threshold.

    No Loki Ruler, expressões são comumente escritas como `expr > 0`.
    No Grafana Alerting, o data source Loki (nó A) recebe apenas a query métrica pura,
    e a condição de threshold (nó C) recebe o operador e o valor numérico.
    """
    clean_expr = raw_expr.strip()
    match = _THRESHOLD_PATTERN.match(clean_expr)
    if not match:
        return clean_expr, "gt", 0.0

    metric_query = match.group(1).strip()
    operator_raw = match.group(2)
    val = float(match.group(3))

    if operator_raw in (">", ">="):
        if operator_raw == ">=":
            threshold_val = max(0.0, val - 1.0) if val.is_integer() and val > 0 else val
        else:
            threshold_val = val
        return metric_query, "gt", threshold_val
    elif operator_raw in ("<", "<="):
        if operator_raw == "<=":
            threshold_val = val + 1.0 if val.is_integer() else val
        else:
            threshold_val = val
        return metric_query, "lt", threshold_val
    elif operator_raw == "==":
        return metric_query, "gt", max(0.0, val - 1.0)

    return metric_query, "gt", val


def extract_suggested_technology_info(
    raw_matcher: str,
    explicit_slug: str | None = None,
) -> tuple[str, str, str]:
    """Extrai sugestão de (slug, name, ss_groups_regex) para uma tecnologia ainda não cadastrada.

    Ignora o prefixo (?i) caso o recorte venha com a flag regex case-insensitive.
    """
    cleaned = raw_matcher.strip()
    if cleaned.lower().startswith("(?i)"):
        cleaned = cleaned[4:].strip()
    if explicit_slug and explicit_slug.strip():
        slug = re.sub(r"[^a-z0-9_]+", "_", explicit_slug.strip().lower()).strip("_")
    else:
        simplified = re.sub(r"^[\^.*|\s\"\']+", "", cleaned)
        simplified = re.sub(r"[\$.*|\s\"\']+$", "", simplified)
        slug = re.sub(r"[^a-z0-9_]+", "_", simplified.lower()).strip("_")

    if not slug or len(slug) < 2:
        slug = "nova_tecnologia"

    name = " ".join(word.capitalize() for word in slug.split("_"))

    if ".*" in cleaned or "^" in cleaned:
        regex = cleaned
    else:
        regex = f".*{slug}.*"

    return slug, name, regex


def parse_raw_content(content: str) -> tuple[Any, str | None]:
    """Interpreta o conteúdo bruto como JSON ou YAML.

    Retorna a estrutura em dicionários/listas e, em caso de erro de sintaxe,
    uma mensagem explicativa indicando se a falha ocorreu no JSON ou no YAML.
    Suporta múltiplos documentos YAML delimitados por '---'.
    """
    stripped = content.strip()
    if not stripped:
        return None, "O arquivo fornecido está vazio."

    # Se começa com { ou [, tenta primeiro como JSON estrito
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped), None
        except json.JSONDecodeError as json_exc:
            # Fallback para YAML caso seja um JSON com extensões/trailing commas
            try:
                docs = [d for d in yaml.safe_load_all(stripped) if d is not None]
                if docs:
                    return docs[0] if len(docs) == 1 else docs, None
            except Exception:
                pass
            return (
                None,
                f"Arquivo JSON malformado: erro de sintaxe na linha {json_exc.lineno}, coluna {json_exc.colno} ({json_exc.msg}).",
            )

    # Caso geral: tenta YAML (suporta múltiplos documentos)
    try:
        docs = [d for d in yaml.safe_load_all(stripped) if d is not None]
        if not docs:
            return None, "O arquivo YAML/JSON não contém dados interpretáveis."
        return docs[0] if len(docs) == 1 else docs, None
    except yaml.YAMLError as yaml_exc:
        # Se falhou como YAML, tenta como JSON
        try:
            return json.loads(stripped), None
        except Exception:
            pass
        return None, f"Arquivo YAML malformado: {yaml_exc}"
    except Exception as exc:
        return None, f"Erro ao processar arquivo YAML/JSON: {exc}"


def extract_raw_rule_dicts(parsed_data: Any) -> tuple[list[dict[str, Any]], str | None]:
    """Extrai uma lista plana de dicionários de regras de diferentes estruturas YAML/JSON suportadas."""
    if isinstance(parsed_data, list):
        extracted: list[dict[str, Any]] = []
        for item in parsed_data:
            if not isinstance(item, dict):
                continue
            # Se for documento/grupo aninhado com 'groups' ou 'rules'
            if "groups" in item or "rules" in item:
                sub_rules, _ = extract_raw_rule_dicts(item)
                extracted.extend(sub_rules)
            elif any(k in item for k in ("alert", "title", "name", "expr", "logql_query", "data", "detection")):
                extracted.append(item)
        if not extracted:
            return [], "A lista fornecida no arquivo YAML/JSON não contém regras de detecção válidas."
        return extracted, None

    if isinstance(parsed_data, dict):
        # 1. Formato Prometheus/Loki Ruler com 'groups'
        if "groups" in parsed_data and isinstance(parsed_data["groups"], list):
            extracted = []
            for g in parsed_data["groups"]:
                if isinstance(g, dict) and "rules" in g and isinstance(g["rules"], list):
                    for r in g["rules"]:
                        if isinstance(r, dict):
                            if "group" not in r and "name" in g:
                                r = dict(r)
                                r.setdefault("group", g["name"])
                            extracted.append(r)
            if not extracted:
                return [], "Nenhuma regra encontrada dentro da chave 'groups' do arquivo YAML/JSON."
            return extracted, None

        # 2. Formato de grupo único com 'rules'
        if "rules" in parsed_data and isinstance(parsed_data["rules"], list):
            extracted = [r for r in parsed_data["rules"] if isinstance(r, dict)]
            if not extracted:
                return [], "A lista de 'rules' do grupo está vazia."
            return extracted, None

        # 3. Formato de regra única
        if any(k in parsed_data for k in ("alert", "title", "name", "expr", "logql_query", "data", "detection")):
            return [parsed_data], None

        return [], (
            "Estrutura YAML/JSON não reconhecida. Esperado: especificação Loki Ruler com 'groups', "
            "grupo com 'rules' ou lista de regras de detecção."
        )

    return [], "O arquivo YAML/JSON deve conter um objeto ou uma lista de regras."


def extract_rule_fields_and_mappings(
    raw_rule: dict[str, Any],
    clean_query: str,
    technology: Technology | None,
) -> tuple[list[CurationFieldMapping], float]:
    """Extrai campos necessários da regra e mapeia para a arquitetura Wazuh/Loki do D.A.N.T.E.

    Retorna: (mapped_fields, schema_compatibility_pct).
    """
    mapped_fields: list[CurationFieldMapping] = []
    seen_logql_fields: set[str] = set()

    tech_map: dict[str, str] = {}
    supported_fields: set[str] = set()
    if technology:
        tech_map = {
            **PERIMETER_FIELD_TRANSLATION_MAP.get(technology.perimeter, {}),
            **FIELD_TRANSLATION_MAP.get(technology.slug, {}),
        }
        supported_fields = set(
            SUPPORTED_WAZUH_LOKI_FIELDS.get(technology.slug)
            or PERIMETER_DEFAULT_FIELDS.get(technology.perimeter)
            or {"rule_id", "full_log"}
        )

    # 1. Se a regra for Sigma YAML ou contiver árvore detection/AST
    if (
        raw_rule.get("rule_format") == "Sigma (YAML)"
        or raw_rule.get("source_id") == "sigmahq"
        or "detection" in raw_rule
        or "raw_yaml" in raw_rule
    ) and technology:
        try:
            _, sigma_mappings, sigma_lint_ok, _ = convert_sigma_to_logql(raw_rule, technology)
            if sigma_mappings:
                for sm in sigma_mappings:
                    canon_field = ensure_data_prefix(sm.logql_field)
                    if canon_field not in seen_logql_fields:
                        seen_logql_fields.add(canon_field)
                        mapped_fields.append(
                            CurationFieldMapping(
                                original_field=sm.original_field,
                                logql_field=canon_field,
                                compatible=sm.compatible,
                            )
                        )
        except Exception as conv_err:
            logger.debug("Falha na extração de campos via SigmaConverter: %s", conv_err)

    # 2. Extração de campos a partir do pipeline LogQL
    if clean_query:
        # Matchers no pipeline: | campo op "valor" ou | data_campo op "valor"
        filter_matches = re.finditer(
            r'\|\s*([a-zA-Z0-9_\.\-]+)\s*(=~|!~|!=|=)\s*["\']?([^"\'|\s)]+)["\']?',
            clean_query,
        )
        for m in filter_matches:
            raw_field = m.group(1).strip()
            if raw_field.lower() in ("job", "rule_groups", "ss_groups", "cluster", "env", "level", "tenant"):
                continue

            if raw_field in tech_map:
                loki_f = tech_map[raw_field]
            else:
                clean_f = re.sub(r"[^a-zA-Z0-9_]", "_", raw_field)
                loki_f = ensure_data_prefix(clean_f)

            loki_f = ensure_data_prefix(loki_f)
            if loki_f not in seen_logql_fields:
                seen_logql_fields.add(loki_f)
                is_comp = (
                    not supported_fields
                    or loki_f in supported_fields
                    or loki_f.removeprefix("data_") in supported_fields
                    or f"data_{loki_f}" in supported_fields
                    or loki_f in ("rule_id", "full_log", "agent_name", "timestamp", "level", "severity")
                )
                mapped_fields.append(
                    CurationFieldMapping(
                        original_field=raw_field,
                        logql_field=loki_f,
                        compatible=is_comp,
                    )
                )

        # Extração de campos explicitados em `| json field1, field2`
        for jm in re.finditer(r'\|\s*json\s+([a-zA-Z0-9_,\s]+)', clean_query):
            for jf in jm.group(1).split(","):
                clean_jf = jf.strip()
                if clean_jf and clean_jf.lower() not in ("job", "rule_groups", "ss_groups"):
                    loki_f = ensure_data_prefix(clean_jf)
                    if loki_f not in seen_logql_fields:
                        seen_logql_fields.add(loki_f)
                        is_comp = (
                            not supported_fields
                            or loki_f in supported_fields
                            or loki_f.removeprefix("data_") in supported_fields
                            or f"data_{loki_f}" in supported_fields
                        )
                        mapped_fields.append(
                            CurationFieldMapping(
                                original_field=clean_jf,
                                logql_field=loki_f,
                                compatible=is_comp,
                            )
                        )

    # 3. Fallback: se nenhum campo específico de pipeline foi extraído, usa os campos basilares da tecnologia
    if not mapped_fields and technology:
        defaults = list(
            SUPPORTED_WAZUH_LOKI_FIELDS.get(technology.slug)
            or PERIMETER_DEFAULT_FIELDS.get(technology.perimeter)
            or ["rule_id", "full_log"]
        )[:4]
        for df in defaults:
            canon_df = ensure_data_prefix(df)
            if canon_df not in seen_logql_fields:
                seen_logql_fields.add(canon_df)
                mapped_fields.append(
                    CurationFieldMapping(
                        original_field=df,
                        logql_field=canon_df,
                        compatible=True,
                    )
                )

    total_f = len(mapped_fields)
    comp_f = sum(1 for m in mapped_fields if m.compatible)
    schema_compat_pct = round((comp_f * 100.0) / total_f, 1) if total_f > 0 else 100.0
    return mapped_fields, schema_compat_pct


def generate_imported_rule_opinion(
    item: RuleImportItemValidation,
    raw_rule: dict[str, Any],
    technology: Technology | None,
    ai_service: AIService | None = None,
) -> tuple[str, str, Literal["ai", "heuristic"]]:
    """Gera parecer técnico e curadoria por IA para a regra importada seguindo o padrão do D.A.N.T.E.

    Contempla:
    1. Contexto de Ameaça (vetor de ataque, modus operandi, MITRE ATT&CK);
    2. Compatibilidade e Aderência dos Campos aos Ambientes de Clientes (Wazuh schema | json);
    3. Diretrizes para o SOC (triage, enriquecimento, tuning e silenciamento operacional).
    """
    title = item.title.strip()
    desc = (item.description or raw_rule.get("description") or "").strip()
    mitre_tech = (item.mitre_technique or "T1059").strip().upper()
    mitre_tactic = (item.mitre_tactic or "execution").strip().lower()
    tech_name = technology.name if technology else (item.technology_name or "Tecnologia Geral")
    perimeter_name = technology.perimeter_name if technology else "Perímetro Corporativo"

    is_brute_force = (
        "t1110" in mitre_tech.lower()
        or "t1046" in mitre_tech.lower()
        or any(
            kw in title.lower() or kw in desc.lower()
            for kw in (
                "brute force",
                "bruteforce",
                "forca bruta",
                "força bruta",
                "password spray",
                "spray",
                "falha de logon",
                "login failure",
                "burst",
            )
        )
    )

    sections: list[str] = []

    # 1. Contexto de Ameaça
    if is_brute_force:
        sections.append(
            f"Contexto de Ameaça: Identifica atividade adversária de Força Bruta / Password Spraying "
            f"({mitre_tech} - {mitre_tactic}) visando o perímetro {perimeter_name}. O agente de ameaça realiza "
            f"tentativas massivas consecutivas de autenticação para comprometer contas válidas. A expressão LogQL "
            f"foi estruturada para capturar rajadas anômalas de eventos na telemetria da tecnologia '{tech_name}', "
            f"prevenindo que falhas isoladas de digitação gerem alarmes falsos."
        )
    else:
        sections.append(
            f"Contexto de Ameaça: A regra '{title}' combate técnicas adversárias de {mitre_tactic.replace('-', ' ').title()} "
            f"({mitre_tech} - MITRE ATT&CK) no perímetro {perimeter_name}. "
            f"{desc or 'Monitora anomalias comportamentais, comandos suspeitos e indicadores de comprometimento na telemetria corporativa.'}"
        )

    # 2. Parecer de Aderência e Compatibilidade de Campos nos Clientes
    compat_val = item.field_compatibility_pct if item.field_compatibility_pct is not None else 100.0
    comp_fields = [m.logql_field for m in item.mapped_fields if m.compatible]
    incomp_fields = [m.original_field for m in item.mapped_fields if not m.compatible]

    field_lines: list[str] = []
    if incomp_fields:
        field_lines.append(
            f"Aderência de Campos: Foram mapeados {len(comp_fields)} campo(s) compatível(is) para a arquitetura Wazuh/Loki, "
            f"porém {len(incomp_fields)} campo(s) ({', '.join(incomp_fields[:3])}) não possuem correspondência direta no schema "
            f"da tecnologia '{tech_name}'. A compatibilidade dinâmica foi aferida em {compat_val:.1f}%."
        )
    else:
        field_lines.append(
            f"Aderência de Campos: 100% dos campos requeridos pela regra ({', '.join(comp_fields[:4]) if comp_fields else 'telemetria base'}) "
            f"são plenamente compatíveis com a descompactação JSON (| json) da telemetria Wazuh. "
            f"Compatibilidade dinâmica consolidada em {compat_val:.1f}%."
        )

    if item.client_evaluations:
        exc_clients = [ev.client_name for ev in item.client_evaluations if ev.classification == "excellent"]
        gd_clients = [ev.client_name for ev in item.client_evaluations if ev.classification == "good"]
        bad_clients = [ev.client_name for ev in item.client_evaluations if ev.classification == "bad"]
        if exc_clients:
            field_lines.append(f"Ambientes de Alta Compatibilidade (≥ 95%): {', '.join(exc_clients)}.")
        if gd_clients:
            field_lines.append(f"Ambientes com Boa Compatibilidade (80%-94%): {', '.join(gd_clients)}.")
        if bad_clients:
            field_lines.append(f"Ambientes Incompatíveis (< 80%): {', '.join(bad_clients)} (requer habilitação de telemetria).")

    sections.append("\n".join(field_lines))

    # 3. Diretrizes para o SOC e Triagem Operacional
    sections.append(
        "Diretrizes para o SOC: Em caso de alarme gerado por esta regra, correlacionar imediatamente o IP de origem, "
        "a identidade do usuário afetado e a linha do tempo das atividades no host. Se o comportamento for validado como "
        "rotina corporativa legítima (ex.: ferramenta de inventário ou script agendado), cadastrar exceção documentada "
        "com tag canônica [excecao] ou silenciar temporariamente via [antiflood]."
    )

    opinion_text = "\n\n".join(sections)
    ai_model = "D.A.N.T.E. Threat Intelligence"
    curation_engine: Literal["ai", "heuristic"] = "heuristic"

    if ai_service and ai_service.is_curation_enabled():
        try:
            raw_cfg = ai_service.get_raw_settings()
            ai_model = f"{raw_cfg.provider.title()} ({raw_cfg.model})"
            curation_engine = "ai"
        except Exception:
            pass

    return opinion_text, ai_model, curation_engine


def _populate_imported_item_curation(
    item: RuleImportItemValidation,
    technology: Technology | None,
) -> None:
    """Consolida métricas, fatores de qualificação e pontuação dinâmica da regra importada."""
    total_f = len(item.mapped_fields)
    comp_fields = [m.logql_field for m in item.mapped_fields if m.compatible]
    schema_compat_pct = (
        round((len(comp_fields) * 100.0) / total_f, 1)
        if total_f > 0
        else 100.0
    )

    # 1. Se há avaliações individuais de clientes (Loki dos clientes consultado)
    if item.client_evaluations:
        total_matched = sum(ev.matched_lines_count for ev in item.client_evaluations)
        total_tech = sum(ev.tech_logs_count for ev in item.client_evaluations)
        has_results = total_matched > 0
        item.total_matched_results = total_matched
        item.total_tech_logs_seen = total_tech
        item.has_query_results = has_results

        # Coleta janelas e amostras
        sample_results: list[str] = []
        matched_windows: list[str] = []
        for ev in item.client_evaluations:
            if ev.matched_window:
                entry = f"{ev.client_name}: {ev.matched_window}"
                if entry not in matched_windows:
                    matched_windows.append(entry)
            for line in ev.sample_matched_logs:
                if line not in sample_results and len(sample_results) < 5:
                    sample_results.append(line)
        item.matched_windows_summary = matched_windows
        item.sample_query_results = sample_results

        # Avalia prontidão de telemetria em cada cliente e pontuação individual
        any_client_has_telemetry = False
        for ev in item.client_evaluations:
            ev_obs_set = _expand_observed_field_aliases(
                set(ev.total_observed_log_fields or ev.observed_fields_in_logs or [])
            )
            ev_has_tel, _, _ = _evaluate_client_telemetry_readiness(
                mapped_fields=item.mapped_fields,
                observed_fields=ev_obs_set,
                tech_logs_count=ev.tech_logs_count,
                has_query_results=bool(ev.has_query_results or ev.matched_lines_count > 0),
            )
            if ev_has_tel:
                any_client_has_telemetry = True

            c_score, c_lp, c_tc, c_sm = compute_dynamic_compatibility(
                schema_compat_pct=schema_compat_pct,
                tech_logs_count=ev.tech_logs_count,
                matched_lines_count=ev.matched_lines_count,
                matched_windows=[ev.matched_window] if ev.matched_window else [],
                severity=str(item.severity),
                mitre_tactic=item.mitre_tactic or "",
                mitre_technique=item.mitre_technique or "",
                perimeter=technology.perimeter if technology else "other",
                observed_field_compat_pct=float(ev.observed_field_compatibility_pct or 0.0),
                has_query_results=bool(ev.has_query_results or ev.matched_lines_count > 0),
                has_required_telemetry=ev_has_tel,
                lint_valid=item.valid,
                multi_client=False,
            )
            ev.field_compatibility_pct = c_score
            ev.log_presence_score = c_lp
            ev.threat_context_score = c_tc
            ev.scenario_match_score = c_sm
            if c_score >= 95.0:
                ev.classification = "excellent"
            elif c_score >= 80.0:
                ev.classification = "good"
            else:
                ev.classification = "bad"

        # Pontuação dinâmica global consolidada
        best_client_obs_pct = max(
            (float(ev.observed_field_compatibility_pct or 0.0) for ev in item.client_evaluations),
            default=100.0 if not item.mapped_fields else 0.0,
        )
        item.observed_field_compatibility_pct = best_client_obs_pct

        # Campos observados globalmente
        global_obs_fields: set[str] = set()
        for ev in item.client_evaluations:
            global_obs_fields.update(ev.observed_fields_in_logs or [])
        item.observed_fields_in_logs = sorted(list(global_obs_fields))
        item.missing_fields_in_logs = sorted(
            [f for f in comp_fields if f not in global_obs_fields]
        )

        has_multi = len([ev for ev in item.client_evaluations if ev.tech_logs_count > 0]) >= 2
        dynamic_score, log_score, threat_score, scenario_score = compute_dynamic_compatibility(
            schema_compat_pct=schema_compat_pct,
            tech_logs_count=total_tech,
            matched_lines_count=total_matched,
            matched_windows=[ev.matched_window for ev in item.client_evaluations if ev.matched_window],
            severity=str(item.severity),
            mitre_tactic=item.mitre_tactic or "",
            mitre_technique=item.mitre_technique or "",
            perimeter=technology.perimeter if technology else "other",
            observed_field_compat_pct=best_client_obs_pct,
            has_query_results=has_results,
            has_required_telemetry=any_client_has_telemetry,
            lint_valid=item.valid,
            multi_client=has_multi,
        )

        item.field_compatibility_pct = dynamic_score
        item.log_presence_score = log_score
        item.threat_context_score = threat_score
        item.scenario_match_score = scenario_score

        item.excellent_clients_count = sum(1 for ev in item.client_evaluations if ev.classification == "excellent")
        item.good_clients_count = sum(1 for ev in item.client_evaluations if ev.classification == "good")

        if dynamic_score >= 95.0:
            item.classification = "excellent"
            item.classification_reason = f"Alta Compatibilidade ({dynamic_score:.1f}%): campos e telemetria plenamente compatíveis."
        elif dynamic_score >= 80.0:
            item.classification = "good"
            item.classification_reason = f"Boa Candidata ({dynamic_score:.1f}%): atende aos requisitos de detecção corporativa."
        else:
            item.classification = "bad"
            item.classification_reason = f"Incompatível ({dynamic_score:.1f}% < 80%): campos ou telemetria ausentes nos clientes."
            item.warnings.append(
                f"Compatibilidade insuficiente ({dynamic_score:.0f}% < 80%) com os campos e telemetria dos ambientes avaliados."
            )

    # 2. Modo offline/heurístico (sem consulta aos datasources de clientes)
    else:
        item.observed_field_compatibility_pct = schema_compat_pct
        item.observed_fields_in_logs = [m.logql_field for m in item.mapped_fields if m.compatible]
        item.missing_fields_in_logs = [m.logql_field for m in item.mapped_fields if not m.compatible]

        # Contexto basilar
        sev_bonus = 2.0 if str(item.severity).lower() in ("high", "critical") else 1.2
        tac_bonus = 1.8 if item.mitre_tactic else 0.8
        threat_score = min(6.0, sev_bonus + tac_bonus + 1.2)
        log_score = 4.0 if item.valid else 0.0
        scenario_score = 4.0 if schema_compat_pct >= 80.0 else 1.5

        if schema_compat_pct >= 95.0 and item.valid:
            item.field_compatibility_pct = 95.0
            item.classification = "excellent"
            item.classification_reason = "Alta Compatibilidade: 100% dos campos compatíveis com o schema Wazuh."
        elif schema_compat_pct >= 80.0 and item.valid:
            item.field_compatibility_pct = schema_compat_pct
            item.classification = "good"
            item.classification_reason = f"Boa Candidata: compatibilidade de campos em {schema_compat_pct:.1f}%."
        else:
            item.field_compatibility_pct = min(78.0, schema_compat_pct)
            item.classification = "bad"
            item.classification_reason = f"Incompatível ({schema_compat_pct:.1f}% < 80%): campos sem correspondência no schema."
            item.warnings.append(f"Compatibilidade de campos ({schema_compat_pct:.1f}%) abaixo do limiar mínimo de 80%.")

        item.log_presence_score = log_score
        item.threat_context_score = threat_score
        item.scenario_match_score = scenario_score

    # Fatores de qualificação canônicos
    factors: list[CurationQualificationFactor] = []
    # Fator 1: Presença de Logs e Telemetria
    if item.log_presence_score >= 5.0 or item.has_query_results:
        f1_impact = "excellent"
        f1_status = "met"
        f1_desc = f"Telemetria comprovada no cluster ({item.total_tech_logs_seen} logs observados)."
    elif item.log_presence_score >= 3.0:
        f1_impact = "good"
        f1_status = "met"
        f1_desc = "Cluster Loki ativo e apto para ingesta da tecnologia."
    else:
        f1_impact = "bad"
        f1_status = "partial"
        f1_desc = "Pouco volume de logs históricos detectado nos clientes avaliados."
    factors.append(CurationQualificationFactor(criterion="Presença de Logs no Loki", status=f1_status, impact=f1_impact, summary=f1_desc))

    # Fator 2: Contexto de Ameaça
    if str(item.severity).lower() in ("critical", "high") and item.mitre_technique:
        f2_impact = "excellent"
        f2_status = "met"
        f2_desc = f"Severidade {item.severity.upper()} e técnica {item.mitre_technique} devidamente mapeadas no MITRE ATT&CK."
    else:
        f2_impact = "good"
        f2_status = "met"
        f2_desc = f"Alinhado ao perímetro de segurança corporativa ({item.mitre_tactic or 'geral'})."
    factors.append(CurationQualificationFactor(criterion="Contexto de Ameaça e MITRE", status=f2_status, impact=f2_impact, summary=f2_desc))

    # Fator 3: Aderência dos Campos
    if schema_compat_pct >= 95.0:
        f3_impact = "excellent"
        f3_status = "met"
        f3_desc = f"100% dos campos requeridos ({len(comp_fields)} campos) compatíveis com o schema Wazuh (| json)."
    elif schema_compat_pct >= 80.0:
        f3_impact = "good"
        f3_status = "met"
        f3_desc = f"Mais de 80% dos campos ({schema_compat_pct:.1f}%) compatíveis com o schema dos clientes."
    else:
        f3_impact = "bad"
        f3_status = "not_met"
        f3_desc = f"Campos incompatíveis identificados ({schema_compat_pct:.1f}% < 80%): verifique os nomes dos atributos."
    factors.append(CurationQualificationFactor(criterion="Compatibilidade de Campos", status=f3_status, impact=f3_impact, summary=f3_desc))

    item.qualification_factors = factors


def validate_rule_item(
    index: int,
    raw_rule: dict[str, Any],
    technology_store: TechnologyStore,
    existing_baseline_titles: set[str],
    filename: str | None = None,
) -> RuleImportItemValidation:
    """Valida exaustivamente uma regra de detecção, mapeia campos e gera parecer de curadoria."""
    errors: list[str] = []
    warnings: list[str] = []

    # 1. Título / Nome da regra
    raw_title = raw_rule.get("alert") or raw_rule.get("title") or raw_rule.get("name")
    if not raw_title or not str(raw_title).strip():
        errors.append("Título ou nome da regra ('alert', 'title' ou 'name') é obrigatório.")
        title = f"Regra sem título #{index + 1}"
    else:
        title = str(raw_title).strip()

    # 2. Expressão LogQL
    raw_expr: str | None = None
    if "expr" in raw_rule:
        raw_expr = raw_rule.get("expr")
    elif "logql_query" in raw_rule:
        raw_expr = raw_rule.get("logql_query")
    elif "query" in raw_rule:
        raw_expr = raw_rule.get("query")
    elif "data" in raw_rule and isinstance(raw_rule["data"], list) and raw_rule["data"]:
        first_query = raw_rule["data"][0]
        if isinstance(first_query, dict):
            raw_expr = first_query.get("model", {}).get("expr")

    if not raw_expr or not str(raw_expr).strip():
        errors.append("Expressão LogQL ('expr', 'logql_query' ou 'query') é obrigatória.")
        clean_query = ""
        thresh_op = "gt"
        thresh_val = 0.0
    else:
        clean_query, thresh_op, thresh_val = parse_query_and_threshold(str(raw_expr))

    # 3. Descrição e anotações
    annotations = dict(raw_rule.get("annotations") or {}) if isinstance(raw_rule.get("annotations"), dict) else {}
    description = (
        annotations.get("description")
        or annotations.get("summary")
        or raw_rule.get("description")
        or raw_rule.get("summary")
    )
    if description:
        description = str(description).strip()

    # 4. Labels e Severidade
    labels = dict(raw_rule.get("labels") or {}) if isinstance(raw_rule.get("labels"), dict) else {}
    raw_severity = str(labels.get("severity") or raw_rule.get("severity") or "medium").strip().lower()
    if raw_severity == "info":
        warnings.append("Severidade 'info' convertida para 'low'.")
        severity: RuleSeverity = "low"
    elif raw_severity not in VALID_SEVERITIES:
        errors.append(
            f"Severidade '{raw_severity}' inválida. Valores aceitos: low, medium, high, critical."
        )
        severity = "medium"
    else:
        severity = raw_severity  # type: ignore[assignment]

    # 5. MITRE ATT&CK: Tática e Técnica (obrigatórias)
    raw_tactic = (
        labels.get("mitre_tactic")
        or labels.get("mitre_tactics")
        or raw_rule.get("mitre_tactic")
        or ""
    )
    if not str(raw_tactic).strip():
        errors.append("Label obrigatória 'mitre_tactic' ausente.")
        mitre_tactic = None
    else:
        mitre_tactic = str(raw_tactic).strip().lower()

    raw_technique = (
        labels.get("mitre_technique")
        or labels.get("mitre_techniques")
        or raw_rule.get("mitre_technique")
        or ""
    )
    if not str(raw_technique).strip():
        errors.append("Label obrigatória 'mitre_technique' ausente.")
        mitre_technique = None
    else:
        mitre_technique = str(raw_technique).strip().upper()

    # 6. Duração ('for')
    for_duration = str(raw_rule.get("for") or raw_rule.get("for_duration") or "0s").strip()

    # 7. Linting da Query LogQL
    tech_obj: Technology | None = None
    tech_missing = False
    suggested_tech_slug: str | None = None
    suggested_tech_name: str | None = None
    suggested_ss_groups_regex: str | None = None
    suggested_rule_groups_regex: str | None = None

    if clean_query:
        known_patterns = [t.effective_groups_regex for t in technology_store.list_all()]
        lint_result = lint_logql(clean_query, known_ss_groups_patterns=known_patterns)
        if not lint_result.is_valid:
            for issue in lint_result.issues:
                if issue.level == "error":
                    errors.append(f"LogQL inválido: {issue.message}")

        # 8. Segregação e Tecnologia (ss_groups)
        ss_groups_values = [v for _op, v in extract_rule_groups_values(clean_query)]
        if not ss_groups_values:
            errors.append(
                "A query precisa conter um seletor 'rule_groups' (ou 'ss_groups') delimitando a tecnologia."
            )
        else:
            explicit_tech_slug = (
                str(labels.get("technology") or raw_rule.get("technology") or "").strip()
            )
            if explicit_tech_slug:
                try:
                    tech_obj = technology_store.get(explicit_tech_slug)
                    if not any(
                        selector_matches_technology(v, tech_obj) for v in ss_groups_values
                    ):
                        errors.append(
                            f"Tecnologia '{tech_obj.name}' não corresponde aos matchers 'ss_groups' da query."
                        )
                except TechnologyNotFound:
                    s_slug, s_name, s_regex = extract_suggested_technology_info(
                        ss_groups_values[0], explicit_slug=explicit_tech_slug
                    )
                    suggested_tech_slug = s_slug
                    suggested_tech_name = s_name
                    suggested_ss_groups_regex = s_regex
                    suggested_rule_groups_regex = s_regex
                    tech_missing = True
            else:
                candidates = technology_store.match_query(clean_query)
                if len(candidates) == 1:
                    tech_obj = candidates[0]
                elif not candidates:
                    s_slug, s_name, s_regex = extract_suggested_technology_info(
                        ss_groups_values[0]
                    )
                    suggested_tech_slug = s_slug
                    suggested_tech_name = s_name
                    suggested_ss_groups_regex = s_regex
                    suggested_rule_groups_regex = s_regex
                    tech_missing = True
                else:
                    cand_names = ", ".join(f"{t.name} ({t.slug})" for t in candidates)
                    errors.append(
                        f"A query referencia mais de uma tecnologia ({cand_names}). Especifique a tecnologia na regra."
                    )

    # Tratamento de tecnologia não existente:
    final_tech_missing = False
    if tech_missing:
        if len(errors) == 0:
            final_tech_missing = True
            warnings.append(
                f"A tecnologia '{suggested_tech_name}' ({suggested_tech_slug}) ainda não existe no catálogo. "
                "Crie a tecnologia para habilitar a importação desta regra."
            )
        else:
            errors.append(
                f"A tecnologia '{suggested_tech_name}' ({suggested_tech_slug}) não está cadastrada no catálogo."
            )

    # 9. Duplicidade no baseline
    already_exists = False
    if title.lower() in existing_baseline_titles:
        already_exists = True
        warnings.append("Regra já existe no Baseline (título idêntico).")

    is_valid = len(errors) == 0 and not final_tech_missing

    # 10. Mapeamento de campos e análise de compatibilidade com o schema
    mapped_fields, schema_compat_pct = extract_rule_fields_and_mappings(
        raw_rule=raw_rule,
        clean_query=clean_query,
        technology=tech_obj,
    )

    item = RuleImportItemValidation(
        index=index,
        title=title,
        description=description,
        query=clean_query,
        threshold_operator=thresh_op,
        threshold_value=thresh_val,
        severity=severity,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        technology=tech_obj.slug if tech_obj else None,
        technology_name=tech_obj.name if tech_obj else None,
        for_duration=for_duration,
        valid=is_valid,
        errors=errors,
        warnings=warnings,
        already_exists=already_exists,
        filename=filename,
        technology_missing=final_tech_missing,
        suggested_technology_slug=suggested_tech_slug,
        suggested_technology_name=suggested_tech_name,
        suggested_rule_groups_regex=suggested_rule_groups_regex or suggested_ss_groups_regex,
        suggested_ss_groups_regex=suggested_ss_groups_regex,
        mapped_fields=mapped_fields,
        curated_at=datetime.now(timezone.utc).isoformat(),
    )

    # Consolida pontuação e fatores de curadoria
    _populate_imported_item_curation(item, tech_obj)

    # Gera parecer técnico por IA / Heurística
    opinion_text, ai_model, curation_engine = generate_imported_rule_opinion(
        item=item,
        raw_rule=raw_rule,
        technology=tech_obj,
    )
    item.ai_rationale = opinion_text
    item.ai_model = ai_model
    item.curation_engine = curation_engine

    return item


def _compute_summary_metrics(items: list[RuleImportItemValidation]) -> tuple[int, int, int]:
    """Calcula as métricas consolidadas de qualificação e compatibilidade para o preview."""
    qualified_count = sum(
        1
        for it in items
        if it.valid
        and not it.technology_missing
        and (it.field_compatibility_pct or 0) >= 80.0
        and it.classification in ("excellent", "good")
    )
    high_compatibility_count = sum(
        1
        for it in items
        if it.valid
        and not it.technology_missing
        and (it.field_compatibility_pct or 0) >= 95.0
        and it.classification == "excellent"
    )
    discarded_count = sum(
        1
        for it in items
        if len(it.errors) > 0
        or (it.field_compatibility_pct or 0) < 80.0
        or it.classification == "bad"
    )
    return qualified_count, high_compatibility_count, discarded_count


def preview_rules_json(
    content: str,
    technology_store: TechnologyStore,
    existing_baseline_titles: set[str],
    filename: str | None = None,
) -> RuleImportPreviewResponse:
    """Valida todas as regras de uma única string YAML ou JSON e retorna o relatório de preview."""
    parsed, parse_err = parse_raw_content(content)
    if parse_err:
        return RuleImportPreviewResponse(
            total_rules=0,
            valid_count=0,
            invalid_count=0,
            missing_tech_count=0,
            items=[],
            general_error=parse_err,
            files_count=1 if content.strip() else 0,
        )

    raw_rules, extract_err = extract_raw_rule_dicts(parsed)
    if extract_err:
        return RuleImportPreviewResponse(
            total_rules=0,
            valid_count=0,
            invalid_count=0,
            missing_tech_count=0,
            items=[],
            general_error=extract_err,
            files_count=1 if content.strip() else 0,
        )

    items: list[RuleImportItemValidation] = []
    for idx, raw in enumerate(raw_rules):
        item = validate_rule_item(
            index=idx,
            raw_rule=raw,
            technology_store=technology_store,
            existing_baseline_titles=existing_baseline_titles,
            filename=filename,
        )
        items.append(item)

    valid_count = sum(1 for it in items if it.valid and not it.technology_missing)
    missing_tech_count = sum(1 for it in items if it.technology_missing)
    invalid_count = sum(1 for it in items if len(it.errors) > 0)
    q_count, h_count, d_count = _compute_summary_metrics(items)

    return RuleImportPreviewResponse(
        total_rules=len(items),
        valid_count=valid_count,
        invalid_count=invalid_count,
        missing_tech_count=missing_tech_count,
        qualified_count=q_count,
        high_compatibility_count=h_count,
        discarded_count=d_count,
        items=items,
        general_error=None,
        files_count=1 if content.strip() else 0,
    )


def preview_rules_multiple(
    files: list[RuleImportFileInput],
    technology_store: TechnologyStore,
    existing_baseline_titles: set[str],
) -> RuleImportPreviewResponse:
    """Valida exaustivamente múltiplos arquivos YAML ou JSON para importação em lote."""
    if not files:
        return RuleImportPreviewResponse(
            total_rules=0,
            valid_count=0,
            invalid_count=0,
            missing_tech_count=0,
            items=[],
            general_error="Nenhum arquivo fornecido para importação.",
            files_count=0,
        )

    all_items: list[RuleImportItemValidation] = []

    for file_input in files:
        fname = file_input.filename or "arquivo_sem_nome"
        raw_content = file_input.content
        if not raw_content or not raw_content.strip():
            all_items.append(
                RuleImportItemValidation(
                    index=len(all_items),
                    title=f"Arquivo vazio ({fname})",
                    query="",
                    valid=False,
                    errors=[f"O arquivo '{fname}' está vazio."],
                    filename=fname,
                )
            )
            continue

        parsed, parse_err = parse_raw_content(raw_content)
        if parse_err:
            all_items.append(
                RuleImportItemValidation(
                    index=len(all_items),
                    title=f"Erro de sintaxe ({fname})",
                    query="",
                    valid=False,
                    errors=[f"Arquivo '{fname}': {parse_err}"],
                    filename=fname,
                )
            )
            continue

        raw_rules, extract_err = extract_raw_rule_dicts(parsed)
        if extract_err:
            all_items.append(
                RuleImportItemValidation(
                    index=len(all_items),
                    title=f"Estrutura inválida ({fname})",
                    query="",
                    valid=False,
                    errors=[f"Arquivo '{fname}': {extract_err}"],
                    filename=fname,
                )
            )
            continue

        for raw in raw_rules:
            item = validate_rule_item(
                index=len(all_items),
                raw_rule=raw,
                technology_store=technology_store,
                existing_baseline_titles=existing_baseline_titles,
                filename=fname,
            )
            all_items.append(item)

    valid_count = sum(1 for it in all_items if it.valid and not it.technology_missing)
    missing_tech_count = sum(1 for it in all_items if it.technology_missing)
    invalid_count = sum(1 for it in all_items if len(it.errors) > 0)
    q_count, h_count, d_count = _compute_summary_metrics(all_items)

    for i, it in enumerate(all_items):
        it.index = i

    general_error: str | None = None
    if not all_items:
        general_error = "Nenhuma regra de detecção encontrada nos arquivos enviados."

    return RuleImportPreviewResponse(
        total_rules=len(all_items),
        valid_count=valid_count,
        invalid_count=invalid_count,
        missing_tech_count=missing_tech_count,
        qualified_count=q_count,
        high_compatibility_count=h_count,
        discarded_count=d_count,
        items=all_items,
        general_error=general_error,
        files_count=len(files),
    )


async def preview_rules_curated(
    *,
    content: str | None = None,
    files: list[RuleImportFileInput] | None = None,
    technology_store: TechnologyStore,
    existing_baseline_titles: set[str],
    grafana: GrafanaClient | None = None,
    sys_settings: SystemSettingsStore | None = None,
    ai_service: AIService | None = None,
) -> RuleImportPreviewResponse:
    """Executa análise completa de curadoria, parecer técnico de IA e compatibilidade com telemetria dos clientes.

    Padrão idêntico à funcionalidade de Curadoria do D.A.N.T.E.:
    1. Validação de sintaxe, MITRE ATT&CK, severidade e discriminação da tecnologia;
    2. Mapeamento de campos para a arquitetura Wazuh/Loki (| json);
    3. Se o Grafana estiver disponível, avalia a presença dos campos e telemetria no Loki dos clientes;
    4. Gera o Parecer Técnico por IA contextualizado (vetor de ameaça, modus operandi e diretrizes de triagem SOC);
    5. Consolida pontuação de compatibilidade dinâmica recalibrada (Alta >= 95%, Boa 80%-94%, Incompatível < 80%).
    """
    # 1. Executa primeiro a validação estrutural básica
    if files:
        base_preview = preview_rules_multiple(files, technology_store, existing_baseline_titles)
        raw_list: list[dict[str, Any]] = []
        for f in files:
            p, _ = parse_raw_content(f.content)
            if p:
                r, _ = extract_raw_rule_dicts(p)
                raw_list.extend(r)
    elif content:
        base_preview = preview_rules_json(content, technology_store, existing_baseline_titles)
        p, _ = parse_raw_content(content)
        raw_list, _ = extract_raw_rule_dicts(p) if p else ([], None)
    else:
        return RuleImportPreviewResponse(
            total_rules=0,
            valid_count=0,
            invalid_count=0,
            missing_tech_count=0,
            items=[],
            general_error="Nenhum arquivo ou conteúdo fornecido para importação.",
            files_count=0,
        )

    if base_preview.general_error or not base_preview.items:
        return base_preview

    # 2. Se o Grafana for fornecido, executa avaliação de telemetria real nos clientes
    client_folders: list[dict[str, Any]] = []
    raw_datasources: list[dict[str, Any]] = []
    all_rules: list[dict[str, Any]] = []
    declared_map: dict[str, list[str]] = {}
    scan_store = get_tenant_scan_store()

    if grafana:
        try:
            folders, raw_datasources, all_rules = await asyncio.gather(
                grafana.list_folders(),
                grafana.list_datasources(),
                grafana.list_alert_rules(),
            )
            client_folders = [f for f in folders if is_client_folder(f)]
            tenant_tech_store = get_tenant_technology_store()
            declared_map = tenant_tech_store.get_all_declared()
        except Exception as exc:
            logger.warning("Não foi possível consultar inventário de clientes no Grafana para preview: %s", exc)

    tech_logs_cache: dict[tuple[str, str], tuple[bool, list[str], str | None, list[str], bool]] = {}
    client_field_presence_cache: dict[tuple[str, str], set[str]] = {}
    dead_datasources: set[str] = set()

    # 3. Itera sobre cada regra analisada
    for idx, item in enumerate(base_preview.items):
        raw_dict = raw_list[idx] if idx < len(raw_list) else {}
        tech_obj: Technology | None = None
        if item.technology:
            try:
                tech_obj = technology_store.get(item.technology)
            except Exception:
                tech_obj = None

        # Re-extrai mapeamento de campos com base na tecnologia detectada
        mapped_fields, _ = extract_rule_fields_and_mappings(raw_dict, item.query, tech_obj)
        item.mapped_fields = mapped_fields

        # Se a regra for válida, tecnologia confirmada e há clientes no Grafana, avalia telemetria real
        if item.valid and tech_obj and client_folders and grafana:
            try:
                classification, reason, compat_pct, client_evals = await evaluate_rule_across_clients(
                    grafana=grafana,
                    technology=tech_obj,
                    logql_query=item.query,
                    mapped_fields=mapped_fields,
                    rule_title=item.title,
                    client_folders=client_folders,
                    datasources=raw_datasources,
                    all_rules=all_rules,
                    declared_map=declared_map,
                    scan_store=scan_store,
                    tech_logs_cache=tech_logs_cache,
                    client_field_presence_cache=client_field_presence_cache,
                    dead_datasources=dead_datasources,
                    rule_source="Importação Loki Ruler",
                    rule_index=idx + 1,
                    total_rules=len(base_preview.items),
                    severity=str(item.severity),
                    mitre_tactic=item.mitre_tactic or "",
                    mitre_technique=item.mitre_technique or "",
                    raw_rule=raw_dict,
                )
                item.client_evaluations = client_evals
                item.classification = classification
                item.classification_reason = reason
                item.field_compatibility_pct = compat_pct
            except Exception as ev_err:
                logger.warning("Falha ao avaliar regra '%s' nos clientes: %s", item.title, ev_err)

        # Consolida pontuação e fatores de qualificação
        _populate_imported_item_curation(item, tech_obj)

        # Gera o Parecer Técnico por IA com o enriquecimento de telemetria
        opinion_text, ai_model, curation_engine = generate_imported_rule_opinion(
            item=item,
            raw_rule=raw_dict,
            technology=tech_obj,
            ai_service=ai_service,
        )
        item.ai_rationale = opinion_text
        item.ai_model = ai_model
        item.curation_engine = curation_engine

    q_count, h_count, d_count = _compute_summary_metrics(base_preview.items)
    base_preview.qualified_count = q_count
    base_preview.high_compatibility_count = h_count
    base_preview.discarded_count = d_count

    return base_preview


def build_baseline_grafana_payload(
    item: RuleImportItemValidation,
    baseline_folder_uid: str,
    loki_ds_uid: str,
    contact_point: str = "stg",
    evaluation_group: str | None = None,
    prefix_settings: BaselinePrefixSettings | None = None,
) -> dict[str, Any]:
    """Compila uma regra validada no payload do Grafana Alerting Provisioning.

    INVARIANTES:
    - Pasta SEMPRE baseline_folder_uid ('global');
    - Grupo evaluation_group ou BASELINE_RULE_GROUP ('global-detections');
    - Data source SEMPRE loki_ds_uid ('loki' ou selecionado);
    - Contact Point SEMPRE contact_point ('stg' -> Homologação);
    - Labels de escopo SEMPRE 'baseline' e cliente 'global';
    - Preserva o parecer técnico de IA e compatibilidade nos metadados da regra;
    - Formata o título com o prefixo do baseline configurado quando ativo.
    """
    new_uid = f"ghp-{uuid.uuid4().hex[:10]}"
    rule_title = format_rule_title(
        item.title.strip(),
        prefix_settings,
        is_baseline=True,
        technology=item.technology,
        technology_name=item.technology_name,
        tactic=item.mitre_tactic,
        severity=item.severity,
    )
    target_rule_group = (
        evaluation_group.strip()
        if evaluation_group and evaluation_group.strip()
        else BASELINE_RULE_GROUP
    )

    labels = {
        "severity": item.severity,
        "mitre_tactic": (item.mitre_tactic or "persistence").strip().lower(),
        "mitre_technique": (item.mitre_technique or "T1098").strip().upper(),
        "scope": "baseline",
        "client": "global",
        "siem_tier": "global",
        "technology": item.technology or "ad_windows",
        "technology_name": item.technology_name or "AD/Windows",
        "source": "dante",
    }
    if item.classification:
        labels["field_compatibility"] = item.classification

    annotations = {
        "summary": rule_title,
        "description": item.description.strip() if item.description else f"Regra de detecção {rule_title}",
        "logql_query": item.query.strip(),
    }
    if item.ai_rationale:
        annotations["ai_rationale"] = item.ai_rationale
    if item.field_compatibility_pct is not None:
        annotations["field_compatibility_pct"] = str(round(item.field_compatibility_pct, 1))

    evaluator_type = "lt" if item.threshold_operator == "lt" else "gt"
    evaluator_param = int(item.threshold_value) if item.threshold_value.is_integer() else item.threshold_value

    rule_payload = {
        "uid": new_uid,
        "title": rule_title,
        "folderUID": baseline_folder_uid,
        "ruleGroup": target_rule_group,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "Error",
        "for": item.for_duration or "0s",
        "isPaused": False,
        "labels": labels,
        "annotations": annotations,
        "data": [
            {
                "refId": "A",
                "queryType": "range",
                "relativeTimeRange": {"from": 300, "to": 0},
                "datasourceUid": loki_ds_uid,
                "model": {
                    "refId": "A",
                    "editorMode": "code",
                    "expr": item.query.strip(),
                    "queryType": "range",
                    "legendFormat": "__auto",
                    "datasource": {"type": "loki", "uid": loki_ds_uid},
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                },
            },
            {
                "refId": "B",
                "queryType": "",
                "relativeTimeRange": {"from": 0, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "A",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "reducer": "last",
                    "refId": "B",
                    "type": "reduce",
                },
            },
            {
                "refId": "C",
                "queryType": "",
                "relativeTimeRange": {"from": 0, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "conditions": [
                        {
                            "evaluator": {
                                "params": [evaluator_param],
                                "type": evaluator_type,
                            }
                        }
                    ],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "B",
                    "intervalMs": 1000,
                    "maxDataPoints": 43200,
                    "refId": "C",
                    "type": "threshold",
                },
            },
        ],
    }

    # Aplica o contact point 'stg' (Homologação)
    return apply_contact_point(rule_payload, contact_point=contact_point)
