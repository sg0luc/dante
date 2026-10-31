"""Validador e compilador de regras importadas (Loki Ruler / Detection-as-Code).

Garante que toda regra importada:
1. Seja validada ponta a ponta: sintaxe JSON, campos obrigatórios, sintaxe LogQL via lint_logql;
2. Tenha seletor 'ss_groups' casado com uma tecnologia do catálogo;
3. Tenha severidade válida e labels MITRE ATT&CK (mitre_tactic, mitre_technique);
4. Seja sempre compilada para a pasta Baseline ('global'), data source 'Loki' e Contact Point 'stg';
5. Não permita que regras inválidas ou com erro sejam salvas sob hipótese alguma.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

import yaml

from .contact_points import apply_contact_point
from .logql_validator import lint_logql
from .schemas import (
    RuleImportExecuteResponse,
    RuleImportFileInput,
    RuleImportItemValidation,
    RuleImportPreviewResponse,
    RuleSeverity,
)
from .technologies import (
    Technology,
    TechnologyNotFound,
    TechnologyStore,
    extract_rule_groups_values,
    extract_ss_groups_values,
    selector_matches_technology,
)
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
            elif any(k in item for k in ("alert", "title", "name", "expr", "logql_query", "data")):
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
        if any(k in parsed_data for k in ("alert", "title", "name", "expr", "logql_query", "data")):
            return [parsed_data], None

        return [], (
            "Estrutura YAML/JSON não reconhecida. Esperado: especificação Loki Ruler com 'groups', "
            "grupo com 'rules' ou lista de regras de detecção."
        )

    return [], "O arquivo YAML/JSON deve conter um objeto ou uma lista de regras."


def validate_rule_item(
    index: int,
    raw_rule: dict[str, Any],
    technology_store: TechnologyStore,
    existing_baseline_titles: set[str],
    filename: str | None = None,
) -> RuleImportItemValidation:
    """Valida exaustivamente uma regra de detecção e seus metadados."""
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
    # Quando a regra está OK (sem outros erros impeditivos), ela é marcada com technology_missing=True
    # para que receba chip amarelo e o botão "Criar Tecnologia", sem ser considerada inválida (vermelha).
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

    return RuleImportItemValidation(
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
    )


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

    return RuleImportPreviewResponse(
        total_rules=len(items),
        valid_count=valid_count,
        invalid_count=invalid_count,
        missing_tech_count=missing_tech_count,
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
        items=all_items,
        general_error=general_error,
        files_count=len(files),
    )


def build_baseline_grafana_payload(
    item: RuleImportItemValidation,
    baseline_folder_uid: str,
    loki_ds_uid: str,
    contact_point: str = "stg",
    evaluation_group: str | None = None,
) -> dict[str, Any]:
    """Compila uma regra validada no payload do Grafana Alerting Provisioning.

    INVARIANTES:
    - Pasta SEMPRE baseline_folder_uid ('global');
    - Grupo evaluation_group ou BASELINE_RULE_GROUP ('global-detections');
    - Data source SEMPRE loki_ds_uid ('loki' ou selecionado);
    - Contact Point SEMPRE contact_point ('stg' -> Homologação);
    - Labels de escopo SEMPRE 'baseline' e cliente 'global'.
    """
    new_uid = f"ghp-{uuid.uuid4().hex[:10]}"
    rule_title = item.title.strip()
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

    annotations = {
        "summary": rule_title,
        "description": item.description.strip() if item.description else f"Regra de detecção {rule_title}",
        "logql_query": item.query.strip(),
    }

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

