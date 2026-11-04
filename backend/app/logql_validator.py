"""Validador e simulador de expressões LogQL (Loki) contra logs fictícios.

Permite que Security Hunters testem regras de detecção escritas em LogQL
injetando linhas de log sintéticas (JSON, logfmt ou raw text) e validem:
  1. Seletores de stream de labels ({app="...", job=~"..."})
  2. Filtros de linha (|=, !=, |~, !~)
  3. Parsers (| json, | logfmt, | pattern, | regexp)
  4. Filtros de expressão (| field > 10, | status = 500)
"""

from __future__ import annotations

import json
import re
from typing import Any
from pydantic import BaseModel, Field, model_validator


class StageResult(BaseModel):
    stage: str
    name: str
    matched: bool
    details: str
    extracted: dict[str, Any] = Field(default_factory=dict)


class LogQLValidationReport(BaseModel):
    is_compatible: bool
    logql_query: str
    message: str
    extracted_fields: dict[str, Any]
    stages: list[StageResult]


class LintIssue(BaseModel):
    level: str  # "error", "warning", "info"
    message: str
    field: str | None = None


class LogQLLintResult(BaseModel):
    is_valid: bool
    query: str
    normalized_query: str
    stream_selector: str | None
    metric_function: str | None
    pipeline_stages: list[str]
    issues: list[LintIssue]
    message: str
    rule_groups_values: list[str] = Field(default_factory=list)
    ss_groups_values: list[str] = Field(default_factory=list)
    job_value: str | None = None
    technologies: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _sync_groups(cls, data: Any) -> Any:
        if isinstance(data, dict):
            vals = data.get("rule_groups_values") or data.get("ss_groups_values") or []
            data.setdefault("rule_groups_values", list(vals))
            data.setdefault("ss_groups_values", list(vals))
        return data


def _pattern_core(pattern: str) -> str:
    """Reduz um recorte regex (ex.: ``.*windows.*`` ou ``(?i).*windows.*``) ao núcleo comparável."""
    core = pattern.strip()
    if core.lower().startswith("(?i)"):
        core = core[4:].strip()
    while core.startswith(".*"):
        core = core[2:]
    while core.endswith(".*"):
        core = core[:-2]
    return core.strip("^$").strip().lower()


def _patterns_overlap(value: str, pattern: str) -> bool:
    """Compara dois recortes de ``ss_groups`` de forma tolerante (substring)."""
    value_core = _pattern_core(value)
    pattern_core = _pattern_core(pattern)
    if not value_core or not pattern_core:
        return False
    return pattern_core in value_core or value_core in pattern_core


def lint_logql(
    query: str,
    known_rule_groups_patterns: list[str] | None = None,
    expected_job: str = "wazuh",
    known_ss_groups_patterns: list[str] | None = None,
) -> LogQLLintResult:
    """Validação (linting) sintática e semântica de uma query LogQL (Loki).

    Verifica:
    1. Não-vazia e balanceamento de chaves, aspas e parênteses.
    2. Presença e sintaxe correta do seletor de stream ({label="valor", ...}).
    3. Validação dos operadores de stream (=, !=, =~, !~).
    4. Validação dos estágios de pipeline (|=, !=, |~, !~, | json, | logfmt, etc.).
    5. Expressões métricas (count_over_time, rate, sum, etc.) e janelas de tempo [1m, 5m].
    6. Recomendações de melhores práticas SIEM (ex: não usar stream completamente vazio {}).
    7. Segregação de tecnologia: ``job`` deve ser o pipeline padrão do SIEM
       (``wazuh``) e ``ss_groups`` deve apontar para uma tecnologia cadastrada,
       quando ``known_ss_groups_patterns`` for informado.
    """
    raw_query = query.strip()
    issues: list[LintIssue] = []
    known_patterns = known_rule_groups_patterns or known_ss_groups_patterns

    if not raw_query:
        return LogQLLintResult(
            is_valid=False,
            query="",
            normalized_query="",
            stream_selector=None,
            metric_function=None,
            pipeline_stages=[],
            issues=[LintIssue(level="error", message="A query LogQL não pode estar vazia.")],
            message="Erro de sintaxe: Query LogQL vazia.",
        )

    # 1. Balanceamento de caracteres estruturais
    brackets = {"{": "}", "(": ")", "[": "]"}
    stack: list[str] = []
    in_quotes = False
    quote_char = ""
    escaped = False

    for idx, ch in enumerate(raw_query):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch in ('"', '`'):
            if not in_quotes:
                in_quotes = True
                quote_char = ch
            elif quote_char == ch:
                in_quotes = False
            continue

        if in_quotes:
            continue

        if ch in brackets:
            stack.append(ch)
        elif ch in brackets.values():
            if not stack:
                issues.append(
                    LintIssue(
                        level="error",
                        message=f"Caractere de fechamento '{ch}' inesperado no caractere {idx+1}.",
                    )
                )
            else:
                expected = brackets[stack.pop()]
                if ch != expected:
                    issues.append(
                        LintIssue(
                            level="error",
                            message=f"Esperado '{expected}', mas encontrado '{ch}' no caractere {idx+1}.",
                        )
                    )

    if in_quotes:
        issues.append(LintIssue(level="error", message="Aspas abertas não foram fechadas."))
    if stack:
        unclosed = ", ".join(f"'{c}'" for c in stack)
        issues.append(LintIssue(level="error", message=f"Blocos abertos não fechados: {unclosed}."))

    # 2. Identificação de seletor de stream
    stream_match = re.search(r"\{([^}]*)\}", raw_query)
    stream_selector = stream_match.group(0) if stream_match else None
    metric_function = None
    job_value: str | None = None
    rule_groups_values: list[str] = []
    ss_groups_values: list[str] = []

    # Verifica se há função de agregação de log (ex: rate, count_over_time, sum)
    metric_match = re.search(r"\b(rate|count_over_time|bytes_over_time|bytes_rate|sum|avg|max|min)\b\s*\(", raw_query, re.IGNORECASE)
    if metric_match:
        metric_function = metric_match.group(1).lower()

    if not stream_selector:
        issues.append(
            LintIssue(
                level="error",
                message="Toda regra LogQL precisa conter ao menos um seletor de stream entre chaves {label=\"valor\"}.",
            )
        )
    else:
        stream_inner = stream_match.group(1).strip()
        if not stream_inner:
            issues.append(
                LintIssue(
                    level="warning",
                    message="Seletor de stream vazio '{}' consome toda a base de logs e pode degradar o Loki. Especifique ao menos um label (ex: {service=\"...\"}).",
                )
            )
        else:
            # Valida os pares de matchers dentro do stream
            matcher_pattern = re.compile(
                r'([a-zA-Z_][a-zA-Z0-9_\-\.]*)\s*(=~|!~|!=|=)\s*(?:"([^"]*)"|`([^`]*)`)'
            )
            found_matchers = list(matcher_pattern.finditer(stream_inner))
            if not found_matchers:
                issues.append(
                    LintIssue(
                        level="error",
                        message=f"Sintaxe inválida no seletor de stream: '{stream_selector}'. Formato esperado: {{label=\"valor\"}}",
                    )
                )
            else:
                # Checa por regex inválido nos operadores =~ e !~
                labels_in_stream = set()
                for m in found_matchers:
                    lbl_name = m.group(1)
                    labels_in_stream.add(lbl_name)
                    op = m.group(2)
                    reg_val = m.group(3) if m.group(3) is not None else m.group(4)
                    if op in ("=~", "!~"):
                        try:
                            re.compile(reg_val)
                        except re.error as e:
                            issues.append(
                                LintIssue(
                                    level="error",
                                    message=f"Expressão regular inválida para a label '{lbl_name}': {e}",
                                )
                            )
                    if lbl_name == "job" and op == "=":
                        job_value = reg_val
                    if lbl_name in ("rule_groups", "ss_groups"):
                        rule_groups_values.append(reg_val)
                        ss_groups_values.append(reg_val)

                # REGRA OBRIGATÓRIA: É necessário que existam duas labels específicas dentro do "{}": "job" e "ss_groups"
                if "job" not in labels_in_stream:
                    issues.append(
                        LintIssue(
                            level="error",
                            message="Label obrigatória ausente no seletor '{}': 'job'. Exemplo: {job=\"auth\", ...}",
                            field="job",
                        )
                    )
                if "ss_groups" not in labels_in_stream:
                    issues.append(
                        LintIssue(
                            level="error",
                            message="Label obrigatória ausente no seletor '{}': 'ss_groups'. Exemplo: {ss_groups=~\".*windows.*\", ...}",
                            field="ss_groups",
                        )
                    )

                # --- Segregação de tecnologia (data source) ------------------
                # Nesta arquitetura todo log de endpoint entra pelo pipeline 'wazuh'.
                if job_value is not None and job_value.strip().lower() != expected_job:
                    issues.append(
                        LintIssue(
                            level="warning",
                            message=(
                                f"A label 'job' está como '{job_value}', mas o pipeline padrão de "
                                f"ingestão deste SIEM é '{expected_job}'. Confirme se a query não "
                                "vai olhar para uma fonte fora da segregação esperada."
                            ),
                            field="job",
                        )
                    )

                if known_patterns is not None and rule_groups_values:
                    matched_patterns = [
                        pattern
                        for pattern in known_patterns
                        if any(_patterns_overlap(value, pattern) for value in rule_groups_values)
                    ]
                    if not matched_patterns:
                        issues.append(
                            LintIssue(
                                level="warning",
                                message=(
                                    "O recorte de grupos de regras ('rule_groups') não corresponde a nenhuma tecnologia "
                                    "cadastrada no catálogo. Cadastre a tecnologia antes de criar a "
                                    "regra para manter a segregação consistente."
                                ),
                                field="rule_groups",
                            )
                        )

    # 3. Identificação de estágios de pipeline (|...)
    pipeline_stages: list[str] = []
    # Remove eventuais fechamentos de agregação métrica (ex: '[5m]\n)') do último pipe
    query_for_pipes = re.sub(r'\[\s*[0-9]+[smhdwMy]\s*\]', '', raw_query).rstrip().rstrip(')')
    pipe_parts = [p.strip() for p in query_for_pipes.split("|")[1:] if p.strip()]
    has_parsing_function = False

    for p in pipe_parts:
        stage_first_word = p.split()[0].lower() if p.split() else ""
        pipeline_stages.append(p)
        if stage_first_word in ("json", "logfmt", "unpack", "pattern", "regexp", "decolorize"):
            has_parsing_function = True
        elif p.startswith(('="', '!=', '=~', '!~', '~')):
            # Filtro de linha válido
            pass
        elif any(comp in p for comp in (">=", "<=", "!=", "==", ">", "<", "=")):
            # Filtro de expressão / label válido
            pass
        else:
            pass

    # REGRA OBRIGATÓRIA: É necessário que exista alguma função na query ("| json", "| logfmt", etc.)
    if not has_parsing_function:
        issues.append(
            LintIssue(
                level="error",
                message="A query deve conter ao menos uma função de parsing/formatação de log (exemplo: '| json', '| logfmt', '| pattern' ou '| regexp').",
                field="pipeline_function",
            )
        )

    has_errors = any(issue.level == "error" for issue in issues)
    is_valid = not has_errors

    if is_valid:
        if any(issue.level == "warning" for issue in issues):
            summary_msg = "Sintaxe LogQL válida, com avisos de otimização."
        else:
            summary_msg = "Sintaxe e semântica LogQL 100% validadas e em conformidade."
    else:
        error_msgs = [i.message for i in issues if i.level == "error"]
        summary_msg = f"Falha na validação LogQL: {'; '.join(error_msgs)}"

    return LogQLLintResult(
        is_valid=is_valid,
        query=raw_query,
        normalized_query=raw_query,
        stream_selector=stream_selector,
        metric_function=metric_function,
        pipeline_stages=pipeline_stages,
        issues=issues,
        message=summary_msg,
        rule_groups_values=rule_groups_values,
        ss_groups_values=ss_groups_values,
        job_value=job_value,
    )


def _parse_logfmt(line: str) -> dict[str, str]:
    """Extrai pares chave=valor no formato logfmt."""
    result: dict[str, str] = {}
    pattern = re.compile(r'([a-zA-Z0-9_\-\.]+)=(?:"([^"]*)"|(\S+))')
    for match in pattern.finditer(line):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = val
    return result


def _try_parse_json(line: str) -> dict[str, Any] | None:
    """Tenta decodificar a linha ou trecho como JSON."""
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        # Tenta localizar um bloco JSON dentro de uma linha com prefixo de data/syslog
        match = re.search(r"(\{.*\})", line)
        if match:
            line = match.group(1)
        else:
            return None
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return None


def evaluate_logql(
    logql: str,
    log_line: str,
    initial_labels: dict[str, str] | None = None,
) -> LogQLValidationReport:
    """Valida se uma linha de log é compatível com a expressão LogQL informada."""
    stages: list[StageResult] = []
    extracted: dict[str, Any] = dict(initial_labels or {})
    current_line = log_line.strip()
    is_overall_matched = True

    # 1. Extração do Seletor de Stream: {label="valor", ...}
    stream_match = re.search(r"\{([^}]+)\}", logql)
    if stream_match:
        selector_content = stream_match.group(1).strip()
        pair_pattern = re.compile(
            r'([a-zA-Z0-9_\-\.]+)\s*(=~|!~|!=|=)\s*"([^"]*)"'
        )
        stream_matched = True
        stream_details: list[str] = []

        # Se não foram fornecidas labels iniciais, tenta enriquecer com dados do log JSON/logfmt
        candidate_json = _try_parse_json(current_line)
        if candidate_json:
            for k, v in candidate_json.items():
                if isinstance(v, (str, int, float, bool)):
                    extracted.setdefault(str(k), str(v))

        for m in pair_pattern.finditer(selector_content):
            lbl_key = m.group(1)
            op = m.group(2)
            lbl_val = m.group(3)
            actual_val = str(extracted.get(lbl_key, ""))

            if op == "=":
                matched = actual_val == lbl_val
            elif op == "!=":
                matched = actual_val != lbl_val
            elif op == "=~":
                matched = bool(re.search(lbl_val, actual_val))
            elif op == "!~":
                matched = not bool(re.search(lbl_val, actual_val))
            else:
                matched = False

            stream_details.append(
                f'{lbl_key} {op} "{lbl_val}" (atual: "{actual_val}") -> {"OK" if matched else "FALHA"}'
            )
            if not matched:
                stream_matched = False

        stages.append(
            StageResult(
                stage="stream_selector",
                name="Seletor de Stream",
                matched=stream_matched,
                details="; ".join(stream_details) if stream_details else "Nenhum matcher específico",
                extracted=dict(extracted),
            )
        )
        if not stream_matched:
            is_overall_matched = False
    else:
        stages.append(
            StageResult(
                stage="stream_selector",
                name="Seletor de Stream",
                matched=True,
                details="Sem seletor de stream restritivo",
                extracted=dict(extracted),
            )
        )

    # 2. Filtros de Linha: |= "...", != "...", |~ "...", !~ "..."
    # Remove eventuais agregadores métricos como count_over_time(...[5m])
    clean_query = logql
    range_metric = re.search(r"[a-z_]+\((.*?)\s*\[[0-9]+[smhdwMy]\]\s*\)", logql, re.DOTALL)
    if range_metric:
        clean_query = range_metric.group(1)

    line_filter_pattern = re.compile(
        r'(\|\s*=|\|\s*!|\|\s*~|\|\s*!~)\s*(?:~|=)?\s*"([^"]*)"'
    )
    for m in line_filter_pattern.finditer(clean_query):
        op_raw = m.group(1).replace(" ", "")
        term = m.group(2)
        match_success = False

        if "|=" in op_raw or op_raw == "|=":
            match_success = term in current_line
            detail = f'Linha contém "{term}"'
        elif "!=" in op_raw or op_raw == "|!=":
            match_success = term not in current_line
            detail = f'Linha NÃO contém "{term}"'
        elif "|~" in op_raw or op_raw == "|~":
            match_success = bool(re.search(term, current_line))
            detail = f'Linha satisfaz regex "{term}"'
        elif "!~" in op_raw or op_raw == "|!~":
            match_success = not bool(re.search(term, current_line))
            detail = f'Linha NÃO satisfaz regex "{term}"'
        else:
            match_success = term in current_line
            detail = f'Filtro: {op_raw} "{term}"'

        stages.append(
            StageResult(
                stage="line_filter",
                name="Filtro de Linha",
                matched=match_success,
                details=f"{detail} -> {'MATCH' if match_success else 'NÃO ENCONTRADO'}",
            )
        )
        if not match_success:
            is_overall_matched = False

    # 3. Parsers: | json, | logfmt, | regexp "...", | pattern "..."
    if "| json" in clean_query or "|json" in clean_query:
        parsed_json = _try_parse_json(current_line)
        if parsed_json is not None:
            for k, v in parsed_json.items():
                extracted[k] = v
            stages.append(
                StageResult(
                    stage="parser",
                    name="Parser JSON",
                    matched=True,
                    details=f"Extraídos {len(parsed_json)} campos com sucesso do payload JSON",
                    extracted=parsed_json,
                )
            )
        else:
            stages.append(
                StageResult(
                    stage="parser",
                    name="Parser JSON",
                    matched=False,
                    details="Falha ao realizar parsing JSON: formato inválido na linha de log",
                )
            )
            is_overall_matched = False

    elif "| logfmt" in clean_query or "|logfmt" in clean_query:
        parsed_logfmt = _parse_logfmt(current_line)
        if parsed_logfmt:
            for k, v in parsed_logfmt.items():
                extracted[k] = v
            stages.append(
                StageResult(
                    stage="parser",
                    name="Parser logfmt",
                    matched=True,
                    details=f"Extraídos {len(parsed_logfmt)} campos via pares chave=valor",
                    extracted=parsed_logfmt,
                )
            )
        else:
            stages.append(
                StageResult(
                    stage="parser",
                    name="Parser logfmt",
                    matched=False,
                    details="Nenhum par chave=valor encontrado na linha",
                )
            )
            is_overall_matched = False

    # 4. Filtros de Expressão / Condição em Campos: | campo > 10, | status = 500, etc.
    # Ex: | attempts >= 5
    condition_matches = re.findall(
        r'\|\s*([a-zA-Z0-9_\-\.]+)\s*(>=|<=|>|<|==|=|!=|=~|!~)\s*("?[^"|\s]+"?)(?:\s*(?:and|or)\s*([a-zA-Z0-9_\-\.]+)\s*(>=|<=|>|<|==|=|!=|=~|!~)\s*("?[^"|\s]+"?))?',
        clean_query,
    )
    for cond_tuple in condition_matches:
        if not cond_tuple[0]:
            continue
        field = cond_tuple[0]
        op = cond_tuple[1]
        raw_val = cond_tuple[2].strip('"')

        # Ignora se foi palavra reservada de parser (ex: "json", "logfmt")
        if field in ("json", "logfmt", "unpack"):
            continue

        actual_val = extracted.get(field)
        cond_matched = False

        if actual_val is None:
            detail = f'Campo "{field}" não existe no log extraído'
        else:
            # Tenta comparação numérica
            try:
                num_actual = float(actual_val)
                num_expected = float(raw_val)
                if op in ("=", "=="):
                    cond_matched = num_actual == num_expected
                elif op == "!=":
                    cond_matched = num_actual != num_expected
                elif op == ">":
                    cond_matched = num_actual > num_expected
                elif op == ">=":
                    cond_matched = num_actual >= num_expected
                elif op == "<":
                    cond_matched = num_actual < num_expected
                elif op == "<=":
                    cond_matched = num_actual <= num_expected
            except (ValueError, TypeError):
                # Comparação por string
                str_actual = str(actual_val)
                str_expected = str(raw_val)
                if op in ("=", "=="):
                    cond_matched = str_actual == str_expected
                elif op == "!=":
                    cond_matched = str_actual != str_expected
                elif op == "=~":
                    cond_matched = bool(re.search(str_expected, str_actual))
                elif op == "!~":
                    cond_matched = not bool(re.search(str_expected, str_actual))

            detail = f'Campo "{field}" ({actual_val}) {op} {raw_val} -> {"VALIDADO" if cond_matched else "NÃO ATINGIU"}'

        stages.append(
            StageResult(
                stage="label_filter",
                name=f"Filtro de Campo [{field}]",
                matched=cond_matched,
                details=detail,
            )
        )
        if not cond_matched:
            is_overall_matched = False

    message = (
        "Log COMPATÍVEL! A linha de log atende a todos os critérios e filtros da regra LogQL."
        if is_overall_matched
        else "Log INCOMPATÍVEL. A linha de log foi descartada em uma ou mais etapas do pipeline LogQL."
    )

    return LogQLValidationReport(
        is_compatible=is_overall_matched,
        logql_query=logql,
        message=message,
        extracted_fields=extracted,
        stages=stages,
    )

