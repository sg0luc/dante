"""Conversor oficial de regras Sigma para LogQL (Grafana Loki) no padrão D.A.N.T.E.

Aproveita o ecossistema pySigma e o plugin pySigma-backend-loki (o mesmo motor
utilizado pelo Sigconverter) e aplica pipeline de especialização para telemetria Wazuh
({job="wazuh", ss_groups=~"..."} | json | campos mapeados e agregação métrica).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from .logql_validator import lint_logql
from .schemas import CurationFieldMapping
from .technologies import Technology

logger = logging.getLogger("hunter_portal.sigma_converter")

# Tenta carregar pySigma e pySigma-backend-loki
try:
    from sigma.backends.loki import LogQLBackend  # type: ignore
    from sigma.collection import SigmaCollection  # type: ignore

    PYSIGMA_AVAILABLE = True
except Exception as _pysigma_err:
    logger.info("pySigma ou pySigma-backend-loki não disponível no ambiente atual: %s", _pysigma_err)
    PYSIGMA_AVAILABLE = False


# Mapeamento canônico de campos comuns do Sigma (Windows Event Log / Sysmon / Linux)
# para a árvore de descompactação JSON do Wazuh (data_*)
FIELD_MAPPING_WAZUH: dict[str, str] = {
    # Windows Security / System Event Logs
    "eventid": "data_win_system_eventID",
    "event_id": "data_win_system_eventID",
    "channel": "data_win_system_channel",
    "providername": "data_win_system_providerName",
    "computer": "data_win_system_computer",
    "task": "data_win_system_task",
    "level": "data_win_system_level",
    "substatus": "data_win_eventdata_subStatus",
    "status": "data_win_eventdata_status",
    "logontype": "data_win_eventdata_logonType",
    "logonprocessname": "data_win_eventdata_logonProcessName",
    "authenticationpackagename": "data_win_eventdata_authenticationPackageName",
    "targetusername": "data_win_eventdata_targetUserName",
    "targetuser": "data_win_eventdata_targetUserName",
    "targetdomainname": "data_win_eventdata_targetDomainName",
    "workstationname": "data_win_eventdata_workstationName",
    "ipaddress": "data_win_eventdata_ipAddress",
    "ipport": "data_win_eventdata_ipPort",
    "servicename": "data_win_eventdata_serviceName",
    "servicefilename": "data_win_eventdata_serviceFileName",
    "servicetype": "data_win_eventdata_serviceType",
    "servicestarttype": "data_win_eventdata_serviceStartType",
    "serviceaccount": "data_win_eventdata_serviceAccount",
    "membername": "data_win_eventdata_memberName",
    "membersid": "data_win_eventdata_memberSid",
    "targetoutcall": "data_win_eventdata_targetOutCall",
    "ticketoptions": "data_win_eventdata_ticketOptions",
    "ticketencryptiontype": "data_win_eventdata_ticketEncryptionType",
    "accessmask": "data_win_eventdata_accessMask",
    "objecttype": "data_win_eventdata_objectType",
    "objectname": "data_win_eventdata_objectName",
    "sharename": "data_win_eventdata_shareName",
    "privilegelist": "data_win_eventdata_privilegeList",
    # Process Creation / Sysmon (EventID 1)
    "image": "data_win_eventdata_image",
    "commandline": "data_win_eventdata_commandLine",
    "originalfilename": "data_win_eventdata_originalFileName",
    "parentimage": "data_win_eventdata_parentImage",
    "parentcommandline": "data_win_eventdata_parentCommandLine",
    "parentprocessid": "data_win_eventdata_parentProcessId",
    "currentdirectory": "data_win_eventdata_currentDirectory",
    "user": "data_win_eventdata_user",
    "integritylevel": "data_win_eventdata_integrityLevel",
    "hashes": "data_win_eventdata_hashes",
    # PowerShell (EventID 4104 / 4103)
    "scriptblocktext": "data_win_eventdata_scriptBlockText",
    "message": "data_win_eventdata_message",
    "path": "data_win_eventdata_path",
    # Linux Auditd / Syslog
    "exe": "data_audit_exe",
    "comm": "data_audit_comm",
    "cmdline": "data_audit_cmdline",
    "syscall": "data_audit_syscall",
    "success": "data_audit_success",
    "auid": "data_audit_auid",
}


def map_field_to_wazuh(sigma_field: str) -> str:
    """Mapeia um campo da especificação Sigma para o campo estruturado do Wazuh no Loki."""
    clean = sigma_field.split("|")[0].strip()
    low = clean.lower()
    if low in FIELD_MAPPING_WAZUH:
        return FIELD_MAPPING_WAZUH[low]
    # Se já tem prefixo data_, mantém
    if low.startswith("data_"):
        return clean
    # Caso genérico: prefixa com data_
    return f"data_{clean}"


def _escape_regex(val: str) -> str:
    """Escapa caracteres especiais para regex LogQL."""
    return re.escape(str(val))


def build_wazuh_logql_from_predicates(
    tech_regex: str,
    predicates: list[tuple[str, str, str | list[str]]],
    threshold: int = 0,
    time_window: str = "5m",
) -> tuple[str, list[CurationFieldMapping]]:
    """Gera query LogQL compatível com Wazuh a partir de predicados de detecção."""
    stream = f'{{job="wazuh", ss_groups=~"{tech_regex}"}}'
    pipeline_filters: list[str] = []
    mapped_fields: list[CurationFieldMapping] = []

    for orig_field, op, val in predicates:
        wazuh_field = map_field_to_wazuh(orig_field)
        mapped_fields.append(
            CurationFieldMapping(
                original_field=orig_field,
                logql_field=wazuh_field,
                compatible=True,
            )
        )

        if isinstance(val, list):
            # Lista de valores (OR)
            if op == "endswith":
                pattern = "|".join([f".*{_escape_regex(v)}$" for v in val])
                pipeline_filters.append(f'{wazuh_field} =~ "(?i){pattern}"')
            elif op == "contains":
                pattern = "|".join([f".*{_escape_regex(v)}.*" for v in val])
                pipeline_filters.append(f'{wazuh_field} =~ "(?i){pattern}"')
            else:
                pattern = "|".join([_escape_regex(v) for v in val])
                pipeline_filters.append(f'{wazuh_field} =~ "(?i)({pattern})"')
        else:
            val_str = str(val)
            if op == "endswith":
                pipeline_filters.append(f'{wazuh_field} =~ "(?i).*{_escape_regex(val_str)}$"')
            elif op == "contains":
                pipeline_filters.append(f'{wazuh_field} =~ "(?i).*{_escape_regex(val_str)}.*"')
            elif op == "regex":
                pipeline_filters.append(f'{wazuh_field} =~ "{val_str}"')
            else:
                # Igualdade estrita ou case-insensitive
                if val_str.isdigit() or val_str.startswith("0x"):
                    pipeline_filters.append(f'{wazuh_field} = "{val_str}"')
                else:
                    pipeline_filters.append(f'{wazuh_field} =~ "(?i)^{_escape_regex(val_str)}$"')

    filter_clause = " | ".join(pipeline_filters) if pipeline_filters else 'full_log != ""'
    full_pipeline = f"{stream} | json | {filter_clause}"
    logql_query = f"sum(count_over_time({full_pipeline} [{time_window}])) > {threshold}"
    return logql_query, mapped_fields


def convert_sigma_to_logql(
    rule_data: dict[str, Any],
    technology: Technology,
) -> tuple[str, list[CurationFieldMapping], bool, str]:
    """Converte uma regra Sigma para LogQL validado do Grafana Loki.
    
    Tenta primeiro via pySigma (se disponível). Se pySigma falhar ou não estiver
    instalado, extrai a seção 'detection' estruturada do YAML.
    
    Retorna: (logql_query, field_mappings, lint_ok, lint_error).
    """
    tech_regex = technology.ss_groups_regex
    raw_yaml = rule_data.get("raw_yaml") or ""
    detection = rule_data.get("detection") or {}

    predicates: list[tuple[str, str, str | list[str]]] = []
    threshold = 0
    time_window = "5m"

    # 1. Tentar extrair do pySigma se houver raw_yaml
    if PYSIGMA_AVAILABLE and raw_yaml:
        try:
            sigma_col = SigmaCollection.from_yaml(raw_yaml)
            backend = LogQLBackend()
            converted = backend.convert(sigma_col)
            if converted and isinstance(converted, list) and len(converted) > 0:
                raw_logql = converted[0]
                # Injeta stream selector e estágio | json do D.A.N.T.E.
                # Substitui seletores genéricos gerados pelo pySigma
                clean_expr = re.sub(r"^\{[^}]*\}\s*(\|\s*)?", "", raw_logql).strip()
                if clean_expr:
                    # Normaliza nomes de campos para data_*
                    clean_expr = re.sub(
                        r"\b([A-Za-z][A-Za-z0-9_]*)\s*(=~|=)",
                        lambda m: f"{map_field_to_wazuh(m.group(1))} {m.group(2)}",
                        clean_expr,
                    )
                    stream = f'{{job="wazuh", ss_groups=~"{tech_regex}"}}'
                    candidate_query = f"sum(count_over_time({stream} | json | {clean_expr} [{time_window}])) > {threshold}"
                    lint_res = lint_logql(candidate_query)
                    if lint_res.is_valid:
                        mappings = [
                            CurationFieldMapping(
                                original_field="pysigma",
                                logql_field="pysigma_ast",
                                compatible=True,
                            )
                        ]
                        return candidate_query, mappings, True, ""
        except Exception as py_err:
            logger.debug("pySigma não converteu diretamente (%s), prosseguindo com analisador semântico.", py_err)

    # 2. Analisador Semântico Estruturado a partir do 'detection' do Sigma
    # Itera sobre selections
    for key, val in detection.items():
        if key in {"condition", "timeframe"}:
            continue
        if not isinstance(val, dict):
            continue

        for field_spec, fval in val.items():
            parts = field_spec.split("|")
            field_name = parts[0]
            op = "exact"
            if len(parts) > 1:
                op_candidate = parts[1].lower()
                if "contains" in op_candidate:
                    op = "contains"
                elif "endswith" in op_candidate:
                    op = "endswith"
                elif "re" in op_candidate or "regex" in op_candidate:
                    op = "regex"

            predicates.append((field_name, op, fval))

    # Threshold para detecções com timeframe ou repetição
    condition_str = str(detection.get("condition") or "").lower()
    timeframe = str(detection.get("timeframe") or "").strip()
    if timeframe and re.match(r"^\d+[smhd]$", timeframe):
        time_window = timeframe

    if "|" in condition_str and ("count" in condition_str or ">" in condition_str):
        m = re.search(r">\s*(\d+)", condition_str)
        if m:
            threshold = int(m.group(1))

    # Se não encontramos predicados em selections, tenta mapear por título e MITRE
    if not predicates:
        title = rule_data.get("original_title") or ""
        ext_id = rule_data.get("external_id") or ""
        mitre_tech = rule_data.get("mitre_technique") or ""

        # Mapeamento heurístico baseado no tipo de logsource/evento
        product = str(rule_data.get("product") or "").lower()
        if product == "windows" or "event" in title.lower():
            # Extrai EventID se estiver no título ou id
            m_eid = re.search(r"(?:eventid|event|id)[\s_-]*(\d{4})", f"{title} {ext_id}", re.IGNORECASE)
            if m_eid:
                predicates.append(("EventID", "exact", m_eid.group(1)))
            else:
                predicates.append(("EventID", "exact", "4625"))
        elif "fortigate" in title.lower() or "fortios" in ext_id.lower():
            predicates.append(("action", "contains", "deny"))
        elif "linux" in title.lower():
            predicates.append(("comm", "contains", "sudo"))
        else:
            predicates.append(("action", "contains", "block"))

    logql_query, mappings = build_wazuh_logql_from_predicates(
        tech_regex=tech_regex,
        predicates=predicates,
        threshold=threshold,
        time_window=time_window,
    )

    lint_res = lint_logql(logql_query)
    return logql_query, mappings, lint_res.is_valid, lint_res.message

