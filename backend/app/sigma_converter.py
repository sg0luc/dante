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
    "eventcode": "data_win_system_eventID",
    "channel": "data_win_system_channel",
    "providername": "data_win_system_providerName",
    "provider_name": "data_win_system_providerName",
    "computer": "data_win_system_computer",
    "computername": "data_win_system_computer",
    "task": "data_win_system_task",
    "level": "data_win_system_level",
    "substatus": "data_win_eventdata_subStatus",
    "status": "data_win_eventdata_status",
    "logontype": "data_win_eventdata_logonType",
    "logonprocessname": "data_win_eventdata_logonProcessName",
    "authenticationpackagename": "data_win_eventdata_authenticationPackageName",
    "targetusername": "data_win_eventdata_targetUserName",
    "targetuser": "data_win_eventdata_targetUserName",
    "accountname": "data_win_eventdata_targetUserName",
    "subjectusername": "data_win_eventdata_subjectUserName",
    "subjectuser": "data_win_eventdata_subjectUserName",
    "targetdomainname": "data_win_eventdata_targetDomainName",
    "subjectdomainname": "data_win_eventdata_subjectDomainName",
    "workstationname": "data_win_eventdata_workstationName",
    "ipaddress": "data_win_eventdata_ipAddress",
    "sourceip": "data_win_eventdata_ipAddress",
    "destinationip": "data_win_eventdata_ipAddress",
    "ipport": "data_win_eventdata_ipPort",
    "destport": "data_win_eventdata_ipPort",
    "destinationport": "data_win_eventdata_ipPort",
    "servicename": "data_win_eventdata_serviceName",
    "servicefilename": "data_win_eventdata_serviceFileName",
    "imagepath": "data_win_eventdata_serviceFileName",
    "servicetype": "data_win_eventdata_serviceType",
    "servicestarttype": "data_win_eventdata_serviceStartType",
    "serviceaccount": "data_win_eventdata_serviceAccount",
    "membername": "data_win_eventdata_memberName",
    "samaccountname": "data_win_eventdata_memberName",
    "newtargetusername": "data_win_eventdata_targetUserName",
    "membersid": "data_win_eventdata_memberSid",
    "targetoutcall": "data_win_eventdata_targetOutCall",
    "ticketoptions": "data_win_eventdata_ticketOptions",
    "ticketencryptiontype": "data_win_eventdata_ticketEncryptionType",
    "accessmask": "data_win_eventdata_accessMask",
    "accesslist": "data_win_eventdata_accessMask",
    "grantedaccess": "data_win_eventdata_grantedAccess",
    "objecttype": "data_win_eventdata_objectType",
    "objectname": "data_win_eventdata_targetObject",
    "targetobject": "data_win_eventdata_targetObject",
    "details": "data_win_eventdata_details",
    "eventtype": "data_win_eventdata_eventType",
    "sharename": "data_win_eventdata_shareName",
    "relativetargetname": "data_win_eventdata_shareName",
    "privilegelist": "data_win_eventdata_privilegeList",
    "taskname": "data_win_eventdata_taskName",
    # Process Creation / Windows 4688 & Sysmon (EventID 1)
    "image": "data_win_eventdata_image",
    "newprocessname": "data_win_eventdata_image",
    "processname": "data_win_eventdata_image",
    "processpath": "data_win_eventdata_image",
    "imagename": "data_win_eventdata_image",
    "application": "data_win_eventdata_image",
    "commandline": "data_win_eventdata_commandLine",
    "processcommandline": "data_win_eventdata_commandLine",
    "originalfilename": "data_win_eventdata_originalFileName",
    "parentimage": "data_win_eventdata_parentImage",
    "parentprocessname": "data_win_eventdata_parentImage",
    "callerprocessname": "data_win_eventdata_parentImage",
    "parentcommandline": "data_win_eventdata_parentCommandLine",
    "parentprocessid": "data_win_eventdata_parentProcessId",
    "currentdirectory": "data_win_eventdata_currentDirectory",
    "user": "data_win_eventdata_user",
    "integritylevel": "data_win_eventdata_integrityLevel",
    "hashes": "data_win_eventdata_hashes",
    "targetimage": "data_win_eventdata_targetImage",
    "sourceimage": "data_win_eventdata_image",
    "targetfilename": "data_win_eventdata_targetFilename",
    "imageloaded": "data_win_eventdata_imageLoaded",
    "queryname": "data_win_eventdata_queryName",
    # PowerShell (EventID 4104 / 4103)
    "scriptblocktext": "data_win_eventdata_scriptBlockText",
    "payload": "data_win_eventdata_scriptBlockText",
    "hostapplication": "data_win_eventdata_commandLine",
    "contextinfo": "data_win_eventdata_scriptBlockText",
    "message": "data_win_eventdata_message",
    "path": "data_win_eventdata_path",
    # Linux Auditd / Syslog
    "exe": "data_command",
    "comm": "data_command",
    "cmdline": "data_command",
    "syscall": "data_audit_syscall",
    "success": "data_pam_status",
    "auid": "data_srcuser",
}

TECH_SPECIFIC_FIELD_MAP: dict[str, dict[str, str]] = {
    "linux": {
        "image": "data_command",
        "commandline": "data_command",
        "command": "data_command",
        "cmdline": "data_command",
        "exe": "data_command",
        "comm": "data_command",
        "parentimage": "data_command",
        "user": "data_srcuser",
        "srcuser": "data_srcuser",
        "uid": "data_srcuser",
        "auid": "data_srcuser",
        "euid": "data_srcuser",
        "dstuser": "data_dstuser",
        "srcip": "data_srcip",
        "src_ip": "data_srcip",
        "rhost": "data_srcip",
        "pam_status": "data_pam_status",
        "status": "data_pam_status",
        "result": "data_pam_status",
        "res": "data_pam_status",
        "success": "data_pam_status",
        "targetfilename": "data_file_path",
        "filename": "data_file_path",
        "name": "data_file_path",
        "path": "data_file_path",
        "file.path": "data_file_path",
    },
    "fortigate": {
        "action": "data_action",
        "blocked": "data_action",
        "srcip": "data_srcip",
        "src_ip": "data_srcip",
        "source.ip": "data_srcip",
        "dstip": "data_dstip",
        "dst_ip": "data_dstip",
        "destination.ip": "data_dstip",
        "dstport": "data_dstport",
        "dst_port": "data_dstport",
        "destination.port": "data_dstport",
        "srcport": "data_srcport",
        "src_port": "data_srcport",
        "subtype": "data_subtype",
        "type": "data_subtype",
        "msg": "data_msg",
        "message": "data_msg",
        "level": "data_level",
        "attack": "data_attack",
        "policyid": "data_policyid",
        "user": "data_user",
        "srcuser": "data_user",
    },
    "office365": {
        "operation": "data_office365_Operation",
        "eventname": "data_office365_Operation",
        "action": "data_office365_Operation",
        "userid": "data_office365_UserId",
        "user": "data_office365_UserId",
        "userprincipalname": "data_office365_UserId",
        "clientip": "data_office365_ClientIP",
        "src_ip": "data_office365_ClientIP",
        "ipaddress": "data_office365_ClientIP",
        "resultstatus": "data_office365_ResultStatus",
        "status": "data_office365_ResultStatus",
        "result": "data_office365_ResultStatus",
        "workload": "data_office365_Workload",
        "eventsource": "data_office365_Workload",
        "service": "data_office365_Workload",
        "objectid": "data_office365_ObjectId",
        "applicationid": "data_office365_ApplicationId",
        "policyname": "data_office365_PolicyName",
    },
    "waf_akamai": {
        "action": "data_action",
        "c-ip": "data_srcip",
        "srcip": "data_srcip",
        "src_ip": "data_srcip",
        "clientip": "data_srcip",
        "cs-method": "data_http_method",
        "http_method": "data_http_method",
        "method": "data_http_method",
        "cs-uri-query": "data_uri",
        "cs-uri-stem": "data_uri",
        "cs-uri": "data_uri",
        "c-uri": "data_uri",
        "uri": "data_uri",
        "url": "data_uri",
        "sc-status": "data_status_code",
        "status_code": "data_status_code",
        "status": "data_status_code",
        "cs-user-agent": "data_user_agent",
        "user_agent": "data_user_agent",
        "cs-host": "data_host",
        "host": "data_host",
        "attack_type": "data_attack_type",
        "rule_tag": "data_rule_tag",
    },
}


def map_field_to_wazuh(sigma_field: str, tech_slug: str = "") -> str:
    """Mapeia um campo da especificação Sigma para o campo estruturado do Wazuh no Loki."""
    clean = sigma_field.split("|")[0].strip()
    low = clean.lower()
    if low in ("rule.id", "rule_id"):
        return "rule_id"
    if low == "full_log":
        return "full_log"
    slug_low = (tech_slug or "").strip().lower()
    if slug_low in TECH_SPECIFIC_FIELD_MAP and low in TECH_SPECIFIC_FIELD_MAP[slug_low]:
        return TECH_SPECIFIC_FIELD_MAP[slug_low][low]
    if low in FIELD_MAPPING_WAZUH:
        return FIELD_MAPPING_WAZUH[low]
    # Se já tem prefixo data_, mantém
    if low.startswith("data_"):
        return clean
    # Caso genérico: prefixa com data_
    return f"data_{clean}"


def _implicit_category_fields(
    rule_data: dict[str, Any],
    technology: Technology,
) -> list[tuple[str, str]]:
    """Retorna os campos de contexto implícitos do logsource/categoria na telemetria Wazuh.

    No Sigma, o 'logsource' (ex.: category: process_creation no Windows -> EventID 4688)
    define os campos base do evento (EventID, TargetUserName, NewProcessName), enquanto
    a seção 'detection' lista os predicados específicos (ex.: CommandLine).
    """
    slug = (technology.slug or "").lower()
    category = str(rule_data.get("category") or "").strip().lower()
    service = str(rule_data.get("service") or "").strip().lower()

    if slug in ("ad_windows", "sysmon"):
        if category == "process_creation":
            return [
                ("EventID", "data_win_system_eventID"),
                ("TargetUserName", "data_win_eventdata_targetUserName"),
                ("NewProcessName", "data_win_eventdata_image"),
            ]
        if category.startswith("registry"):
            return [
                ("EventID", "data_win_system_eventID"),
                ("TargetUserName", "data_win_eventdata_targetUserName"),
                ("NewProcessName", "data_win_eventdata_image"),
                ("TargetObject", "data_win_eventdata_targetObject"),
            ]
        if category in ("ps_script", "ps_module", "ps_classic_start", "powershell") or service == "powershell":
            return [
                ("EventID", "data_win_system_eventID"),
                ("Channel", "data_win_system_channel"),
                ("TargetUserName", "data_win_eventdata_targetUserName"),
                ("ScriptBlockText", "data_win_eventdata_scriptBlockText"),
            ]
        if service == "security" or category == "security":
            return [
                ("EventID", "data_win_system_eventID"),
                ("Channel", "data_win_system_channel"),
                ("TargetUserName", "data_win_eventdata_targetUserName"),
            ]
        if category in ("file_event", "file_delete", "file_change", "file_rename"):
            return [
                ("EventID", "data_win_system_eventID"),
                ("TargetUserName", "data_win_eventdata_targetUserName"),
                ("NewProcessName", "data_win_eventdata_image"),
                ("TargetFilename", "data_win_eventdata_targetFilename"),
            ]
        if category in ("driver_load", "image_load"):
            return [
                ("EventID", "data_win_system_eventID"),
                ("ImageLoaded", "data_win_eventdata_imageLoaded"),
                ("Hashes", "data_win_eventdata_hashes"),
                ("Signed", "data_win_eventdata_signed"),
            ]
        if category == "dns_query":
            return [
                ("EventID", "data_win_system_eventID"),
                ("QueryName", "data_QueryName"),
                ("QueryStatus", "data_win_eventdata_queryStatus"),
                ("QueryResults", "data_win_eventdata_queryResults"),
            ]
        if category in ("process_access", "create_remote_thread", "pipe_created", "wmi_event"):
            return [
                ("EventID", "data_win_system_eventID"),
                ("TargetImage", "data_win_eventdata_targetImage"),
                ("GrantedAccess", "data_win_eventdata_grantedAccess"),
                ("CallTrace", "data_win_eventdata_callTrace"),
            ]
        if category == "network_connection":
            return [
                ("EventID", "data_win_system_eventID"),
                ("TargetUserName", "data_win_eventdata_targetUserName"),
                ("NewProcessName", "data_win_eventdata_image"),
                ("DestinationIp", "data_win_eventdata_destinationIp"),
            ]
        return [
            ("EventID", "data_win_system_eventID"),
            ("TargetUserName", "data_win_eventdata_targetUserName"),
        ]
    if slug in ("linux", "linux_os"):
        return [
            ("rule.id", "rule_id"),
            ("srcuser", "data_srcuser"),
            ("srcip", "data_srcip"),
        ]
    if slug == "fortigate":
        return [
            ("rule.id", "rule_id"),
            ("action", "data_action"),
            ("srcip", "data_srcip"),
            ("dstip", "data_dstip"),
        ]
    if slug == "office365":
        return [
            ("Workload", "data_office365_Workload"),
            ("Operation", "data_office365_Operation"),
            ("ResultStatus", "data_office365_ResultStatus"),
            ("UserId", "data_office365_UserId"),
        ]
    if slug == "waf_akamai":
        return [
            ("action", "data_action"),
            ("srcip", "data_srcip"),
            ("http_method", "data_http_method"),
            ("uri", "data_uri"),
        ]
    return []


_RE2_META_RE = re.compile(r"([.^$*+?{}[\]\\|()])")


def _escape_regex(val: str) -> str:
    """Escapa metacaracteres RE2 e duplica barras para string literal dupla do LogQL."""
    clean = str(val).replace('"', "").replace("\r", "").replace("\n", "")
    re2_escaped = _RE2_META_RE.sub(r"\\\1", clean)
    return re2_escaped.replace("\\", "\\\\")


def build_wazuh_logql_from_predicates(
    tech_regex: str,
    predicates: list[tuple[str, str, str | list[str]]],
    threshold: int = 0,
    time_window: str = "5m",
    tech_slug: str = "",
) -> tuple[str, list[CurationFieldMapping]]:
    """Gera query LogQL compatível com Wazuh a partir de predicados de detecção."""
    stream = f'{{job="wazuh", ss_groups=~"{tech_regex}"}}'
    pipeline_filters: list[str] = []
    mapped_fields: list[CurationFieldMapping] = []
    seen_logql_fields: set[str] = set()

    for orig_field, op, val in predicates:
        wazuh_field = map_field_to_wazuh(orig_field, tech_slug=tech_slug)
        if wazuh_field not in seen_logql_fields:
            seen_logql_fields.add(wazuh_field)
            mapped_fields.append(
                CurationFieldMapping(
                    original_field=orig_field,
                    logql_field=wazuh_field,
                    compatible=True,
                )
            )

        if isinstance(val, list):
            # Lista de valores (OR) - limita a 8 itens para manter a query enxuta e performática no Loki
            str_vals = [str(v) for v in val if v is not None][:8]
            if not str_vals:
                continue
            if op == "endswith":
                pattern = "|".join([f".*{_escape_regex(v)}$" for v in str_vals])
                pipeline_filters.append(f'{wazuh_field} =~ "(?i){pattern}"')
            elif op == "contains":
                pattern = "|".join([f".*{_escape_regex(v)}.*" for v in str_vals])
                pipeline_filters.append(f'{wazuh_field} =~ "(?i){pattern}"')
            else:
                pattern = "|".join([_escape_regex(v) for v in str_vals])
                pipeline_filters.append(f'{wazuh_field} =~ "(?i)({pattern})"')
        else:
            if val is None or str(val).strip() == "":
                continue
            val_str = str(val)
            if op == "endswith":
                pipeline_filters.append(f'{wazuh_field} =~ "(?i).*{_escape_regex(val_str)}$"')
            elif op == "contains":
                pipeline_filters.append(f'{wazuh_field} =~ "(?i).*{_escape_regex(val_str)}.*"')
            elif op == "regex":
                safe_re = val_str.replace('"', "").replace("\r", "").replace("\n", "").replace("\\", "\\\\")
                pipeline_filters.append(f'{wazuh_field} =~ "{safe_re}"')
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


def _extract_predicates_from_detection(
    detection: dict[str, Any],
) -> list[tuple[str, str, str | list[str]]]:
    """Extrai os predicados positivos (campo, operador, valor) da seção detection do Sigma."""
    predicates: list[tuple[str, str, str | list[str]]] = []
    if not isinstance(detection, dict):
        return predicates

    condition_str = str(detection.get("condition") or "").lower()
    for key, val in detection.items():
        if key in {"condition", "timeframe"}:
            continue
        # Ignora blocos de exclusão ('filter*') quando usados em 'not ... filter'
        if key.lower().startswith("filter") and "not " in condition_str:
            continue
        dict_blocks: list[dict[str, Any]] = []
        if isinstance(val, dict):
            dict_blocks.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    dict_blocks.append(item)

        for block in dict_blocks:
            for field_spec, fval in block.items():
                if fval is None:
                    continue
                parts = str(field_spec).split("|")
                field_name = parts[0].strip()
                if not field_name:
                    continue
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
    return predicates


def _enrich_mappings_with_category_context(
    mappings: list[CurationFieldMapping],
    rule_data: dict[str, Any],
    technology: Technology,
) -> list[CurationFieldMapping]:
    """Combina os campos explícitos da regra com os campos base do evento (ex: EvtID 4688)."""
    implicit = _implicit_category_fields(rule_data, technology)
    result: list[CurationFieldMapping] = []
    seen_logql: set[str] = set()

    for orig_f, logql_f in implicit:
        if logql_f not in seen_logql:
            seen_logql.add(logql_f)
            result.append(
                CurationFieldMapping(
                    original_field=orig_f,
                    logql_field=logql_f,
                    compatible=True,
                )
            )
    for m in mappings:
        if m.logql_field and m.logql_field != "pysigma_ast" and m.logql_field not in seen_logql:
            seen_logql.add(m.logql_field)
            result.append(m)
    return result


def convert_sigma_to_logql(
    rule_data: dict[str, Any],
    technology: Technology,
) -> tuple[str, list[CurationFieldMapping], bool, str]:
    """Converte uma regra Sigma para LogQL validado do Grafana Loki.
    
    Extrai os predicados estruturados do YAML Sigma mapeando para o schema JSON do Wazuh
    (com suporte à validação AST do pySigma quando disponível) e retorna os campos reais
    mapeados da regra enriquecidos pelo contexto do logsource/categoria.
    
    Retorna: (logql_query, field_mappings, lint_ok, lint_error).
    """
    tech_regex = technology.ss_groups_regex
    tech_slug = technology.slug
    raw_yaml = rule_data.get("raw_yaml") or ""
    detection = rule_data.get("detection") or {}

    predicates = _extract_predicates_from_detection(detection)
    threshold = 0
    time_window = "5m"

    # Threshold para detecções com timeframe ou repetição
    condition_str = str(detection.get("condition") if isinstance(detection, dict) else "").lower()
    timeframe = str(detection.get("timeframe") if isinstance(detection, dict) else "").strip()
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

        product = str(rule_data.get("product") or "").lower()
        if product == "windows" or "event" in title.lower():
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

    logql_query, structured_mappings = build_wazuh_logql_from_predicates(
        tech_regex=tech_regex,
        predicates=predicates,
        threshold=threshold,
        time_window=time_window,
        tech_slug=tech_slug,
    )
    enriched_mappings = _enrich_mappings_with_category_context(
        structured_mappings, rule_data, technology
    )

    lint_res = lint_logql(logql_query)
    if lint_res.is_valid:
        return logql_query, enriched_mappings, True, ""

    # Fallback via pySigma se disponível
    if PYSIGMA_AVAILABLE and raw_yaml:
        try:
            sigma_col = SigmaCollection.from_yaml(raw_yaml)
            backend = LogQLBackend()
            converted = backend.convert(sigma_col)
            if converted and isinstance(converted, list) and len(converted) > 0:
                raw_logql = converted[0]
                clean_expr = re.sub(r"^\{[^}]*\}\s*(\|\s*)?", "", raw_logql).strip()
                clean_expr = re.sub(r"^\b(?:logfmt|json)\b\s*(\|\s*)?", "", clean_expr).strip()
                if clean_expr and not clean_expr.startswith("|"):
                    stream = f'{{job="wazuh", ss_groups=~"{tech_regex}"}}'
                    candidate_query = f"sum(count_over_time({stream} | json | {clean_expr} [{time_window}])) > {threshold}"
                    cand_lint = lint_logql(candidate_query)
                    if cand_lint.is_valid:
                        return candidate_query, enriched_mappings, True, ""
        except Exception as py_err:
            logger.debug("pySigma fallback não converteu (%s).", py_err)

    return logql_query, enriched_mappings, lint_res.is_valid, lint_res.message

