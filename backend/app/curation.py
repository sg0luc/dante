"""Motor de Curadoria de Regras de Detecção do D.A.N.T.E.

Fluxo ponta a ponta da funcionalidade:
1. Pesquisa regras de detecção nas 4 fontes confiáveis oficiais:
   - https://github.com/SigmaHQ/sigma
   - https://detection.fyi/
   - https://research.splunk.com/detections/
   - https://elastic.github.io/detection-rules-explorer/
2. Para cada regra:
   2.1. Valida se o data source / logsource da regra é compatível com a base de
        tecnologias existentes e ativas no D.A.N.T.E. (ex.: AD/Windows, Sysmon,
        Office365, Fortigate, Linux, etc.).
   2.2. Converte a regra do formato original (Sigma YAML, Splunk SPL, Elastic EQL/KQL)
        para o formato LogQL, preservando todas as diretrizes do D.A.N.T.E.
        (job="wazuh", rule_groups, | json, agregação métrica e validação via lint_logql).
   2.3. Executa a query convertida no Loki de todos os clientes e, com base nos
        resultados obtidos e na compatibilidade de campos, categoriza a regra como
        excelente candidata ('excellent'), boa candidata ('good') ou má candidata ('bad').
   2.4. Insere e armazena apenas as excelentes e boas candidatas na base da página
        "Curadoria", apontando em quais clientes cada regra é excelente ou boa candidata.
3. Implementação:
   - Permite implementar a regra curada no Baseline Global e exatamente nos clientes
     recomendados pelos resultados da curadoria, sempre mediante confirmação explícita.

Regras permanentes:
1. Roda periodicamente, uma vez ao dia, todos os dias, às 08h00 (America/Sao_Paulo).
2. Nunca insere na curadoria uma regra considerada má candidata ('bad').
3. Nunca repete regras que já existem ou que já foram curadas por esta feature.
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

import httpx

from .ai import AIService

from .config import Settings, get_settings
from .contact_points import apply_contact_point, resolve_stage_receiver
from .grafana_client import GrafanaClient, GrafanaError
from .logql_validator import lint_logql
from .sigma_converter import convert_sigma_to_logql
from .sigma_manager import ensure_sigma_repo, pull_sigma_repo, scan_local_sigma_rules
from .schemas import (
    CuratedRuleItem,
    CurationCandidateQuality,
    CurationClientEvaluation,
    CurationFieldMapping,
    CurationMetrics,
    CurationOverviewResponse,
    CurationProgressState,
    CurationQualificationFactor,
    CurationRunResponse,
    CurationRunSummary,
    CurationScheduleInfo,
    CurationSourceId,
    CurationSourceInfo,
    ImplementCuratedRuleRequest,
    ImplementCuratedRuleResponse,
    ImplementedRuleResult,
    RuleSeverity,
)
from .system_settings_store import SystemSettingsStore
from .technologies import (
    DETECTION_PERIMETERS,
    Technology,
    TechnologyStore,
    infer_perimeter,
    normalize_perimeter,
)
from .technology_insights import (
    client_has_technology,
    find_implemented_rule,
    is_client_folder,
    strip_scope_prefix,
)
from .tenant_scan import TenantScanStore, TenantScanStoreError
from .tenant_technologies import TenantTechnologyStore, TenantTechnologyStoreError
from .tenants import (
    BASELINE_RULE_GROUP,
    LOKI_DATASOURCE_TYPES,
    RULE_GROUP_INTERVAL_SECONDS,
    bind_rule_datasource,
    detection_rules,
    find_tenant_datasource,
    resolve_baseline_loki_datasource,
    tenant_rule_group,
)

logger = logging.getLogger("hunter_portal.curation")

# =============================================================================
# 1. Fontes confiáveis oficiais
# =============================================================================
TRUSTED_SOURCES: list[dict[str, str]] = [
    {
        "id": "sigmahq",
        "name": "SigmaHQ",
        "url": "https://github.com/SigmaHQ/sigma",
        "format_label": "Sigma (YAML)",
        "description": "Repositório comunitário padrão de assinaturas Sigma genéricas para SIEM.",
    },
    {
        "id": "detection_fyi",
        "name": "detection.fyi",
        "url": "https://detection.fyi/",
        "format_label": "Sigma / KQL",
        "description": " Diretório curado de regras de detecção de ameaças e técnicas MITRE ATT&CK.",
    },
    {
        "id": "splunk_research",
        "name": "Splunk Security Research",
        "url": "https://research.splunk.com/detections/",
        "format_label": "Splunk SPL",
        "description": "Catálogo de detecções analíticas desenvolvidas pelo time Splunk Threat Research.",
    },
    {
        "id": "elastic_rules",
        "name": "Elastic Detection Rules",
        "url": "https://elastic.github.io/detection-rules-explorer/",
        "format_label": "Elastic EQL / KQL",
        "description": "Regras oficiais de detecção Elastic Security mapeadas para ECS e MITRE ATT&CK.",
    },
]

# Mapa canônico de campos do formato original (Sigma / CIM / ECS) para o flatten JSON do Wazuh no Loki
FIELD_TRANSLATION_MAP: dict[str, dict[str, str]] = {
    "ad_windows": {
        "EventID": "data_win_system_eventID",
        "event.code": "data_win_system_eventID",
        "EventCode": "data_win_system_eventID",
        "TargetUserName": "data_win_eventdata_targetUserName",
        "user.name": "data_win_eventdata_targetUserName",
        "SubjectUserName": "data_win_eventdata_subjectUserName",
        "IpAddress": "data_win_eventdata_ipAddress",
        "source.ip": "data_win_eventdata_ipAddress",
        "src_ip": "data_win_eventdata_ipAddress",
        "LogonType": "data_win_eventdata_logonType",
        "Status": "data_win_eventdata_status",
        "SubStatus": "data_win_eventdata_subStatus",
        "TicketEncryptionType": "data_win_eventdata_ticketEncryptionType",
        "ServiceName": "data_win_eventdata_serviceName",
        "ServiceFileName": "data_win_eventdata_serviceFileName",
        "AccessMask": "data_win_eventdata_accessMask",
        "TaskName": "data_win_eventdata_taskName",
        "Image": "data_win_eventdata_image",
        "process.executable": "data_win_eventdata_image",
        "CommandLine": "data_win_eventdata_commandLine",
        "process.command_line": "data_win_eventdata_commandLine",
        "ParentImage": "data_win_eventdata_parentImage",
        "process.parent.executable": "data_win_eventdata_parentImage",
        "TargetImage": "data_win_eventdata_targetImage",
        "GrantedAccess": "data_win_eventdata_grantedAccess",
        "User": "data_win_eventdata_user",
        "ScriptBlockText": "data_win_eventdata_scriptBlockText",
        "powershell.file.script_block_text": "data_win_eventdata_scriptBlockText",
        "TargetObject": "data_win_eventdata_targetObject",
        "registry.path": "data_win_eventdata_targetObject",
        "ShareName": "data_win_eventdata_shareName",
        "file.share.name": "data_win_eventdata_shareName",
        "PrivilegeList": "data_win_eventdata_privilegeList",
        "AuthenticationPackageName": "data_win_eventdata_authenticationPackageName",
        "GroupName": "data_win_eventdata_targetUserName",
        "MemberName": "data_win_eventdata_memberName",
        "rule.id": "rule_id",
    },
    "sysmon": {
        "EventID": "data_win_system_eventID",
        "event.code": "data_win_system_eventID",
        "EventCode": "data_win_system_eventID",
        "Image": "data_win_eventdata_image",
        "process.executable": "data_win_eventdata_image",
        "CommandLine": "data_win_eventdata_commandLine",
        "process.command_line": "data_win_eventdata_commandLine",
        "ParentImage": "data_win_eventdata_parentImage",
        "process.parent.executable": "data_win_eventdata_parentImage",
        "TargetImage": "data_win_eventdata_targetImage",
        "GrantedAccess": "data_win_eventdata_grantedAccess",
        "User": "data_win_eventdata_user",
        "TargetObject": "data_win_eventdata_targetObject",
        "rule.id": "rule_id",
    },
    "office365": {
        "Operation": "data_office365_Operation",
        "event.action": "data_office365_Operation",
        "UserId": "data_office365_UserId",
        "user.id": "data_office365_UserId",
        "ClientIP": "data_office365_ClientIP",
        "source.ip": "data_office365_ClientIP",
        "ResultStatus": "data_office365_ResultStatus",
        "event.outcome": "data_office365_ResultStatus",
        "Workload": "data_office365_Workload",
        "event.dataset": "data_office365_Workload",
        "ObjectId": "data_office365_ObjectId",
        "ApplicationId": "data_office365_ApplicationId",
        "PolicyName": "data_office365_PolicyName",
        "rule.id": "rule_id",
    },
    "fortigate": {
        "action": "data_action",
        "event.action": "data_action",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "dstip": "data_dstip",
        "destination.ip": "data_dstip",
        "dstport": "data_dstport",
        "destination.port": "data_dstport",
        "subtype": "data_subtype",
        "msg": "data_msg",
        "level": "data_level",
        "attack": "data_attack",
        "policyid": "data_policyid",
        "user": "data_user",
        "rule.id": "rule_id",
    },
    "linux": {
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "srcuser": "data_srcuser",
        "dstuser": "data_dstuser",
        "user.target.name": "data_dstuser",
        "command": "data_command",
        "process.command_line": "data_command",
        "process.executable": "data_command",
        "pam_status": "data_pam_status",
        "file.path": "data_file_path",
        "rule.id": "rule_id",
    },
    "dns": {
        "query_name": "data_query_name",
        "dns.question.name": "data_query_name",
        "qtype": "data_qtype",
        "dns.question.type": "data_qtype",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "response_length": "data_response_length",
        "rcode": "data_rcode",
        "rule.id": "rule_id",
    },
    "waf_akamai": {
        "action": "data_action",
        "event.action": "data_action",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "http_method": "data_http_method",
        "http.request.method": "data_http_method",
        "uri": "data_uri",
        "url.path": "data_uri",
        "attack_type": "data_attack_type",
        "rule_tag": "data_rule_tag",
        "status_code": "data_status_code",
        "http.response.status_code": "data_status_code",
        "rule_id": "rule_id",
        "rule.id": "rule_id",
    },
}

# Campos nativos suportados pelo pipeline Wazuh -> Vector -> Loki por tecnologia
# Suporta tanto formato com prefixo data_ (padrão) quanto formato legado para compatibilidade total
SUPPORTED_WAZUH_LOKI_FIELDS: dict[str, set[str]] = {
    "ad_windows": {
        "rule_id",
        "win_system_eventID",
        "data_win_system_eventID",
        "win_system_computer",
        "data_win_system_computer",
        "win_system_channel",
        "data_win_system_channel",
        "win_eventdata_targetUserName",
        "data_win_eventdata_targetUserName",
        "win_eventdata_subjectUserName",
        "data_win_eventdata_subjectUserName",
        "win_eventdata_ipAddress",
        "data_win_eventdata_ipAddress",
        "win_eventdata_status",
        "data_win_eventdata_status",
        "win_eventdata_subStatus",
        "data_win_eventdata_subStatus",
        "win_eventdata_logonType",
        "data_win_eventdata_logonType",
        "win_eventdata_ticketEncryptionType",
        "data_win_eventdata_ticketEncryptionType",
        "win_eventdata_serviceName",
        "data_win_eventdata_serviceName",
        "win_eventdata_serviceFileName",
        "data_win_eventdata_serviceFileName",
        "win_eventdata_accessMask",
        "data_win_eventdata_accessMask",
        "win_eventdata_taskName",
        "data_win_eventdata_taskName",
        "win_eventdata_image",
        "data_win_eventdata_image",
        "win_eventdata_commandLine",
        "data_win_eventdata_commandLine",
        "win_eventdata_parentImage",
        "data_win_eventdata_parentImage",
        "win_eventdata_targetImage",
        "data_win_eventdata_targetImage",
        "win_eventdata_grantedAccess",
        "data_win_eventdata_grantedAccess",
        "win_eventdata_user",
        "data_win_eventdata_user",
        "win_eventdata_scriptBlockText",
        "data_win_eventdata_scriptBlockText",
        "win_eventdata_targetObject",
        "data_win_eventdata_targetObject",
        "win_eventdata_shareName",
        "data_win_eventdata_shareName",
        "win_eventdata_privilegeList",
        "data_win_eventdata_privilegeList",
        "win_eventdata_authenticationPackageName",
        "data_win_eventdata_authenticationPackageName",
        "win_eventdata_memberName",
        "data_win_eventdata_memberName",
        "full_log",
    },
    "sysmon": {
        "rule_id",
        "win_system_eventID",
        "data_win_system_eventID",
        "win_eventdata_image",
        "data_win_eventdata_image",
        "win_eventdata_commandLine",
        "data_win_eventdata_commandLine",
        "win_eventdata_parentImage",
        "data_win_eventdata_parentImage",
        "win_eventdata_targetImage",
        "data_win_eventdata_targetImage",
        "win_eventdata_grantedAccess",
        "data_win_eventdata_grantedAccess",
        "win_eventdata_user",
        "data_win_eventdata_user",
        "win_eventdata_targetObject",
        "data_win_eventdata_targetObject",
        "full_log",
    },
    "office365": {
        "Operation": "data_office365_Operation",
        "event.action": "data_office365_Operation",
        "UserId": "data_office365_UserId",
        "user.id": "data_office365_UserId",
        "ClientIP": "data_office365_ClientIP",
        "source.ip": "data_office365_ClientIP",
        "ResultStatus": "data_office365_ResultStatus",
        "event.outcome": "data_office365_ResultStatus",
        "Workload": "data_office365_Workload",
        "event.dataset": "data_office365_Workload",
        "ObjectId": "data_office365_ObjectId",
        "ApplicationId": "data_office365_ApplicationId",
        "PolicyName": "data_office365_PolicyName",
        "rule.id": "rule_id",
    },
    "fortigate": {
        "action": "data_action",
        "event.action": "data_action",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "dstip": "data_dstip",
        "destination.ip": "data_dstip",
        "dstport": "data_dstport",
        "destination.port": "data_dstport",
        "subtype": "data_subtype",
        "msg": "data_msg",
        "level": "data_level",
        "attack": "data_attack",
        "policyid": "data_policyid",
        "user": "data_user",
        "rule.id": "rule_id",
    },
    "linux": {
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "srcuser": "data_srcuser",
        "dstuser": "data_dstuser",
        "user.target.name": "data_dstuser",
        "command": "data_command",
        "process.command_line": "data_command",
        "process.executable": "data_command",
        "pam_status": "data_pam_status",
        "file.path": "data_file_path",
        "rule.id": "rule_id",
    },
    "dns": {
        "query_name": "data_query_name",
        "dns.question.name": "data_query_name",
        "qtype": "data_qtype",
        "dns.question.type": "data_qtype",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "response_length": "data_response_length",
        "rcode": "data_rcode",
        "rule.id": "rule_id",
    },
    "waf_akamai": {
        "action": "data_action",
        "event.action": "data_action",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "http_method": "data_http_method",
        "http.request.method": "data_http_method",
        "uri": "data_uri",
        "url.path": "data_uri",
        "attack_type": "data_attack_type",
        "rule_tag": "data_rule_tag",
        "status_code": "data_status_code",
        "http.response.status_code": "data_status_code",
        "rule_id": "rule_id",
        "rule.id": "rule_id",
    },
}

# Campos nativos suportados pelo pipeline Wazuh -> Vector -> Loki por tecnologia
SUPPORTED_WAZUH_LOKI_FIELDS: dict[str, set[str]] = {
    "ad_windows": {
        "rule_id",
        "win_system_eventID",
        "win_system_computer",
        "win_system_channel",
        "win_eventdata_targetUserName",
        "win_eventdata_subjectUserName",
        "win_eventdata_ipAddress",
        "win_eventdata_status",
        "win_eventdata_subStatus",
        "win_eventdata_logonType",
        "win_eventdata_ticketEncryptionType",
        "win_eventdata_serviceName",
        "win_eventdata_serviceFileName",
        "win_eventdata_accessMask",
        "win_eventdata_taskName",
        "win_eventdata_image",
        "win_eventdata_commandLine",
        "win_eventdata_parentImage",
        "win_eventdata_targetImage",
        "win_eventdata_grantedAccess",
        "win_eventdata_user",
        "win_eventdata_scriptBlockText",
        "win_eventdata_targetObject",
        "win_eventdata_shareName",
        "win_eventdata_privilegeList",
        "win_eventdata_authenticationPackageName",
        "win_eventdata_memberName",
        "full_log",
    },
    "sysmon": {
        "rule_id",
        "win_system_eventID",
        "win_eventdata_image",
        "win_eventdata_commandLine",
        "win_eventdata_parentImage",
        "win_eventdata_targetImage",
        "win_eventdata_grantedAccess",
        "win_eventdata_user",
        "win_eventdata_targetObject",
        "full_log",
    },
    "office365": {
        "rule_id",
        "data_office365_Operation",
        "data_office365_UserId",
        "data_office365_ClientIP",
        "data_office365_ResultStatus",
        "data_office365_Workload",
        "data_office365_ObjectId",
        "data_office365_ApplicationId",
        "data_office365_PolicyName",
        "full_log",
    },
    "fortigate": {
        "rule_id",
        "data_srcip",
        "data_dstip",
        "data_action",
        "data_dstport",
        "data_subtype",
        "data_msg",
        "data_level",
        "data_attack",
        "data_policyid",
        "data_user",
        "full_log",
    },
    "linux": {
        "rule_id",
        "data_srcip",
        "data_srcuser",
        "data_dstuser",
        "data_command",
        "data_pam_status",
        "data_file_path",
        "full_log",
    },
    "dns": {
        "rule_id",
        "data_query_name",
        "data_qtype",
        "data_srcip",
        "data_response_length",
        "data_rcode",
        "full_log",
    },
    "waf_akamai": {
        "rule_id",
        "data_action",
        "data_srcip",
        "data_http_method",
        "data_uri",
        "data_attack_type",
        "data_rule_tag",
        "data_status_code",
        "full_log",
    },
}

# =============================================================================
# Mapeamentos e Schemas Padrão por PERÍMETRO DE DETECÇÃO (Detection Perimeter)
# Amarra regras ao escopo tecnológico (Firewall, WAF, Antimalware/EDR, etc.)
# =============================================================================
PERIMETER_DEFAULT_FIELDS: dict[str, set[str]] = {
    "firewall": {
        "rule_id",
        "data_srcip",
        "data_dstip",
        "data_action",
        "data_dstport",
        "data_srcport",
        "data_subtype",
        "data_msg",
        "data_level",
        "data_attack",
        "data_policyid",
        "data_user",
        "full_log",
    },
    "waf_web": {
        "rule_id",
        "data_action",
        "data_srcip",
        "data_http_method",
        "data_uri",
        "data_attack_type",
        "data_rule_tag",
        "data_status_code",
        "data_host",
        "data_user_agent",
        "full_log",
    },
    "endpoint_edr": {
        "rule_id",
        "win_system_eventID",
        "data_win_system_eventID",
        "win_eventdata_image",
        "data_win_eventdata_image",
        "win_eventdata_commandLine",
        "data_win_eventdata_commandLine",
        "win_eventdata_parentImage",
        "data_win_eventdata_parentImage",
        "win_eventdata_targetImage",
        "data_win_eventdata_targetImage",
        "win_eventdata_user",
        "data_win_eventdata_user",
        "win_eventdata_scriptBlockText",
        "data_win_eventdata_scriptBlockText",
        "data_file_path",
        "data_process_name",
        "data_process_id",
        "data_parent_process",
        "data_threat_name",
        "data_sha256",
        "data_action",
        "full_log",
    },
    "identity_iam": {
        "rule_id",
        "win_system_eventID",
        "data_win_system_eventID",
        "win_eventdata_targetUserName",
        "data_win_eventdata_targetUserName",
        "win_eventdata_subjectUserName",
        "data_win_eventdata_subjectUserName",
        "win_eventdata_ipAddress",
        "data_win_eventdata_ipAddress",
        "win_eventdata_status",
        "data_win_eventdata_status",
        "win_eventdata_subStatus",
        "data_win_eventdata_subStatus",
        "win_eventdata_logonType",
        "data_win_eventdata_logonType",
        "win_eventdata_ticketEncryptionType",
        "data_win_eventdata_ticketEncryptionType",
        "win_eventdata_serviceName",
        "data_win_eventdata_serviceName",
        "win_eventdata_serviceFileName",
        "data_win_eventdata_serviceFileName",
        "win_eventdata_accessMask",
        "data_win_eventdata_accessMask",
        "win_eventdata_taskName",
        "data_win_eventdata_taskName",
        "win_eventdata_targetObject",
        "data_win_eventdata_targetObject",
        "win_eventdata_privilegeList",
        "data_win_eventdata_privilegeList",
        "data_user",
        "data_srcip",
        "full_log",
    },
    "cloud_saas": {
        "rule_id",
        "data_office365_Operation",
        "data_office365_UserId",
        "data_office365_ClientIP",
        "data_office365_ResultStatus",
        "data_office365_Workload",
        "data_office365_ObjectId",
        "data_office365_ApplicationId",
        "data_office365_PolicyName",
        "data_user",
        "data_srcip",
        "full_log",
    },
    "os_host": {
        "rule_id",
        "data_srcip",
        "data_srcuser",
        "data_dstuser",
        "data_command",
        "data_pam_status",
        "data_file_path",
        "full_log",
    },
    "network_ids": {
        "rule_id",
        "data_query_name",
        "data_qtype",
        "data_srcip",
        "data_dstip",
        "data_response_length",
        "data_rcode",
        "data_alert",
        "full_log",
    },
    "email_gateway": {
        "rule_id",
        "data_sender",
        "data_recipient",
        "data_subject",
        "data_action",
        "data_threat_type",
        "data_attachment",
        "full_log",
    },
    "other": {"rule_id", "full_log"},
}

PERIMETER_FIELD_TRANSLATION_MAP: dict[str, dict[str, str]] = {
    "firewall": {
        "action": "data_action",
        "event.action": "data_action",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "src_ip": "data_srcip",
        "dstip": "data_dstip",
        "destination.ip": "data_dstip",
        "dst_ip": "data_dstip",
        "dstport": "data_dstport",
        "destination.port": "data_dstport",
        "dst_port": "data_dstport",
        "srcport": "data_srcport",
        "source.port": "data_srcport",
        "subtype": "data_subtype",
        "msg": "data_msg",
        "level": "data_level",
        "attack": "data_attack",
        "policyid": "data_policyid",
        "user": "data_user",
        "rule.id": "rule_id",
    },
    "waf_web": {
        "action": "data_action",
        "event.action": "data_action",
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "client.ip": "data_srcip",
        "http_method": "data_http_method",
        "http.request.method": "data_http_method",
        "method": "data_http_method",
        "uri": "data_uri",
        "url.path": "data_uri",
        "url": "data_uri",
        "attack_type": "data_attack_type",
        "rule_tag": "data_rule_tag",
        "status_code": "data_status_code",
        "http.response.status_code": "data_status_code",
        "status": "data_status_code",
        "host": "data_host",
        "user_agent": "data_user_agent",
        "rule.id": "rule_id",
    },
    "endpoint_edr": {
        "EventID": "data_win_system_eventID",
        "Image": "data_win_eventdata_image",
        "process.executable": "data_win_eventdata_image",
        "process_path": "data_file_path",
        "CommandLine": "data_win_eventdata_commandLine",
        "process.command_line": "data_win_eventdata_commandLine",
        "ParentImage": "data_win_eventdata_parentImage",
        "process.parent.executable": "data_win_eventdata_parentImage",
        "TargetImage": "data_win_eventdata_targetImage",
        "User": "data_win_eventdata_user",
        "user.name": "data_win_eventdata_user",
        "file.path": "data_file_path",
        "process_name": "data_process_name",
        "threat_name": "data_threat_name",
        "sha256": "data_sha256",
        "hash.sha256": "data_sha256",
        "action": "data_action",
        "rule.id": "rule_id",
    },
    "identity_iam": {
        "EventID": "data_win_system_eventID",
        "TargetUserName": "data_win_eventdata_targetUserName",
        "user.target.name": "data_win_eventdata_targetUserName",
        "SubjectUserName": "data_win_eventdata_subjectUserName",
        "user.name": "data_win_eventdata_subjectUserName",
        "TicketEncryptionType": "data_win_eventdata_ticketEncryptionType",
        "ServiceName": "data_win_eventdata_serviceName",
        "IpAddress": "data_win_eventdata_ipAddress",
        "source.ip": "data_win_eventdata_ipAddress",
        "LogonType": "data_win_eventdata_logonType",
        "Status": "data_win_eventdata_status",
        "SubStatus": "data_win_eventdata_subStatus",
        "user": "data_user",
        "srcip": "data_srcip",
        "rule.id": "rule_id",
    },
    "cloud_saas": {
        "Operation": "data_office365_Operation",
        "event.action": "data_office365_Operation",
        "UserId": "data_office365_UserId",
        "user.email": "data_office365_UserId",
        "ClientIP": "data_office365_ClientIP",
        "source.ip": "data_office365_ClientIP",
        "ResultStatus": "data_office365_ResultStatus",
        "Workload": "data_office365_Workload",
        "ObjectId": "data_office365_ObjectId",
        "ApplicationId": "data_office365_ApplicationId",
        "PolicyName": "data_office365_PolicyName",
        "user": "data_user",
        "srcip": "data_srcip",
        "rule.id": "rule_id",
    },
    "os_host": {
        "srcip": "data_srcip",
        "source.ip": "data_srcip",
        "srcuser": "data_srcuser",
        "dstuser": "data_dstuser",
        "command": "data_command",
        "process.command_line": "data_command",
        "pam_status": "data_pam_status",
        "file.path": "data_file_path",
        "rule.id": "rule_id",
    },
    "network_ids": {
        "query_name": "data_query_name",
        "dns.question.name": "data_query_name",
        "qtype": "data_qtype",
        "srcip": "data_srcip",
        "dstip": "data_dstip",
        "response_length": "data_response_length",
        "rcode": "data_rcode",
        "alert": "data_alert",
        "rule.id": "rule_id",
    },
    "email_gateway": {
        "sender": "data_sender",
        "recipient": "data_recipient",
        "subject": "data_subject",
        "action": "data_action",
        "threat_type": "data_threat_type",
        "attachment": "data_attachment",
        "rule.id": "rule_id",
    },
}

# =============================================================================
# URLs Canônicas e Validador Estrito de Fontes Confiáveis Oficiais
# =============================================================================
CANONICAL_SOURCE_URLS: dict[str, str] = {'sigma-win-security-kerberoasting-rc4-4769': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberoasting_rc4.yml', 'sigma-win-security-audit-log-cleared-1102': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_audit_log_cleared.yml', 'sigma-sysmon-lsass-memory-dump-t1003-001': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_procdump_lsass.yml', 'sigma-win-security-pass-the-hash-logontype9': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_pth_logon_type_9.yml', 'sigma-win-security-domain-admin-member-added-4728': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_domain_admin_member_added.yml', 'sigma-win-security-malicious-service-install-4697': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_service_install_4697.yml', 'sigma-win-powershell-scriptblock-download-cradle-4104': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_download_cradles.yml', 'sigma-win-security-admin-account-bruteforce-4625': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_admin_logon_fail_burst.yml', 'sigma-fortigate-admin-account-created-cli': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_admin_account_created.yml', 'sigma-fortigate-firewall-policy-modified': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_firewall_policy_modified.yml', 'sigma-fortigate-smb-port-445-blocked-lateral': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_inbound_sensitive_ports.yml', 'sigma-o365-sharepoint-mass-file-download': 'https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/m365_sharepoint_mass_file_download.yml', 'sigma-o365-oauth-app-admin-consent-granted': 'https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/m365_oauth_app_admin_consent_granted.yml', 'sigma-linux-sudoers-file-tampering': 'https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_sudoers_tampering.yml', 'sigma-linux-reverse-shell-bash-netcat': 'https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_reverse_shell.yml', 'sigma-akamai-waf-sqli-attack-blocked': 'https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_sqli_attack_blocked.yml', 'sigma-akamai-waf-rce-command-injection': 'https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_rce_command_injection.yml', 'sigma-dns-high-entropy-txt-tunneling': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_high_entropy_txt_tunneling.yml', 'sigma-win-security-account-lockout-4740': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_lockout.yml', 'sigma-win-security-user-modified-pwd-reset': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_user_management.yml', 'sigma-fortigate-high-volume-denied-traffic': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_high_volume_denied_traffic.yml', 'sigma-fortigate-outbound-suspicious-ports': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_outbound_suspicious_ports.yml', 'sigma-aws-cloudtrail-root-access-key-created': 'https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_cloudtrail_root_access_key_created.yml', 'sigma-fw-paloalto-c2-beaconing': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_c2_beaconing.yml', 'sigma-fw-checkpoint-portscan-drop': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_portscan_drop.yml', 'sigma-fw-inbound-rdp-smb-wan': 'https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_inbound_sensitive_ports.yml', 'sigma-waf-sqli-union-select': 'https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_waf_sqli_union_select.yml', 'sigma-waf-xss-script-injection': 'https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_waf_xss_script_injection.yml', 'sigma-edr-process-injection-remotethread': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_createremotethread.yml', 'sigma-edr-vssadmin-shadow-delete': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_vssadmin_delete_shadows.yml', 'sigma-ad-dcsync-replication-event-4662': 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml', 'sigma-m365-inbox-forwarding-rule': 'https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/m365_inbox_forwarding_rule_external.yml', 'detfyi-win-ad-replication-non-machine-account-dcsync': 'https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_ad_replication_non_machine_account/', 'detfyi-win-kerberos-golden-ticket-tgt-4768': 'https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_kerberos_golden_ticket/', 'detfyi-win-password-spraying-ntlm-4625': 'https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_password_spraying_ntlm_4625/', 'detfyi-win-certutil-urlcache-download': 'https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_certutil_download/', 'detfyi-win-registry-run-key-persistence': 'https://detection.fyi/sigmahq/sigma/windows/registry/registry_set_asep_reg_keys_persistence_currentversion/', 'detfyi-win-shadow-copy-deletion-vssadmin': 'https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_vssadmin_delete_shadow_copies/', 'detfyi-o365-inbox-forwarding-exfiltration-t1114': 'https://detection.fyi/sigmahq/sigma/cloud/m365/threat_management/microsoft365_susp_inbox_forwarding/', 'detfyi-o365-exchange-transport-rule-created': 'https://detection.fyi/sigmahq/sigma/cloud/m365/exchange/exchange_transport_rule_created/', 'detfyi-o365-mfa-fatigue-push-spam': 'https://detection.fyi/sigmahq/sigma/cloud/m365/azuread/azure_ad_mfa_fatigue_spam/', 'detfyi-fortigate-sslvpn-bruteforce-t1133': 'https://detection.fyi/sigmahq/sigma/network/fortinet/fortios_sslvpn_bruteforce/', 'detfyi-fortigate-denied-internal-scan-t1046': 'https://detection.fyi/sigmahq/sigma/network/fortinet/fortios_denied_internal_scan/', 'detfyi-fortigate-c2-beaconing-suspicious-port': 'https://detection.fyi/sigmahq/sigma/network/fortinet/fortios_c2_beaconing/', 'detfyi-linux-ssh-authorized-keys-modified': 'https://detection.fyi/sigmahq/sigma/linux/file_event/file_event_lnx_ssh_authorized_keys_modify/', 'detfyi-linux-execution-from-tmp-shm': 'https://detection.fyi/sigmahq/sigma/linux/process_creation/proc_creation_lnx_execution_from_tmp/', 'detfyi-akamai-waf-path-traversal-lfi': 'https://detection.fyi/sigmahq/sigma/web/web_path_traversal_lfi_blocked/', 'detfyi-akamai-waf-ssrf-metadata-probe': 'https://detection.fyi/sigmahq/sigma/web/web_ssrf_cloud_metadata_probe/', 'detfyi-win-security-logon-failure-4625': 'https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_failed_logons/', 'detfyi-win-security-explicit-credential-logon-4648': 'https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_explicit_logon/', 'detfyi-fortigate-admin-ports-traffic-blocked': 'https://detection.fyi/sigmahq/sigma/network/fortinet/fortigate_admin_ports/', 'detection-fyi-waf-ssrf-cloud-metadata': 'https://detection.fyi/elastic/detection-rules/cross-platform/credential_access_web_server_cloud_imds_ssrf_request/', 'detection-fyi-edr-lolbas-certutil-download': 'https://detection.fyi/elastic/detection-rules/windows/defense_evasion_suspicious_certutil_commands/', 'splunk-win-rdp-network-bruteforce-4625-t1021': 'https://research.splunk.com/endpoint/windows_rdp_network_brute_force/', 'splunk-win-asrep-roasting-preauth-disabled-4738': 'https://research.splunk.com/endpoint/kerberos_pre_authentication_disabled_user/', 'splunk-win-smb-admin-share-access-5140': 'https://research.splunk.com/endpoint/windows_administrative_smb_share_access/', 'splunk-win-special-privileges-new-logon-4672': 'https://research.splunk.com/endpoint/windows_special_privileges_assigned_logon/', 'splunk-win-account-password-reset-4724': 'https://research.splunk.com/endpoint/windows_user_account_password_reset/', 'splunk-win-wmi-remote-process-creation': 'https://research.splunk.com/endpoint/wmi_provider_host_spawning_suspicious_process/', 'splunk-o365-privileged-role-assigned-t1098-003': 'https://research.splunk.com/cloud/o365_privileged_role_assigned/', 'splunk-o365-federation-trust-modified': 'https://research.splunk.com/cloud/o365_azure_ad_domain_federation_modified/', 'splunk-o365-conditional-access-policy-disabled': 'https://research.splunk.com/cloud/entra_id_conditional_access_policy_disabled/', 'splunk-fortigate-admin-login-bruteforce': 'https://research.splunk.com/network/fortigate_admin_login_brute_force/', 'splunk-fortigate-ips-critical-exploit-blocked': 'https://research.splunk.com/network/fortigate_ips_critical_exploit_blocked/', 'splunk-linux-pam-su-root-bruteforce': 'https://research.splunk.com/endpoint/linux_pam_su_privilege_escalation_failure/', 'splunk-linux-systemd-persistence-unit': 'https://research.splunk.com/endpoint/linux_systemd_service_unit_created/', 'splunk-akamai-waf-xss-payload-blocked': 'https://research.splunk.com/web/waf_cross_site_scripting_payload_blocked/', 'splunk-akamai-waf-log4shell-jndi-injection': 'https://research.splunk.com/web/waf_log4j_jndi_lookup_exploitation_attempt/', 'splunk-win-security-user-account-created-4720': 'https://research.splunk.com/endpoint/windows_user_account_created/', 'splunk-win-security-special-privileges-logon-4672': 'https://research.splunk.com/endpoint/windows_special_privileges_assigned_logon/', 'splunk-fortigate-admin-login-failure': 'https://research.splunk.com/network/fortigate_admin_login_failure/', 'splunk-okta-mfa-policy-bypass': 'https://research.splunk.com/cloud/okta_mfa_policy_disabled_or_modified/', 'splunk-fw-tor-exit-node-connection': 'https://research.splunk.com/network/firewall_communication_with_tor_exit_node/', 'splunk-waf-path-traversal-attack': 'https://research.splunk.com/web/waf_directory_path_traversal_attempt/', 'splunk-edr-powershell-encoded-execution': 'https://research.splunk.com/endpoint/powershell_suspicious_encoded_command/', 'splunk-ad-sensitive-group-member-added': 'https://research.splunk.com/endpoint/11656928-181a-4663-87a7-0e6e737c385e/', 'splunk-aws-cloudtrail-root-access-key': 'https://research.splunk.com/cloud/aws_cloudtrail_root_access_key_created/', 'elastic-win-scheduled-task-persistence-4698': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_scheduled_task_creation.toml', 'elastic-sysmon-powershell-encoded-command-t1059-001': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_powershell_encoded_command.toml', 'elastic-win-new-local-user-account-4720': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_local_scheduled_user_creation.toml', 'elastic-win-regsvr32-remote-scriptlet-exec': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_regsvr32_remote_scriptlet.toml', 'elastic-win-rundll32-suspicious-invocation': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_suspicious_rundll32_execution.toml', 'elastic-win-eventlog-service-stopped-1100': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_eventlog_service_stopped.toml', 'elastic-linux-sshd-invalid-user-bruteforce-t1110': 'https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_sshd_invalid_user_bruteforce.toml', 'elastic-linux-kernel-module-load-insmod': 'https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_kernel_module_load_insmod.toml', 'elastic-linux-crontab-persistence-modification': 'https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_crontab_file_modified.toml', 'elastic-o365-dlp-policy-sensitive-match': 'https://github.com/elastic/detection-rules/blob/main/rules/integrations/m365/dlp_policy_sensitive_rule_match.toml', 'elastic-o365-anonymous-sharing-link-created': 'https://github.com/elastic/detection-rules/blob/main/rules/integrations/m365/anonymous_sharing_link_created.toml', 'elastic-fortigate-ipsec-vpn-negotiation-failure': 'https://github.com/elastic/detection-rules/blob/main/rules/network/fortinet_ipsec_vpn_negotiation_failure.toml', 'elastic-akamai-waf-credential-stuffing-login': 'https://github.com/elastic/detection-rules/blob/main/rules/web/akamai_waf_high_rate_credential_stuffing.toml', 'elastic-akamai-waf-graphql-introspection-probe': 'https://github.com/elastic/detection-rules/blob/main/rules/web/akamai_waf_graphql_introspection_probe.toml', 'elastic-win-security-user-account-deleted-4726': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_user_account_deleted.toml', 'elastic-win-security-group-member-added': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_group_member_added.toml', 'elastic-fortigate-utm-security-signature-blocked': 'https://github.com/elastic/detection-rules/blob/main/rules/network/fortinet_utm_security_signature_blocked.toml', 'elastic-win-proprietary-edr-kernel-call-tree': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_kernel_call_tree_anomaly.toml', 'elastic-fw-ssl-vpn-bruteforce': 'https://github.com/elastic/detection-rules/blob/main/rules/network/firewall_ssl_vpn_bruteforce_failure.toml', 'elastic-waf-log4j-jndi-rce': 'https://github.com/elastic/detection-rules/blob/main/rules/web/web_waf_log4j_jndi_rce.toml', 'elastic-edr-lsass-memory-access-mimikatz': 'https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_lsass_memory_mimikatz.toml'}

ROOT_OR_DIR_URL_PATTERNS: tuple[str, ...] = (
    "https://detection.fyi/",
    "https://detection.fyi",
    "https://research.splunk.com/detections/",
    "https://research.splunk.com/detections",
    "https://research.splunk.com/",
    "https://research.splunk.com",
    "https://elastic.github.io/detection-rules-explorer/",
    "https://elastic.github.io/detection-rules-explorer",
    "https://github.com/SigmaHQ/sigma",
    "https://github.com/SigmaHQ/sigma/",
)


def validate_trusted_source_url(url: str, source_id: str = "") -> tuple[bool, str]:
    """Valida que a URL da regra de detecção é oficial, canônica e direta.

    Rejeita terminantemente links para raiz do domínio ou diretórios genéricos (/tree/).
    """
    clean = str(url or "").strip()
    if not clean or not clean.startswith("https://"):
        return False, "URL inválida ou ausente (deve iniciar com https://)"
    if clean in ROOT_OR_DIR_URL_PATTERNS or clean.rstrip("/") in ROOT_OR_DIR_URL_PATTERNS:
        return False, "URL aponta apenas para a raiz do site da fonte, violando o requisito de rastreabilidade analítica"
    if "/tree/master" in clean or "/tree/main" in clean:
        return False, "URL aponta para diretório genérico em vez do arquivo de assinatura da regra"
    return True, "URL canônica válida"


def get_canonical_source_url(external_id: str, current_url: str = "") -> str:
    """Retorna a URL canônica real e direta da regra original na respectiva fonte."""
    clean_id = str(external_id or "").strip()
    if clean_id in CANONICAL_SOURCE_URLS:
        return CANONICAL_SOURCE_URLS[clean_id]
    valid, _ = validate_trusted_source_url(current_url)
    if valid:
        return current_url
    return current_url or "https://github.com/SigmaHQ/sigma"

# =============================================================================
# Catálogo completo de regras das 4 fontes confiáveis (SigmaHQ, detection.fyi, Splunk, Elastic)
# Nomes mantidos em inglês tal qual nas fontes pesquisadas.
# Inclui todas as regras compatíveis por tecnologia E regras más candidatas (que devem ser
# filtradas e barradas pelos passos 2.1, 2.3 e Regra 2).
# =============================================================================
RAW_SOURCE_CANDIDATES: list[dict[str, Any]] = [
    # --- 1. SigmaHQ (https://github.com/SigmaHQ/sigma) -----------------------
    {
        "external_id": "sigma-win-security-kerberoasting-rc4-4769",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberoasting_rc4.yml",
        "original_title": "Kerberoasting Activity - RC4 Ticket Request (Event 4769)",
        "description": (
            "Detecta solicitações de Service Ticket Kerberos (EventID 4769) utilizando "
            "criptografia RC4-HMAC (0x17) para contas de serviço, técnica clássica de "
            "Kerberoasting para quebra offline de senhas no Active Directory."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Kerberoasting Activity - RC4 Ticket Request (Event 4769)\n"
            "id: 4095452e-84c8-40a2-b62c-9471d91e237a\n"
            "status: stable\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4769'\n"
            "    TicketEncryptionType: '0x17'\n"
            "  condition: selection\n"
            "level: high\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1558.003"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1558.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4769"},
            {"field": "TicketEncryptionType", "op": "=", "value": "0x17"},
        ],
    },
    {
        "external_id": "sigma-win-security-audit-log-cleared-1102",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_audit_log_cleared.yml",
        "original_title": "Windows Security Audit Log Cleared (Event 1102)",
        "description": (
            "Detecta a limpeza do log de eventos de Segurança do Windows (EventID 1102), "
            "ação frequentemente executada por atacantes após comprometer um endpoint ou "
            "Controlador de Domínio para apagar rastros forenses."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Windows Security Audit Log Cleared (Event 1102)\n"
            "id: d99b79d2-0a6f-4f46-ad8b-260b6e17f982\n"
            "status: stable\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '1102'\n"
            "  condition: selection\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.defense_evasion\n"
            "  - attack.t1070.001"
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "critical",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1070.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "1102"},
        ],
    },
    {
        "external_id": "sigma-sysmon-lsass-memory-dump-t1003-001",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_hktl_procdump_lsass.yml",
        "original_title": "LSASS Memory Dump via Comsvcs or ProcDump",
        "description": (
            "Detecta criação de processo (EventID 1 / 4688) utilizando comsvcs.dll MiniDump "
            "ou procdump para extrair credenciais em texto claro e hashes NTLM da memória do LSASS."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: LSASS Memory Dump via Comsvcs or ProcDump\n"
            "id: 8b2c4e1a-7c9d-4e5a-9b1f-3a5d7e9f1b2c\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "  service: sysmon\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '1'\n"
            "    CommandLine|re: '(?i).*(MiniDump|procdump.*lsass).*'\n"
            "  condition: selection\n"
            "level: critical\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1003.001"
        ),
        "datasource_hints": ["sysmon", "ad_windows"],
        "severity": "critical",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1003.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "1"},
            {"field": "CommandLine", "op": "=~", "value": "(?i).*(MiniDump|procdump|lsass).*"},
        ],
    },
    {
        "external_id": "sigma-win-security-pass-the-hash-logontype9",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_pth_logon_type_9.yml",
        "original_title": "Pass-the-Hash Activity via NewCredentials Logon (Event 4624)",
        "description": (
            "Detecta sessões de logon NewCredentials (EventID 4624, LogonType 9) com pacote "
            "Negotiate/NTLM associadas ao uso de Mimikatz sekurlsa::pth ou ferramentas de Pass-the-Hash."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Pass-the-Hash Activity via NewCredentials Logon (Event 4624)\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4624'\n"
            "    LogonType: '9'\n"
            "  condition: selection\n"
            "level: high"
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "lateral-movement",
        "mitre_technique": "T1550.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4624"},
            {"field": "LogonType", "op": "=", "value": "9"},
        ],
    },
    {
        "external_id": "sigma-win-security-domain-admin-member-added-4728",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_domain_admin_member_added.yml",
        "original_title": "Member Added to Security-Enabled Global Group (Event 4728)",
        "description": (
            "Detecta a inclusão de conta de usuário em grupos globais privilegiados do Active Directory "
            "(EventID 4728 / 4732), como Domain Admins ou Enterprise Admins."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Member Added to Security-Enabled Global Group (Event 4728)\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4728'\n"
            "    TargetUserName|re: '(?i).*(Domain Admins|Enterprise Admins|Administrators).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=~", "value": "4728|4732"},
            {"field": "TargetUserName", "op": "=~", "value": "(?i).*(Domain Admins|Enterprise Admins|Administrators).*"},
        ],
    },
    {
        "external_id": "sigma-win-security-malicious-service-install-4697",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_service_install_4697.yml",
        "original_title": "New Service Installed in the System Security Log (Event 4697)",
        "description": (
            "Detecta a instalação de um novo serviço Windows (EventID 4697), técnica comum "
            "para persistência de privilégio SYSTEM e execução remota via PsExec/SMBExec."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: New Service Installed in the System Security Log (Event 4697)\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4697'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1543.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4697"},
        ],
    },
    {
        "external_id": "sigma-win-powershell-scriptblock-download-cradle-4104",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_download_cradles.yml",
        "original_title": "PowerShell WebClient Download Cradle Execution (Event 4104)",
        "description": (
            "Identifica blocos de script PowerShell (EventID 4104) contendo chamadas Net.WebClient, "
            "DownloadString ou Invoke-WebRequest para download e execução fileless em memória."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: PowerShell WebClient Download Cradle Execution (Event 4104)\n"
            "logsource:\n"
            "  product: windows\n"
            "  category: ps_script\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4104'\n"
            "    ScriptBlockText|re: '(?i).*(DownloadString|Net[.]WebClient|Invoke-WebRequest).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["windows", "ad_windows"],
        "severity": "high",
        "mitre_tactic": "execution",
        "mitre_technique": "T1059.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4104"},
            {"field": "ScriptBlockText", "op": "=~", "value": "(?i).*(DownloadString|WebClient|Invoke-WebRequest).*"},
        ],
    },
    {
        "external_id": "sigma-win-security-admin-account-bruteforce-4625",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_admin_logon_fail_burst.yml",
        "original_title": "Windows Administrator Account Logon Failure Burst (Event 4625)",
        "description": (
            "Detecta falhas repetidas de autenticação (EventID 4625) direcionadas especificamente "
            "à conta privilegiada Administrator no Windows / Active Directory."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Windows Administrator Account Logon Failure Burst (Event 4625)\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4625'\n"
            "    TargetUserName: 'Administrator'\n"
            "  condition: selection | count() > 3"
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110.001",
        "threshold_operator": "gt",
        "threshold_value": 3,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4625"},
            {"field": "TargetUserName", "op": "=", "value": "Administrator"},
        ],
    },
    {
        "external_id": "sigma-fortigate-admin-account-created-cli",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_admin_account_created.yml",
        "original_title": "FortiGate New Administrator Account Created",
        "description": (
            "Detecta eventos de criação ou modificação de conta administrativa no FortiOS "
            "para persistência em appliance de borda."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: FortiGate New Administrator Account Created\n"
            "logsource:\n"
            "  product: fortigate\n"
            "  service: event\n"
            "detection:\n"
            "  selection:\n"
            "    subtype: 'system'\n"
            "    action: 'add'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1136.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=", "value": "system"},
            {"field": "action", "op": "=", "value": "add"},
        ],
    },
    {
        "external_id": "sigma-fortigate-firewall-policy-modified",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_firewall_policy_modified.yml",
        "original_title": "FortiGate Firewall Security Policy Modified or Disabled",
        "description": (
            "Identifica alterações ou exclusões de regras de filtragem no firewall FortiGate "
            "que podem abrir acesso externo não autorizado."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: FortiGate Firewall Security Policy Modified or Disabled\n"
            "logsource:\n"
            "  product: fortigate\n"
            "detection:\n"
            "  selection:\n"
            "    subtype: 'system'\n"
            "    action|re: 'edit|delete'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1562.004",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=", "value": "system"},
            {"field": "action", "op": "=~", "value": "edit|delete"},
        ],
    },
    {
        "external_id": "sigma-fortigate-smb-port-445-blocked-lateral",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_inbound_sensitive_ports.yml",
        "original_title": "FortiGate Blocked SMB Port 445 Lateral Movement Attempt",
        "description": (
            "Detecta bloqueios de conexões SMB (porta 445) no firewall FortiGate, "
            "indicando tentativa de movimentação lateral ou propagação SMB entre segmentos."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: FortiGate Blocked SMB Port 445 Lateral Movement Attempt\n"
            "logsource:\n"
            "  product: fortigate\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'deny'\n"
            "    dstport: '445'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "high",
        "mitre_tactic": "lateral-movement",
        "mitre_technique": "T1021.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=", "value": "deny"},
            {"field": "dstport", "op": "=", "value": "445"},
        ],
    },
    {
        "external_id": "sigma-o365-sharepoint-mass-file-download",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/m365_sharepoint_mass_file_download.yml",
        "original_title": "Office 365 Mass File Download from SharePoint or OneDrive",
        "description": (
            "Detecta volume elevado de operações FileDownloaded ou FileSyncDownloadedFull no "
            "SharePoint Online / OneDrive, sugerindo exfiltração em massa de arquivos corporativos."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Office 365 Mass File Download from SharePoint or OneDrive\n"
            "logsource:\n"
            "  product: m365\n"
            "  service: sharepoint\n"
            "detection:\n"
            "  selection:\n"
            "    Workload: 'SharePoint'\n"
            "    Operation|re: 'FileDownloaded|FileSyncDownloadedFull'\n"
            "  condition: selection | count() > 25"
        ),
        "datasource_hints": ["office365", "m365"],
        "severity": "high",
        "mitre_tactic": "exfiltration",
        "mitre_technique": "T1567",
        "threshold_operator": "gt",
        "threshold_value": 25,
        "for_duration": "0s",
        "predicates": [
            {"field": "Workload", "op": "=~", "value": "SharePoint|OneDrive"},
            {"field": "Operation", "op": "=~", "value": "FileDownloaded|FileSyncDownloadedFull"},
        ],
    },
    {
        "external_id": "sigma-o365-oauth-app-admin-consent-granted",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/m365_oauth_app_admin_consent_granted.yml",
        "original_title": "Office 365 Suspicious OAuth Application Admin Consent Granted",
        "description": (
            "Detecta concessão de consentimento administrativo a aplicativo OAuth no Entra ID / "
            "Office 365 (Consent to application), vetor usado em ataques de Illicit Consent Grant."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Office 365 Suspicious OAuth Application Admin Consent Granted\n"
            "logsource:\n"
            "  product: m365\n"
            "  service: azuread\n"
            "detection:\n"
            "  selection:\n"
            "    Operation: 'Consent to application.'\n"
            "    ResultStatus: 'Success'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["office365", "m365", "azuread"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Operation", "op": "=~", "value": "Consent to application.*"},
            {"field": "ResultStatus", "op": "=", "value": "Success"},
        ],
    },
    {
        "external_id": "sigma-linux-sudoers-file-tampering",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_sudoers_tampering.yml",
        "original_title": "Linux Sudoers File Modification via Command Line",
        "description": (
            "Detecta comandos que alteram diretamente /etc/sudoers ou /etc/sudoers.d para "
            "conceder escalonamento persistente de privilégio NOPASSWD em hosts Linux."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Linux Sudoers File Modification via Command Line\n"
            "logsource:\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    command|re: '(?i).*(/etc/sudoers|NOPASSWD).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "critical",
        "mitre_tactic": "privilege-escalation",
        "mitre_technique": "T1548.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "command", "op": "=~", "value": "(?i).*(/etc/sudoers|NOPASSWD).*"},
        ],
    },
    {
        "external_id": "sigma-linux-reverse-shell-bash-netcat",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_reverse_shell.yml",
        "original_title": "Linux Potential Reverse Shell via Bash or Netcat",
        "description": (
            "Detecta invocação de shells interativas redirecionadas para sockets de rede "
            "(/dev/tcp/, nc -e /bin/sh, bash -i) em servidores Linux."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Linux Potential Reverse Shell via Bash or Netcat\n"
            "logsource:\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    command|re: '(?i)*(/dev/tcp/|nc -e|bash -i).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "critical",
        "mitre_tactic": "execution",
        "mitre_technique": "T1059.004",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "command", "op": "=~", "value": "(?i).*(/dev/tcp/|nc -e|bash -i).*"},
        ],
    },
    {
        "external_id": "sigma-akamai-waf-sqli-attack-blocked",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_sqli_attack_blocked.yml",
        "original_title": "Akamai WAF SQL Injection Payload Blocked at Edge",
        "description": (
            "Detecta requisições HTTP contendo vetores de SQL Injection (UNION SELECT, OR 1=1, "
            "sleep/benchmark) interceptadas pelo WAF Akamai."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Akamai WAF SQL Injection Payload Blocked at Edge\n"
            "logsource:\n"
            "  category: webserver\n"
            "  product: akamai\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'deny'\n"
            "    uri|re: '(?i).*(union.*select|select.*from|information_schema).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=", "value": "deny"},
            {"field": "uri", "op": "=~", "value": "(?i).*(union.*select|information_schema).*"},
        ],
    },
    {
        "external_id": "sigma-akamai-waf-rce-command-injection",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_rce_command_injection.yml",
        "original_title": "Akamai WAF Remote Command Injection Attempt in URI",
        "description": (
            "Identifica tentativas de execução remota de comandos (OS Command Injection) "
            "em parâmetros de URI inspecionados pelo WAF Akamai."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Akamai WAF Remote Command Injection Attempt in URI\n"
            "logsource:\n"
            "  category: webserver\n"
            "  product: akamai\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'deny'\n"
            "    uri|re: '(?i).*(/bin/sh|/etc/passwd|cmd[.]exe|whoami).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "critical",
        "mitre_tactic": "execution",
        "mitre_technique": "T1059",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=", "value": "deny"},
            {"field": "uri", "op": "=~", "value": "(?i).*(/bin/sh|/etc/passwd|cmd[.]exe|whoami).*"},
        ],
    },
    {
        "external_id": "sigma-dns-high-entropy-txt-tunneling",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/dns/net_dns_high_entropy_txt_tunneling.yml",
        "original_title": "DNS High Volume TXT Query Tunneling Activity",
        "description": (
            "Detecta consultas DNS do tipo TXT em alto volume associadas a ferramentas de "
            "DNS Tunneling e comando e controle (iodine, dnscat2)."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: DNS High Volume TXT Query Tunneling Activity\n"
            "logsource:\n"
            "  category: dns\n"
            "detection:\n"
            "  selection:\n"
            "    qtype: 'TXT'\n"
            "  condition: selection | count() > 20"
        ),
        "datasource_hints": ["dns"],
        "severity": "high",
        "mitre_tactic": "command-and-control",
        "mitre_technique": "T1071.004",
        "threshold_operator": "gt",
        "threshold_value": 20,
        "for_duration": "0s",
        "predicates": [
            {"field": "qtype", "op": "=", "value": "TXT"},
        ],
    },
    {
        "external_id": "sigma-win-security-account-lockout-4740",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_account_lockout.yml",
        "original_title": "User Account Locked Out (Event 4740)",
        "description": (
            "Detecta eventos de bloqueio de conta de usuário no Active Directory (EventID 4740) "
            "decorrentes de múltiplas tentativas consecutivas de logon com senha incorreta, "
            "indicando possíveis ataques de força bruta, password spraying ou credencial defasada."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: User Account Locked Out (Event 4740)\n"
            "id: 603f0b27-4187-43f6-953b-e1c8b320d321\n"
            "status: stable\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4740'\n"
            "  condition: selection\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1110.001"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "medium",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4740"},
        ],
    },
    {
        "external_id": "sigma-win-security-user-modified-pwd-reset",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_user_management.yml",
        "original_title": "Windows User Account Modified or Password Reset (Event 4738 / 4724)",
        "description": (
            "Detecta modificações em contas de usuário ou tentativas de redefinição de senha "
            "(EventID 4738 ou 4724) no Active Directory, técnica de persistência para manutenção de acesso."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Windows User Account Modified or Password Reset (Event 4738 / 4724)\n"
            "id: a49d1078-d069-450a-9d0b-6a5c1e55e8d2\n"
            "status: stable\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID|re: '4738|4724'\n"
            "  condition: selection\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.persistence\n"
            "  - attack.t1098"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=~", "value": "4738|4724"},
        ],
    },
    {
        "external_id": "sigma-fortigate-high-volume-denied-traffic",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_high_volume_denied_traffic.yml",
        "original_title": "FortiGate High Volume Dropped or Denied Network Traffic",
        "description": (
            "Detecta conexões de rede bloqueadas ou negadas pelas políticas de firewall no FortiOS "
            "(action deny, drop ou block), alertando para varreduras externas ou tráfego hostil não autorizado."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: FortiGate High Volume Dropped or Denied Network Traffic\n"
            "id: f8b71d99-31c4-42b7-a3f1-7c9e5e6c1a2b\n"
            "logsource:\n"
            "  product: fortigate\n"
            "  service: traffic\n"
            "detection:\n"
            "  selection:\n"
            "    action|re: '(?i)deny|drop|block|close'\n"
            "  condition: selection\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.initial_access\n"
            "  - attack.t1190"
        ),
        "datasource_hints": ["fortigate", "fortinet", "firewall"],
        "severity": "medium",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=~", "value": "(?i)deny|drop|block|close"},
        ],
    },
    {
        "external_id": "sigma-fortigate-outbound-suspicious-ports",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/fortinet/fortios_outbound_suspicious_ports.yml",
        "original_title": "FortiGate Outbound Traffic Blocked on Suspicious Ports",
        "description": (
            "Monitora conexões de saída bloqueadas pelo firewall para portas suspeitas frequentemente "
            "utilizadas por cavalos de Tróia e canais de comando e controle (4444, 5555, 6667, 8888, 9001)."
        ),
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: FortiGate Outbound Traffic Blocked on Suspicious Ports\n"
            "id: 7b3e9a11-82d4-4a6c-9c7f-1d8f5b2e9a3c\n"
            "logsource:\n"
            "  product: fortigate\n"
            "detection:\n"
            "  selection:\n"
            "    action|re: '(?i)deny|drop|block|close'\n"
            "    dstport|re: '4444|5555|6667|8888|9001'\n"
            "  condition: selection\n"
            "level: high\n"
            "tags:\n"
            "  - attack.command_and_control\n"
            "  - attack.t1071"
        ),
        "datasource_hints": ["fortigate", "fortinet", "firewall"],
        "severity": "high",
        "mitre_tactic": "command-and-control",
        "mitre_technique": "T1071",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=~", "value": "(?i)deny|drop|block|close"},
            {"field": "dstport", "op": "=~", "value": "4444|5555|6667|8888|9001"},
        ],
    },

    # --- 2. detection.fyi (https://detection.fyi/) ---------------------------
    {
        "external_id": "detfyi-win-ad-replication-non-machine-account-dcsync",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_ad_replication_non_machine_account/",
        "original_title": "Active Directory Replication from Non Machine Account - DcSync Indicator",
        "description": (
            "Detecta requisições de replicação de diretório Active Directory (EventID 4662) "
            "originadas de contas que não são de computador (non-machine accounts), "
            "comportamento clássico de ataques DCSync (Mimikatz / secretsdump) para extrair hashes NTLM."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "title: Active Directory Replication from Non Machine Account - DcSync Indicator\n"
            "id: 17d619c1-e020-4347-957e-1d1207455c93\n"
            "status: test\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4662\n"
            "    AccessMask: '0x100'\n"
            "  condition: selection\n"
            "tags:\n"
            "  - attack.credential_access\n"
            "  - attack.t1003.006"
        ),
        "datasource_hints": ["windows", "ad_windows", "active_directory"],
        "severity": "critical",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1003.006",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4662"},
            {"field": "AccessMask", "op": "=", "value": "0x100"},
        ],
    },
    {
        "external_id": "detfyi-win-kerberos-golden-ticket-tgt-4768",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_kerberos_golden_ticket/",
        "original_title": "Kerberos TGT Request with RC4 Encryption (Golden Ticket 4768)",
        "description": (
            "Detecta requisições de Ticket Granting Ticket (EventID 4768) utilizando "
            "criptografia legada RC4 (0x17), indicativo de uso de Golden Ticket ou downgrade Kerberos."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "SecurityEvent\n"
            "| where EventID == 4768\n"
            "| where TicketEncryptionType == '0x17'"
        ),
        "datasource_hints": ["windows", "ad_windows", "active_directory"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1558.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4768"},
            {"field": "TicketEncryptionType", "op": "=", "value": "0x17"},
        ],
    },
    {
        "external_id": "detfyi-win-password-spraying-ntlm-4625",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_password_spraying_ntlm_4625/",
        "original_title": "Active Directory Password Spraying Attack (SubStatus 0xC000006A)",
        "description": (
            "Detecta múltiplas falhas de senha incorreta (EventID 4625, SubStatus 0xC000006A) "
            "características de ataques de Password Spraying contra contas do domínio."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "SecurityEvent\n"
            "| where EventID == 4625 and SubStatus == '0xc000006a'\n"
            "| summarize count() by IpAddress | where count_ > 10"
        ),
        "datasource_hints": ["windows", "ad_windows"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110.003",
        "threshold_operator": "gt",
        "threshold_value": 10,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4625"},
            {"field": "SubStatus", "op": "=~", "value": "(?i)0xc000006a"},
        ],
    },
    {
        "external_id": "detfyi-win-certutil-urlcache-download",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_certutil_download/",
        "original_title": "Suspicious File Download via Certutil URLCache",
        "description": (
            "Detecta abuso do binário nativo certutil.exe (LOLBin) com parâmetros -urlcache "
            "ou -split para baixar payloads maliciosos da internet."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "DeviceProcessEvents\n"
            "| where ProcessCommandLine has_all ('certutil', '-urlcache')"
        ),
        "datasource_hints": ["windows", "ad_windows", "sysmon"],
        "severity": "high",
        "mitre_tactic": "command-and-control",
        "mitre_technique": "T1105",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "CommandLine", "op": "=~", "value": "(?i).*certutil.*(urlcache|verifyctl).*"},
        ],
    },
    {
        "external_id": "detfyi-win-registry-run-key-persistence",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/registry/registry_set_asep_reg_keys_persistence_currentversion/",
        "original_title": "Registry Run Key Modification for Startup Persistence",
        "description": (
            "Detecta modificações nas chaves de registro CurrentVersion\\Run ou RunOnce "
            "(Sysmon EventID 13 / 4657) utilizadas para persistência na inicialização do Windows."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "DeviceRegistryEvents\n"
            "| where RegistryKey endswith '\\\\CurrentVersion\\\\Run'"
        ),
        "datasource_hints": ["windows", "ad_windows", "sysmon"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1547.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "TargetObject", "op": "=~", "value": "(?i).*CurrentVersion.*(Run|RunOnce).*"},
        ],
    },
    {
        "external_id": "detfyi-win-shadow-copy-deletion-vssadmin",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_vssadmin_delete_shadow_copies/",
        "original_title": "Volume Shadow Copy Deletion via Vssadmin or WMIC",
        "description": (
            "Detecta exclusão de cópias de sombra de volume (vssadmin delete shadows / "
            "wmic shadowcopy delete), etapa crítica pré-criptografia em ataques de ransomware."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "DeviceProcessEvents\n"
            "| where ProcessCommandLine matches regex '(?i)(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete)'"
        ),
        "datasource_hints": ["windows", "ad_windows", "sysmon"],
        "severity": "critical",
        "mitre_tactic": "impact",
        "mitre_technique": "T1490",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "CommandLine", "op": "=~", "value": "(?i).*(delete.*shadows|shadowcopy.*delete).*"},
        ],
    },
    {
        "external_id": "detfyi-o365-inbox-forwarding-exfiltration-t1114",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/cloud/m365/threat_management/microsoft365_susp_inbox_forwarding/",
        "original_title": "Office 365 Suspicious Inbox Forwarding Rule Created",
        "description": (
            "Detecta a criação ou modificação de regras de encaminhamento automático de caixa de "
            "entrada no Exchange Online (New-InboxRule / Set-InboxRule), usada após comprometimento "
            "de conta (BEC) para exfiltrar e-mails confidenciais."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "OfficeActivity\n"
            "| where Workload == 'Exchange'\n"
            "| where Operation in ('New-InboxRule', 'Set-InboxRule')\n"
            "// MITRE ATT&CK: T1114.003 (Email Forwarding Rule)"
        ),
        "datasource_hints": ["office365", "m365", "exchange"],
        "severity": "high",
        "mitre_tactic": "collection",
        "mitre_technique": "T1114.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Operation", "op": "=~", "value": "New-InboxRule|Set-InboxRule"},
        ],
    },
    {
        "external_id": "detfyi-o365-exchange-transport-rule-created",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/cloud/m365/exchange/exchange_transport_rule_created/",
        "original_title": "Exchange Online Mail Flow Transport Rule Created",
        "description": (
            "Detecta criação de regras de transporte globais no Exchange Online (New-TransportRule) "
            "para redirecionamento silencioso de mensagens de todo o tenant."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "OfficeActivity\n"
            "| where Workload == 'Exchange' and Operation in ('New-TransportRule', 'Set-TransportRule')"
        ),
        "datasource_hints": ["office365", "m365", "exchange"],
        "severity": "critical",
        "mitre_tactic": "collection",
        "mitre_technique": "T1114.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Workload", "op": "=", "value": "Exchange"},
            {"field": "Operation", "op": "=~", "value": "New-TransportRule|Set-TransportRule"},
        ],
    },
    {
        "external_id": "detfyi-o365-mfa-fatigue-push-spam",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/cloud/m365/azuread/azure_ad_mfa_fatigue_spam/",
        "original_title": "Microsoft Entra ID Repeated MFA Push Failures",
        "description": (
            "Identifica múltiplas falhas seguidas de autenticação multifator (UserLoginFailed) "
            "no Entra ID / Office 365, padrão característico de ataques de MFA Fatigue / Push Bombing."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "OfficeActivity\n"
            "| where Workload == 'AzureActiveDirectory' and Operation == 'UserLoginFailed'\n"
            "| summarize count() by UserId | where count_ > 5"
        ),
        "datasource_hints": ["office365", "m365", "azuread"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1621",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "Operation", "op": "=", "value": "UserLoginFailed"},
            {"field": "ResultStatus", "op": "=~", "value": "Failed|Failure"},
        ],
    },
    {
        "external_id": "detfyi-fortigate-sslvpn-bruteforce-t1133",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/network/fortinet/fortios_sslvpn_bruteforce/",
        "original_title": "FortiGate SSL-VPN Multiple Authentication Failures",
        "description": (
            "Detecta tentativas repetidas de login malsucedidas no portal SSL-VPN do FortiGate, "
            "indicando ataque de força bruta ou credential stuffing contra acesso remoto."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "title: FortiGate SSL-VPN Multiple Authentication Failures\n"
            "logsource:\n"
            "  product: fortigate\n"
            "  service: sslvpn\n"
            "detection:\n"
            "  selection:\n"
            "    subtype: 'vpn'\n"
            "    action: 'ssl-login-fail'\n"
            "  condition: selection | count() by srcip > 5"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1133",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=", "value": "vpn"},
            {"field": "action", "op": "=~", "value": "ssl-login-fail|deny"},
        ],
    },
    {
        "external_id": "detfyi-fortigate-denied-internal-scan-t1046",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/network/fortinet/fortios_denied_internal_scan/",
        "original_title": "FortiGate High Volume Denied Internal Traffic Burst",
        "description": (
            "Detecta múltiplos pacotes negados (action=deny) pelo FortiGate originados de sub-redes "
            "internas, indicando varredura horizontal de serviços ou tentativa de movimentação lateral."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "title: FortiGate High Volume Denied Internal Traffic Burst\n"
            "logsource:\n"
            "  product: fortigate\n"
            "  service: firewall\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'deny'\n"
            "    srcip|re: '^10\\..*'\n"
            "  condition: selection | count() > 5"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "high",
        "mitre_tactic": "discovery",
        "mitre_technique": "T1046",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=", "value": "deny"},
            {"field": "srcip", "op": "=~", "value": "10[.].*"},
        ],
    },
    {
        "external_id": "detfyi-fortigate-c2-beaconing-suspicious-port",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/network/fortinet/fortios_c2_beaconing/",
        "original_title": "FortiGate Outbound Traffic Blocked to Known C2 Port",
        "description": (
            "Detecta conexões de saída bloqueadas pelo FortiGate para portas associadas a frameworks "
            "de C2 e Metasploit/Cobalt Strike (4444, 5555, 8443, 9001)."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "title: FortiGate Outbound Traffic Blocked to Known C2 Port\n"
            "logsource:\n"
            "  product: fortigate\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'deny'\n"
            "    dstport|re: '4444|5555|9001'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "high",
        "mitre_tactic": "command-and-control",
        "mitre_technique": "T1571",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=", "value": "deny"},
            {"field": "dstport", "op": "=~", "value": "4444|5555|9001"},
        ],
    },
    {
        "external_id": "detfyi-linux-ssh-authorized-keys-modified",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/linux/file_event/file_event_lnx_ssh_authorized_keys_modify/",
        "original_title": "Linux Unauthorized SSH Authorized_Keys Modification",
        "description": (
            "Detecta comandos que gravam chaves públicas em ~/.ssh/authorized_keys "
            "para manter acesso persistente via SSH em servidores Linux."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "LinuxAuditD\n"
            "| where command contains 'authorized_keys'"
        ),
        "datasource_hints": ["linux", "sshd", "syslog"],
        "severity": "high",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098.004",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "command", "op": "=~", "value": "(?i).*authorized_keys.*"},
        ],
    },
    {
        "external_id": "detfyi-linux-execution-from-tmp-shm",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/linux/process_creation/proc_creation_lnx_execution_from_tmp/",
        "original_title": "Linux Binary Execution from World-Writable /tmp or /dev/shm",
        "description": (
            "Identifica execução de binários ou scripts diretamente a partir de diretórios "
            "temporários (/tmp, /var/tmp, /dev/shm), comportamento comum de droppers e cryptominers."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "// Source: https://detection.fyi/\n"
            "LinuxAuditD\n"
            "| where command matches regex '^(/tmp/|/dev/shm/|/var/tmp/)'"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "high",
        "mitre_tactic": "execution",
        "mitre_technique": "T1204.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "command", "op": "=~", "value": "(?i).*(\\/tmp\\/|\\/dev\\/shm\\/|\\/var\\/tmp\\/).*"},
        ],
    },
    {
        "external_id": "detfyi-akamai-waf-path-traversal-lfi",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/web/web_path_traversal_lfi_blocked/",
        "original_title": "Akamai WAF Local File Inclusion and Path Traversal Attempt",
        "description": (
            "Detecta sequências de travessia de diretório (../, ..%2f, /etc/shadow, win.ini) "
            "bloqueadas ou alertadas no WAF Akamai."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "title: Akamai WAF Local File Inclusion and Path Traversal Attempt\n"
            "logsource:\n"
            "  product: akamai\n"
            "detection:\n"
            "  selection:\n"
            "    uri|re: '(?i).*([.][.]/|[.][.]%2f|/etc/shadow|win[.]ini).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "uri", "op": "=~", "value": "(?i).*([.][.]%2f|/etc/shadow|win[.]ini).*"},
        ],
    },
    {
        "external_id": "detfyi-akamai-waf-ssrf-metadata-probe",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/web/web_ssrf_cloud_metadata_probe/",
        "original_title": "Akamai WAF Cloud Metadata Service SSRF Probe",
        "description": (
            "Detecta tentativas de Server-Side Request Forgery (SSRF) visando o endpoint de "
            "metadados de nuvem (169.254.169.254 / latest/meta-data) no WAF Akamai."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "title: Akamai WAF Cloud Metadata Service SSRF Probe\n"
            "logsource:\n"
            "  product: akamai\n"
            "detection:\n"
            "  selection:\n"
            "    uri|re: '(?i).*(169[.]254[.]169[.]254|latest/meta-data).*'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "critical",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1552.005",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "uri", "op": "=~", "value": "(?i).*(169[.]254[.]169[.]254|meta-data).*"},
        ],
    },
    {
        "external_id": "detfyi-win-security-logon-failure-4625",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_failed_logons/",
        "original_title": "Multiple Failed Windows Logon Attempts (Event 4625)",
        "description": (
            "Monitora eventos de falha de autenticação (EventID 4625) em controladores de domínio e "
            "servidores Windows corporativos, cobrindo senhas incorretas, contas inexistentes ou ataques de força bruta."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "SecurityEvent\n"
            "| where EventID == 4625\n"
            "| summarize count() by TargetUserName, IpAddress, bin(TimeGenerated, 5m)"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4625"},
        ],
    },
    {
        "external_id": "detfyi-win-security-explicit-credential-logon-4648",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/windows/builtin/security/win_security_explicit_logon/",
        "original_title": "Logon Attempted Using Explicit Credentials (Event 4648)",
        "description": (
            "Detecta tentativas de autenticação utilizando credenciais explícitas fornecidas diretamente "
            "(EventID 4648), típico de comandos 'runas', sessões de rede remotas ou movimentação lateral."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "SecurityEvent\n"
            "| where EventID == 4648\n"
            "| summarize count() by TargetUserName, SubjectUserName, bin(TimeGenerated, 5m)"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "lateral-movement",
        "mitre_technique": "T1078",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4648"},
        ],
    },
    {
        "external_id": "detfyi-fortigate-admin-ports-traffic-blocked",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/sigmahq/sigma/network/fortinet/fortigate_admin_ports/",
        "original_title": "FortiGate Inbound Traffic Blocked on Administrative Ports",
        "description": (
            "Identifica tentativas de tráfego de entrada em portas administrativas críticas "
            "(SSH 22, Telnet 23, RDP 3389, portas HTTPS de gerência 8443 e 10443) bloqueadas pelo firewall."
        ),
        "original_format": "Sigma / KQL",
        "original_syntax": (
            "CommonSecurityLog\n"
            "| where DeviceVendor =~ 'Fortinet' and DeviceAction in~ ('deny', 'drop', 'block', 'close')\n"
            "| where DestinationPort in (22, 23, 3389, 8443, 10443)"
        ),
        "datasource_hints": ["fortigate", "fortinet", "firewall"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=~", "value": "(?i)deny|drop|block|close"},
            {"field": "dstport", "op": "=~", "value": "22|23|3389|8443|10443"},
        ],
    },

    # --- 3. Splunk Security Research (https://research.splunk.com/detections/)
    {
        "external_id": "splunk-win-rdp-network-bruteforce-4625-t1021",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/windows_rdp_network_brute_force/",
        "original_title": "Windows Remote Desktop Network Logon Brute Force (EventCode 4625)",
        "description": (
            "Detecta falhas repetidas de autenticação de rede ou Remote Interactive (LogonType 3 ou 10) "
            "no Windows (EventID 4625), indicando movimentação lateral ou força bruta SMB/RDP."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=4625 LogonType IN (3, 10)\n"
            "| stats count min(_time) as firstTime max(_time) as lastTime by IpAddress, TargetUserName\n"
            "| where count > 5"
        ),
        "datasource_hints": ["windows", "ad_windows", "wineventlog_security"],
        "severity": "high",
        "mitre_tactic": "lateral-movement",
        "mitre_technique": "T1021.001",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventCode", "op": "=", "value": "4625"},
            {"field": "LogonType", "op": "=~", "value": "3|10"},
        ],
    },
    {
        "external_id": "splunk-win-asrep-roasting-preauth-disabled-4738",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/kerberos_pre_authentication_disabled_user/",
        "original_title": "Kerberos Pre-Authentication Disabled for User Account (EventCode 4738)",
        "description": (
            "Detecta modificação de conta no Active Directory (EventID 4738) que desabilita "
            "a pré-autenticação Kerberos (DONT_REQ_PREAUTH), expondo a conta a AS-REP Roasting."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=4738\n"
            "| stats count by TargetUserName, SubjectUserName"
        ),
        "datasource_hints": ["windows", "ad_windows", "wineventlog_security"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1558.004",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventCode", "op": "=", "value": "4738"},
        ],
    },
    {
        "external_id": "splunk-win-smb-admin-share-access-5140",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/windows_administrative_smb_share_access/",
        "original_title": "Windows Administrative SMB Share Access ADMIN$ or C$ (EventCode 5140)",
        "description": (
            "Detecta acesso de rede a compartilhamentos administrativos padrão (ADMIN$, C$, IPC$) "
            "via EventID 5140, frequentemente associado a movimentação lateral."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=5140 ShareName IN (\"*ADMIN$*\", \"*C$*\")\n"
            "| stats count by IpAddress, SubjectUserName, ShareName"
        ),
        "datasource_hints": ["windows", "ad_windows", "wineventlog_security"],
        "severity": "high",
        "mitre_tactic": "lateral-movement",
        "mitre_technique": "T1021.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventCode", "op": "=", "value": "5140"},
            {"field": "ShareName", "op": "=~", "value": "(?i).*(ADMIN|C).*"},
        ],
    },
    {
        "external_id": "splunk-win-special-privileges-new-logon-4672",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/windows_special_privileges_assigned_logon/",
        "original_title": "Windows Special Privileges Assigned to New Logon (EventCode 4672)",
        "description": (
            "Monitora atribuição de privilégios equivalentes a administrador (SeDebugPrivilege, "
            "SeTcbPrivilege, SeTakeOwnershipPrivilege) em novos logons (EventID 4672)."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=4672 PrivilegeList=\"*SeDebugPrivilege*\"\n"
            "| stats count by SubjectUserName"
        ),
        "datasource_hints": ["windows", "ad_windows", "wineventlog_security"],
        "severity": "medium",
        "mitre_tactic": "privilege-escalation",
        "mitre_technique": "T1078",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventCode", "op": "=", "value": "4672"},
            {"field": "PrivilegeList", "op": "=~", "value": "(?i).*SeDebugPrivilege.*"},
        ],
    },
    {
        "external_id": "splunk-win-account-password-reset-4724",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/windows_user_account_password_reset/",
        "original_title": "Windows User Account Password Reset Attempt (EventCode 4724)",
        "description": (
            "Detecta tentativas de redefinição forçada de senha de conta de usuário (EventID 4724) "
            "no Active Directory para sequestro de conta (Account Manipulation)."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=4724\n"
            "| stats count by SubjectUserName, TargetUserName"
        ),
        "datasource_hints": ["windows", "ad_windows", "wineventlog_security"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventCode", "op": "=", "value": "4724"},
        ],
    },
    {
        "external_id": "splunk-win-wmi-remote-process-creation",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/wmi_provider_host_spawning_suspicious_process/",
        "original_title": "WMI Provider Host Spawning Suspicious Child Process",
        "description": (
            "Detecta o processo WmiPrvSE.exe gerando interpretadores de comando (cmd.exe, "
            "powershell.exe), indicador clássico de execução remota via WMI."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "| tstats count from datamodel=Endpoint.Processes where "
            "Processes.parent_process_name=\"wmiprvse.exe\" Processes.process_name IN (\"cmd.exe\",\"powershell.exe\")"
        ),
        "datasource_hints": ["windows", "ad_windows", "sysmon"],
        "severity": "high",
        "mitre_tactic": "execution",
        "mitre_technique": "T1047",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "ParentImage", "op": "=~", "value": "(?i).*wmiprvse[.]exe"},
            {"field": "Image", "op": "=~", "value": "(?i).*(cmd|powershell)[.]exe"},
        ],
    },
    {
        "external_id": "splunk-o365-privileged-role-assigned-t1098-003",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/cloud/o365_privileged_role_assigned/",
        "original_title": "O365 Privileged Directory Role Assigned to User",
        "description": (
            "Detecta a adição de um usuário a uma função administrativa privilegiada no Microsoft Entra ID "
            "/ Office 365 (Add member to role), permitindo persistência administrativa no tenant cloud."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`o365_management_activity` Workload=AzureActiveDirectory\n"
            "Operation=\"Add member to role.\" ResultStatus=\"Success\"\n"
            "| stats count by UserId, ClientIP, Operation"
        ),
        "datasource_hints": ["office365", "o365", "azuread"],
        "severity": "critical",
        "mitre_tactic": "privilege-escalation",
        "mitre_technique": "T1098.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Operation", "op": "=~", "value": "Add member to role.*"},
            {"field": "ResultStatus", "op": "=~", "value": "Success|Succeeded"},
        ],
    },
    {
        "external_id": "splunk-o365-federation-trust-modified",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/cloud/o365_azure_ad_domain_federation_modified/",
        "original_title": "Office 365 Azure AD Domain Federation Settings Modified",
        "description": (
            "Detecta modificação de configuração de federação de domínio no Entra ID (Set-MsolDomainFederationSettings / "
            "Set federation settings on domain), técnica Golden SAML para forjar tokens de autenticação."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`o365_management_activity` Workload=AzureActiveDirectory\n"
            "Operation IN (\"Set federation settings on domain.\", \"Set domain authentication.\")"
        ),
        "datasource_hints": ["office365", "o365", "azuread"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1484.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Workload", "op": "=", "value": "AzureActiveDirectory"},
            {"field": "Operation", "op": "=~", "value": "Set federation settings.*|Set domain authentication.*"},
        ],
    },
    {
        "external_id": "splunk-o365-conditional-access-policy-disabled",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/cloud/entra_id_conditional_access_policy_disabled/",
        "original_title": "Entra ID Conditional Access Policy Modified or Deleted",
        "description": (
            "Identifica alteração ou remoção de políticas de Acesso Condicional no Entra ID / "
            "Office 365 para enfraquecer exigências de MFA e conformidade de dispositivo."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`o365_management_activity` Workload=AzureActiveDirectory\n"
            "Operation IN (\"Update conditional access policy.\", \"Delete conditional access policy.\")"
        ),
        "datasource_hints": ["office365", "o365", "azuread"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1556",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Operation", "op": "=~", "value": "(Update|Delete) conditional access policy.*"},
        ],
    },
    {
        "external_id": "splunk-fortigate-admin-login-bruteforce",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/network/fortigate_admin_login_brute_force/",
        "original_title": "FortiGate Administrative Interface Login Brute Force",
        "description": (
            "Detecta falhas sucessivas de login administrativo (SSH/HTTPS) na gerência do "
            "appliance FortiGate."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "sourcetype=fgt_event subtype=system action=login status=failed\n"
            "| stats count by srcip, user | where count > 5"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=", "value": "system"},
            {"field": "action", "op": "=~", "value": "login.*"},
        ],
    },
    {
        "external_id": "splunk-fortigate-ips-critical-exploit-blocked",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/network/fortigate_ips_critical_exploit_blocked/",
        "original_title": "FortiGate IPS Critical Remote Exploit Signature Triggered",
        "description": (
            "Detecta acionamento de assinatura de prevenção de intrusão (IPS subtype=ips) "
            "de severidade crítica no firewall FortiGate."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "sourcetype=fgt_utm subtype=ips level=critical\n"
            "| stats count by srcip, dstip, attack"
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "critical",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=", "value": "ips"},
            {"field": "action", "op": "=~", "value": "dropped|blocked|deny"},
        ],
    },
    {
        "external_id": "splunk-linux-pam-su-root-bruteforce",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/linux_pam_su_privilege_escalation_failure/",
        "original_title": "Linux PAM Su Privilege Escalation Authentication Failure",
        "description": (
            "Detecta falhas repetidas no módulo PAM ao tentar trocar para a conta root via comando "
            "su em servidores Linux."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "index=os sourcetype=linux_secure pam_status=failed dstuser=root\n"
            "| stats count by srcuser | where count > 3"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "high",
        "mitre_tactic": "privilege-escalation",
        "mitre_technique": "T1548.003",
        "threshold_operator": "gt",
        "threshold_value": 3,
        "for_duration": "0s",
        "predicates": [
            {"field": "pam_status", "op": "=", "value": "failed"},
            {"field": "dstuser", "op": "=", "value": "root"},
        ],
    },
    {
        "external_id": "splunk-linux-systemd-persistence-unit",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/linux_systemd_service_unit_created/",
        "original_title": "Linux Systemd Service Unit Created or Reloaded via Command",
        "description": (
            "Identifica comandos systemctl enable / daemon-reload ou gravação em /etc/systemd/system "
            "para persistência de serviços maliciosos no Linux."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "index=os sourcetype=linux_audit command IN (\"*systemctl enable*\", \"*/etc/systemd/system/*\")"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1543.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "command", "op": "=~", "value": "(?i).*(systemctl enable|/etc/systemd/system).*"},
        ],
    },
    {
        "external_id": "splunk-akamai-waf-xss-payload-blocked",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/web/waf_cross_site_scripting_payload_blocked/",
        "original_title": "Akamai WAF Cross-Site Scripting (XSS) Payload Blocked",
        "description": (
            "Detecta tentativas de injeção de scripts maliciosos (<script>, javascript:, onerror=) "
            "bloqueadas na camada de borda pelo WAF Akamai."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "sourcetype=akamai:siem action=deny uri IN (\"*<script*\", \"*javascript:*\", \"*onerror=*\")"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "medium",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1189",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "action", "op": "=", "value": "deny"},
            {"field": "uri", "op": "=~", "value": "(?i).*(<script|javascript:|onerror=).*"},
        ],
    },
    {
        "external_id": "splunk-akamai-waf-log4shell-jndi-injection",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/web/waf_log4j_jndi_lookup_exploitation_attempt/",
        "original_title": "Akamai WAF Log4j JNDI Lookup Exploitation Attempt",
        "description": (
            "Detecta strings de exploração Log4Shell (${jndi:ldap://, ${jndi:rmi://) "
            "em requisições inspecionadas pelo WAF Akamai."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "sourcetype=akamai:siem uri=\"*jndi:*\"\n"
            "| stats count by srcip, uri, action"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "critical",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "uri", "op": "=~", "value": "(?i).*jndi:(ldap|rmi|dns).*"},
        ],
    },
    {
        "external_id": "splunk-win-security-user-account-created-4720",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/windows_user_account_created/",
        "original_title": "Windows User Account Created (Event 4720)",
        "description": (
            "Detecta a criação de novas contas de usuário (EventID 4720) no Active Directory ou em "
            "servidores locais, monitorando tentativas de persistência ou provisionamento não planejado."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=4720 "
            "| stats count min(_time) as firstTime max(_time) as lastTime by TargetUserName, SubjectUserName"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1136.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4720"},
        ],
    },
    {
        "external_id": "splunk-win-security-special-privileges-logon-4672",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/windows_special_privileges_assigned_logon/",
        "original_title": "Special Privileges Assigned to New Logon (Event 4672)",
        "description": (
            "Detecta logons bem-sucedidos em controladores de domínio e servidores Windows onde privilégios "
            "administrativos de alto impacto foram atribuídos à nova sessão (SeDebugPrivilege, SeSecurityPrivilege)."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`wineventlog_security` EventCode=4672 "
            "| stats count by SubjectUserName, ComputerName"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "privilege-escalation",
        "mitre_technique": "T1078.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4672"},
        ],
    },
    {
        "external_id": "splunk-fortigate-admin-login-failure",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/network/fortigate_admin_login_failure/",
        "original_title": "FortiGate Administrator Login Failed or Authentication Error",
        "description": (
            "Detecta tentativas falhadas de autenticação de administradores na interface de gerência do FortiOS, "
            "alertando contra tentativas de acesso não autorizado à infraestrutura central do firewall."
        ),
        "original_format": "Splunk SPL",
        "original_syntax": (
            "`fortigate` subtype=system (action=failed OR action=login-failed OR action=deny) "
            "| stats count by user, srcip"
        ),
        "datasource_hints": ["fortigate", "fortinet", "firewall"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=~", "value": "(?i)system|auth|admin"},
            {"field": "action", "op": "=~", "value": "(?i)failed|failure|deny|login-failed"},
        ],
    },

    # --- 4. Elastic Detection Rules (https://elastic.github.io/detection-rules-explorer/)
    {
        "external_id": "elastic-win-scheduled-task-persistence-4698",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_scheduled_task_creation.toml",
        "original_title": "Windows Scheduled Task Created via Security Event (4698)",
        "description": (
            "Identifica a criação de novas tarefas agendadas no Windows através do evento de "
            "segurança 4698, mecanismo recorrente para execução persistente ou remota."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "event.category : \"iam\" or event.code : \"4698\"\n"
            "and winlog.channel : \"Security\"\n"
            "and winlog.event_data.TaskName : *"
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1053.005",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "event.code", "op": "=", "value": "4698"},
        ],
    },
    {
        "external_id": "elastic-sysmon-powershell-encoded-command-t1059-001",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_powershell_encoded_command.toml",
        "original_title": "Suspicious PowerShell Execution with EncodedCommand",
        "description": (
            "Detecta a execução do interpretador PowerShell utilizando parâmetros de codificação "
            "Base64 (-enc / -EncodedCommand) capturados pelo Sysmon / Windows EventChannel (EventID 1)."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "process where host.os.type == \"windows\" and event.code == \"1\"\n"
            "and process.executable : \"*powershell.exe\"\n"
            "and process.command_line : (\"*-enc*\", \"*-EncodedCommand*\")"
        ),
        "datasource_hints": ["sysmon", "ad_windows"],
        "severity": "high",
        "mitre_tactic": "execution",
        "mitre_technique": "T1059.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "event.code", "op": "=", "value": "1"},
            {"field": "process.command_line", "op": "=~", "value": "(?i).*(-enc|-EncodedCommand).*"},
        ],
    },
    {
        "external_id": "elastic-win-new-local-user-account-4720",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_local_scheduled_user_creation.toml",
        "original_title": "Windows New User Account Created (Event 4720)",
        "description": (
            "Detecta a criação de uma nova conta de usuário local ou de domínio no Windows "
            "(EventID 4720) para manutenção de acesso persistente."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "iam where host.os.type == \"windows\" and event.code == \"4720\""
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1136.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "event.code", "op": "=", "value": "4720"},
        ],
    },
    {
        "external_id": "elastic-win-regsvr32-remote-scriptlet-exec",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_regsvr32_remote_scriptlet.toml",
        "original_title": "Signed Binary Proxy Execution via Regsvr32 Scrobj",
        "description": (
            "Detecta abuso de regsvr32.exe com scrobj.dll e URLs HTTP/HTTPS (técnica Squiblydoo) "
            "para contornar controle de aplicação (AppLocker)."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "process where host.os.type == \"windows\" and process.executable : \"*regsvr32.exe\"\n"
            "and process.command_line : (\"*scrobj.dll*\", \"*http:*\", \"*https:*\")"
        ),
        "datasource_hints": ["windows", "ad_windows", "sysmon"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1218.010",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "process.command_line", "op": "=~", "value": "(?i).*regsvr32.*(scrobj|http).*"},
        ],
    },
    {
        "external_id": "elastic-win-rundll32-suspicious-invocation",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_suspicious_rundll32_execution.toml",
        "original_title": "Suspicious Rundll32 Execution from Unusual Directory",
        "description": (
            "Identifica execuções de rundll32.exe carregando DLLs de diretórios temporários "
            "(AppData, Temp, ProgramData) ou via javascript/mshtml."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "process where host.os.type == \"windows\" and process.executable : \"*rundll32.exe\"\n"
            "and process.command_line : (\"*AppData*\", \"*ProgramData*\", \"*mshtml*\")"
        ),
        "datasource_hints": ["windows", "ad_windows", "sysmon"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1218.011",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "process.command_line", "op": "=~", "value": "(?i).*rundll32.*(AppData|ProgramData|mshtml).*"},
        ],
    },
    {
        "external_id": "elastic-win-eventlog-service-stopped-1100",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_eventlog_service_stopped.toml",
        "original_title": "Windows Event Log Service Shutdown (Event 1100)",
        "description": (
            "Detecta encerramento do serviço de registro de eventos do Windows (EventID 1100), "
            "podendo indicar tentativa de interromper coleta de telemetria de segurança."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "event.code : \"1100\" and winlog.channel : \"Security\""
        ),
        "datasource_hints": ["windows", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1562.002",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "event.code", "op": "=", "value": "1100"},
        ],
    },
    {
        "external_id": "elastic-linux-sshd-invalid-user-bruteforce-t1110",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/linux/credential_access_sshd_invalid_user_bruteforce.toml",
        "original_title": "Linux SSHD Brute Force Against Non-Existent Users (Rule 5710)",
        "description": (
            "Identifica múltiplas falhas de autenticação PAM no daemon SSHD (regra Wazuh 5710) "
            "utilizando nomes de usuários inválidos ou enumeração de contas em servidores Linux."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "authentication where host.os.type == \"linux\" and rule.id == \"5710\"\n"
            "and pam_status == \"failed\" and source.ip : *"
        ),
        "datasource_hints": ["linux", "sshd", "syslog"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110.001",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "rule.id", "op": "=", "value": "5710"},
            {"field": "pam_status", "op": "=", "value": "failed"},
        ],
    },
    {
        "external_id": "elastic-linux-kernel-module-load-insmod",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_kernel_module_load_insmod.toml",
        "original_title": "Linux Kernel Module Loaded via Insmod or Modprobe",
        "description": (
            "Detecta carregamento dinâmico de módulos de kernel Linux via insmod ou modprobe, "
            "técnica empregada por rootkits LKM para ocultação de processos."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "process where host.os.type == \"linux\" and process.command_line : (\"*insmod*\", \"*modprobe*\")"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1547.006",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "process.command_line", "op": "=~", "value": "(?i).*(insmod|modprobe).*"},
        ],
    },
    {
        "external_id": "elastic-linux-crontab-persistence-modification",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_crontab_file_modified.toml",
        "original_title": "Linux Suspicious Crontab Enumeration or Modification",
        "description": (
            "Identifica alterações em arquivos /etc/crontab, /var/spool/cron ou execução de "
            "crontab -e para agendamento persistente de tarefas em hosts Linux."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "process where host.os.type == \"linux\" and process.command_line : (\"*crontab*\", \"*/etc/cron*\")"
        ),
        "datasource_hints": ["linux", "syslog"],
        "severity": "medium",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1053.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "process.command_line", "op": "=~", "value": "(?i).*(crontab|/etc/cron).*"},
        ],
    },
    {
        "external_id": "elastic-o365-dlp-policy-sensitive-match",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/integrations/m365/dlp_policy_sensitive_rule_match.toml",
        "original_title": "Microsoft 365 DLP Policy Match on Sensitive Information",
        "description": (
            "Detecta acionamento de regras de Data Loss Prevention (DLP) no Microsoft 365 "
            "(RuleMatch) indicando compartilhamento ou envio externo de dados sensíveis."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "event.dataset : \"o365.audit\" and event.action : \"RuleMatch\""
        ),
        "datasource_hints": ["office365", "m365"],
        "severity": "high",
        "mitre_tactic": "exfiltration",
        "mitre_technique": "T1048",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "event.action", "op": "=", "value": "RuleMatch"},
        ],
    },
    {
        "external_id": "elastic-o365-anonymous-sharing-link-created",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/integrations/m365/anonymous_sharing_link_created.toml",
        "original_title": "SharePoint Anonymous Link Created for Corporate Document",
        "description": (
            "Detecta geração de links de compartilhamento anônimo (AnonymousLinkCreated) "
            "no SharePoint Online / OneDrive, expondo documentos internos sem autenticação."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "event.dataset : \"o365.audit\" and event.action : \"AnonymousLinkCreated\""
        ),
        "datasource_hints": ["office365", "m365"],
        "severity": "medium",
        "mitre_tactic": "exfiltration",
        "mitre_technique": "T1567",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "event.action", "op": "=", "value": "AnonymousLinkCreated"},
        ],
    },
    {
        "external_id": "elastic-fortigate-ipsec-vpn-negotiation-failure",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/network/fortinet_ipsec_vpn_negotiation_failure.toml",
        "original_title": "FortiGate IPSec VPN Phase-1 Negotiation Failure Spike",
        "description": (
            "Detecta múltiplas falhas de negociação IKE/IPSec Phase-1 no FortiGate, "
            "indicando tentativa de enumeração de peers VPN ou ataque a chave pré-compartilhada."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "event.dataset : \"fortinet.firewall\" and subtype : \"vpn\" and event.action : \"negotiate\""
        ),
        "datasource_hints": ["fortigate", "fortinet"],
        "severity": "medium",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1133",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=", "value": "vpn"},
            {"field": "event.action", "op": "=", "value": "negotiate"},
        ],
    },
    {
        "external_id": "elastic-akamai-waf-credential-stuffing-login",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/web/akamai_waf_high_rate_credential_stuffing.toml",
        "original_title": "Akamai WAF High Rate POST Credential Stuffing on Auth URI",
        "description": (
            "Detecta rajadas de requisições POST bloqueadas em endpoints de autenticação (/login, "
            "/auth, /oauth/token) no WAF Akamai características de Credential Stuffing."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "http.request.method : \"POST\" and event.action : \"deny\" and url.path : (\"*/login*\", \"*/auth*\")"
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110.004",
        "threshold_operator": "gt",
        "threshold_value": 10,
        "for_duration": "0s",
        "predicates": [
            {"field": "http.request.method", "op": "=", "value": "POST"},
            {"field": "event.action", "op": "=", "value": "deny"},
            {"field": "url.path", "op": "=~", "value": "(?i).*(/login|/auth|/token).*"},
        ],
    },
    {
        "external_id": "elastic-akamai-waf-graphql-introspection-probe",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/web/akamai_waf_graphql_introspection_probe.toml",
        "original_title": "Akamai WAF GraphQL Introspection and Schema Enumeration",
        "description": (
            "Detecta consultas de introspecção GraphQL (__schema, __type) interceptadas "
            "pelo WAF Akamai visant mapear endpoints e objetos internos da API."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "url.path : \"*/graphql*\" and event.action : \"deny\""
        ),
        "datasource_hints": ["waf_akamai", "akamai"],
        "severity": "medium",
        "mitre_tactic": "discovery",
        "mitre_technique": "T1590",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "url.path", "op": "=~", "value": "(?i).*(/graphql|__schema).*"},
            {"field": "event.action", "op": "=", "value": "deny"},
        ],
    },
    {
        "external_id": "elastic-win-security-user-account-deleted-4726",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_user_account_deleted.toml",
        "original_title": "Windows User Account Deleted (Event 4726)",
        "description": (
            "Identifica a exclusão de contas de usuário (EventID 4726) no Active Directory, técnica empregada "
            "em sabotagem interna ou por adversários para eliminar vestígios de contas de teste pós-invasão."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "iam where event.action == \"user-account-deleted\" and winlog.event_id == 4726"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "medium",
        "mitre_tactic": "impact",
        "mitre_technique": "T1531",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4726"},
        ],
    },
    {
        "external_id": "elastic-win-security-group-member-added",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_group_member_added.toml",
        "original_title": "Member Added to Security-Enabled Group (Event 4728 / 4732 / 4756)",
        "description": (
            "Detecta a inclusão de membros em grupos de segurança no Active Directory (EventID 4728, 4732 ou 4756), "
            "técnica essencial de concessão de acessos privilegiados para operadores e atacantes."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "iam where winlog.event_id in (4728, 4732, 4756)"
        ),
        "datasource_hints": ["windows", "active_directory", "ad_windows", "security"],
        "severity": "high",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=~", "value": "4728|4732|4756"},
        ],
    },
    {
        "external_id": "elastic-fortigate-utm-security-signature-blocked",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/network/fortinet_utm_security_signature_blocked.toml",
        "original_title": "FortiGate UTM Security Signature Triggered (IPS / Antivirus)",
        "description": (
            "Detecta alertas e bloqueios dos motores de segurança unificada UTM (IPS, Antivírus, App-Control "
            "ou WebFilter) no FortiGate, indicando ataques e explorações barrados no perímetro de rede."
        ),
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "network where event.dataset == \"fortinet.firewall\" and "
            "subtype in (\"ips\", \"virus\", \"app-ctrl\", \"webfilter\") and "
            "event.action in (\"deny\", \"drop\", \"block\", \"blocked\", \"dropped\", \"close\")"
        ),
        "datasource_hints": ["fortigate", "fortinet", "firewall"],
        "severity": "critical",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "subtype", "op": "=~", "value": "(?i)ips|virus|app-ctrl|webfilter"},
            {"field": "action", "op": "=~", "value": "(?i)deny|drop|block|blocked|dropped|close"},
        ],
    },

    # --- 5. Candidatas que devem ser classificadas como MÁS CANDIDATAS (Regra 2)
    # 5.1. Incompatível por tecnologia inexistente no catálogo D.A.N.T.E. (Passo 2.1)
    {
        "external_id": "sigma-aws-cloudtrail-root-access-key-created",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/aws_cloudtrail_root_access_key_created.yml",
        "original_title": "AWS IAM Root Access Key Created",
        "description": "Detecta criação de Access Key para o usuário root na AWS CloudTrail.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: AWS IAM Root Access Key Created\n"
            "logsource:\n"
            "  product: aws\n"
            "  service: cloudtrail\n"
            "detection:\n"
            "  selection:\n"
            "    eventName: 'CreateAccessKey'\n"
            "  condition: selection"
        ),
        "datasource_hints": ["aws_cloudtrail", "aws"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "eventName", "op": "=", "value": "CreateAccessKey"},
        ],
    },
    # 5.2. Incompatível por tecnologia Okta inexistente no catálogo D.A.N.T.E. (Passo 2.1)
    {
        "external_id": "splunk-okta-mfa-policy-bypass",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/cloud/okta_mfa_policy_disabled_or_modified/",
        "original_title": "Okta MFA Policy Disabled or Modified",
        "description": "Detecta desativação de políticas de MFA nos logs de sistema do Okta.",
        "original_format": "Splunk SPL",
        "original_syntax": "`okta` eventType=\"policy.lifecycle.deactivate\"",
        "datasource_hints": ["okta", "okta_im2"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1556",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "eventType", "op": "=", "value": "policy.lifecycle.deactivate"},
        ],
    },
    # 5.3. Passa no Passo 2.1 (Windows), mas REPROVA no Passo 2.3 por incompatibilidade de
    #      campos proprietários de EDR inexistentes no Wazuh/Loki dos clientes -> Má Candidata!
    {
        "external_id": "elastic-win-proprietary-edr-kernel-call-tree",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_kernel_call_tree_anomaly.toml",
        "original_title": "Proprietary EDR Kernel Call Tree Hash Anomaly",
        "description": "Regra dependente de telemetria proprietária de kernel inexistente no pipeline Wazuh/Loki.",
        "original_format": "Elastic EQL / KQL",
        "original_syntax": (
            "event.dataset : \"edr.proprietary\" and "
            "crowdstrike.falcon_tree_id : * and tanium.kernel_call_hash : *"
        ),
        "datasource_hints": ["windows", "ad_windows"],
        "severity": "medium",
        "mitre_tactic": "execution",
        "mitre_technique": "T1204",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "crowdstrike.falcon_tree_id", "op": "=~", "value": ".+"},
            {"field": "tanium.kernel_call_hash", "op": "=~", "value": ".+"},
            {"field": "carbonblack.process_guid_raw", "op": "=~", "value": ".+"},
        ],
    },

    # =========================================================================
    # REGRAS ORIENTADAS A PERÍMETRO (FIREWALL, WAF/WEB, ANTIMALWARE/EDR, CLOUD)
    # =========================================================================
    # --- Perímetro: Firewall (Palo Alto, Check Point, pfSense, Fortigate, etc.)
    {
        "external_id": "sigma-fw-paloalto-c2-beaconing",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_c2_beaconing.yml",
        "original_title": "Firewall Outbound C2 Beaconing Communication",
        "description": "Detecta conexões de saída em portas não-padrão ou tráfego repetitivo associado a canais de Command & Control (C2) no perímetro de Firewall.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Firewall Outbound C2 Beaconing Communication\n"
            "logsource:\n"
            "  category: firewall\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'allow'\n"
            "    destination.port: '8443'\n"
            "  condition: selection\n"
            "level: high"
        ),
        "perimeter": "firewall",
        "datasource_hints": ["paloalto", "firewall", "fortigate", "fortinet", "panos"],
        "severity": "high",
        "mitre_tactic": "command-and-control",
        "mitre_technique": "T1071.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_action", "op": "=", "value": "allow"},
            {"field": "data_dstport", "op": "=", "value": "8443"},
        ],
    },
    {
        "external_id": "sigma-fw-checkpoint-portscan-drop",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_portscan_drop.yml",
        "original_title": "Firewall Multiple Port Scan Drops from External Source",
        "description": "Detecta rajada de pacotes bloqueados no Firewall originados do mesmo endereço IP externo contra múltiplas portas da borda.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Firewall Multiple Port Scan Drops from External Source\n"
            "logsource:\n"
            "  category: firewall\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'deny'\n"
            "    subtype: 'packet_drop'\n"
            "  condition: selection\n"
            "level: medium"
        ),
        "perimeter": "firewall",
        "datasource_hints": ["checkpoint", "firewall", "fortigate", "fortinet", "pfsense"],
        "severity": "medium",
        "mitre_tactic": "reconnaissance",
        "mitre_technique": "T1046",
        "threshold_operator": "gt",
        "threshold_value": 5,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_action", "op": "=", "value": "deny"},
            {"field": "data_subtype", "op": "=", "value": "packet_drop"},
        ],
    },
    {
        "external_id": "sigma-fw-inbound-rdp-smb-wan",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/network/net_firewall_inbound_sensitive_ports.yml",
        "original_title": "Firewall Blocked Inbound Access to Sensitive Ports (RDP/SMB)",
        "description": "Identifica tentativas externas bloqueadas de conexão direta da Internet contra portas críticas como RDP (3389) ou SMB (445).",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Firewall Blocked Inbound Access to Sensitive Ports (RDP/SMB)\n"
            "logsource:\n"
            "  category: firewall\n"
            "detection:\n"
            "  selection:\n"
            "    dstport:\n"
            "      - '3389'\n"
            "      - '445'\n"
            "    action: 'deny'\n"
            "  condition: selection\n"
            "level: high"
        ),
        "perimeter": "firewall",
        "datasource_hints": ["firewall", "fortigate", "paloalto", "pfsense", "opnsense"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_action", "op": "=", "value": "deny"},
            {"field": "data_dstport", "op": "=~", "value": "3389|445"},
        ],
    },
    {
        "external_id": "splunk-fw-tor-exit-node-connection",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/network/firewall_communication_with_tor_exit_node/",
        "original_title": "Firewall Communication with Known Tor Exit Node",
        "description": "Detecta tráfego de rede ou sessões estabelecidas com nós de saída da rede Tor através dos logs de borda do Firewall.",
        "original_format": "Splunk SPL",
        "original_syntax": "`firewall` action=allowed subtype=tor_connection",
        "perimeter": "firewall",
        "datasource_hints": ["firewall", "fortigate", "cisco_asa", "fortinet"],
        "severity": "high",
        "mitre_tactic": "command-and-control",
        "mitre_technique": "T1090.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_action", "op": "=", "value": "allowed"},
            {"field": "data_subtype", "op": "=", "value": "tor_connection"},
        ],
    },
    {
        "external_id": "elastic-fw-ssl-vpn-bruteforce",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/network/firewall_ssl_vpn_bruteforce_failure.toml",
        "original_title": "Firewall Multiple Failed SSL VPN Logins",
        "description": "Detecta múltiplos acessos de autenticação VPN rejeitados seguidos por tentativa de login no portal de acesso remoto do Firewall.",
        "original_format": "Elastic EQL / KQL",
        "original_syntax": "event.category: \"authentication\" and firewall.action: \"deny\" and firewall.subtype: \"sslvpn_login\"",
        "perimeter": "firewall",
        "datasource_hints": ["firewall", "fortigate", "fortinet", "sslvpn", "paloalto"],
        "severity": "medium",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110.001",
        "threshold_operator": "gt",
        "threshold_value": 3,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_action", "op": "=", "value": "deny"},
            {"field": "data_subtype", "op": "=", "value": "sslvpn_login"},
        ],
    },
    # --- Perímetro: WAF / Web (Akamai, Cloudflare, AWS WAF, ModSecurity, etc.)
    {
        "external_id": "sigma-waf-sqli-union-select",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_waf_sqli_union_select.yml",
        "original_title": "WAF SQL Injection Pattern Detected in HTTP Request",
        "description": "Detecta vetores clássicos de SQL Injection contendo palavras-chave como UNION SELECT ou OR 1=1 na URI ou corpo da requisição web.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: WAF SQL Injection Pattern Detected in HTTP Request\n"
            "logsource:\n"
            "  category: web\n"
            "detection:\n"
            "  selection:\n"
            "    uri|contains: 'union select'\n"
            "  condition: selection\n"
            "level: critical"
        ),
        "perimeter": "waf_web",
        "datasource_hints": ["waf", "web", "waf_akamai", "cloudflare", "awswaf"],
        "severity": "critical",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_uri", "op": "=~", "value": "(?i).*union.*select.*"},
            {"field": "data_action", "op": "=", "value": "block"},
        ],
    },
    {
        "external_id": "sigma-waf-xss-script-injection",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/web/web_waf_xss_script_injection.yml",
        "original_title": "WAF Cross-Site Scripting (XSS) Attack Blocked",
        "description": "Identifica tentativas de injeção de scripts maliciosos (XSS) com tags <script> ou handlers javascript: bloqueadas pelo Web Application Firewall.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: WAF Cross-Site Scripting (XSS) Attack Blocked\n"
            "logsource:\n"
            "  category: web\n"
            "detection:\n"
            "  selection:\n"
            "    action: 'block'\n"
            "    attack_type: 'XSS'\n"
            "  condition: selection\n"
            "level: high"
        ),
        "perimeter": "waf_web",
        "datasource_hints": ["waf", "web", "waf_akamai", "cloudflare", "modsecurity"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1059.007",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_attack_type", "op": "=", "value": "XSS"},
            {"field": "data_action", "op": "=", "value": "block"},
        ],
    },
    {
        "external_id": "splunk-waf-path-traversal-attack",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/web/waf_directory_path_traversal_attempt/",
        "original_title": "WAF Directory Path Traversal Attempt",
        "description": "Detecta padrões de escape de diretório (../, ..%2f ou /etc/passwd) submetidos contra aplicações web corporativas.",
        "original_format": "Splunk SPL",
        "original_syntax": "`waf` uri=\"*../*\" action=\"block\"",
        "perimeter": "waf_web",
        "datasource_hints": ["waf", "web", "waf_akamai", "awswaf", "imperva"],
        "severity": "high",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_uri", "op": "=~", "value": ".*(\\.\\./|\\.\\.%2[fF]).*"},
            {"field": "data_action", "op": "=", "value": "block"},
        ],
    },
    {
        "external_id": "elastic-waf-log4j-jndi-rce",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/web/web_waf_log4j_jndi_rce.toml",
        "original_title": "WAF Log4j JNDI Remote Code Execution Attempt",
        "description": "Detecta strings contendo `${jndi:ldap://` ou `${jndi:dns://` enviadas em cabeçalhos HTTP ou query strings bloqueadas pelo WAF.",
        "original_format": "Elastic EQL / KQL",
        "original_syntax": "http.request.uri : \"*${jndi:*\" and waf.action : \"block\"",
        "perimeter": "waf_web",
        "datasource_hints": ["waf", "web", "waf_akamai", "cloudflare", "awswaf"],
        "severity": "critical",
        "mitre_tactic": "initial-access",
        "mitre_technique": "T1190",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_uri", "op": "=~", "value": "(?i).*\\$\\{jndi:.*"},
            {"field": "data_action", "op": "=", "value": "block"},
        ],
    },
    {
        "external_id": "detection-fyi-waf-ssrf-cloud-metadata",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/elastic/detection-rules/cross-platform/credential_access_web_server_cloud_imds_ssrf_request/",
        "original_title": "WAF Server-Side Request Forgery Targeting Cloud Metadata",
        "description": "Identifica requisições HTTP maliciosas direcionadas ao endereço de metadados de nuvem 169.254.169.254 para roubo de tokens IAM de instâncias.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: WAF Server-Side Request Forgery Targeting Cloud Metadata\n"
            "logsource:\n"
            "  category: web\n"
            "detection:\n"
            "  selection:\n"
            "    uri|contains: '169.254.169.254'\n"
            "  condition: selection\n"
            "level: critical"
        ),
        "perimeter": "waf_web",
        "datasource_hints": ["waf", "web", "waf_akamai", "awswaf", "cloudflare"],
        "severity": "critical",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1552.005",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_uri", "op": "=~", "value": ".*169\\.254\\.169\\.254.*"},
            {"field": "data_action", "op": "=", "value": "block"},
        ],
    },
    # --- Perímetro: Antimalware / EDR (CrowdStrike, Symantec, Kaspersky, Sophos, Defender, etc.)
    {
        "external_id": "sigma-edr-process-injection-remotethread",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_createremotethread.yml",
        "original_title": "EDR Suspicious Process Injection via CreateRemoteThread",
        "description": "Detecta tentativa de injeção de código em processos legítimos do sistema operacional reportada por agentes de endpoint/EDR.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: EDR Suspicious Process Injection via CreateRemoteThread\n"
            "logsource:\n"
            "  category: edr\n"
            "detection:\n"
            "  selection:\n"
            "    threat_name: 'ProcessInjection'\n"
            "    action: 'blocked'\n"
            "  condition: selection\n"
            "level: critical"
        ),
        "perimeter": "endpoint_edr",
        "datasource_hints": ["crowdstrike", "edr", "symantec", "kaspersky", "sophos", "defender", "ad_windows"],
        "severity": "critical",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1055.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_threat_name", "op": "=", "value": "ProcessInjection"},
            {"field": "data_action", "op": "=", "value": "blocked"},
        ],
    },
    {
        "external_id": "sigma-edr-vssadmin-shadow-delete",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_vssadmin_delete_shadows.yml",
        "original_title": "EDR Volume Shadow Copy Deletion via VSSAdmin (Ransomware)",
        "description": "Detecta comando vssadmin.exe delete shadows comumente executado por cepas de Ransomware antes de iniciar a criptografia de discos.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: EDR Volume Shadow Copy Deletion via VSSAdmin (Ransomware)\n"
            "logsource:\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\vssadmin.exe'\n"
            "    CommandLine|contains: 'delete shadows'\n"
            "  condition: selection\n"
            "level: critical"
        ),
        "perimeter": "endpoint_edr",
        "datasource_hints": ["crowdstrike", "kaspersky", "symantec", "sophos", "defender", "ad_windows"],
        "severity": "critical",
        "mitre_tactic": "impact",
        "mitre_technique": "T1490",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "win_eventdata_image", "op": "=~", "value": "(?i).*vssadmin\\.exe"},
            {"field": "win_eventdata_commandLine", "op": "=~", "value": "(?i).*delete.*shadows.*"},
        ],
    },
    {
        "external_id": "splunk-edr-powershell-encoded-execution",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/powershell_suspicious_encoded_command/",
        "original_title": "EDR Suspicious PowerShell EncodedCommand Execution",
        "description": "Identifica execução de PowerShell com parâmetros de código Base64 (-enc, -encodedcommand) frequentemente usados por loaders de ameaças.",
        "original_format": "Splunk SPL",
        "original_syntax": "`endpoint` process_name=\"powershell.exe\" command_line=\"*-enc*\"",
        "perimeter": "endpoint_edr",
        "datasource_hints": ["sophos", "crowdstrike", "symantec", "kaspersky", "defender", "ad_windows"],
        "severity": "high",
        "mitre_tactic": "execution",
        "mitre_technique": "T1059.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "win_eventdata_image", "op": "=~", "value": "(?i).*powershell\\.exe"},
            {"field": "win_eventdata_commandLine", "op": "=~", "value": "(?i).*-(e|enc|encodedcommand).*"},
        ],
    },
    {
        "external_id": "elastic-edr-lsass-memory-access-mimikatz",
        "source_id": "elastic_rules",
        "source_name": "Elastic Detection Rules",
        "source_url": "https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_lsass_memory_mimikatz.toml",
        "original_title": "EDR LSASS Process Memory Dump (Credential Theft)",
        "description": "Detecta acesso anômalo de leitura/cópia de memória ao processo lsass.exe visando extração de hashes NTLM e credenciais em texto claro.",
        "original_format": "Elastic EQL / KQL",
        "original_syntax": "process.name : \"lsass.exe\" and event.action : \"memory_dump_attempt\"",
        "perimeter": "endpoint_edr",
        "datasource_hints": ["crowdstrike", "defender", "kaspersky", "symantec", "sophos", "ad_windows"],
        "severity": "critical",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1003.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "win_eventdata_targetImage", "op": "=~", "value": "(?i).*lsass\\.exe"},
            {"field": "win_eventdata_grantedAccess", "op": "=~", "value": "(?i).*0x1010.*"},
        ],
    },
    {
        "external_id": "detection-fyi-edr-lolbas-certutil-download",
        "source_id": "detection_fyi",
        "source_name": "detection.fyi",
        "source_url": "https://detection.fyi/elastic/detection-rules/windows/defense_evasion_suspicious_certutil_commands/",
        "original_title": "EDR LOLBAS Remote File Download via Certutil",
        "description": "Detecta o uso do utilitário administrativo legítimo certutil.exe com os switches -urlcache e -split para download de payloads remotos.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: EDR LOLBAS Remote File Download via Certutil\n"
            "logsource:\n"
            "  category: process_creation\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\certutil.exe'\n"
            "    CommandLine|contains: 'urlcache'\n"
            "  condition: selection\n"
            "level: high"
        ),
        "perimeter": "endpoint_edr",
        "datasource_hints": ["crowdstrike", "symantec", "kaspersky", "sophos", "defender", "ad_windows"],
        "severity": "high",
        "mitre_tactic": "defense-evasion",
        "mitre_technique": "T1105",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "win_eventdata_image", "op": "=~", "value": "(?i).*certutil\\.exe"},
            {"field": "win_eventdata_commandLine", "op": "=~", "value": "(?i).*urlcache.*"},
        ],
    },
    # --- Perímetro: Identidade (Active Directory, Kerberos, Okta, etc.)
    {
        "external_id": "sigma-ad-dcsync-replication-event-4662",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml",
        "original_title": "Active Directory Replication from Non Machine Account - DcSync Indicator",
        "description": "Detecta solicitação não autorizada de sincronização de credenciais do domínio utilizando privilégios DS-Replication-Get-Changes-All.",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Active Directory Replication from Non Machine Account - DcSync Indicator\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: '4662'\n"
            "    AccessMask: '0x100'\n"
            "  condition: selection\n"
            "level: critical"
        ),
        "perimeter": "identity_iam",
        "datasource_hints": ["ad_windows", "active_directory", "windows", "security"],
        "severity": "critical",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1003.006",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4662"},
            {"field": "win_eventdata_accessMask", "op": "=", "value": "0x100"},
        ],
    },
    {
        "external_id": "splunk-ad-sensitive-group-member-added",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/endpoint/11656928-181a-4663-87a7-0e6e737c385e/",
        "original_title": "Active Directory Sensitive Domain Group Member Added (Event 4728)",
        "description": "Identifica a inclusão de um usuário comum dentro do grupo Domain Admins ou Enterprise Admins (EventID 4728 / 4732).",
        "original_format": "Splunk SPL",
        "original_syntax": "`security` EventCode=4728 TargetUserName=\"*Admin*\"",
        "perimeter": "identity_iam",
        "datasource_hints": ["ad_windows", "active_directory", "windows", "security"],
        "severity": "high",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "EventID", "op": "=", "value": "4728"},
            {"field": "win_eventdata_targetUserName", "op": "=~", "value": "(?i).*Admin.*"},
        ],
    },
    # --- Perímetro: Cloud / SaaS (Microsoft 365, AWS CloudTrail, etc.)
    {
        "external_id": "sigma-m365-inbox-forwarding-rule",
        "source_id": "sigmahq",
        "source_name": "SigmaHQ",
        "source_url": "https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/m365/m365_inbox_forwarding_rule_external.yml",
        "original_title": "Microsoft 365 Mailbox Forwarding Rule Created to External Domain",
        "description": "Detecta a criação de regra oculta de encaminhamento automático de emails para um domínio externo, comum em ataques de Business Email Compromise (BEC).",
        "original_format": "Sigma (YAML)",
        "original_syntax": (
            "title: Microsoft 365 Mailbox Forwarding Rule Created to External Domain\n"
            "logsource:\n"
            "  service: office365\n"
            "detection:\n"
            "  selection:\n"
            "    Operation: 'New-InboxRule'\n"
            "    Parameters|contains: 'ForwardTo'\n"
            "  condition: selection\n"
            "level: high"
        ),
        "perimeter": "cloud_saas",
        "datasource_hints": ["office365", "m365", "exchange", "cloud"],
        "severity": "high",
        "mitre_tactic": "collection",
        "mitre_technique": "T1114.003",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "Operation", "op": "=", "value": "New-InboxRule"},
            {"field": "ResultStatus", "op": "=", "value": "True"},
        ],
    },
    {
        "external_id": "splunk-aws-cloudtrail-root-access-key",
        "source_id": "splunk_research",
        "source_name": "Splunk Security Research",
        "source_url": "https://research.splunk.com/cloud/aws_cloudtrail_root_access_key_created/",
        "original_title": "AWS CloudTrail Access Key Created for Root Account",
        "description": "Gera alerta quando uma chave de acesso programático (Access Key) é gerada para a conta raiz (Root) da organização na AWS.",
        "original_format": "Splunk SPL",
        "original_syntax": "`cloudtrail` eventName=\"CreateAccessKey\" userIdentity.type=\"Root\"",
        "perimeter": "cloud_saas",
        "datasource_hints": ["aws", "cloudtrail", "cloud_saas", "cloud"],
        "severity": "critical",
        "mitre_tactic": "persistence",
        "mitre_technique": "T1098.001",
        "threshold_operator": "gt",
        "threshold_value": 0,
        "for_duration": "0s",
        "predicates": [
            {"field": "data_office365_Operation", "op": "=", "value": "CreateAccessKey"},
            {"field": "data_office365_UserId", "op": "=~", "value": "(?i).*Root.*"},
        ],
    },
]


# =============================================================================
# 2. Funções de Pesquisa, Validação de Tecnologia e Conversão para LogQL
# =============================================================================
def build_technology_search_filters(technologies: list[Technology]) -> list[str]:
    """Constrói os termos de filtro de busca nos sites com base nas tecnologias e perímetros existentes no D.A.N.T.E."""
    enabled_techs = [t for t in technologies if t.enabled]
    terms: list[str] = []
    for tech in enabled_techs:
        slug = tech.slug.strip().lower()
        if slug and slug not in terms:
            terms.append(slug)
        if tech.perimeter and tech.perimeter != "other" and tech.perimeter not in terms:
            terms.append(tech.perimeter)
        core_regex = tech.rule_groups_regex.replace(".*", "").strip("^$").strip().lower()
        if core_regex and core_regex not in terms:
            terms.append(core_regex)
    return terms


async def probe_trusted_sources(technologies: list[Technology] | None = None) -> dict[str, bool]:
    """Consulta as 4 fontes confiáveis de detecção filtrando apenas pelas tecnologias existentes no D.A.N.T.E."""
    reachability: dict[str, bool] = {}
    tech_filters = build_technology_search_filters(technologies or [])
    params = {"technologies": ",".join(tech_filters)} if tech_filters else None
    async with httpx.AsyncClient(timeout=3.5, follow_redirects=True) as client:
        for src in TRUSTED_SOURCES:
            src_id = src["id"]
            try:
                resp = await client.head(src["url"], params=params)
                reachability[src_id] = resp.status_code < 500
            except Exception:
                reachability[src_id] = False
    return reachability


def match_rule_to_technology(
    raw_rule: dict[str, Any],
    technologies: list[Technology],
) -> Technology | None:
    """Passo 2.1: Valida se a fonte de dados da regra é compatível com o ecossistema do D.A.N.T.E.

    A compatibilidade é ancorada no PERÍMETRO DE DETECÇÃO da tecnologia:
      - 'Fortigate' cobre o perímetro 'Firewall'
      - 'WAF Akamai' cobre o perímetro 'WAF / Web'
      - 'CrowdStrike' / 'Symantec' / 'Kaspersky' / 'Sophos' cobrem o perímetro 'Antimalware/EDR'
      - 'AD/Windows' cobre o perímetro 'Identidade' e 'Antimalware/EDR'
      - 'Office365' cobre o perímetro 'Cloud / SaaS'

    Se o cliente possui uma tecnologia ativa no perímetro da regra, qualquer regra daquele
    perímetro é absorvida e adaptada para a tecnologia correspondente.
    """
    enabled_techs = [t for t in technologies if t.enabled]
    if not enabled_techs:
        return None

    by_slug = {t.slug.lower(): t for t in enabled_techs}
    hints = [str(h).strip().lower() for h in (raw_rule.get("datasource_hints") or []) if h]

    # 1. Match direto prioritário por slug nos hints
    for hint in hints:
        if hint in by_slug:
            return by_slug[hint]
        # Sinônimos comuns de logsource (Sigma / Splunk / Elastic)
        if hint in ("windows", "active_directory", "ad", "wineventlog_security", "security") and "ad_windows" in by_slug:
            return by_slug["ad_windows"]
        if hint in ("m365", "o365", "exchange", "azuread", "entra_id") and "office365" in by_slug:
            return by_slug["office365"]
        if hint in ("fortinet", "fortios", "sslvpn") and "fortigate" in by_slug:
            return by_slug["fortigate"]

    # 2. Match por PERÍMETRO DE DETECÇÃO (amarrado ao escopo tecnológico)
    rule_perimeter = str(raw_rule.get("perimeter") or "").strip().lower()
    if not rule_perimeter or rule_perimeter == "other":
        rule_perimeter = infer_perimeter(
            slug=hints[0] if hints else "",
            name=str(raw_rule.get("original_title") or ""),
            hints=hints,
        )[0]

    # Tecnologias ativas que atendem a este perímetro
    techs_in_perimeter = [t for t in enabled_techs if t.perimeter == rule_perimeter]

    # Suporte cruzado: AD/Windows também absorve Antimalware/EDR via EventLog/Sysmon se não houver EDR dedicado
    if not techs_in_perimeter and rule_perimeter == "endpoint_edr" and "ad_windows" in by_slug:
        techs_in_perimeter = [by_slug["ad_windows"]]

    if techs_in_perimeter:
        # Se houver mais de uma tecnologia no mesmo perímetro, prioriza a que tem mais aderência aos hints
        for tech in techs_in_perimeter:
            core_regex = tech.rule_groups_regex.replace(".*", "").strip("^$").lower()
            for hint in hints:
                if (
                    hint == tech.slug
                    or hint == tech.name.lower()
                    or (core_regex and len(core_regex) >= 3 and core_regex in hint)
                ):
                    return tech
        return techs_in_perimeter[0]

    # 3. Match tolerante secundário por regex de ss_groups
    for hint in hints:
        for tech in enabled_techs:
            core_regex = tech.rule_groups_regex.replace(".*", "").strip("^$").lower()
            if (
                hint == tech.name.lower()
                or (core_regex and len(core_regex) >= 3 and (hint == core_regex or core_regex in hint))
            ):
                return tech

    return None


def search_rules_in_trusted_sources(
    technologies: list[Technology],
    max_local_sigma: int = 30,
) -> list[dict[str, Any]]:
    """Pesquisa regras de detecção nos 4 sites confiáveis filtrando APENAS para
    tecnologias que já existem e estão ativas no D.A.N.T.E.

    Integra automaticamente regras do repositório local do SigmaHQ
    (clonado em /data/sigma-repo com URLs 100% canônicas derivadas do caminho real)
    combinadas com os candidatos das fontes adicionais (detection.fyi, Splunk e Elastic).
    """
    enabled_techs = [t for t in technologies if t.enabled]
    if not enabled_techs:
        return []

    all_candidates: list[dict[str, Any]] = []
    seen_external_ids: set[str] = set()

    # 1. Carrega regras legítimas do repositório local SigmaHQ se clonado
    try:
        local_sigma_rules = scan_local_sigma_rules(max_rules=max_local_sigma)
        for cand in local_sigma_rules:
            ext_id = str(cand.get("external_id") or "").strip()
            if ext_id and ext_id not in seen_external_ids:
                seen_external_ids.add(ext_id)
                hints = [
                    cand.get("product"),
                    cand.get("category"),
                    cand.get("service"),
                ]
                cand["datasource_hints"] = [str(h).lower() for h in hints if h]
                all_candidates.append(cand)
    except Exception as exc:
        logger.debug("Leitura do repositório local do SigmaHQ: %s", exc)

    # 2. Mescla com os candidatos canônicos das demais fontes oficiais
    for candidate in RAW_SOURCE_CANDIDATES:
        ext_id = str(candidate.get("external_id") or "").strip()
        if ext_id and ext_id in seen_external_ids:
            continue
        all_candidates.append(candidate)

    return [
        candidate
        for candidate in all_candidates
        if match_rule_to_technology(candidate, enabled_techs) is not None
    ]


def has_unprocessed_compatible_rules(
    curation_store: "CurationStore",
    technologies: list[Technology],
) -> bool:
    """Verifica se existem regras compatíveis nas fontes cadastradas que ainda não
    foram incorporadas na database interna cumulativa de curadoria.
    """
    enabled_techs = [t for t in technologies if t.enabled]
    if not enabled_techs:
        return False
    known_patterns = [t.effective_groups_regex for t in technologies]
    for candidate in search_rules_in_trusted_sources(enabled_techs):
        tech = match_rule_to_technology(candidate, enabled_techs)
        if tech is None:
            continue
        logql_query, mapped_fields, lint_ok, _ = convert_rule_to_logql(
            candidate, tech, known_patterns
        )
        if not lint_ok or any(not m.compatible for m in mapped_fields):
            continue
        ext_id = str(candidate.get("external_id") or "").strip()
        orig_title = str(candidate.get("original_title") or "").strip()
        if not curation_store.is_seen(ext_id, orig_title, orig_title, logql_query):
            return True
    return False


def ensure_data_prefix(field_name: str) -> str:
    """Garante que campos de dados do evento tenham o prefixo 'data_'."""
    name = str(field_name or "").strip()
    if not name:
        return name
    # Exceções que não recebem prefixo 'data_':
    # 1. rule_id (extraído diretamente da raiz de rule.id pelo pipeline Wazuh -> Vector -> Loki)
    # 2. full_log, timestamp (raiz do log)
    # 3. Campos que já possuem o prefixo 'data_'
    if (
        name == "rule_id"
        or name == "full_log"
        or name == "timestamp"
        or name.startswith("data_")
    ):
        return name
    return f"data_{name}"


def ensure_data_prefix_in_logql(logql: str) -> str:
    """Normaliza expressões LogQL para que filtros de campos de dados possuam o prefixo 'data_'.

    Ex:
      '| action="deny"' -> '| data_action="deny"'
      '| srcip="10.0.0.1"' -> '| data_srcip="10.0.0.1"'
      '| dstport="445"' -> '| data_dstport="445"'
      'sum by (srcip)' -> 'sum by (data_srcip)'
    """
    if not logql or not isinstance(logql, str):
        return logql

    # 1. Normaliza agregações sum by (...)
    def _rep_by(m: re.Match) -> str:
        fields = [f.strip() for f in m.group(1).split(",")]
        new_fields = [ensure_data_prefix(f) for f in fields]
        return f"sum by ({', '.join(new_fields)})"

    res = re.sub(r"\bsum\s+by\s*\(([^)]+)\)", _rep_by, logql, flags=re.IGNORECASE)

    # 2. Normaliza filtros em estágios de pipeline | field op "val"
    def _rep_filter(m: re.Match) -> str:
        field = m.group(1).strip()
        op = m.group(2)
        val = m.group(3)
        return f"| {ensure_data_prefix(field)}{op}{val}"

    # Padrão: | <campo><op>"<val>" onde op é =, !=, =~, !~
    res = re.sub(
        r"\|\s*([a-zA-Z0-9_.]+)\s*(=~|!~|!=|=)\s*(\"[^\"]*\"|`[^`]*`|\d+)",
        _rep_filter,
        res,
    )
    return res


def convert_rule_to_logql(
    raw_rule: dict[str, Any],
    technology: Technology,
    known_rule_groups_patterns: list[str],
) -> tuple[str, list[CurationFieldMapping], bool, str]:
    """Passo 2.2: Converte a regra do formato original para LogQL seguindo as diretrizes do D.A.N.T.E.

    Retorna ``(logql_query, mapped_fields, lint_valid, lint_message)``.
    """
    # Integração oficial pySigma: se a regra for Sigma ou contiver AST/detection,
    # utiliza o motor de tradução Sigma especializado para Loki/Wazuh.
    if (
        raw_rule.get("rule_format") == "Sigma (YAML)"
        or raw_rule.get("source_id") == "sigmahq"
        or "detection" in raw_rule
        or "raw_yaml" in raw_rule
    ):
        try:
            sigma_query, sigma_mappings, sigma_lint_ok, _ = convert_sigma_to_logql(
                raw_rule, technology
            )
            if sigma_lint_ok:
                return sigma_query, sigma_mappings, True, ""
        except Exception as conv_err:
            logger.debug("Falha na conversão via pySigma/SigmaConverter: %s", conv_err)

    tech_map = {
        **PERIMETER_FIELD_TRANSLATION_MAP.get(technology.perimeter, {}),
        **FIELD_TRANSLATION_MAP.get(technology.slug, {}),
    }
    supported_fields = (
        SUPPORTED_WAZUH_LOKI_FIELDS.get(technology.slug)
        or PERIMETER_DEFAULT_FIELDS.get(technology.perimeter)
        or {"rule_id", "full_log"}
    )

    predicates = raw_rule.get("predicates") or []
    mapped_fields: list[CurationFieldMapping] = []
    filter_stages: list[str] = []

    for pred in predicates:
        orig_field = str(pred.get("field") or "").strip()
        op = str(pred.get("op") or "=").strip()
        val = str(pred.get("value") or "").replace('"', "")
        if not orig_field:
            continue

        # Traduz o nome do campo original para o flatten JSON do Wazuh no Loki com prefixo data_
        if orig_field in tech_map:
            logql_field = tech_map[orig_field]
        else:
            # Fallback: converte pontos em underscore e assegura prefixo data_
            clean_field = re.sub(r"[^a-zA-Z0-9_]", "_", orig_field)
            logql_field = ensure_data_prefix(clean_field)

        logql_field = ensure_data_prefix(logql_field)

        is_compatible = (
            logql_field in supported_fields
            or logql_field.removeprefix("data_") in supported_fields
            or f"data_{logql_field}" in supported_fields
            or logql_field in ("rule_id", "full_log")
        )
        mapped_fields.append(
            CurationFieldMapping(
                original_field=orig_field,
                logql_field=logql_field,
                compatible=is_compatible,
            )
        )

        if op in ("=~", "!~", "!=", "="):
            filter_stages.append(f'{logql_field}{op}"{val}"')
        else:
            filter_stages.append(f'{logql_field}="{val}"')

    stream_selector = f'{{job="{technology.job}", ss_groups=~"{technology.ss_groups_regex}"}}'
    pipeline = " | json"
    if filter_stages:
        pipeline += " | " + " | ".join(filter_stages)

    # Reforço de contexto de ameaça real na query convertida para LogQL:
    # Se a regra for de força bruta, repetições, varreduras ou bursts, adiciona threshold estatístico (> 5).
    title_lower = str(raw_rule.get("original_title") or raw_rule.get("title") or "").lower()
    desc_lower = str(raw_rule.get("description") or "").lower()
    tech_mitre = str(raw_rule.get("mitre_technique") or "").upper()
    orig_threshold = raw_rule.get("threshold_value")

    is_brute_force = (
        "t1110" in tech_mitre
        or "t1046" in tech_mitre
        or any(
            kw in title_lower or kw in desc_lower
            for kw in (
                "brute force",
                "bruteforce",
                "força bruta",
                "forca bruta",
                "password spray",
                "spraying",
                "login failure burst",
                "multiple failures",
                "multiple authentication",
                "repeated mfa",
                "port scan",
                "burst",
            )
        )
    )

    threshold_suffix = ""
    if is_brute_force:
        val = 5
        if isinstance(orig_threshold, (int, float)) and orig_threshold > 0:
            val = max(int(orig_threshold), 5)
        threshold_suffix = f" > {val}"
    elif isinstance(orig_threshold, (int, float)) and orig_threshold > 0:
        threshold_suffix = f" > {int(orig_threshold)}"

    raw_query = f"sum(count_over_time({stream_selector}{pipeline} [5m])){threshold_suffix}"
    logql_query = ensure_data_prefix_in_logql(raw_query)

    lint_res = lint_logql(
        logql_query,
        known_rule_groups_patterns=known_rule_groups_patterns,
        expected_job=technology.job,
    )
    return logql_query, mapped_fields, lint_res.is_valid, lint_res.message


def generate_threat_rationale(
    raw_rule: dict[str, Any],
    technology: Technology,
    logql_query: str,
    is_brute_force: bool = False,
    threshold_value: int | None = None,
) -> str:
    """Gera parecer técnico contextualizado com foco no contexto de ameaça da regra.

    Explica o vetor de ataque, o modus operandi da ameaça, o enriquecimento da query LogQL
    (incluindo limiares estatísticos como > 5 para força bruta) e diretrizes de triagem para o SOC.
    """
    title = str(raw_rule.get("original_title") or raw_rule.get("title") or "Regra de Detecção").strip()
    desc = str(raw_rule.get("description") or "").strip()
    mitre_tech = str(raw_rule.get("mitre_technique") or "").strip()
    mitre_tactic = str(raw_rule.get("mitre_tactic") or "").strip()

    threat_sections: list[str] = []
    if is_brute_force:
        threat_sections.append(
            f"Contexto de Ameaça: Identifica atividade adversária de Força Bruta / Password Spraying "
            f"({mitre_tech or 'T1110'} - {mitre_tactic or 'credential-access'}). O atacante tenta comprometer "
            f"contas válidas por meio de múltiplas tentativas consecutivas de autenticação. A query LogQL foi "
            f"reforçada com o filtro de threshold '> {threshold_value or 5}' ao final da agregação métrica, "
            f"assegurando que falhas pontuais e isoladas de digitação não disparem alarmes e que apenas "
            f"rajadas repetidas e anômalas gerem incidentes operacionais."
        )
    else:
        threat_sections.append(
            f"Contexto de Ameaça: A regra '{title}' combate técnicas adversárias de "
            f"{mitre_tactic or 'execução maliciosa'} ({mitre_tech or 'MITRE ATT&CK'}). "
            f"{desc or 'Monitora anomalias comportamentais e indicadores de comprometimento na telemetria corporativa.'}"
        )

    # O parecer foca estritamente no contexto de ameaça sem detalhar conversão de sintaxe ao usuário

    threat_sections.append(
        "Diretrizes para o SOC: Em caso de alarme, correlacionar o IP de origem, usuário alvo e horários dos disparos. "
        "Caso o tráfego seja legítimo (ex.: rotina interna automatizada de inventário), realizar tuning através de "
        "filtros de exclusão ou silêncio temporário com tag canônica [excecao] ou [antiflood]."
    )

    return "\n\n".join(threat_sections)


def _extract_stream_expression(logql_query: str) -> str:
    """Extrai o seletor e pipeline de stream de uma query métrica LogQL para consulta de linhas."""
    raw = logql_query.strip()
    start_brace = raw.find("{")
    if start_brace == -1:
        return raw
    range_match = re.search(r"\[\s*\d+[smhdwy]\s*\]", raw[start_brace:])
    if range_match:
        extracted = raw[start_brace : start_brace + range_match.start()].strip()
        if extracted:
            return extracted
    return raw


def _flatten_json_items(obj: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Achata chaves e valores de um objeto JSON com '_' (comportamento do `| json` no Loki)."""
    items: dict[str, Any] = {}
    for k, v in obj.items():
        clean_k = f"{prefix}_{k}" if prefix else str(k)
        if isinstance(v, dict):
            items.update(_flatten_json_items(v, clean_k))
        else:
            items[clean_k] = v
    return items


def _flatten_json_keys(obj: dict[str, Any], prefix: str = "") -> set[str]:
    """Achata chaves de um objeto JSON com '_' (mesmo comportamento do `| json` no Loki)."""
    return set(_flatten_json_items(obj, prefix).keys())


# =============================================================================
# 2.5. Janelas Temporais Progressivas & Estado de Progresso em Tempo Real
# =============================================================================
CURATION_QUERY_WINDOWS: list[tuple[str, str]] = [
    ("now-15m", "15 minutos"),
    ("now-1h", "1 hora"),
    ("now-6h", "6 horas"),
    ("now-24h", "24 horas"),
    ("now-3d", "3 dias"),
]

_PROGRESS_LOCK = threading.Lock()
_CURATION_PROGRESS = CurationProgressState()


def get_curation_progress() -> CurationProgressState:
    """Retorna uma cópia segura do estado atual de execução da curadoria."""
    with _PROGRESS_LOCK:
        return _CURATION_PROGRESS.model_copy(deep=True)


def _now_time_label() -> str:
    now_local = datetime.now(timezone(timedelta(hours=-3)))
    return now_local.strftime("%H:%M:%S")


def _reset_curation_progress(trigger: str) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    with _PROGRESS_LOCK:
        global _CURATION_PROGRESS
        _CURATION_PROGRESS = CurationProgressState(
            running=True,
            percent=2,
            phase="Inicializando curadoria e sondando fontes confiáveis",
            current_action="Iniciando ciclo de curadoria e consultando fontes confiáveis...",
            total_window_steps=len(CURATION_QUERY_WINDOWS),
            recent_logs=[
                f"[{_now_time_label()}] Ciclo de curadoria iniciado (gatilho: {trigger}).",
                f"[{_now_time_label()}] Sondando catálogo de regras nas 4 fontes confiáveis e inventário de clientes no Grafana...",
            ],
            started_at=now_iso,
            updated_at=now_iso,
            finished_at=None,
        )


def _reset_to_idle_progress() -> None:
    """Reseta o progresso para o estado ocioso zerado (0%), inativo e sem logs."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with _PROGRESS_LOCK:
        global _CURATION_PROGRESS
        _CURATION_PROGRESS = CurationProgressState(
            running=False,
            percent=0,
            phase="Aguardando execução",
            current_action="Curadoria limpa e zerada. Clique em 'Iniciar' ou aguarde o agendamento diário.",
            total_window_steps=len(CURATION_QUERY_WINDOWS),
            recent_logs=[],
            started_at=None,
            updated_at=now_iso,
            finished_at=None,
        )


def _update_curation_progress(
    *,
    running: bool | None = None,
    percent: int | None = None,
    phase: str | None = None,
    current_action: str | None = None,
    current_client_name: str | None = None,
    current_client_uid: str | None = None,
    current_client_index: int | None = None,
    total_clients: int | None = None,
    current_rule_title: str | None = None,
    current_rule_source: str | None = None,
    current_rule_index: int | None = None,
    total_rules: int | None = None,
    current_window_label: str | None = None,
    current_window_step: int | None = None,
    windows_evaluated_current: list[str] | None = None,
    log_line: str | None = None,
    finished: bool = False,
) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    with _PROGRESS_LOCK:
        if running is not None:
            _CURATION_PROGRESS.running = running
        if percent is not None:
            _CURATION_PROGRESS.percent = max(0, min(100, int(percent)))
        if phase is not None:
            _CURATION_PROGRESS.phase = phase
        if current_action is not None:
            _CURATION_PROGRESS.current_action = current_action
        if current_client_name is not None:
            _CURATION_PROGRESS.current_client_name = current_client_name
        if current_client_uid is not None:
            _CURATION_PROGRESS.current_client_uid = current_client_uid
        if current_client_index is not None:
            _CURATION_PROGRESS.current_client_index = current_client_index
        if total_clients is not None:
            _CURATION_PROGRESS.total_clients = total_clients
        if current_rule_title is not None:
            _CURATION_PROGRESS.current_rule_title = current_rule_title
        if current_rule_source is not None:
            _CURATION_PROGRESS.current_rule_source = current_rule_source
        if current_rule_index is not None:
            _CURATION_PROGRESS.current_rule_index = current_rule_index
        if total_rules is not None:
            _CURATION_PROGRESS.total_rules = total_rules
        if current_window_label is not None:
            _CURATION_PROGRESS.current_window_label = current_window_label
        if current_window_step is not None:
            _CURATION_PROGRESS.current_window_step = current_window_step
        if windows_evaluated_current is not None:
            _CURATION_PROGRESS.windows_evaluated_current = list(windows_evaluated_current)
        if log_line:
            entry = f"[{_now_time_label()}] {log_line}"
            _CURATION_PROGRESS.recent_logs.append(entry)
            if len(_CURATION_PROGRESS.recent_logs) > 40:
                _CURATION_PROGRESS.recent_logs = _CURATION_PROGRESS.recent_logs[-40:]
        _CURATION_PROGRESS.updated_at = now_iso
        if finished:
            _CURATION_PROGRESS.finished_at = now_iso


def _record_timeout_event(client_name: str, window_label: str, detail: str = "") -> None:
    msg = f"{client_name} (janela de {window_label})"
    if detail:
        msg = f"{msg}: {detail}"
    with _PROGRESS_LOCK:
        if msg not in _CURATION_PROGRESS.timed_out_clients:
            _CURATION_PROGRESS.timed_out_clients.append(msg)


async def _query_loki_lines(
    grafana: GrafanaClient,
    datasource_uid: str,
    expr: str,
    limit: int = 25,
    time_from: str = "now-15m",
    timeout: float = 4.0,
) -> tuple[bool, list[str], bool, str]:
    """Executa uma query de stream LogQL no datasource do cliente via /api/ds/query.

    Retorna ``(ok, lines, timed_out, error_detail)``.
    Nunca propaga exceção de timeout para não interromper o ciclo de curadoria.
    """
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"uid": datasource_uid, "type": "loki"},
                "expr": expr,
                "queryType": "range",
                "lines": limit,
                "maxLines": limit,
            }
        ],
        "from": time_from,
        "to": "now",
    }
    try:
        res = await asyncio.wait_for(
            grafana._request("POST", "/api/ds/query", json=body),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, [], True, f"Timeout ({timeout:.0f}s) na janela {time_from}"
    except GrafanaError as exc:
        msg_lower = str(exc.message or "").lower()
        is_to = (
            exc.status_code in (504, 408)
            or "timeout" in msg_lower
            or "tempo esgotado" in msg_lower
            or "context deadline exceeded" in msg_lower
        )
        return False, [], is_to, str(exc.message)
    except httpx.TimeoutException:
        return False, [], True, f"Timeout HTTP na janela {time_from}"
    except Exception as exc:
        msg_lower = str(exc).lower()
        is_to = "timeout" in msg_lower or "timed out" in msg_lower or "deadline" in msg_lower
        return False, [], is_to, str(exc)[:160]

    lines: list[str] = []
    results = (res or {}).get("results", {})
    frames = (results.get("A") or {}).get("frames", [])
    for frame in frames:
        fields = (frame.get("schema") or {}).get("fields", [])
        data_values = (frame.get("data") or {}).get("values", [])
        line_idx = next(
            (
                i
                for i, f in enumerate(fields)
                if str(f.get("name", "")).lower() in ("body", "line", "message", "value")
            ),
            -1,
        )
        if line_idx != -1 and len(data_values) > line_idx:
            for item in data_values[line_idx]:
                lines.append(str(item))
    return True, lines, False, ""


async def _query_loki_lines_progressive(
    grafana: GrafanaClient,
    datasource_uid: str,
    expr: str,
    *,
    limit: int = 25,
    client_name: str = "",
    client_uid: str = "",
    client_index: int = 1,
    total_clients: int = 1,
    rule_title: str = "",
    rule_source: str = "",
    rule_index: int = 1,
    total_rules: int = 1,
    update_global_progress: bool = True,
    window_timeout: float = 4.0,
) -> tuple[bool, list[str], str | None, list[str], bool, str | None]:
    """Executa a query no Loki do cliente em 5 etapas progressivas de janela:
    1. Janela de 15 minutos (now-15m)
    2. Janela de 1 hora (now-1h)
    3. Janela de 6 horas (now-6h)
    4. Janela de 24 horas (now-24h)
    5. Janela de 3 dias (now-3d)

    Caso sejam encontrados logs em uma janela específica, interrompe imediatamente
    e NÃO roda a query com janelas mais extensas.
    Se ocorrer timeout em uma janela, registra o evento e prossegue sem parar a curadoria.
    """
    windows_evaluated: list[str] = []
    any_ok = False
    timed_out_any = False
    timeout_detail: str | None = None
    total_steps = len(CURATION_QUERY_WINDOWS)
    short_title = rule_title if len(rule_title) <= 42 else f"{rule_title[:39]}..."

    for step_idx, (window_expr, window_label) in enumerate(CURATION_QUERY_WINDOWS, start=1):
        if _STOP_REQUESTED:
            raise asyncio.CancelledError("Parada de curadoria solicitada pelo operador.")
        if update_global_progress:
            total_r = max(total_rules, 1)
            total_c = max(total_clients, 1)
            r_zero = max(rule_index - 1, 0)
            c_zero = max(client_index - 1, 0)
            w_frac = (step_idx - 0.5) / total_steps
            unit = (r_zero + (c_zero + w_frac) / total_c) / total_r
            pct = min(95, max(20, int(round(20 + unit * 75))))
            _update_curation_progress(
                percent=pct,
                phase="Executando queries em etapas no Loki dos clientes",
                current_client_name=client_name,
                current_client_uid=client_uid,
                current_client_index=client_index,
                total_clients=total_clients,
                current_rule_title=rule_title,
                current_rule_source=rule_source,
                current_rule_index=rule_index,
                total_rules=total_rules,
                current_window_step=step_idx,
                current_window_label=f"Etapa {step_idx}/{total_steps}: Janela de {window_label} ({window_expr})",
                windows_evaluated_current=windows_evaluated + [window_label],
                current_action=f"Avaliando '{short_title}' no cliente {client_name}",
            )

        ok, lines, is_to, err_msg = await _query_loki_lines(
            grafana,
            datasource_uid,
            expr,
            limit=limit,
            time_from=window_expr,
            timeout=window_timeout,
        )
        windows_evaluated.append(window_label)

        if ok:
            any_ok = True
            if len(lines) > 0:
                if update_global_progress:
                    skipped_count = total_steps - step_idx
                    skip_note = (
                        f" ({skipped_count} janela(s) mais extensa(s) ignorada(s))"
                        if skipped_count > 0
                        else ""
                    )
                    _update_curation_progress(
                        windows_evaluated_current=windows_evaluated,
                        log_line=(
                            f"✓ [{client_name}] '{rule_title}': {len(lines)} log(s) encontrado(s) na "
                            f"Etapa {step_idx}/{total_steps} (Janela de {window_label}){skip_note}."
                        ),
                    )
                return True, lines, window_label, windows_evaluated, timed_out_any, timeout_detail

            # Otimização: se a Etapa 1 (now-15m) retornou 0 eventos sem timeout, sondamos now-3d
            # pois [now-1h, now] ⊂ [now-6h, now] ⊂ [now-24h, now] ⊂ [now-3d, now].
            # Se now-3d também tiver 0 eventos, todas as 5 etapas progressivas possuem 0 eventos.
            if step_idx == 1 and total_steps > 1:
                last_expr, _last_label = CURATION_QUERY_WINDOWS[-1]
                ok_last, lines_last, is_to_last, _err_last = await _query_loki_lines(
                    grafana,
                    datasource_uid,
                    expr,
                    limit=limit,
                    time_from=last_expr,
                    timeout=window_timeout,
                )
                if ok_last and not is_to_last and len(lines_last) == 0:
                    windows_evaluated = [w[1] for w in CURATION_QUERY_WINDOWS]
                    break

        if is_to:
            timed_out_any = True
            timeout_detail = (
                f"Timeout na Etapa {step_idx}/{total_steps} (Janela de {window_label} / {window_expr})"
                + (f": {err_msg}" if err_msg else "")
            )
            _record_timeout_event(client_name or datasource_uid, window_label, err_msg)
            if update_global_progress:
                _update_curation_progress(
                    windows_evaluated_current=windows_evaluated,
                )
            # Se esta janela já sofreu timeout no Loki do cliente, não disparamos janelas mais extensas
            break

    if update_global_progress and not timed_out_any:
        _update_curation_progress(
            windows_evaluated_current=windows_evaluated,
            log_line=(
                f"• [{client_name}] '{rule_title}': 0 eventos retornados após consultar as "
                f"{len(windows_evaluated)} etapas ({' → '.join(windows_evaluated)})."
            ),
        )
    return any_ok, [], None, windows_evaluated, timed_out_any, timeout_detail


def compute_dynamic_compatibility(
    *,
    schema_compat_pct: float,
    tech_logs_count: int,
    matched_lines_count: int,
    matched_windows: list[str],
    severity: str = "high",
    mitre_tactic: str = "",
    mitre_technique: str = "",
    perimeter: str = "other",
    observed_field_compat_pct: float = 0.0,
    has_query_results: bool = False,
    lint_valid: bool = True,
    multi_client: bool = False,
) -> tuple[float, float, float, float]:
    """Calcula a porcentagem de compatibilidade dinâmica do D.A.N.T.E. ponderando:
    1. Presença de logs no Loki (volume de telemetria, janelas e recência temporal);
    2. Contexto de ameaça (severidade, criticidade MITRE ATT&CK, subtécnica e perímetro);
    3. Correspondência dos logs com o cenário de ameaça (campos observados nos logs reais,
       resultados comprovados na query e validação de schema).

    Retorna: (total_compat_pct, log_presence_delta, threat_context_delta, scenario_match_delta).
    Regras candidatas com schema homologado variam dinamicamente de 80.0% a 100.0%.
    Regras com schema incompatível (< 80.0%) ou erros críticos são descartadas.
    """
    if schema_compat_pct < 80.0:
        return round(schema_compat_pct, 1), 0.0, 0.0, 0.0

    base_admission = 80.0

    # 1. Presença de logs (até +8.0%)
    if tech_logs_count > 100:
        p_vol = 4.0
    elif tech_logs_count >= 20:
        p_vol = 3.2
    elif tech_logs_count >= 5:
        p_vol = 2.4
    elif tech_logs_count >= 1:
        p_vol = 1.6
    else:
        p_vol = 0.8

    any_15m = any("15 minutos" in w for w in matched_windows)
    any_1h = any("1 hora" in w for w in matched_windows)
    any_6h = any("6 horas" in w for w in matched_windows)
    any_24h = any("24 horas" in w for w in matched_windows)
    any_3d = any("3 dias" in w for w in matched_windows)

    if any_15m:
        p_rec = 3.0
    elif any_1h:
        p_rec = 2.4
    elif any_6h:
        p_rec = 1.8
    elif any_24h:
        p_rec = 1.2
    elif any_3d:
        p_rec = 0.8
    elif tech_logs_count > 0:
        p_rec = 1.0
    else:
        p_rec = 0.4

    p_multi = 1.0 if multi_client else 0.4
    log_presence_delta = min(8.0, p_vol + p_rec + p_multi)

    # 2. Contexto de ameaça (até +6.0%)
    sev_clean = str(severity or "high").lower()
    if sev_clean == "critical":
        t_sev = 2.5
    elif sev_clean == "high":
        t_sev = 2.0
    elif sev_clean == "medium":
        t_sev = 1.2
    else:
        t_sev = 0.6

    tactic_clean = str(mitre_tactic or "").lower()
    high_impact_tactics = {
        "credential-access",
        "privilege-escalation",
        "defense-evasion",
        "lateral-movement",
        "execution",
        "persistence",
        "command-and-control",
    }
    medium_impact_tactics = {"initial-access", "discovery", "impact", "collection", "exfiltration"}
    if tactic_clean in high_impact_tactics:
        t_tac = 2.0
    elif tactic_clean in medium_impact_tactics or tactic_clean:
        t_tac = 1.4
    else:
        t_tac = 0.8

    tech_clean = str(mitre_technique or "").upper()
    if "." in tech_clean:
        t_spec = 1.0
    elif tech_clean.startswith("T"):
        t_spec = 0.7
    else:
        t_spec = 0.3

    perim_clean = str(perimeter or "").lower()
    core_perims = {"identity_iam", "firewall", "waf_web", "antimalware_edr", "cloud_saas"}
    t_perim = 0.5 if perim_clean in core_perims else 0.2
    threat_context_delta = min(6.0, t_sev + t_tac + t_spec + t_perim)

    # 3. Correspondência dos logs com cenário de ameaça (até +6.0%)
    if observed_field_compat_pct >= 100.0:
        m_obs = 3.0
    elif observed_field_compat_pct >= 75.0:
        m_obs = 2.4
    elif observed_field_compat_pct >= 50.0:
        m_obs = 1.8
    elif observed_field_compat_pct >= 25.0:
        m_obs = 1.2
    elif observed_field_compat_pct > 0.0:
        m_obs = 0.8
    else:
        m_obs = 0.5

    has_results_bool = bool(has_query_results or matched_lines_count > 0)
    if has_results_bool:
        m_match = 2.5
    elif tech_logs_count > 0:
        m_match = 1.0
    else:
        m_match = 0.5

    m_lint = 0.5 if lint_valid else 0.0
    scenario_match_delta = min(6.0, m_obs + m_match + m_lint)

    # REGRA CRÍTICA D.A.N.T.E.: SOMENTE regras com evidência comprovada de logs encontrados
    # na query da regra (has_query_results / matched_lines_count > 0) podem atingir 80.0%+ de compatibilidade.
    # Sem eventos encontrados no Loki, a regra é estritamente limitada a < 80.0% (teto de 75.0%)
    # e descartada da lista de candidatas para implementação no SIEM.
    if not has_results_bool:
        base_no_logs = 40.0
        score_no_logs = (
            base_no_logs
            + (log_presence_delta * 0.5)
            + (threat_context_delta * 0.8)
            + (scenario_match_delta * 0.6)
        )
        total_score = min(75.0, max(30.0, round(score_no_logs, 1)))
        return (
            total_score,
            round(log_presence_delta, 1),
            round(threat_context_delta, 1),
            round(scenario_match_delta, 1),
        )

    total_score = round(
        base_admission + log_presence_delta + threat_context_delta + scenario_match_delta, 1
    )
    total_score = min(100.0, max(80.0, total_score))
    return (
        total_score,
        round(log_presence_delta, 1),
        round(threat_context_delta, 1),
        round(scenario_match_delta, 1),
    )


async def evaluate_rule_across_clients(
    *,
    grafana: GrafanaClient,
    technology: Technology,
    logql_query: str,
    mapped_fields: list[CurationFieldMapping],
    rule_title: str,
    client_folders: list[dict[str, Any]],
    datasources: list[dict[str, Any]],
    all_rules: list[dict[str, Any]],
    declared_map: dict[str, list[str]],
    scan_store: TenantScanStore,
    tech_logs_cache: dict[tuple[str, str], tuple[bool, list[str], str | None, list[str], bool]] | None = None,
    dead_datasources: set[str] | None = None,
    rule_source: str = "",
    rule_index: int = 1,
    total_rules: int = 1,
    severity: str = "high",
    mitre_tactic: str = "",
    mitre_technique: str = "",
) -> tuple[Literal["excellent", "good", "bad"], str, float, list[CurationClientEvaluation]]:
    """Passo 2.3: Executa a query convertida no Loki de todos os clientes em etapas progressivas
    (15m -> 1h -> 6h -> 24h -> 3d) e categoriza a regra.

    Critérios obrigatórios de qualificação:
    1. Compatibilidade dos campos convertidos para LogQL com os logs reais vistos durante as queries.
    2. Resultados obtidos no retorno da query: se não houver evidências de resultados nos logs
       (matched_lines_count == 0), a regra de detecção NÃO pode ser categorizada como 'excellent'.
    3. Resiliência a timeout: se der timeout em um cliente, não interrompe a curadoria.
    """
    total_fields = len(mapped_fields)
    compatible_fields_list = [m.logql_field for m in mapped_fields if m.compatible]
    incompatible_fields_list = [m.original_field for m in mapped_fields if not m.compatible]

    schema_compat_pct = (
        round((len(compatible_fields_list) * 100.0) / total_fields, 1)
        if total_fields > 0
        else 100.0
    )

    # Se a regra possuir compatibilidade de campos inferior a 80.0%,
    # ela não é considerada candidata e nunca entra na curadoria.
    if incompatible_fields_list or schema_compat_pct < 80.0:
        bad_reason = (
            f"Não elegível: compatibilidade de campos ({schema_compat_pct:.1f}%) inferior ao limiar mínimo de 80.0% "
            f"para implementação ({len(incompatible_fields_list)} campo(s) incompatível(is): {', '.join(incompatible_fields_list)})."
        )
        return "bad", bad_reason, schema_compat_pct, []

    stream_expr = _extract_stream_expression(logql_query)
    tech_base_expr = f'{{job="{technology.job}", ss_groups=~"{technology.ss_groups_regex}"}} | json'
    baseline_ds = resolve_baseline_loki_datasource(datasources)

    client_evaluations: list[CurationClientEvaluation] = []
    global_observed_fields: set[str] = set()
    global_field_samples: dict[str, list[str]] = {}
    valid_folders = [f for f in client_folders if str(f.get("uid") or "").strip()]
    total_clients = max(len(valid_folders), 1)

    for c_idx, folder in enumerate(valid_folders, start=1):
        if _STOP_REQUESTED:
            raise asyncio.CancelledError("Parada de curadoria solicitada pelo operador.")
        c_uid = str(folder.get("uid") or "").strip()
        c_name = str(folder.get("title") or c_uid).strip()

        try:
            c_ds = find_tenant_datasource(c_name, c_uid, datasources) or baseline_ds
            ds_uid = str(c_ds.get("uid") or "loki")
            ds_name = str(c_ds.get("name") or ds_uid)

            c_rules = [r for r in all_rules if str(r.get("folderUID") or "") == c_uid]
            already_impl = find_implemented_rule({"title": rule_title, "uid": ""}, c_rules) is not None
            declared_slugs = declared_map.get(c_uid, [])
            _has_tech_footprint = client_has_technology(c_rules, technology, declared_slugs)

            try:
                scan_rec = scan_store.record_for(c_uid)
            except TenantScanStoreError:
                scan_rec = None
            scanned_tech_logs = 0
            if scan_rec:
                for t_item in scan_rec.get("technologies", []):
                    if str(t_item.get("slug") or "").lower() == technology.slug and t_item.get("found"):
                        scanned_tech_logs = max(scanned_tech_logs, int(t_item.get("logs_count") or 1))

            short_title = rule_title if len(rule_title) <= 42 else f"{rule_title[:39]}..."
            action_label = f"Avaliando '{short_title}' no cliente {c_name}"
            cache_key = (ds_uid, technology.slug)

            # Se o datasource deste cliente já apresentou timeout severo na menor janela (15m),
            # registramos internamente no back-end sem travar novamente nas 5 janelas
            if dead_datasources is not None and ds_uid in dead_datasources:
                rule_query_ok = False
                matched_lines: list[str] = []
                matched_window: str | None = None
                windows_evaluated = ["15 minutos"]
                rule_timed_out = True
                rule_timeout_detail = (
                    f"Datasource Loki '{ds_name}' indisponível na janela de 15 minutos"
                )
                tech_query_ok = False
                tech_lines: list[str] = []
                _update_curation_progress(
                    current_client_name=c_name,
                    current_client_uid=c_uid,
                    current_client_index=c_idx,
                    total_clients=total_clients,
                    current_rule_title=rule_title,
                    current_rule_source=rule_source,
                    current_rule_index=rule_index,
                    total_rules=total_rules,
                    current_window_step=1,
                    current_window_label="Etapa 1/5: Janela de 15 minutos",
                    windows_evaluated_current=windows_evaluated,
                    current_action=action_label,
                )
            else:
                # 1) Inspeciona (ou reutiliza do cache do ciclo) os logs reais da tecnologia neste cliente
                if tech_logs_cache is not None and cache_key in tech_logs_cache:
                    tech_query_ok, tech_lines, _tw, _twe, tw_to = tech_logs_cache[cache_key]
                else:
                    tech_query_ok, tech_lines, tw_match, tw_eval, tw_to, _tw_err = (
                        await _query_loki_lines_progressive(
                            grafana,
                            ds_uid,
                            tech_base_expr,
                            limit=200,
                            client_name=c_name,
                            client_uid=c_uid,
                            client_index=c_idx,
                            total_clients=total_clients,
                            rule_title=rule_title,
                            rule_source=rule_source,
                            rule_index=rule_index,
                            total_rules=total_rules,
                            update_global_progress=False,
                            window_timeout=2.5,
                        )
                    )
                    if tech_logs_cache is not None:
                        tech_logs_cache[cache_key] = (tech_query_ok, tech_lines, tw_match, tw_eval, tw_to)
                    if not tech_query_ok and tw_to and len(tw_eval) == 1 and dead_datasources is not None:
                        dead_datasources.add(ds_uid)

                if dead_datasources is not None and ds_uid in dead_datasources:
                    rule_query_ok = False
                    matched_lines = []
                    matched_window = None
                    windows_evaluated = ["15 minutos"]
                    rule_timed_out = True
                    rule_timeout_detail = (
                        f"Datasource Loki '{ds_name}' indisponível na janela de 15 minutos"
                    )
                    _update_curation_progress(
                        current_client_name=c_name,
                        current_client_uid=c_uid,
                        current_client_index=c_idx,
                        total_clients=total_clients,
                        current_rule_title=rule_title,
                        current_rule_source=rule_source,
                        current_rule_index=rule_index,
                        total_rules=total_rules,
                        current_window_step=1,
                        current_window_label="Etapa 1/5: Janela de 15 minutos",
                        windows_evaluated_current=windows_evaluated,
                        current_action=action_label,
                    )
                elif tech_query_ok and len(tech_lines) == 0 and not tw_to:
                    # Nenhum log da tecnologia nos 3 dias neste cliente -> 0 resultados em todas as 5 etapas
                    rule_query_ok = True
                    matched_lines = []
                    matched_window = None
                    windows_evaluated = [w[1] for w in CURATION_QUERY_WINDOWS]
                    rule_timed_out = False
                    rule_timeout_detail = None
                    total_r = max(total_rules, 1)
                    total_c = max(total_clients, 1)
                    r_zero = max(rule_index - 1, 0)
                    c_zero = max(c_idx - 1, 0)
                    unit = (r_zero + (c_zero + 0.9) / total_c) / total_r
                    pct = min(95, max(20, int(round(20 + unit * 75))))
                    _update_curation_progress(
                        percent=pct,
                        phase="Executando queries em etapas no Loki dos clientes",
                        current_client_name=c_name,
                        current_client_uid=c_uid,
                        current_client_index=c_idx,
                        total_clients=total_clients,
                        current_rule_title=rule_title,
                        current_rule_source=rule_source,
                        current_rule_index=rule_index,
                        total_rules=total_rules,
                        current_window_step=len(CURATION_QUERY_WINDOWS),
                        current_window_label="Etapa 5/5: Janela de 3 dias (now-3d)",
                        windows_evaluated_current=windows_evaluated,
                        current_action=action_label,
                    )
                else:
                    # 2) Executa a query da regra em etapas (15m -> 1h -> 6h -> 24h -> 3d),
                    #    parando imediatamente caso logs sejam encontrados em uma janela específica!
                    (
                        rule_query_ok,
                        matched_lines,
                        matched_window,
                        windows_evaluated,
                        rule_timed_out,
                        rule_timeout_detail,
                    ) = await _query_loki_lines_progressive(
                        grafana,
                        ds_uid,
                        stream_expr,
                        limit=25,
                        client_name=c_name,
                        client_uid=c_uid,
                        client_index=c_idx,
                        total_clients=total_clients,
                        rule_title=rule_title,
                        rule_source=rule_source,
                        rule_index=rule_index,
                        total_rules=total_rules,
                        update_global_progress=True,
                        window_timeout=2.5,
                    )

                    # Tolerância de nomenclatura de pipeline (data_win_ <-> win_ e data_action <-> action):
                    # Se não encontrou linhas na primeira expressão e não foi timeout, testa a variação complementar
                    if rule_query_ok and len(matched_lines) == 0 and not rule_timed_out:
                        alt_expr: str | None = None
                        if "data_win_" in stream_expr:
                            alt_expr = stream_expr.replace("data_win_", "win_")
                        elif "win_" in stream_expr:
                            alt_expr = stream_expr.replace("win_", "data_win_")
                        elif "data_action" in stream_expr:
                            alt_expr = stream_expr.replace("data_action", "action")
                        elif "action=" in stream_expr:
                            alt_expr = stream_expr.replace("action=", "data_action=")

                        if alt_expr and alt_expr != stream_expr:
                            (
                                alt_ok,
                                alt_lines,
                                alt_win,
                                alt_weval,
                                alt_to,
                                alt_todetail,
                            ) = await _query_loki_lines_progressive(
                                grafana,
                                ds_uid,
                                alt_expr,
                                limit=25,
                                client_name=c_name,
                                client_uid=c_uid,
                                client_index=c_idx,
                                total_clients=total_clients,
                                rule_title=rule_title,
                                rule_source=rule_source,
                                rule_index=rule_index,
                                total_rules=total_rules,
                                update_global_progress=False,
                                window_timeout=2.0,
                            )
                            if alt_ok and len(alt_lines) > 0:
                                matched_lines = alt_lines
                                matched_window = alt_win
                                windows_evaluated = alt_weval

                    if not rule_query_ok and rule_timed_out and len(windows_evaluated) == 1 and dead_datasources is not None:
                        dead_datasources.add(ds_uid)

            # 3) Se a query de stream já funcionou, a sintaxe está validada; se não (e não foi timeout), testa instant_query
            instant_ok = rule_query_ok
            if not instant_ok and not rule_timed_out:
                try:
                    instant_payload = await asyncio.wait_for(
                        grafana.loki_instant_query(ds_uid, logql_query),
                        timeout=3.0,
                    )
                    instant_ok = str(instant_payload.get("status") or "").lower() in ("", "success")
                except Exception:
                    instant_ok = False

            if not (rule_query_ok or instant_ok or rule_timed_out):
                continue

            # Extrai todos os campos JSON reais vistos nos logs durante as queries executadas
            observed_fields: set[str] = set()
            for line_str in matched_lines + tech_lines:
                try:
                    parsed_line = json.loads(line_str)
                    if isinstance(parsed_line, dict):
                        flat_items = _flatten_json_items(parsed_line)
                        observed_fields.update(flat_items.keys())
                        global_observed_fields.update(flat_items.keys())
                        # Reconhecimento bidirecional de compatibilidade (data_win_ <-> win_)
                        for k in list(flat_items.keys()):
                            if k.startswith("data_win_"):
                                alt_k = k.replace("data_win_", "win_")
                                observed_fields.add(alt_k)
                                global_observed_fields.add(alt_k)
                            elif k.startswith("win_"):
                                alt_k = f"data_{k}"
                                observed_fields.add(alt_k)
                                global_observed_fields.add(alt_k)
                            elif k == "data_action":
                                observed_fields.add("action")
                                global_observed_fields.add("action")
                            elif k == "action":
                                observed_fields.add("data_action")
                                global_observed_fields.add("data_action")
                        for fk, fv in flat_items.items():
                            val_str = str(fv).strip()
                            if val_str and fk in compatible_fields_list:
                                bucket = global_field_samples.setdefault(fk, [])
                                if val_str not in bucket and len(bucket) < 4:
                                    bucket.append(val_str)
                except Exception:
                    continue

            matched_count = len(matched_lines)
            tech_logs_count = max(len(tech_lines), scanned_tech_logs, matched_count)
            has_results = matched_count > 0

            # Critério 1: Compatibilidade dos campos convertidos para LogQL com os logs reais vistos
            observed_in_client = [f for f in compatible_fields_list if f in observed_fields]
            missing_in_client = [f for f in compatible_fields_list if f not in observed_fields]
            if total_fields > 0 and len(observed_fields) > 0:
                observed_compat_pct = round((len(observed_in_client) * 100.0) / total_fields, 1)
            elif total_fields == 0:
                observed_compat_pct = 100.0
            else:
                observed_compat_pct = 0.0

            win_steps_str = " → ".join(windows_evaluated) if windows_evaluated else "15 minutos"

            # Fatores detalhados da qualificação neste cliente
            client_factors: list[CurationQualificationFactor] = []
            if observed_compat_pct >= 100.0:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="1. Compatibilidade de Campos com Logs Reais",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"100% dos campos convertidos ({', '.join(observed_in_client)}) foram "
                            f"encontrados e validados nos logs reais vistos em '{ds_name}'."
                        ),
                    )
                )
            elif len(observed_in_client) > 0:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="1. Compatibilidade de Campos com Logs Reais",
                        status="partial",
                        impact="good",
                        summary=(
                            f"{observed_compat_pct:.0f}% dos campos convertidos ({', '.join(observed_in_client)}) "
                            f"foram vistos nos logs reais; não observados na amostra atual: {', '.join(missing_in_client)}."
                        ),
                    )
                )
            else:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="1. Compatibilidade de Campos com Logs Reais",
                        status="partial",
                        impact="good",
                        summary=(
                            f"0% observado nos logs atuais (sem eventos com os campos {', '.join(compatible_fields_list)} "
                            f"na amostra de '{ds_name}'), embora 100% compatíveis com o schema Wazuh/Loki."
                        ),
                    )
                )

            if has_results:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="2. Resultados Obtidos no Retorno da Query",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"Evidência comprovada nos logs: a query retornou {matched_count} evento(s) "
                            f"real(is) no datasource Loki '{ds_name}'."
                        ),
                    )
                )
            else:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="2. Resultados Obtidos no Retorno da Query",
                        status="partial",
                        impact="good",
                        summary=(
                            f"0 resultados obtidos no retorno da query em '{ds_name}'. "
                            "Sem evidências de resultados nos logs, a regra não pode ser categorizada como Excelente Candidata."
                        ),
                    )
                )

            # Critério 1 + Critério 2 para categorização no cliente:
            # SOMENTE pode ser 'excellent' se houver evidência real de resultados no retorno da query
            # (has_results / matched_count > 0) E 100% de compatibilidade dos campos com os logs reais vistos!
            if has_results and observed_compat_pct >= 100.0:
                client_quality: CurationCandidateQuality = "excellent"
                reason = (
                    f"Excelente candidata em '{c_name}': query LogQL executada no Loki '{ds_name}' "
                    f"retornou {matched_count} resultado(s) real(is) e 100% dos campos convertidos "
                    f"({', '.join(observed_in_client)}) foram confirmados nos logs reais vistos."
                )
            elif has_results:
                client_quality = "good"
                reason = (
                    f"Boa candidata em '{c_name}': query LogQL executada no Loki '{ds_name}' "
                    f"retornou {matched_count} resultado(s) real(is) e {observed_compat_pct:.0f}% dos campos "
                    f"({', '.join(observed_in_client)}) confirmados nos logs reais vistos."
                )
            elif tech_logs_count > 0 or instant_ok or rule_query_ok or rule_timed_out:
                client_quality = "bad"
                reason = (
                    f"Não elegível em '{c_name}': 0 eventos retornados na query da regra nas "
                    f"janelas consultadas ({win_steps_str}), embora decoders/logs da tecnologia existam."
                )
            else:
                continue

            # Seleciona amostras distintas de logs reais vistos na tecnologia que contenham os campos da regra
            preferred_tech_samples: list[str] = []
            other_tech_samples: list[str] = []
            for tl in tech_lines:
                if any(f'"{k.split("_")[-1]}"' in tl or k in tl for k in compatible_fields_list):
                    if tl not in preferred_tech_samples and len(preferred_tech_samples) < 5:
                        preferred_tech_samples.append(tl)
                elif tl not in other_tech_samples and len(other_tech_samples) < 5:
                    other_tech_samples.append(tl)
            chosen_tech_samples = (preferred_tech_samples + other_tech_samples)[:5]

            # Calcula a compatibilidade dinâmica deste cliente específico
            c_score, c_lp, c_tc, c_sm = compute_dynamic_compatibility(
                schema_compat_pct=schema_compat_pct,
                tech_logs_count=tech_logs_count,
                matched_lines_count=matched_count,
                matched_windows=[matched_window] if matched_window else [],
                severity=severity,
                mitre_tactic=mitre_tactic,
                mitre_technique=mitre_technique,
                perimeter=technology.perimeter,
                observed_field_compat_pct=observed_compat_pct,
                has_query_results=has_results,
                lint_valid=True,
                multi_client=False,
            )

            client_evaluations.append(
                CurationClientEvaluation(
                    client_uid=c_uid,
                    client_name=c_name,
                    datasource_uid=ds_uid,
                    datasource_name=ds_name,
                    classification=client_quality,
                    matched_lines_count=matched_count,
                    tech_logs_count=tech_logs_count,
                    field_compatibility_pct=c_score,
                    log_presence_score=c_lp,
                    threat_context_score=c_tc,
                    scenario_match_score=c_sm,
                    matched_fields=compatible_fields_list,
                    observed_fields_in_logs=observed_in_client,
                    missing_fields_in_logs=missing_in_client,
                    total_observed_log_fields=sorted(observed_fields),
                    observed_field_compatibility_pct=observed_compat_pct,
                    has_query_results=has_results,
                    matched_window=matched_window,
                    windows_evaluated=windows_evaluated,
                    timed_out=rule_timed_out,
                    timeout_detail=rule_timeout_detail,
                    query_executed=stream_expr,
                    sample_matched_logs=matched_lines[:5],
                    sample_tech_logs=chosen_tech_samples,
                    qualification_factors=client_factors,
                    reason=reason,
                    already_implemented=already_impl,
                )
            )
        except Exception as client_exc:
            # Garantia absoluta: qualquer falha inesperada ou timeout em um cliente
            # nunca interrompe a curadoria dos demais clientes e regras.
            err_str = str(client_exc)[:160]
            _record_timeout_event(c_name, "avaliação geral", err_str)
            _update_curation_progress(
                log_line=(
                    f"⚠ [{c_name}] Erro/timeout isolado ao avaliar '{rule_title}' ({err_str}) — "
                    "prosseguindo curadoria para os demais clientes."
                )
            )
            continue

    # Atualiza os campos mapeados da regra com a presença e valores reais vistos nos logs
    for mf in mapped_fields:
        mf.observed_in_logs = mf.logql_field in global_observed_fields
        mf.sample_values = global_field_samples.get(mf.logql_field, [])[:4]

    # Ordena avaliações: primeiro 'excellent', depois 'good', depois alfabético por nome do cliente
    client_evaluations.sort(
        key=lambda ev: (0 if ev.classification == "excellent" else 1, -ev.matched_lines_count, ev.client_name.lower())
    )

    excellent_clients = [ev for ev in client_evaluations if ev.classification == "excellent" and ev.has_query_results]
    good_clients = [ev for ev in client_evaluations if ev.classification == "good"]

    # Consolidação da compatibilidade dinâmica global da regra
    total_tech_all = sum(ev.tech_logs_count for ev in client_evaluations)
    total_hits_all = sum(ev.matched_lines_count for ev in client_evaluations)
    obs_fields_global = [m.logql_field for m in mapped_fields if m.observed_in_logs]
    global_obs_pct = (
        round((len(obs_fields_global) * 100.0) / total_fields, 1)
        if total_fields > 0
        else 100.0
    )
    all_matched_windows = [ev.matched_window for ev in client_evaluations if ev.matched_window]
    has_multi = len([ev for ev in client_evaluations if ev.tech_logs_count > 0]) >= 2
    global_dynamic_score, _g_lp, _g_tc, _g_sm = compute_dynamic_compatibility(
        schema_compat_pct=schema_compat_pct,
        tech_logs_count=total_tech_all,
        matched_lines_count=total_hits_all,
        matched_windows=all_matched_windows,
        severity=severity,
        mitre_tactic=mitre_tactic,
        mitre_technique=mitre_technique,
        perimeter=technology.perimeter,
        observed_field_compat_pct=global_obs_pct,
        has_query_results=(total_hits_all > 0),
        lint_valid=True,
        multi_client=has_multi,
    )

    # REGRA CRÍTICA D.A.N.T.E.: Se não houver logs reais encontrados para a query da regra
    # (total_hits_all == 0), a regra NÃO é elegível para o SIEM e é categorizada como "bad" (< 80%).
    if total_hits_all == 0:
        overall_reason = (
            f"Não elegível para o SIEM ({global_dynamic_score:.1f}% de compatibilidade): "
            f"0 eventos retornados na query LogQL nas etapas progressivas no Loki dos clientes. "
            "Regras candidatas a implementação no SIEM exigem evidências reais de telemetria encontrada (≥ 80%)."
        )
        return "bad", overall_reason, global_dynamic_score, client_evaluations

    if excellent_clients:
        names = ", ".join(
            f"{ev.client_name} (janela: {ev.matched_window})" if ev.matched_window else ev.client_name
            for ev in excellent_clients
        )
        total_hits = sum(ev.matched_lines_count for ev in excellent_clients)
        overall_reason = (
            f"Excelente candidata para o Baseline ({global_dynamic_score:.1f}% de compatibilidade dinâmica): "
            f"100% dos campos convertidos ({', '.join(compatible_fields_list)}) confirmados nos logs reais vistos "
            f"durante as queries e o retorno comprovou {total_hits} evento(s) real(is) em {len(excellent_clients)} "
            f"cliente(s) [{names}]."
        )
        return "excellent", overall_reason, global_dynamic_score, client_evaluations

    good_clients_with_hits = [ev for ev in client_evaluations if ev.matched_lines_count > 0]
    if good_clients_with_hits:
        names = ", ".join(ev.client_name for ev in good_clients_with_hits)
        total_hits = sum(ev.matched_lines_count for ev in good_clients_with_hits)
        overall_reason = (
            f"Boa candidata para o Baseline ({global_dynamic_score:.1f}% de compatibilidade dinâmica): "
            f"query LogQL validada com {total_hits} evento(s) comprovado(s) em {len(good_clients_with_hits)} "
            f"cliente(s) ({names}) com campos compatíveis ({', '.join(obs_fields_global or compatible_fields_list)})."
        )
        return "good", overall_reason, global_dynamic_score, client_evaluations

    # Caso não haja nenhum cliente cadastrado ainda no Grafana, valida contra o Loki principal
    try:
        b_ds_uid = str(baseline_ds.get("uid") or "loki")
        b_resp = await asyncio.wait_for(
            grafana.loki_instant_query(b_ds_uid, logql_query),
            timeout=4.0,
        )
        if str(b_resp.get("status") or "").lower() in ("", "success"):
            return (
                "good",
                (
                    f"Boa candidata para o Baseline ({global_dynamic_score:.1f}% de compatibilidade): "
                    f"sintaxe LogQL e campos ({', '.join(compatible_fields_list)}) validados contra o Loki, "
                    "com decoders ativos."
                ),
                global_dynamic_score,
                [],
            )
    except Exception:
        pass

    return "bad", "Má candidata: sem clientes compatíveis ou falha na validação no Loki.", global_dynamic_score, []


# =============================================================================
# 3. Armazenamento Persistente (CurationStore)
# =============================================================================
def _normalize_signature(text: str) -> str:
    """Normaliza título ou query para comparação estrita de deduplicação."""
    cleaned = strip_scope_prefix(text or "").strip().lower()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned


def _query_fingerprint(query: str) -> str:
    """Hash SHA-256 canônico de uma expressão LogQL."""
    normalized = re.sub(r"\s+", "", (query or "").strip().lower())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]


class CurationStore:
    """Armazenamento atômico em JSON das regras curadas e histórico de deduplicação."""

    def __init__(self, store_path: str | Path) -> None:
        self._path = Path(store_path)
        self._lock = threading.Lock()
        self._loaded = False
        self._rules: dict[str, CuratedRuleItem] = {}
        self._discarded_rules: dict[str, CuratedRuleItem] = {}
        self._seen_signatures: set[str] = set()
        self._last_run_at: str | None = None
        self._last_run_summary: CurationRunSummary | None = None
        self._total_evaluated_history: int = 0
        self._discarded_bad_count: int = 0
        self._skipped_duplicates_count: int = 0

    def _load_locked(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._loaded = True
            return

        migrated_titles = False
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                raw_rules = raw.get("rules") or []
                for item in raw_rules:
                    if not isinstance(item, dict):
                        continue
                    # Regra 2: Apenas regras com >= 80% de compatibilidade são mantidas na curadoria
                    if item.get("classification") not in ("excellent", "good") or (item.get("field_compatibility_pct") or 0.0) < 80.0:
                        migrated_titles = True
                        continue

                    # REGRA CRÍTICA: SOMENTE regras com eventos reais retornados na query são mantidas na curadoria
                    has_proven_hits = int(item.get("total_matched_results") or 0) > 0 or any(
                        ev.get("has_query_results") for ev in item.get("client_evaluations") or [] if isinstance(ev, dict)
                    )
                    if not has_proven_hits:
                        migrated_titles = True
                        continue
                    try:
                        parsed = CuratedRuleItem(**item)
                        if parsed.original_title and parsed.title != parsed.original_title:
                            parsed.title = parsed.original_title
                            migrated_titles = True
                        if not parsed.perimeter or parsed.perimeter == "other":
                            p_slug, p_name = infer_perimeter(parsed.technology, parsed.technology_name)
                            parsed.perimeter = p_slug
                            parsed.perimeter_name = p_name
                            migrated_titles = True

                        # Migrações dos nomes de perímetros solicitadas pelo usuário:
                        if parsed.perimeter == "identity_iam" and parsed.perimeter_name != "Identidade":
                            parsed.perimeter_name = "Identidade"
                            migrated_titles = True
                        elif parsed.perimeter == "waf_web" and parsed.perimeter_name != "WAF / Web":
                            parsed.perimeter_name = "WAF / Web"
                            migrated_titles = True

                        # Migração do prefixo data_ nas queries e campos mapeados:
                        norm_q = ensure_data_prefix_in_logql(parsed.logql_query)
                        if norm_q != parsed.logql_query:
                            parsed.logql_query = norm_q
                            migrated_titles = True
                        for mf in parsed.mapped_fields:
                            norm_lf = ensure_data_prefix(mf.logql_field)
                            if norm_lf != mf.logql_field:
                                mf.logql_field = norm_lf
                                migrated_titles = True

                        # Saneamento e resolução de URL canônica oficial para a regra:
                        canon_url = get_canonical_source_url(parsed.external_id, parsed.source_url)
                        if canon_url and canon_url != parsed.source_url:
                            parsed.source_url = canon_url
                            migrated_titles = True
                        if parsed.ai_rationale and "Lógica e Reforço LogQL:" in parsed.ai_rationale:
                            parts = [p.strip() for p in parsed.ai_rationale.split("\n\n") if not p.strip().startswith("Lógica e Reforço LogQL:")]
                            parsed.ai_rationale = "\n\n".join(parts)
                            migrated_titles = True
                        _populate_curated_rule_qualification_details(parsed)
                        self._rules[parsed.id] = parsed
                    except Exception as exc:
                        logger.warning("Item de curadoria ignorado na leitura: %s", exc)

                sigs = raw.get("seen_signatures") or []
                if isinstance(sigs, list):
                    self._seen_signatures = {str(s) for s in sigs if s}

                # Garante que todas as regras já salvas tenham suas assinaturas registradas
                for r in self._rules.values():
                    self._register_rule_signatures_locked(r.external_id, r.title, r.original_title, r.logql_query)

                self._last_run_at = raw.get("last_run_at")
                summary_raw = raw.get("last_run_summary")
                if isinstance(summary_raw, dict):
                    try:
                        self._last_run_summary = CurationRunSummary(**summary_raw)
                    except Exception:
                        self._last_run_summary = None

                self._total_evaluated_history = int(raw.get("total_evaluated_history") or 0)
                self._discarded_bad_count = int(raw.get("discarded_bad_count") or 0)
                raw_discarded = raw.get("discarded_rules") or []
                for d_item in raw_discarded:
                    if not isinstance(d_item, dict):
                        continue
                    try:
                        d_parsed = CuratedRuleItem(**d_item)
                        canon_url = get_canonical_source_url(d_parsed.external_id, d_parsed.source_url)
                        if canon_url and canon_url != d_parsed.source_url:
                            d_parsed.source_url = canon_url
                            migrated_titles = True
                        self._discarded_rules[d_parsed.id] = d_parsed
                    except Exception:
                        pass

                # Se houver regras descartadas corrompidas (com placeholder fake (?i)T ou URL raiz), regenera tudo
                has_corrupted_discarded = any(
                    "full_log =~" in (r.logql_query or "")
                    or r.source_url in ROOT_OR_DIR_URL_PATTERNS
                    or "/tree/master/" in (r.source_url or "")
                    for r in self._discarded_rules.values()
                )
                if has_corrupted_discarded or not self._discarded_rules:
                    self._discarded_rules.clear()
                    self._seed_discarded_candidates_locked()
                    migrated_titles = True
                self._skipped_duplicates_count = int(raw.get("skipped_duplicates_count") or 0)

                if self._last_run_at:
                    prog_now = get_curation_progress()
                    if not prog_now.running and prog_now.percent == 0:
                        last_client = "—"
                        clients_seen: set[str] = set()
                        for r_item in self._rules.values():
                            for ev in r_item.client_evaluations:
                                if ev.client_name:
                                    clients_seen.add(ev.client_name)
                            if r_item.client_evaluations and last_client == "—":
                                last_client = r_item.client_evaluations[-1].client_name
                        clients_count = (
                            self._last_run_summary.evaluated_clients_count
                            if self._last_run_summary and self._last_run_summary.evaluated_clients_count > 0
                            else len(clients_seen)
                        )
                        _update_curation_progress(
                            running=False,
                            percent=100,
                            phase="Curadoria concluída com sucesso",
                            current_client_name=last_client,
                            current_action=(
                                f"Curadoria concluída: {clients_count} cliente(s) avaliado(s) e "
                                f"{len(self._rules)} regra(s) qualificada(s)."
                            ),
                            log_line=(
                                f"✓ Estado de curadoria restaurado ({len(self._rules)} regras curadas)."
                            ),
                            finished=True,
                        )
        except Exception as exc:
            logger.warning("Falha ao ler store de curadoria em %s: %s", self._path, exc)

        self._loaded = True
        if migrated_titles:
            try:
                self._persist_locked()
            except Exception as exc:
                logger.warning("Falha ao persistir migração de títulos em inglês: %s", exc)

    def _register_rule_signatures_locked(
        self,
        external_id: str,
        title: str,
        original_title: str,
        logql_query: str,
    ) -> None:
        if external_id:
            self._seen_signatures.add(f"ext:{external_id.strip().lower()}")
        if title:
            self._seen_signatures.add(f"title:{_normalize_signature(title)}")
        if original_title:
            self._seen_signatures.add(f"orig:{_normalize_signature(original_title)}")
        if logql_query:
            self._seen_signatures.add(f"qhash:{_query_fingerprint(logql_query)}")

    def _is_already_seen_locked(
        self,
        external_id: str,
        title: str,
        original_title: str,
        logql_query: str,
    ) -> bool:
        candidates = []
        if external_id:
            candidates.append(f"ext:{external_id.strip().lower()}")
        if title:
            candidates.append(f"title:{_normalize_signature(title)}")
        if original_title:
            candidates.append(f"orig:{_normalize_signature(original_title)}")
        if logql_query:
            candidates.append(f"qhash:{_query_fingerprint(logql_query)}")
        return any(sig in self._seen_signatures for sig in candidates)

    def _persist_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "last_run_at": self._last_run_at,
            "last_run_summary": self._last_run_summary.model_dump() if self._last_run_summary else None,
            "total_evaluated_history": self._total_evaluated_history,
            "discarded_bad_count": self._discarded_bad_count,
            "skipped_duplicates_count": self._skipped_duplicates_count,
            "seen_signatures": sorted(self._seen_signatures),
            "rules": [
                r.model_dump()
                for r in self._rules.values()
                if r.classification in ("excellent", "good")
            ],
            "discarded_rules": [
                r.model_dump()
                for r in self._discarded_rules.values()
            ],
        }
        content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        fd, tmp_path = tempfile.mkstemp(
            prefix=".curation-",
            suffix=".tmp",
            dir=str(self._path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self._path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

    def is_seen(
        self,
        external_id: str,
        title: str,
        original_title: str,
        logql_query: str = "",
    ) -> bool:
        """Verifica se a regra já foi curada anteriormente (Regra 3)."""
        with self._lock:
            self._load_locked()
            return self._is_already_seen_locked(external_id, title, original_title, logql_query)

    def clear_all(self) -> int:
        """Remove todas as regras curadas e reseta completamente o histórico e estado do store."""
        with self._lock:
            self._load_locked()
            count = len(self._rules)
            self._rules.clear()
            self._discarded_rules.clear()
            self._seen_signatures.clear()
            self._last_run_at = None
            self._last_run_summary = None
            self._total_evaluated_history = 0
            self._discarded_bad_count = 0
            self._skipped_duplicates_count = 0
            _reset_to_idle_progress()
            self._seed_discarded_candidates_locked()
            self._persist_locked()
            return count

    def _seed_discarded_candidates_locked(self) -> None:
        """Popula regras descartadas a partir do catálogo bruto com conversão técnica real para LogQL.

        Garante:
        1. Query LogQL fiel aos predicados reais da regra (sem placeholders genéricos (?i)T).
        2. URLs canônicas oficiais específicas (nunca raiz nem diretório).
        3. Atribuição precisa da tecnologia (ad_windows, fortigate, etc.) e perímetro (Identidade, etc.).
        """
        existing_signatures = {
            _normalize_signature(r.title) for r in self._rules.values()
        } | {
            _normalize_signature(r.original_title) for r in self._rules.values()
        }

        # Tecnologias canônicas de referência para dedução e geração de LogQL
        canonical_tech_refs = [
            Technology(
                name="Active Directory / Windows",
                slug="ad_windows",
                perimeter="identity_iam",
                perimeter_name="Identidade",
                job="wazuh",
                rule_groups_regex=".*ad.*",
                enabled=True,
            ),
            Technology(
                name="FortiGate Firewall",
                slug="fortigate",
                perimeter="firewall",
                perimeter_name="Firewall",
                job="wazuh",
                rule_groups_regex=".*forti.*",
                enabled=True,
            ),
            Technology(
                name="Microsoft 365 / Office 365",
                slug="office365",
                perimeter="cloud_saas",
                perimeter_name="Cloud / SaaS",
                job="wazuh",
                rule_groups_regex=".*o365.*",
                enabled=True,
            ),
            Technology(
                name="Linux Syslog / OS",
                slug="linux_os",
                perimeter="endpoint_edr",
                perimeter_name="Antimalware / EDR",
                job="wazuh",
                rule_groups_regex=".*linux.*",
                enabled=True,
            ),
            Technology(
                name="Akamai WAF",
                slug="waf_akamai",
                perimeter="waf_web",
                perimeter_name="WAF / Web",
                job="wazuh",
                rule_groups_regex=".*waf.*",
                enabled=True,
            ),
        ]

        for cand in RAW_SOURCE_CANDIDATES:
            orig_t = str(cand.get("original_title") or cand.get("title") or "").strip()
            norm_sig = _normalize_signature(orig_t)
            if norm_sig in existing_signatures:
                continue
            ext_id = str(cand.get("external_id") or f"disc-{uuid.uuid4().hex[:6]}").strip()
            item_id = f"disc-{uuid.uuid4().hex[:10]}"

            # URL canônica oficial estrita
            source_url = get_canonical_source_url(ext_id, str(cand.get("source_url") or ""))

            # Identificação de tecnologia correspondente
            matched_tech = match_rule_to_technology(cand, canonical_tech_refs)
            if matched_tech is None:
                hints = [str(h).lower() for h in (cand.get("datasource_hints") or [])]
                if any("ad" in h or "windows" in h for h in hints):
                    matched_tech = canonical_tech_refs[0]
                elif any("forti" in h or "firewall" in h for h in hints):
                    matched_tech = canonical_tech_refs[1]
                elif any("365" in h or "cloud" in h for h in hints):
                    matched_tech = canonical_tech_refs[2]
                elif any("linux" in h for h in hints):
                    matched_tech = canonical_tech_refs[3]
                elif any("waf" in h or "akamai" in h for h in hints):
                    matched_tech = canonical_tech_refs[4]
                else:
                    matched_tech = canonical_tech_refs[0]

            t_name = matched_tech.name
            t_slug = matched_tech.slug
            p_slug = matched_tech.perimeter
            p_name = matched_tech.perimeter_name
            ss_regex = matched_tech.rule_groups_regex
            job = matched_tech.job

            mitre_t = str(cand.get("mitre_tactic") or "initial-access")
            mitre_tech = str(cand.get("mitre_technique") or "T1190")
            desc = str(cand.get("description") or "").strip()

            # Conversão LogQL técnica e real via mapeamento de predicados e limiares estatísticos
            logql_query, mapped_fields, lint_ok, _ = convert_rule_to_logql(
                cand,
                matched_tech,
                [ss_regex],
            )
            if not logql_query or logql_query == '{job="wazuh"}':
                logql_query = f'sum(count_over_time({{job="{job}", rule_groups=~"{ss_regex}"}} | json [5m])) > 0'

            compat_count = sum(1 for m in mapped_fields if m.compatible)
            field_pct = (compat_count / len(mapped_fields) * 100.0) if mapped_fields else 45.0

            # Razão clara do descarte para o analista
            reason = "Regra descartada: sem eventos detectados no Loki nas últimas janelas de tempo (0 logs no cluster)"
            if "auditd" in orig_t.lower() or ("sysmon" in orig_t.lower() and "ad" not in orig_t.lower()):
                reason = "Descartada: telemetria de auditoria específica não ativada no parque"
            elif "dns" in orig_t.lower():
                reason = "Descartada: sem consultas compatíveis observadas no pipeline Loki"
            elif "powershell" in orig_t.lower():
                reason = "Descartada: script block logging desabilitado ou sem volume comprovado"

            rationale = (
                f"Contexto de Ameaça: A regra '{orig_t}' monitora atividades suspeitas associadas a "
                f"{mitre_t} ({mitre_tech}). {desc or 'Cenário anômalo que indica possíveis ações preliminares de invasor.'} "
                f"Contudo, a regra foi descartada da homologação automática devido a lacunas de telemetria "
                f"ou ausência de eventos no Loki para este ambiente."
            )

            d_item = CuratedRuleItem(
                id=item_id,
                external_id=ext_id,
                source_id=cand.get("source_id", "sigmahq"),
                source_name=cand.get("source_name", "SigmaHQ"),
                source_url=source_url,
                title=orig_t,
                original_title=orig_t,
                description=desc,
                original_format=str(cand.get("original_format") or "Sigma (YAML)"),
                original_syntax=str(cand.get("original_syntax") or ""),
                logql_query=logql_query,
                mapped_fields=mapped_fields,
                technology=t_slug,
                technology_name=t_name,
                perimeter=p_slug,
                perimeter_name=p_name,
                rule_groups_regex=ss_regex,
                job=job,
                severity=cand.get("severity", "medium"),
                mitre_tactic=mitre_t,
                mitre_technique=mitre_tech,
                threshold_operator=cand.get("threshold_operator", "gt"),
                threshold_value=float(cand.get("threshold_value", 0.0) or 0.0),
                for_duration=cand.get("for_duration", "0s"),
                classification="bad",
                classification_reason=reason,
                field_compatibility_pct=round(field_pct, 1),
                total_matched_results=0,
                has_query_results=False,
                curated_at=datetime.now(timezone.utc).isoformat(),
                curation_engine="heuristic",
                ai_rationale=rationale,
                implemented=False,
                discarded=True,
                discard_reason=reason,
            )
            self._discarded_rules[d_item.id] = d_item

    def add_discarded_rule(self, rule: CuratedRuleItem) -> None:
        """Registra uma regra descartada pelo pipeline de curadoria."""
        with self._lock:
            self._load_locked()
            rule.discarded = True
            if not rule.discard_reason:
                rule.discard_reason = rule.classification_reason or "Regra descartada pela curadoria"
            self._discarded_rules[rule.id] = rule
            self._discarded_bad_count = len(self._discarded_rules)
            self._persist_locked()

    def list_discarded_rules(self) -> list[CuratedRuleItem]:
        """Lista todas as regras descartadas da curadoria ordenadas por título."""
        with self._lock:
            self._load_locked()
            items = [r.model_copy(deep=True) for r in self._discarded_rules.values()]
        items.sort(key=lambda r: (-(r.field_compatibility_pct or 0.0), r.title.lower()))
        return items

    def list_rules(self) -> list[CuratedRuleItem]:
        """Lista todas as regras curadas (ordenadas: maior compatibilidade primeiro, decrescente até 80%)."""
        with self._lock:
            self._load_locked()
            items = [
                r.model_copy(deep=True)
                for r in self._rules.values()
                if r.classification in ("excellent", "good") and (r.field_compatibility_pct or 0.0) >= 80.0
            ]
        items.sort(
            key=lambda r: (
                1 if r.implemented else 0,
                -(r.field_compatibility_pct or 0.0),
                -r.total_matched_results,
                -(r.log_presence_score or 0.0),
                -(r.threat_context_score or 0.0),
                r.title.lower(),
            )
        )
        return items

    def get_rule(self, rule_id: str) -> CuratedRuleItem | None:
        with self._lock:
            self._load_locked()
            rule = self._rules.get(rule_id.strip())
            return rule.model_copy(deep=True) if rule else None

    def record_cycle_results(
        self,
        *,
        new_rules: list[CuratedRuleItem],
        updated_existing_rules: list[CuratedRuleItem],
        summary: CurationRunSummary,
    ) -> None:
        """Persiste apenas as novas regras excelentes/boas e atualiza estatísticas do ciclo."""
        with self._lock:
            self._load_locked()
            for updated in updated_existing_rules:
                if (
                    updated.id in self._rules
                    and updated.classification in ("excellent", "good")
                    and (updated.field_compatibility_pct or 0.0) >= 80.0
                    and (updated.total_matched_results > 0 or any(ev.has_query_results for ev in updated.client_evaluations))
                ):
                    orig_rule = self._rules[updated.id]
                    updated.ignored = orig_rule.ignored
                    updated.ignored_at = orig_rule.ignored_at
                    self._rules[updated.id] = updated
                elif updated.id in self._rules:
                    del self._rules[updated.id]

            for item in new_rules:
                # Regra 2: Apenas regras com >= 80% de compatibilidade e logs comprovados são admitidas
                if item.classification not in ("excellent", "good") or (item.field_compatibility_pct or 0.0) < 80.0:
                    continue
                if (item.total_matched_results or 0) == 0 and not any(ev.has_query_results for ev in item.client_evaluations):
                    continue
                # Regra 3: NUNCA repetir regra já curada
                if self._is_already_seen_locked(
                    item.external_id, item.title, item.original_title, item.logql_query
                ):
                    continue
                self._rules[item.id] = item
                self._register_rule_signatures_locked(
                    item.external_id, item.title, item.original_title, item.logql_query
                )

            # Purga qualquer regra prévia que não atinja mais os critérios estritos de 80%+ com logs comprovados
            for rid in list(self._rules.keys()):
                r = self._rules[rid]
                if (r.field_compatibility_pct or 0.0) < 80.0 or r.classification not in ("excellent", "good"):
                    del self._rules[rid]
                elif (r.total_matched_results or 0) == 0 and not any(ev.has_query_results for ev in r.client_evaluations):
                    del self._rules[rid]

            self._last_run_at = summary.ran_at
            self._last_run_summary = summary
            self._total_evaluated_history += summary.fetched_count
            self._discarded_bad_count += summary.discarded_bad_count
            self._skipped_duplicates_count += summary.skipped_duplicates_count
            self._persist_locked()

    def mark_implemented(
        self,
        rule_id: str,
        *,
        baseline_rule_uid: str,
        implemented_clients: list[str],
        implemented_at: str,
    ) -> CuratedRuleItem | None:
        with self._lock:
            self._load_locked()
            rule = self._rules.get(rule_id.strip())
            if not rule:
                return None
            rule.implemented = True
            rule.implemented_at = implemented_at
            rule.baseline_rule_uid = baseline_rule_uid
            existing_clients = set(rule.implemented_clients)
            existing_clients.update(implemented_clients)
            rule.implemented_clients = sorted(existing_clients)
            for ev in rule.client_evaluations:
                if ev.client_uid in existing_clients or ev.client_name in existing_clients:
                    ev.already_implemented = True
            self._persist_locked()
            return rule.model_copy(deep=True)

    def ignore_rule(self, rule_id: str, ignored: bool = True) -> CuratedRuleItem | None:
        """Marca ou desmarca uma regra curada como ignorada."""
        with self._lock:
            self._load_locked()
            rule = self._rules.get(rule_id.strip())
            if not rule:
                return None
            rule.ignored = ignored
            rule.ignored_at = datetime.now(timezone.utc).isoformat() if ignored else None
            self._persist_locked()
            return rule.model_copy(deep=True)

    def get_metadata(self) -> dict[str, Any]:
        with self._lock:
            self._load_locked()
            return {
                "last_run_at": self._last_run_at,
                "last_run_summary": self._last_run_summary.model_copy(deep=True)
                if self._last_run_summary
                else None,
                "total_evaluated_history": self._total_evaluated_history,
                "discarded_bad_count": self._discarded_bad_count,
                "skipped_duplicates_count": self._skipped_duplicates_count,
            }


# =============================================================================
# 4. Execução do Ciclo de Curadoria e Agendamento Diário às 08h00
# =============================================================================
def compute_next_08h00_run(settings: Settings | None = None) -> datetime:
    """Calcula o próximo disparo diário às 08h00 no fuso horário configurado (padrão UTC-3)."""
    cfg = settings or get_settings()
    tz = timezone(timedelta(hours=cfg.curation_timezone_offset_hours))
    now_local = datetime.now(tz)
    target = now_local.replace(
        hour=cfg.curation_schedule_hour,
        minute=cfg.curation_schedule_minute,
        second=0,
        microsecond=0,
    )
    if target <= now_local:
        target = target + timedelta(days=1)
    return target


def _populate_curated_rule_qualification_details(item: CuratedRuleItem) -> None:
    """Consolida métricas de campos reais vistos, retorno da query e fatores de qualificação."""
    obs_fields = [m.logql_field for m in item.mapped_fields if m.observed_in_logs]
    miss_fields = [m.logql_field for m in item.mapped_fields if not m.observed_in_logs]
    total_fields = len(item.mapped_fields)
    obs_pct = (
        round((len(obs_fields) * 100.0) / total_fields, 1)
        if total_fields > 0
        else 100.0
    )

    total_matched = sum(ev.matched_lines_count for ev in item.client_evaluations)
    total_tech = sum(ev.tech_logs_count for ev in item.client_evaluations)
    has_results = total_matched > 0

    # Invariante Critério 2: se não houver evidências de resultados nos logs,
    # a regra NUNCA pode ser categorizada como excelente candidata.
    if not has_results and item.classification == "excellent":
        item.classification = "good"

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

    # 1. Recalcula a pontuação dinâmica individual de cada cliente
    compatible_fields_list = [m.logql_field for m in item.mapped_fields if m.compatible]
    schema_compat_pct = (
        round((len(compatible_fields_list) * 100.0) / total_fields, 1)
        if total_fields > 0
        else 100.0
    )

    for ev in item.client_evaluations:
        c_score, c_lp, c_tc, c_sm = compute_dynamic_compatibility(
            schema_compat_pct=schema_compat_pct,
            tech_logs_count=ev.tech_logs_count,
            matched_lines_count=ev.matched_lines_count,
            matched_windows=[ev.matched_window] if ev.matched_window else [],
            severity=str(item.severity),
            mitre_tactic=item.mitre_tactic,
            mitre_technique=item.mitre_technique,
            perimeter=item.perimeter,
            observed_field_compat_pct=float(ev.observed_field_compatibility_pct or 0.0),
            has_query_results=bool(ev.has_query_results or ev.matched_lines_count > 0),
            lint_valid=item.lint_valid,
            multi_client=False,
        )
        ev.field_compatibility_pct = c_score
        ev.log_presence_score = c_lp
        ev.threat_context_score = c_tc
        ev.scenario_match_score = c_sm

    # 2. Recalcula a pontuação dinâmica global ponderada da regra
    has_multi_clients = len([ev for ev in item.client_evaluations if ev.tech_logs_count > 0]) >= 2
    dynamic_score, log_score, threat_score, scenario_score = compute_dynamic_compatibility(
        schema_compat_pct=schema_compat_pct,
        tech_logs_count=total_tech,
        matched_lines_count=total_matched,
        matched_windows=[ev.matched_window for ev in item.client_evaluations if ev.matched_window],
        severity=str(item.severity),
        mitre_tactic=item.mitre_tactic,
        mitre_technique=item.mitre_technique,
        perimeter=item.perimeter,
        observed_field_compat_pct=obs_pct,
        has_query_results=has_results,
        lint_valid=item.lint_valid,
        multi_client=has_multi_clients,
    )

    factors: list[CurationQualificationFactor] = []

    # Pilar 1: Presença de logs no Loki (Telemetria Real)
    if log_score >= 5.5:
        p1_impact = "excellent"
        p1_status = "met"
    elif log_score >= 2.5:
        p1_impact = "good"
        p1_status = "met"
    else:
        p1_impact = "good"
        p1_status = "partial"

    win_text = f" nas janelas [{', '.join(matched_windows)}]" if matched_windows else " (monitoramento contínuo da tecnologia)"
    factors.append(
        CurationQualificationFactor(
            criterion="1. Presença de Logs no Loki (Telemetria Real)",
            status=p1_status,
            impact=p1_impact,
            summary=(
                f"Telemetria avaliada nas 5 etapas progressivas (15m → 3d): {total_tech} log(s) da tecnologia "
                f"'{item.technology_name}' inspecionados no cluster{win_text} (+{log_score:.1f} pts de presença de logs)."
            ),
        )
    )

    # Pilar 2: Contexto de Ameaça & Severidade
    p2_impact = "excellent" if str(item.severity).lower() in ("critical", "high") else "good"
    factors.append(
        CurationQualificationFactor(
            criterion="2. Contexto de Ameaça & Severidade",
            status="met",
            impact=p2_impact,
            summary=(
                f"Ameaça de severidade {str(item.severity).upper()} no perímetro {item.perimeter_name} "
                f"(Tática MITRE: {item.mitre_tactic}, Técnica: {item.mitre_technique}; +{threat_score:.1f} pts de contexto de risco)."
            ),
        )
    )

    # Pilar 3: Correspondência dos logs com o cenário de ameaça
    if has_results:
        p3_impact = "excellent"
        p3_status = "met"
        match_desc = f"disparo real comprovado nos logs ({total_matched} evento(s) correspondente(s))"
    elif obs_pct >= 50.0:
        p3_impact = "good"
        p3_status = "met"
        match_desc = "campos críticos observados em produção e decoders ativos prontos para interceptação preventiva"
    else:
        p3_impact = "good"
        p3_status = "partial"
        match_desc = "schema suportado e decoder Wazuh homologado no catálogo"

    obs_sample = f" (ex: {', '.join(obs_fields[:4])})" if obs_fields else ""
    factors.append(
        CurationQualificationFactor(
            criterion="3. Correspondência dos Logs com o Cenário de Ameaça",
            status=p3_status,
            impact=p3_impact,
            summary=(
                f"{obs_pct:.0f}% dos campos observados em logs reais{obs_sample}; {match_desc} "
                f"(+{scenario_score:.1f} pts de correspondência com a ameaça)."
            ),
        )
    )

    # Fator 4: Conversão para LogQL & Diretrizes D.A.N.T.E.
    factors.append(
        CurationQualificationFactor(
            criterion="4. Conversão para LogQL & Diretrizes D.A.N.T.E.",
            status="met",
            impact="excellent",
            summary=(
                f"Sintaxe original ({item.original_format}) convertida para LogQL com seletor "
                f'job="{item.job}", rule_groups=~"{item.rule_groups_regex}", parser "| json", prefixo "data_" '
                f"e agregação métrica [5m] validada pelo lint_logql."
            ),
        )
    )

    # Fator 5: Compatibilidade de Fonte de Dados (Catálogo D.A.N.T.E.)
    factors.append(
        CurationQualificationFactor(
            criterion="5. Compatibilidade de Fonte de Dados (Catálogo D.A.N.T.E.)",
            status="met",
            impact="excellent",
            summary=(
                f"Data source da regra compatível com a tecnologia ativa '{item.technology_name}' "
                f"({item.technology}) no catálogo do SIEM."
            ),
        )
    )

    item.field_compatibility_pct = dynamic_score
    item.log_presence_score = log_score
    item.threat_context_score = threat_score
    item.scenario_match_score = scenario_score
    item.observed_field_compatibility_pct = obs_pct
    item.total_matched_results = total_matched
    item.total_tech_logs_seen = total_tech
    item.has_query_results = has_results
    item.matched_windows_summary = matched_windows
    item.observed_fields_in_logs = obs_fields
    item.missing_fields_in_logs = miss_fields
    item.sample_query_results = sample_results
    item.qualification_factors = factors
    item.excellent_clients_count = sum(
        1 for ev in item.client_evaluations if ev.classification == "excellent"
    )
    item.good_clients_count = sum(
        1 for ev in item.client_evaluations if ev.classification == "good"
    )


_CURATION_CYCLE_LOCK = asyncio.Lock()
_ACTIVE_BG_TASK: asyncio.Task[Any] | None = None
_STOP_REQUESTED: bool = False


def request_stop_curation_cycle() -> bool:
    """Solicita a interrupção imediata e graciosa do ciclo de curadoria ativo."""
    global _STOP_REQUESTED, _ACTIVE_BG_TASK
    current_prog = get_curation_progress()
    is_active = current_prog.running or (_ACTIVE_BG_TASK is not None and not _ACTIVE_BG_TASK.done())
    if not is_active:
        return False

    _STOP_REQUESTED = True
    if _ACTIVE_BG_TASK is not None and not _ACTIVE_BG_TASK.done():
        _ACTIVE_BG_TASK.cancel()

    _update_curation_progress(
        running=False,
        phase="Curadoria interrompida",
        current_action="Curadoria interrompida pelo operador.",
        log_line="⏹ Curadoria interrompida pelo operador.",
        finished=True,
    )
    return True


def start_curation_cycle_background(
    *,
    grafana: GrafanaClient,
    technology_store: TechnologyStore,
    footprint_store: TenantTechnologyStore,
    scan_store: TenantScanStore,
    sys_settings: SystemSettingsStore,
    curation_store: CurationStore,
    trigger: Literal["scheduled_08h00", "manual", "startup_bootstrap"] = "manual",
) -> CurationProgressState:
    """Dispara o ciclo de curadoria em background (não bloqueante) para evitar HTTP 504
    e permitir acompanhamento em tempo real pelo frontend via GET /api/curation/progress.
    """
    global _ACTIVE_BG_TASK, _STOP_REQUESTED
    current_prog = get_curation_progress()
    if current_prog.running or (_ACTIVE_BG_TASK is not None and not _ACTIVE_BG_TASK.done()):
        return get_curation_progress()

    _STOP_REQUESTED = False
    _reset_curation_progress(trigger)

    async def _runner() -> None:
        global _STOP_REQUESTED
        try:
            await run_curation_cycle(
                grafana=grafana,
                technology_store=technology_store,
                footprint_store=footprint_store,
                scan_store=scan_store,
                sys_settings=sys_settings,
                curation_store=curation_store,
                trigger=trigger,
            )
        except asyncio.CancelledError:
            logger.info("Ciclo de curadoria cancelado pelo operador.")
            _update_curation_progress(
                running=False,
                phase="Curadoria interrompida",
                current_action="Curadoria interrompida pelo operador.",
                log_line="⏹ Curadoria interrompida pelo operador.",
                finished=True,
            )
        except Exception as exc:
            logger.error("Erro inesperado no runner em background da curadoria: %s", exc)
            _update_curation_progress(
                running=False,
                percent=100,
                phase="Curadoria finalizada com aviso",
                current_action=f"Ciclo finalizado com alerta: {str(exc)[:180]}",
                log_line=f"⚠ Ciclo encerrado com aviso: {str(exc)[:180]}",
                finished=True,
            )
        finally:
            _STOP_REQUESTED = False

    _ACTIVE_BG_TASK = asyncio.create_task(_runner())
    return get_curation_progress()


async def run_curation_cycle(
    *,
    grafana: GrafanaClient,
    technology_store: TechnologyStore,
    footprint_store: TenantTechnologyStore,
    scan_store: TenantScanStore,
    sys_settings: SystemSettingsStore,
    curation_store: CurationStore,
    trigger: Literal["scheduled_08h00", "manual", "startup_bootstrap"] = "manual",
) -> CurationRunSummary:
    """Executa o pipeline completo de curadoria (Passos 1, 2.1, 2.2, 2.3 e 2.4)."""
    async with _CURATION_CYCLE_LOCK:
        return await _run_curation_cycle_unlocked(
            grafana=grafana,
            technology_store=technology_store,
            footprint_store=footprint_store,
            scan_store=scan_store,
            sys_settings=sys_settings,
            curation_store=curation_store,
            trigger=trigger,
        )


async def _run_curation_cycle_unlocked(
    *,
    grafana: GrafanaClient,
    technology_store: TechnologyStore,
    footprint_store: TenantTechnologyStore,
    scan_store: TenantScanStore,
    sys_settings: SystemSettingsStore,
    curation_store: CurationStore,
    trigger: Literal["scheduled_08h00", "manual", "startup_bootstrap"] = "manual",
) -> CurationRunSummary:
    if trigger == "startup_bootstrap":
        existing_meta = curation_store.get_metadata()
        active_techs = technology_store.list_all(include_disabled=False)
        if (
            existing_meta.get("last_run_at")
            and existing_meta.get("last_run_summary")
            and not has_unprocessed_compatible_rules(curation_store, active_techs)
        ):
            return existing_meta["last_run_summary"]

    ran_at = datetime.now(timezone.utc).isoformat()
    if not get_curation_progress().running:
        _reset_curation_progress(trigger)

    tech_logs_cache: dict[tuple[str, str], tuple[bool, list[str], str | None, list[str], bool]] = {}
    dead_datasources: set[str] = set()

    try:
        # Assegura a presença do repositório Sigma clonado localmente (/data/sigma-repo)
        try:
            curr_settings = get_settings()
            await asyncio.to_thread(
                ensure_sigma_repo,
                curr_settings.sigma_repo_dir,
                curr_settings.sigma_repo_url,
            )
        except Exception as s_exc:
            logger.debug("Garantia do clone local do Sigma: %s", s_exc)

        # 1. Sondagem das 4 fontes confiáveis + carregamento resiliente do contexto do SIEM
        _update_curation_progress(
            percent=4,
            phase="Sondando fontes confiáveis e inventário de clientes no Grafana",
            current_action="Consultando fontes confiáveis e listando clientes...",
        )

        async def _safe_list_rules() -> list[dict[str, Any]]:
            try:
                return await asyncio.wait_for(grafana.list_alert_rules(), timeout=10.0)
            except Exception as exc:
                _update_curation_progress(
                    log_line=f"⚠ Aviso ao listar regras existentes no Grafana ({str(exc)[:100]}) — prosseguindo curadoria."
                )
                return []

        async def _safe_list_folders() -> list[dict[str, Any]]:
            try:
                return await asyncio.wait_for(grafana.list_folders(), timeout=10.0)
            except Exception as exc:
                _update_curation_progress(
                    log_line=f"⚠ Aviso ao listar pastas de clientes no Grafana ({str(exc)[:100]}) — prosseguindo curadoria."
                )
                return []

        async def _safe_list_datasources() -> list[dict[str, Any]]:
            try:
                return await asyncio.wait_for(grafana.list_datasources(), timeout=10.0)
            except Exception as exc:
                _update_curation_progress(
                    log_line=f"⚠ Aviso ao listar datasources no Grafana ({str(exc)[:100]}) — prosseguindo curadoria."
                )
                return []

        technologies = technology_store.list_all(include_disabled=False)
        known_patterns = [t.effective_groups_regex for t in technology_store.list_all()]
        baseline_uid = sys_settings.get_baseline_folder_uid()
        existing_tech_names = ", ".join(t.name for t in technologies) if technologies else "nenhuma"

        _reachability, raw_rules_grafana, raw_folders, raw_datasources = await asyncio.gather(
            probe_trusted_sources(technologies),
            _safe_list_rules(),
            _safe_list_folders(),
            _safe_list_datasources(),
        )

        all_rules = detection_rules(raw_rules_grafana)
        client_folders = sorted(
            [f for f in raw_folders if is_client_folder(f, baseline_folder_uid=baseline_uid)],
            key=lambda f: str(f.get("title") or "").lower(),
        )

        try:
            declared_map = footprint_store.declared_map()
        except TenantTechnologyStoreError:
            declared_map = {}

        # Conjunto de títulos/queries já existentes no Grafana (Baseline ou Clientes) para nunca repetir
        existing_grafana_titles: set[str] = set()
        existing_grafana_qhashes: set[str] = set()
        for gr in all_rules:
            t_norm = _normalize_signature(str(gr.get("title") or ""))
            if t_norm:
                existing_grafana_titles.add(t_norm)
            q_ann = str((gr.get("annotations") or {}).get("logql_query") or "").strip()
            if q_ann:
                existing_grafana_qhashes.add(_query_fingerprint(q_ann))

        # Contagem de clientes por tecnologia e perímetro para priorizar as mais prevalentes no parque
        tech_client_counts: dict[str, int] = {}
        perim_client_counts: dict[str, int] = {}
        for f in client_folders:
            c_uid = str(f.get("uid") or "").strip()
            c_rules = [r for r in all_rules if str(r.get("folderUID") or "") == c_uid]
            declared_slugs = declared_map.get(c_uid, [])
            try:
                scan_rec = scan_store.record_for(c_uid) if scan_store else None
            except Exception:
                scan_rec = None
            scanned_techs = {
                str(t.get("slug") or "").lower()
                for t in (scan_rec.get("technologies") or [])
                if t.get("found")
            } if scan_rec else set()

            seen_perims_in_client: set[str] = set()
            for t in technologies:
                has_t = (
                    t.slug in declared_slugs
                    or t.slug in scanned_techs
                    or client_has_technology(c_rules, t, declared_slugs)
                )
                if has_t:
                    tech_client_counts[t.slug] = tech_client_counts.get(t.slug, 0) + 1
                    seen_perims_in_client.add(t.perimeter)
            for p in seen_perims_in_client:
                perim_client_counts[p] = perim_client_counts.get(p, 0) + 1

        # Ordena tecnologias para curadoria: maior presença em clientes primeiro,
        # dando preferência analítica aos perímetros corporativos líderes (Identidade, Cloud / SaaS, Firewall)
        def _tech_priority(t: Technology) -> tuple[int, int, str]:
            c_cnt = tech_client_counts.get(t.slug, 0)
            p_core = 2 if t.perimeter in ("identity_iam", "cloud_saas") else (1 if t.perimeter in ("firewall", "antimalware_edr") else 0)
            return (c_cnt, p_core, t.name)

        technologies.sort(key=_tech_priority, reverse=True)

        # Filtra as buscas nos 4 sites confiáveis APENAS para tecnologias que já existem no D.A.N.T.E.
        searched_candidates = search_rules_in_trusted_sources(technologies)

        # Priorização estrita da IA e do pipeline: curar primeiro as regras dos perímetros e tecnologias
        # presentes na maior quantidade de clientes (Identidade - Windows, Cloud / SaaS - Office, etc.)
        def _candidate_priority(cand: dict[str, Any]) -> tuple[int, int, str]:
            cand_tech = match_rule_to_technology(cand, technologies)
            if not cand_tech:
                return (-1, -1, "")
            t_cnt = tech_client_counts.get(cand_tech.slug, 0)
            p_core = 2 if cand_tech.perimeter in ("identity_iam", "cloud_saas") else (1 if cand_tech.perimeter in ("firewall", "antimalware_edr") else 0)
            p_cnt = perim_client_counts.get(cand_tech.perimeter, 0)
            return (t_cnt, p_core + p_cnt, str(cand.get("original_title") or ""))

        searched_candidates.sort(key=_candidate_priority, reverse=True)
        fetched_count = len(searched_candidates)
        compatible_tech_count = 0
        converted_logql_count = 0
        excellent_added = 0
        good_added = 0
        discarded_bad_count = 0
        skipped_duplicates_count = 0

        first_client_name = (
            str(client_folders[0].get("title") or client_folders[0].get("uid") or "").strip()
            if client_folders
            else "—"
        )

        _update_curation_progress(
            percent=7,
            phase="Validando compatibilidade tecnológica e convertendo regras para LogQL",
            total_clients=len(client_folders),
            current_client_name=first_client_name,
            current_action=f"Validando {fetched_count} regras para {len(client_folders)} cliente(s)...",
            log_line=(
                f"Busca filtrada nas 4 fontes apenas para as tecnologias existentes no D.A.N.T.E. "
                f"({existing_tech_names}): {fetched_count} regra(s) encontrada(s) para avaliar em "
                f"{len(client_folders)} cliente(s)."
            ),
        )

        # Pré-processa Passo 2.1 (tecnologia), Passo 2.2 (conversão LogQL) e Regra 3 (deduplicação)
        cur_settings = get_settings()
        ai_service = AIService(
            sys_settings=sys_settings,
            cache_path=cur_settings.curation_ai_cache_path,
            settings=cur_settings,
        )
        ai_enabled = ai_service.is_curation_enabled() if hasattr(ai_service, "is_curation_enabled") else ai_service.is_configured()
        ai_raw_cfg = ai_service.get_raw_settings()
        ai_provider_used = ai_raw_cfg.provider if ai_enabled else None
        ai_model_used = ai_raw_cfg.model if ai_enabled else None
        ai_curated_count = 0
        heuristic_curated_count = 0
        ai_circuit_broken = False
        consecutive_ai_failures = 0
        total_cands = max(len(searched_candidates), 1)

        if ai_enabled:
            _update_curation_progress(
                log_line=f"🤖 Motor de Inteligência Artificial ATIVO ({ai_raw_cfg.provider.title()} - {ai_raw_cfg.model})."
            )
        else:
            _update_curation_progress(
                log_line="⚙ Motor heurístico ativo (IA não configurada ou desativada nas configurações)."
            )

        prepared_new_candidates: list[
            tuple[
                dict[str, Any],
                Technology,
                str,
                str,
                list[CurationFieldMapping],
                bool,
                str,
                Literal["ai", "heuristic"],
                str | None,
                str | None,
                str,
                str,
            ]
        ] = []
        for cand_idx, candidate in enumerate(searched_candidates, start=1):
            if _STOP_REQUESTED:
                raise asyncio.CancelledError("Parada de curadoria solicitada pelo operador.")
            ext_id = str(candidate.get("external_id") or "").strip()
            orig_title = str(candidate.get("original_title") or "").strip()

            # Passo 2.1: Validar compatibilidade da fonte de dados com as tecnologias do D.A.N.T.E.
            tech = match_rule_to_technology(candidate, technologies)
            if tech is None:
                discarded_bad_count += 1
                _update_curation_progress(
                    log_line=f"✗ Descartada (Passo 2.1 - fonte de dados incompatível): '{orig_title}'."
                )
                try:
                    canon_url = get_canonical_source_url(ext_id, str(candidate.get("source_url") or ""))
                    ref_tech = match_rule_to_technology(
                        candidate,
                        [
                            Technology(name="Active Directory / Windows", slug="ad_windows", perimeter="identity_iam", perimeter_name="Identidade", job="wazuh", rule_groups_regex=".*ad.*", enabled=True),
                            Technology(name="FortiGate Firewall", slug="fortigate", perimeter="firewall", perimeter_name="Firewall", job="wazuh", rule_groups_regex=".*forti.*", enabled=True),
                            Technology(name="Microsoft 365 / Office 365", slug="office365", perimeter="cloud_saas", perimeter_name="Cloud / SaaS", job="wazuh", rule_groups_regex=".*o365.*", enabled=True),
                            Technology(name="Linux Syslog / OS", slug="linux_os", perimeter="endpoint_edr", perimeter_name="Antimalware / EDR", job="wazuh", rule_groups_regex=".*linux.*", enabled=True),
                            Technology(name="Akamai WAF", slug="waf_akamai", perimeter="waf_web", perimeter_name="WAF / Web", job="wazuh", rule_groups_regex=".*waf.*", enabled=True),
                        ],
                    )
                    if ref_tech:
                        disc_logql, disc_mf, _, _ = convert_rule_to_logql(candidate, ref_tech, [ref_tech.rule_groups_regex])
                        disc_tech_slug = ref_tech.slug
                        disc_tech_name = ref_tech.name
                        disc_perim_slug = ref_tech.perimeter
                        disc_perim_name = ref_tech.perimeter_name
                        disc_regex = ref_tech.rule_groups_regex
                    else:
                        disc_logql = 'sum(count_over_time({job="wazuh"} | json [5m])) > 0'
                        disc_mf = []
                        disc_tech_slug = "other"
                        disc_tech_name = "Incompatível"
                        disc_perim_slug = "other"
                        disc_perim_name = "Outro"
                        disc_regex = ".*"

                    disc_item = CuratedRuleItem(
                        id=f"disc-{uuid.uuid4().hex[:10]}",
                        external_id=ext_id or f"disc-{uuid.uuid4().hex[:6]}",
                        source_id=candidate.get("source_id", "sigmahq"),
                        source_name=candidate.get("source_name", "SigmaHQ"),
                        source_url=canon_url,
                        title=orig_title,
                        original_title=orig_title,
                        description=str(candidate.get("description") or ""),
                        original_format=str(candidate.get("original_format") or "Sigma (YAML)"),
                        original_syntax=str(candidate.get("original_syntax") or ""),
                        logql_query=disc_logql,
                        mapped_fields=disc_mf,
                        technology=disc_tech_slug,
                        technology_name=disc_tech_name,
                        perimeter=disc_perim_slug,
                        perimeter_name=disc_perim_name,
                        rule_groups_regex=disc_regex,
                        job="wazuh",
                        severity=candidate.get("severity", "medium"),
                        mitre_tactic=str(candidate.get("mitre_tactic") or "initial-access"),
                        mitre_technique=str(candidate.get("mitre_technique") or "T1190"),
                        threshold_operator="gt",
                        threshold_value=0.0,
                        for_duration="0s",
                        classification="bad",
                        classification_reason="Descartada no Passo 2.1: tecnologia não ativada no parque avaliado",
                        field_compatibility_pct=0.0,
                        curated_at=ran_at,
                        curation_engine=curation_engine,
                        ai_rationale=f"Contexto de Ameaça: A regra '{orig_title}' monitora táticas de intrusão ({candidate.get('mitre_technique', 'T1190')}), mas a tecnologia correspondente não está habilitada.",
                        implemented=False,
                        discarded=True,
                        discard_reason="Fonte de dados incompatível com as tecnologias configuradas",
                    )
                    curation_store.add_discarded_rule(disc_item)
                except Exception:
                    pass
                continue

            compatible_tech_count += 1

            # Regra 3 (antecipada): se a regra já foi vista no store ou já existe no Grafana, pula antes de gastar recursos
            if (
                curation_store.is_seen(ext_id, orig_title, orig_title, "")
                or _normalize_signature(orig_title) in existing_grafana_titles
            ):
                skipped_duplicates_count += 1
                continue

            # Mantém o nome da regra em inglês tal qual está nas fontes pesquisadas
            canonical_title = orig_title

            # Passo 2.2: Converter para LogQL (via IA se configurada, ou fallback para motor heurístico)
            # Garantia: NENHUM log do Loki é enviado para a IA (apenas schema e regra).
            curation_engine: Literal["ai", "heuristic"] = "heuristic"
            ai_model: str | None = None
            ai_rationale: str | None = None
            mitre_tactic = str(candidate.get("mitre_tactic") or "execution")
            mitre_technique = str(candidate.get("mitre_technique") or "T1059")

            if ai_enabled and not ai_circuit_broken:
                supported_f_list = list(
                    SUPPORTED_WAZUH_LOKI_FIELDS.get(tech.slug)
                    or PERIMETER_DEFAULT_FIELDS.get(tech.perimeter)
                    or ["rule_id", "full_log"]
                )
                prevalence_desc = (
                    f"Presente em {tech_client_counts.get(tech.slug, 0)} de "
                    f"{max(len(client_folders), 1)} cliente(s) corporativo(s) (Perímetro: {tech.perimeter_name})"
                )
                try:
                    (
                        ai_logql,
                        ai_mapped,
                        ai_lint_ok,
                        ai_lint_msg,
                        ai_tac,
                        ai_tech_id,
                        ai_rat,
                    ) = await ai_service.curate_rule_with_ai(
                        raw_rule=candidate,
                        technology=tech,
                        supported_fields=supported_f_list,
                        known_rule_groups_patterns=known_patterns,
                        client_prevalence=prevalence_desc,
                    )
                    consecutive_ai_failures = 0
                    if ai_lint_ok:
                        logql_query = ensure_data_prefix_in_logql(ai_logql)
                        mapped_fields = [
                            CurationFieldMapping(
                                original_field=m.original_field,
                                logql_field=ensure_data_prefix(m.logql_field),
                                compatible=m.compatible,
                            )
                            for m in ai_mapped
                        ]
                        lint_ok = True
                        lint_msg = ai_lint_msg
                        curation_engine = "ai"
                        ai_model = ai_model_used
                        ai_rationale = ai_rat
                        if ai_tac:
                            mitre_tactic = ai_tac
                        if ai_tech_id:
                            mitre_technique = ai_tech_id
                        ai_curated_count += 1
                    else:
                        logql_query, mapped_fields, lint_ok, lint_msg = convert_rule_to_logql(
                            candidate, tech, known_patterns
                        )
                        heuristic_curated_count += 1
                except Exception as ai_exc:
                    consecutive_ai_failures += 1
                    logger.warning("Falha na tradução com IA para '%s' (%s); fallback heurístico.", canonical_title, ai_exc)
                    if consecutive_ai_failures >= 3:
                        ai_circuit_broken = True
                        _update_curation_progress(
                            log_line=(
                                f"⚠ Circuit Breaker IA acionado ({consecutive_ai_failures} falhas consecutivas: {str(ai_exc)[:60]}). "
                                "Alternando para motor heurístico seguro no restante do ciclo para garantir performance."
                            )
                        )
                    logql_query, mapped_fields, lint_ok, lint_msg = convert_rule_to_logql(
                        candidate, tech, known_patterns
                    )
                    heuristic_curated_count += 1
            else:
                logql_query, mapped_fields, lint_ok, lint_msg = convert_rule_to_logql(
                    candidate, tech, known_patterns
                )
                heuristic_curated_count += 1

            if not ai_rationale:
                c_title_l = str(candidate.get("original_title") or candidate.get("title") or "").lower()
                c_desc_l = str(candidate.get("description") or "").lower()
                c_mitre = str(candidate.get("mitre_technique") or "").upper()
                c_is_bf = (
                    "t1110" in c_mitre
                    or "t1046" in c_mitre
                    or any(
                        kw in c_title_l or kw in c_desc_l
                        for kw in (
                            "brute force",
                            "bruteforce",
                            "força bruta",
                            "forca bruta",
                            "password spray",
                            "spraying",
                            "login failure burst",
                            "multiple failures",
                            "multiple authentication",
                            "repeated mfa",
                            "port scan",
                            "burst",
                        )
                    )
                )
                ai_rationale = generate_threat_rationale(
                    candidate,
                    tech,
                    logql_query,
                    is_brute_force=c_is_bf,
                    threshold_value=5 if c_is_bf else None,
                )
                ai_model = ai_model or "D.A.N.T.E. Threat Context"

            if not lint_ok:
                discarded_bad_count += 1
                _update_curation_progress(
                    log_line=f"✗ Descartada (Passo 2.2 - falha no lint_logql): '{canonical_title}'."
                )
                continue

            converted_logql_count += 1

            # Atualização dinâmica de progresso (varia suavemente entre 7% e 19%)
            conv_pct = min(19, max(7, 7 + int((cand_idx / total_cands) * 12)))
            _update_curation_progress(
                percent=conv_pct,
                phase="Validando compatibilidade tecnológica e convertendo regras para LogQL",
                current_rule_title=canonical_title,
                current_action=f"Convertendo regra ({cand_idx}/{total_cands}): '{canonical_title[:38]}...'",
                log_line=(
                    f"[{_now_time_label()}] 🤖 [{cand_idx}/{total_cands}] Regra '{canonical_title}' convertida para LogQL ({curation_engine.upper()})."
                ) if (cand_idx % 3 == 1 or cand_idx == total_cands or curation_engine == "ai") else None,
            )

            # Regra 3: Nunca repetir regras que já foram curadas na database interna cumulativa (verificação de qhash)
            if curation_store.is_seen(ext_id, canonical_title, orig_title, logql_query):
                skipped_duplicates_count += 1
                continue

            prepared_new_candidates.append(
                (
                    candidate,
                    tech,
                    canonical_title,
                    logql_query,
                    mapped_fields,
                    lint_ok,
                    lint_msg,
                    curation_engine,
                    ai_model,
                    ai_rationale,
                    mitre_tactic,
                    mitre_technique,
                )
            )

        existing_pending_rules: list[CuratedRuleItem] = []
        for r in curation_store.list_rules():
            if r.implemented:
                still_in_grafana = (
                    find_implemented_rule({"uid": r.baseline_rule_uid or "", "title": r.title}, all_rules)
                    is not None
                )
                if not still_in_grafana:
                    r.implemented = False
                    r.implemented_at = None
                    r.baseline_rule_uid = None
                    r.implemented_clients = []
                    existing_pending_rules.append(r)
            else:
                existing_pending_rules.append(r)
        total_work_rules = max(len(prepared_new_candidates) + len(existing_pending_rules), 1)
        work_rule_idx = 0

        new_curated_items: list[CuratedRuleItem] = []

        # Executa Passo 2.3 para as novas regras candidatas
        for (
            candidate,
            tech,
            canonical_title,
            logql_query,
            mapped_fields,
            lint_ok,
            lint_msg,
            curation_engine,
            ai_model,
            ai_rationale,
            mitre_tactic,
            mitre_technique,
        ) in prepared_new_candidates:
            if _STOP_REQUESTED:
                raise asyncio.CancelledError("Parada de curadoria solicitada pelo operador.")
            work_rule_idx += 1
            ext_id = str(candidate.get("external_id") or "").strip()
            orig_title = str(candidate.get("original_title") or "").strip()
            src_name = str(candidate.get("source_name") or "")

            classification, reason, compat_pct, client_evals = await evaluate_rule_across_clients(
                grafana=grafana,
                technology=tech,
                logql_query=logql_query,
                mapped_fields=mapped_fields,
                rule_title=canonical_title,
                client_folders=client_folders,
                datasources=raw_datasources,
                all_rules=all_rules,
                declared_map=declared_map,
                scan_store=scan_store,
                tech_logs_cache=tech_logs_cache,
                dead_datasources=dead_datasources,
                rule_source=src_name,
                rule_index=work_rule_idx,
                total_rules=total_work_rules,
                severity=str(candidate.get("severity") or "high"),
                mitre_tactic=mitre_tactic,
                mitre_technique=mitre_technique,
            )

            # Regra 2: Apenas regras com compatibilidade >= 80% são consideradas candidatas para o SIEM
            if compat_pct < 80.0 or classification not in ("excellent", "good"):
                discarded_bad_count += 1
                _update_curation_progress(
                    log_line=f"✗ Descartada (Passo 2.3 - compatibilidade {compat_pct:.0f}% < 80%): '{canonical_title}'."
                )
                try:
                    disc_item = CuratedRuleItem(
                        id=f"disc-{uuid.uuid4().hex[:10]}",
                        external_id=ext_id,
                        source_id=candidate["source_id"],
                        source_name=candidate["source_name"],
                        source_url=candidate["source_url"],
                        title=canonical_title,
                        original_title=orig_title,
                        description=str(candidate.get("description") or ""),
                        original_format=str(candidate.get("original_format") or "Sigma (YAML)"),
                        original_syntax=str(candidate.get("original_syntax") or ""),
                        logql_query=logql_query,
                        technology=tech.slug,
                        technology_name=tech.name,
                        perimeter=tech.perimeter,
                        perimeter_name=tech.perimeter_name,
                        rule_groups_regex=tech.rule_groups_regex,
                        job=tech.job,
                        severity=candidate.get("severity", "high"),
                        mitre_tactic=mitre_tactic,
                        mitre_technique=mitre_technique,
                        threshold_operator=str(candidate.get("threshold_operator") or "gt"),
                        threshold_value=float(candidate.get("threshold_value") or 0.0),
                        for_duration=str(candidate.get("for_duration") or "0s"),
                        classification=classification,
                        classification_reason=reason,
                        field_compatibility_pct=compat_pct,
                        mapped_fields=mapped_fields,
                        lint_valid=lint_ok,
                        lint_message=lint_msg,
                        client_evaluations=client_evals,
                        curated_at=ran_at,
                        curation_engine=curation_engine,
                        ai_model=ai_model,
                        ai_rationale=ai_rationale,
                        implemented=False,
                        discarded=True,
                        discard_reason=reason or f"Compatibilidade insuficiente ({compat_pct:.0f}% < 80%)",
                    )
                    _populate_curated_rule_qualification_details(disc_item)
                    curation_store.add_discarded_rule(disc_item)
                except Exception:
                    pass
                continue

            exc_count = sum(1 for ev in client_evals if ev.classification == "excellent")
            gd_count = sum(1 for ev in client_evals if ev.classification == "good")

            curated_item = CuratedRuleItem(
                id=f"cur-{uuid.uuid4().hex[:10]}",
                external_id=ext_id,
                source_id=candidate["source_id"],
                source_name=candidate["source_name"],
                source_url=candidate["source_url"],
                title=canonical_title,
                original_title=orig_title,
                description=str(candidate.get("description") or ""),
                original_format=str(candidate.get("original_format") or "Sigma (YAML)"),
                original_syntax=str(candidate.get("original_syntax") or ""),
                logql_query=logql_query,
                technology=tech.slug,
                technology_name=tech.name,
                perimeter=tech.perimeter,
                perimeter_name=tech.perimeter_name,
                rule_groups_regex=tech.rule_groups_regex,
                job=tech.job,
                severity=candidate.get("severity", "high"),
                mitre_tactic=mitre_tactic,
                mitre_technique=mitre_technique,
                threshold_operator=str(candidate.get("threshold_operator") or "gt"),
                threshold_value=float(candidate.get("threshold_value") or 0.0),
                for_duration=str(candidate.get("for_duration") or "0s"),
                classification=classification,
                classification_reason=reason,
                field_compatibility_pct=compat_pct,
                mapped_fields=mapped_fields,
                lint_valid=lint_ok,
                lint_message=lint_msg,
                client_evaluations=client_evals,
                excellent_clients_count=exc_count,
                good_clients_count=gd_count,
                curated_at=ran_at,
                curation_engine=curation_engine,
                ai_model=ai_model,
                ai_rationale=ai_rationale,
                implemented=False,
            )
            _populate_curated_rule_qualification_details(curated_item)
            new_curated_items.append(curated_item)
            if curated_item.classification == "excellent":
                excellent_added += 1
            else:
                good_added += 1

        # Reavalia também os clientes das regras pendentes já existentes na curadoria
        # (em etapas progressivas de 15m -> 1h -> 6h -> 24h -> 3d)
        updated_existing: list[CuratedRuleItem] = []
        for existing_item in existing_pending_rules:
            if _STOP_REQUESTED:
                raise asyncio.CancelledError("Parada de curadoria solicitada pelo operador.")
            work_rule_idx += 1
            try:
                tech_obj = technology_store.get(existing_item.technology)
            except Exception:
                continue
            new_class, new_reason, new_compat, new_evals = await evaluate_rule_across_clients(
                grafana=grafana,
                technology=tech_obj,
                logql_query=existing_item.logql_query,
                mapped_fields=existing_item.mapped_fields,
                rule_title=existing_item.title,
                client_folders=client_folders,
                datasources=raw_datasources,
                all_rules=all_rules,
                declared_map=declared_map,
                scan_store=scan_store,
                tech_logs_cache=tech_logs_cache,
                dead_datasources=dead_datasources,
                rule_source=existing_item.source_name,
                rule_index=work_rule_idx,
                total_rules=total_work_rules,
                severity=str(existing_item.severity),
                mitre_tactic=existing_item.mitre_tactic,
                mitre_technique=existing_item.mitre_technique,
            )
            if new_compat >= 80.0 and new_class in ("excellent", "good"):
                existing_item.classification = new_class
                existing_item.classification_reason = new_reason
                existing_item.field_compatibility_pct = new_compat
                existing_item.client_evaluations = new_evals
                _populate_curated_rule_qualification_details(existing_item)
                updated_existing.append(existing_item)

        current_prog = get_curation_progress()
        timed_out_list = list(current_prog.timed_out_clients)

        summary = CurationRunSummary(
            ran_at=ran_at,
            trigger=trigger,
            fetched_count=fetched_count,
            compatible_tech_count=compatible_tech_count,
            converted_logql_count=converted_logql_count,
            new_curated_count=len(new_curated_items),
            excellent_added=excellent_added,
            good_added=good_added,
            discarded_bad_count=discarded_bad_count,
            skipped_duplicates_count=skipped_duplicates_count,
            evaluated_clients_count=len(client_folders),
            timed_out_clients_count=len(timed_out_list),
            timed_out_clients=timed_out_list,
            ai_curated_count=ai_curated_count,
            heuristic_curated_count=heuristic_curated_count,
            ai_provider_used=ai_provider_used,
            ai_model_used=ai_model_used,
        )

        curation_store.record_cycle_results(
            new_rules=new_curated_items,
            updated_existing_rules=updated_existing,
            summary=summary,
        )

        last_client_name = (
            str(client_folders[-1].get("title") or client_folders[-1].get("uid") or "").strip()
            if client_folders
            else "—"
        )
        _update_curation_progress(
            running=False,
            percent=100,
            phase="Curadoria concluída com sucesso",
            current_window_step=len(CURATION_QUERY_WINDOWS),
            current_window_label="Concluído (100%)",
            current_client_name=last_client_name,
            current_action=(
                f"Curadoria concluída: {len(client_folders)} cliente(s) avaliado(s) e "
                f"{len(curation_store.list_rules())} regra(s) qualificada(s)."
            ),
            log_line=(
                f"✓ Curadoria 100% concluída: {len(new_curated_items)} nova(s) ({excellent_added} excelente(s), "
                f"{good_added} boa(s)), {len(updated_existing)} atualizada(s)."
            ),
            finished=True,
        )

        logger.info(
            "Ciclo de curadoria (%s) concluído: %d novas (%d excelentes, %d boas), %d más descartadas, %d duplicadas ignoradas.",
            trigger,
            len(new_curated_items),
            excellent_added,
            good_added,
            discarded_bad_count,
            skipped_duplicates_count,
        )
        return summary
    except asyncio.CancelledError:
        _update_curation_progress(
            running=False,
            phase="Curadoria interrompida",
            current_action="Curadoria interrompida pelo operador.",
            log_line="⏹ Curadoria interrompida pelo operador.",
            finished=True,
        )
        raise
    except Exception as exc:
        _update_curation_progress(
            running=False,
            percent=100,
            phase="Curadoria finalizada com alerta",
            current_action=f"Ciclo finalizado com erro tratado: {str(exc)[:180]}",
            log_line=f"⚠ Erro tratado no ciclo de curadoria: {str(exc)[:180]}",
            finished=True,
        )
        raise


def build_curation_overview(
    curation_store: CurationStore,
    settings: Settings | None = None,
) -> CurationOverviewResponse:
    """Monta a resposta consolidada da página de Curadoria."""
    cfg = settings or get_settings()
    rules = curation_store.list_rules()
    meta = curation_store.get_metadata()

    next_run = compute_next_08h00_run(cfg)
    daily_time_str = f"{cfg.curation_schedule_hour:02d}:{cfg.curation_schedule_minute:02d}"
    tz_sign = "+" if cfg.curation_timezone_offset_hours >= 0 else "-"
    tz_abs = abs(cfg.curation_timezone_offset_hours)

    schedule = CurationScheduleInfo(
        enabled=True,
        cron_expression=f"{cfg.curation_schedule_minute} {cfg.curation_schedule_hour} * * *",
        daily_time=daily_time_str,
        timezone=f"America/Sao_Paulo (UTC{tz_sign}{tz_abs:02d}:00)",
        last_run_at=meta["last_run_at"],
        next_run_at=next_run.isoformat(),
        last_run_summary=meta["last_run_summary"],
    )

    by_source: dict[str, int] = {}
    for r in rules:
        by_source[r.source_id] = by_source.get(r.source_id, 0) + 1

    sources_out = [
        CurationSourceInfo(
            id=src["id"],  # type: ignore[arg-type]
            name=src["name"],
            url=src["url"],
            format_label=src["format_label"],
            description=src["description"],
            curated_count=by_source.get(src["id"], 0),
            canonical_rules_count=len([c for c in RAW_SOURCE_CANDIDATES if c.get("source_id") == src["id"]]),
            status="verified",
        )
        for src in TRUSTED_SOURCES
    ]

    excellent_count = sum(1 for r in rules if r.classification == "excellent")
    good_count = sum(1 for r in rules if r.classification == "good")
    high_compat_count = sum(1 for r in rules if (r.field_compatibility_pct or 0.0) >= 95.0)
    medium_compat_count = sum(1 for r in rules if 80.0 <= (r.field_compatibility_pct or 0.0) < 95.0)
    implemented_count = sum(1 for r in rules if r.implemented)
    ignored_count = sum(1 for r in rules if getattr(r, "ignored", False))
    pending_count = len(rules) - implemented_count

    metrics = CurationMetrics(
        total_curated=len(rules),
        excellent_count=excellent_count,
        good_count=good_count,
        high_compatibility_count=high_compat_count,
        medium_compatibility_count=medium_compat_count,
        pending_count=pending_count,
        implemented_count=implemented_count,
        ignored_count=ignored_count,
        total_evaluated_history=meta["total_evaluated_history"],
        discarded_bad_count=meta["discarded_bad_count"],
        skipped_duplicates_count=meta["skipped_duplicates_count"],
    )

    return CurationOverviewResponse(
        generated_at=datetime.now(timezone.utc).isoformat(),
        schedule=schedule,
        sources=sources_out,
        metrics=metrics,
        rules=rules,
        discarded_rules=curation_store.list_discarded_rules(),
        progress=get_curation_progress(),
    )


# =============================================================================
# 5. Implementação de Regra Curada (Baseline + Clientes Recomendados)
# =============================================================================
async def implement_curated_rule(
    *,
    rule_id: str,
    payload: ImplementCuratedRuleRequest,
    grafana: GrafanaClient,
    technology_store: TechnologyStore,
    sys_settings: SystemSettingsStore,
    curation_store: CurationStore,
) -> ImplementCuratedRuleResponse:
    """Implementa uma regra da Curadoria no Baseline Global e nos clientes indicados.

    Garante todas as invariantes do D.A.N.T.E.:
    - Confirmação explícita obrigatória (payload.confirm == True).
    - Validação no servidor via lint_logql antes de qualquer escrita.
    - Criação no Baseline Global (pasta 'global' ou arbitrada, grupo 'global-detections').
    - Replicação para cada cliente recomendado no grupo '5m', apontando para o
      datasource Loki dedicado do cliente, sem provenance e com Contact Point 'stg'/'dev'.
    """
    rule = curation_store.get_rule(rule_id)
    if rule is None:
        raise ValueError(f"Regra curada '{rule_id}' não encontrada.")
    if (rule.field_compatibility_pct or 0.0) < 80.0:
        raise ValueError(
            f"Regra curada '{rule.title}' possui compatibilidade de {rule.field_compatibility_pct}% "
            "inferior ao limiar mínimo de 80.0% e não é candidata para implementação no SIEM."
        )

    # Validação LogQL obrigatória no servidor (Invariante 5)
    known_patterns = [t.effective_groups_regex for t in technology_store.list_all()]
    lint_res = lint_logql(
        rule.logql_query,
        known_rule_groups_patterns=known_patterns,
        expected_job=rule.job,
    )
    if not lint_res.is_valid:
        errors = "; ".join(i.message for i in lint_res.issues if i.level == "error")
        raise RuntimeError(f"Falha na validação LogQL no servidor: {errors or lint_res.message}")

    raw_rules, raw_folders, raw_datasources, raw_cps = await asyncio.gather(
        grafana.list_alert_rules(),
        grafana.list_folders(),
        grafana.list_datasources(),
        grafana.list_contact_points(),
    )
    all_rules = detection_rules(raw_rules)
    baseline_folder_uid = sys_settings.get_baseline_folder_uid()
    baseline_ds = resolve_baseline_loki_datasource(raw_datasources)
    loki_ds_uid = str(baseline_ds.get("uid") or "loki")

    stg_contact_point = resolve_stage_receiver(
        "stg",
        stage_mapping=sys_settings.get_stage_contact_points(),
        available_contact_points=raw_cps,
    )

    # 1. Verifica se a regra já existe no Baseline Global; se não, cria no Baseline
    global_rules = [
        r
        for r in all_rules
        if str(r.get("folderUID") or "").strip().lower() in (baseline_folder_uid.lower(), "global")
    ]
    existing_baseline = find_implemented_rule({"title": rule.title, "uid": ""}, global_rules)

    evaluator_type = "lt" if rule.threshold_operator == "lt" else "gt"
    evaluator_param = (
        int(rule.threshold_value)
        if float(rule.threshold_value).is_integer()
        else float(rule.threshold_value)
    )

    baseline_labels = {
        "severity": rule.severity,
        "mitre_tactic": rule.mitre_tactic.strip().lower(),
        "mitre_technique": rule.mitre_technique.strip().upper(),
        "scope": "baseline",
        "client": "global",
        "siem_tier": "global",
        "technology": rule.technology,
        "technology_name": rule.technology_name,
        "curation_source": rule.source_id,
        "source": "dante_curated",
    }
    baseline_annotations = {
        "summary": rule.title,
        "description": rule.description,
        "logql_query": rule.logql_query,
        "runbook_url": rule.source_url,
        "curated_rule_id": rule.id,
        "curation_source_name": rule.source_name,
    }

    if existing_baseline is not None:
        baseline_rule_uid = str(existing_baseline.get("uid") or "")
        baseline_payload = copy.deepcopy(existing_baseline)
    else:
        baseline_rule_uid = f"ghp-{uuid.uuid4().hex[:10]}"
        baseline_payload = {
            "uid": baseline_rule_uid,
            "title": rule.title,
            "folderUID": baseline_folder_uid,
            "ruleGroup": BASELINE_RULE_GROUP,
            "condition": "C",
            "noDataState": "OK",
            "execErrState": "Error",
            "for": rule.for_duration or "0s",
            "isPaused": False,
            "labels": baseline_labels,
            "annotations": baseline_annotations,
            "data": [
                {
                    "refId": "A",
                    "queryType": "range",
                    "relativeTimeRange": {"from": 300, "to": 0},
                    "datasourceUid": loki_ds_uid,
                    "model": {
                        "refId": "A",
                        "editorMode": "code",
                        "expr": rule.logql_query,
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
        apply_contact_point(baseline_payload, contact_point=stg_contact_point)
        await grafana.create_alert_rule(baseline_payload)
        await grafana.set_rule_group_interval(
            baseline_folder_uid,
            BASELINE_RULE_GROUP,
            RULE_GROUP_INTERVAL_SECONDS,
        )

    # 2. Determina os clientes alvo (exatamente onde a regra é excelente/boa candidata)
    recommended_uids = [
        ev.client_uid
        for ev in rule.client_evaluations
        if ev.classification in ("excellent", "good")
    ]
    target_client_uids = (
        [u.strip() for u in payload.client_uids if u.strip()]
        if payload.client_uids
        else recommended_uids
    )

    folder_map = {
        str(f.get("uid") or ""): f
        for f in raw_folders
        if is_client_folder(f, baseline_folder_uid=baseline_folder_uid)
    }

    client_results: list[ImplementedRuleResult] = []
    implemented_client_names: list[str] = []

    for c_uid in target_client_uids:
        target_folder = folder_map.get(c_uid)
        if target_folder is None:
            client_results.append(
                ImplementedRuleResult(
                    uid=c_uid,
                    title=f"[{c_uid}] {rule.title}",
                    status="failed",
                    detail=f"Pasta do cliente '{c_uid}' não encontrada no Grafana.",
                )
            )
            continue

        c_name = str(target_folder.get("title") or c_uid).strip()
        c_rules = [r for r in all_rules if str(r.get("folderUID") or "") == c_uid]

        existing_in_client = find_implemented_rule(
            {"uid": baseline_rule_uid, "title": rule.title}, c_rules
        )
        if existing_in_client is not None:
            client_results.append(
                ImplementedRuleResult(
                    uid=str(existing_in_client.get("uid") or baseline_rule_uid),
                    title=str(existing_in_client.get("title") or f"[{c_name}] {rule.title}"),
                    status="skipped",
                    detail=f"Regra já implementada no cliente '{c_name}'.",
                )
            )
            implemented_client_names.append(c_name)
            continue

        clone_uid = f"ghp-{uuid.uuid4().hex[:10]}"
        clone_title = f"[{c_name}] {rule.title}"
        target_group = (
            payload.evaluation_group.strip()
            if payload.evaluation_group and payload.evaluation_group.strip()
            else tenant_rule_group(c_name)
        )

        rule_copy = copy.deepcopy(baseline_payload)
        for field in ("id", "updated", "provenance", "readOnly", "orgID"):
            rule_copy.pop(field, None)
        rule_copy["uid"] = clone_uid
        rule_copy["folderUID"] = c_uid
        rule_copy["title"] = clone_title
        rule_copy["ruleGroup"] = target_group
        rule_copy["isPaused"] = False

        c_labels = dict(rule_copy.get("labels") or {})
        c_labels.update(
            {
                "scope": "client",
                "client": c_name,
                "siem_tier": "client",
                "technology": rule.technology,
                "technology_name": rule.technology_name,
            }
        )
        rule_copy["labels"] = c_labels

        c_annotations = dict(rule_copy.get("annotations") or {})
        c_annotations.update(
            {
                "cloned_from": baseline_rule_uid,
                "client_name": c_name,
                "baseline_technology": rule.technology,
                "curated_rule_id": rule.id,
            }
        )
        rule_copy["annotations"] = c_annotations

        client_ds = find_tenant_datasource(c_name, c_uid, raw_datasources) or baseline_ds
        bind_rule_datasource(rule_copy, client_ds)
        apply_contact_point(rule_copy, contact_point=stg_contact_point)

        try:
            await grafana.create_alert_rule(rule_copy)
            await grafana.set_rule_group_interval(
                c_uid,
                target_group,
                RULE_GROUP_INTERVAL_SECONDS,
            )
            client_results.append(
                ImplementedRuleResult(
                    uid=clone_uid,
                    title=clone_title,
                    status="created",
                    detail=f"Implementada no cliente '{c_name}' (grupo '{target_group}', estágio '{stg_contact_point}').",
                )
            )
            implemented_client_names.append(c_name)
        except GrafanaError as exc:
            client_results.append(
                ImplementedRuleResult(
                    uid=clone_uid,
                    title=clone_title,
                    status="failed",
                    detail=f"{c_name}: {exc.message}",
                )
            )

    created_count = sum(1 for r in client_results if r.status == "created")
    skipped_count = sum(1 for r in client_results if r.status == "skipped")
    failed_count = sum(1 for r in client_results if r.status == "failed")
    implemented_at = datetime.now(timezone.utc).isoformat()

    curation_store.mark_implemented(
        rule.id,
        baseline_rule_uid=baseline_rule_uid,
        implemented_clients=implemented_client_names,
        implemented_at=implemented_at,
    )

    msg = (
        f"Regra '{rule.title}' implementada no Baseline Global e processada em "
        f"{len(target_client_uids)} cliente(s): {created_count} criada(s), "
        f"{skipped_count} já existente(s), {failed_count} falha(s)."
    )

    return ImplementCuratedRuleResponse(
        message=msg,
        rule_id=rule.id,
        baseline_rule_uid=baseline_rule_uid,
        baseline_rule_title=rule.title,
        baseline_folder_uid=baseline_folder_uid,
        technology=rule.technology,
        technology_name=rule.technology_name,
        contact_point=stg_contact_point,
        total_clients_targeted=len(target_client_uids),
        created_in_clients=created_count,
        skipped_in_clients=skipped_count,
        failed_in_clients=failed_count,
        client_results=client_results,
        implemented_at=implemented_at,
    )


# =============================================================================
# 6. Background Scheduler (Todos os dias às 08h00)
# =============================================================================
async def curation_daily_scheduler_loop(
    *,
    settings: Settings,
    grafana: GrafanaClient,
    technology_store: TechnologyStore,
    footprint_store: TenantTechnologyStore,
    scan_store: TenantScanStore,
    sys_settings: SystemSettingsStore,
    curation_store: CurationStore,
) -> None:
    """Loop assíncrono que executa a curadoria todos os dias no horário programado (08h00).
    
    Executa exclusivamente quando o horário agendado chegar ou quando acionado manualmente
    pelo usuário via botão 'Iniciar', garantindo que um catálogo limpo permaneça em 0%.
    """
    while True:
        next_run = compute_next_08h00_run(settings)
        now = datetime.now(next_run.tzinfo)
        wait_seconds = max((next_run - now).total_seconds(), 1.0)
        logger.info(
            "Agendador de Curadoria: próxima execução diária programada para %s (em %.0fs)",
            next_run.isoformat(),
            wait_seconds,
        )
        try:
            await asyncio.sleep(wait_seconds)
            # Sincronização diária do repositório SigmaHQ às 08h00
            if getattr(settings, "sigma_auto_pull_on_schedule", True):
                try:
                    logger.info("Rotina 08h00: executando git pull no repositório SigmaHQ local...")
                    pull_ok, pull_msg = await asyncio.to_thread(pull_sigma_repo, settings.sigma_repo_dir)
                    logger.info("Rotina 08h00: resultado da sincronização do repositório Sigma: %s", pull_msg)
                except Exception as pull_err:
                    logger.warning("Rotina 08h00: falha ao sincronizar repositório Sigma: %s", pull_err)

            await run_curation_cycle(
                grafana=grafana,
                technology_store=technology_store,
                footprint_store=footprint_store,
                scan_store=scan_store,
                sys_settings=sys_settings,
                curation_store=curation_store,
                trigger="scheduled_08h00",
            )
        except asyncio.CancelledError:
            logger.info("Agendador diário de Curadoria encerrado.")
            raise
        except Exception as exc:
            logger.error("Erro na execução agendada das 08h00 da Curadoria: %s", exc)
            await asyncio.sleep(60.0)
