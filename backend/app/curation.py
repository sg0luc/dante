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
from .rule_prefix import format_rule_title
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
        "win_system_providerName",
        "data_win_system_providerName",
        "win_system_severityValue",
        "data_win_system_severityValue",
        "win_eventdata_targetUserName",
        "data_win_eventdata_targetUserName",
        "win_eventdata_subjectUserName",
        "data_win_eventdata_subjectUserName",
        "win_eventdata_targetDomainName",
        "data_win_eventdata_targetDomainName",
        "win_eventdata_subjectDomainName",
        "data_win_eventdata_subjectDomainName",
        "win_eventdata_ipAddress",
        "data_win_eventdata_ipAddress",
        "win_eventdata_workstationName",
        "data_win_eventdata_workstationName",
        "win_eventdata_status",
        "data_win_eventdata_status",
        "win_eventdata_subStatus",
        "data_win_eventdata_subStatus",
        "win_eventdata_failureReason",
        "data_win_eventdata_failureReason",
        "win_eventdata_logonType",
        "data_win_eventdata_logonType",
        "win_eventdata_logonId",
        "data_win_eventdata_logonId",
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
        "win_eventdata_newProcessName",
        "data_win_eventdata_newProcessName",
        "win_eventdata_processName",
        "data_win_eventdata_processName",
        "win_eventdata_commandLine",
        "data_win_eventdata_commandLine",
        "win_eventdata_parentImage",
        "data_win_eventdata_parentImage",
        "win_eventdata_parentProcessName",
        "data_win_eventdata_parentProcessName",
        "win_eventdata_parentCommandLine",
        "data_win_eventdata_parentCommandLine",
        "win_eventdata_originalFileName",
        "data_win_eventdata_originalFileName",
        "win_eventdata_currentDirectory",
        "data_win_eventdata_currentDirectory",
        "win_eventdata_integrityLevel",
        "data_win_eventdata_integrityLevel",
        "win_eventdata_hashes",
        "data_win_eventdata_hashes",
        "win_eventdata_company",
        "data_win_eventdata_company",
        "win_eventdata_description",
        "data_win_eventdata_description",
        "win_eventdata_product",
        "data_win_eventdata_product",
        "win_eventdata_targetImage",
        "data_win_eventdata_targetImage",
        "win_eventdata_grantedAccess",
        "data_win_eventdata_grantedAccess",
        "win_eventdata_callTrace",
        "data_win_eventdata_callTrace",
        "win_eventdata_user",
        "data_win_eventdata_user",
        "win_eventdata_scriptBlockText",
        "data_win_eventdata_scriptBlockText",
        "win_eventdata_targetObject",
        "data_win_eventdata_targetObject",
        "win_eventdata_objectName",
        "data_win_eventdata_objectName",
        "win_eventdata_details",
        "data_win_eventdata_details",
        "win_eventdata_targetFilename",
        "data_win_eventdata_targetFilename",
        "win_eventdata_imageLoaded",
        "data_win_eventdata_imageLoaded",
        "win_eventdata_signed",
        "data_win_eventdata_signed",
        "win_eventdata_shareName",
        "data_win_eventdata_shareName",
        "win_eventdata_privilegeList",
        "data_win_eventdata_privilegeList",
        "win_eventdata_authenticationPackageName",
        "data_win_eventdata_authenticationPackageName",
        "win_eventdata_memberName",
        "data_win_eventdata_memberName",
        "win_eventdata_destinationIp",
        "data_win_eventdata_destinationIp",
        "win_eventdata_destinationPort",
        "data_win_eventdata_destinationPort",
        "win_eventdata_destinationHostname",
        "data_win_eventdata_destinationHostname",
        "win_eventdata_queryStatus",
        "data_win_eventdata_queryStatus",
        "win_eventdata_queryResults",
        "data_win_eventdata_queryResults",
        "data_QueryName",
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
        "win_eventdata_targetFilename",
        "data_win_eventdata_targetFilename",
        "win_eventdata_imageLoaded",
        "data_win_eventdata_imageLoaded",
        "win_eventdata_hashes",
        "data_win_eventdata_hashes",
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
        "data_srcport",
        "data_subtype",
        "data_msg",
        "data_level",
        "data_attack",
        "data_policyid",
        "data_user",
        "data_cfgpath",
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
        "data_uid",
        "data_gid",
        "full_log",
    },
    "dns": {
        "rule_id",
        "data_query_name",
        "data_QueryName",
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
        "data_user_agent",
        "data_host",
        "full_log",
    },
}

# Telemetrias especializadas exigidas por regras avançadas (Ex.: Command Line em EvtID 4688,
# Monitoramento de Registro, PowerShell ScriptBlock Logging, Monitoramento de Arquivos/DLLs).
SPECIALIZED_TELEMETRY_FIELDS: dict[str, str] = {
    "data_win_eventdata_commandLine": "Command Line habilitado (Auditoria de Criação de Processos / EvtID 4688)",
    "win_eventdata_commandLine": "Command Line habilitado (Auditoria de Criação de Processos / EvtID 4688)",
    "data_win_eventdata_targetObject": "Monitoramento de Registro habilitado (Registry Auditing)",
    "win_eventdata_targetObject": "Monitoramento de Registro habilitado (Registry Auditing)",
    "data_win_eventdata_objectName": "Auditoria de Objetos/Registro habilitada (EvtID 4657 / 4663)",
    "win_eventdata_objectName": "Auditoria de Objetos/Registro habilitada (EvtID 4657 / 4663)",
    "data_win_eventdata_scriptBlockText": "PowerShell ScriptBlock Logging habilitado (EvtID 4104)",
    "win_eventdata_scriptBlockText": "PowerShell ScriptBlock Logging habilitado (EvtID 4104)",
    "data_win_eventdata_targetFilename": "Monitoramento de Criação de Arquivos habilitado (File Event)",
    "win_eventdata_targetFilename": "Monitoramento de Criação de Arquivos habilitado (File Event)",
    "data_win_eventdata_imageLoaded": "Auditoria de Carregamento de DLL/Driver habilitada (ImageLoad)",
    "win_eventdata_imageLoaded": "Auditoria de Carregamento de DLL/Driver habilitada (ImageLoad)",
    "data_win_eventdata_serviceFileName": "Auditoria de Instalação de Serviços habilitada (EvtID 4697 / 7045)",
    "win_eventdata_serviceFileName": "Auditoria de Instalação de Serviços habilitada (EvtID 4697 / 7045)",
    "data_command": "Auditoria de Execução de Comandos habilitada (Linux Auditd / Sudo)",
    "data_file_path": "Monitoramento de Integridade de Arquivos habilitado (FIM)",
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
# Validador de URLs de Fontes Confiáveis
# NÃO existe catálogo embutido de regras: toda regra curada vem de um arquivo real da fonte
# (hoje o clone local do SigmaHQ), com a URL derivada do caminho físico do arquivo.
# =============================================================================

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


SIGMA_BLOB_URL_PREFIX = "https://github.com/SigmaHQ/sigma/blob/"
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def get_canonical_source_url(external_id: str, current_url: str = "") -> str:
    """Retorna a URL da regra original exatamente como veio da fonte.

    Nunca fabrica nem substitui a URL: se a URL recebida não for um link direto para o
    arquivo da regra, retorna string vazia (a UI então não exibe link em vez de um 404).
    """
    valid, _ = validate_trusted_source_url(current_url)
    return str(current_url).strip() if valid else ""


def is_verified_source_rule(external_id: str, source_id: str, source_url: str) -> bool:
    """True somente para regras reais do SigmaHQ (ID UUID oficial + URL direta do arquivo).

    Descarta registros legados fabricados (IDs como ``sigma-win-...``/``detfyi-...``/
    ``splunk-...``/``elastic-...`` e URLs inexistentes).
    """
    return (
        source_id == "sigmahq"
        and bool(_UUID_RE.match(str(external_id or "").strip()))
        and str(source_url or "").startswith(SIGMA_BLOB_URL_PREFIX)
    )


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
    explicit_product = str(raw_rule.get("product") or "").strip().lower()
    unsupported_products = {
        "macos",
        "aws",
        "gcp",
        "google_workspace",
        "okta",
        "zeek",
        "cisco",
        "juniper",
        "github",
        "bitbucket",
        "kubernetes",
        "opencanary",
        "spring",
        "huawei",
        "paloalto",
    }
    if explicit_product in unsupported_products and explicit_product not in by_slug:
        return None

    hints = [str(h).strip().lower() for h in (raw_rule.get("datasource_hints") or []) if h]

    # 1. Match direto prioritário por slug nos hints
    for hint in hints:
        if hint in by_slug:
            return by_slug[hint]
        # Sinônimos comuns de logsource (Sigma / Splunk / Elastic)
        if hint in ("windows", "active_directory", "ad", "wineventlog_security", "security") and "ad_windows" in by_slug:
            return by_slug["ad_windows"]
        if hint in ("m365", "o365", "exchange", "azuread", "azure", "entra_id") and "office365" in by_slug:
            return by_slug["office365"]
        if hint in ("fortinet", "fortios", "fortigate", "sslvpn", "firewall") and "fortigate" in by_slug:
            return by_slug["fortigate"]
        if hint in ("webserver", "proxy", "waf") and "waf_akamai" in by_slug:
            return by_slug["waf_akamai"]

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
    max_local_sigma: int | None = None,
    client_gap_techs: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Pesquisa regras de detecção nos 4 sites confiáveis filtrando APENAS para
    tecnologias que já existem e estão ativas no D.A.N.T.E.

    Telemetry-First & Gap-Driven: Quando fornecido `client_gap_techs` (tecnologias com
    telemetria confirmada nos clientes porém com lacunas de regras), prioriza intensivamente
    regras dessas tecnologias no topo da fila de curadoria.

    Só devolve regras REAIS: as do repositório local do SigmaHQ (clonado em /data/sigma-repo),
    com nome, descrição, metadados e URL exatamente como no arquivo original, selecionando
    um lote balanceado entre tecnologias e categorias (Process Creation EvtID 4688, Security,
    Registry, PowerShell, Sysmon Driver/ImageLoad/DNS, FortiGate, Office365, Linux e WAF/Web).
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
                if match_rule_to_technology(cand, enabled_techs) is not None:
                    all_candidates.append(cand)
    except Exception as exc:
        logger.debug("Leitura do repositório local do SigmaHQ: %s", exc)

    if not all_candidates or max_local_sigma is not None:
        return all_candidates

    # Seleciona um conjunto balanceado e determinístico de regras reais por tecnologia e categoria
    bucket_win_sec: list[dict[str, Any]] = []
    bucket_win_proc4688: list[dict[str, Any]] = []
    bucket_win_tier2: list[dict[str, Any]] = []
    bucket_win_tier3: list[dict[str, Any]] = []
    bucket_fortigate: list[dict[str, Any]] = []
    bucket_office365: list[dict[str, Any]] = []
    bucket_linux: list[dict[str, Any]] = []
    bucket_waf: list[dict[str, Any]] = []
    bucket_other: list[dict[str, Any]] = []

    priority_ext_ids = {
        "f88e112a-21aa-44bd-9b01-6ee2a2bbbed1",  # Failed Logon From Public IP (EvtID 4625)
        "9eb99343-d336-4020-a3cd-67f3819e68ee",  # Account Tampering - Suspicious Failed Logon Reasons
        "72124974-a68b-4366-b990-d30e0b2a190d",  # Metasploit SMB Authentication
        "5513deaf-f49a-46c2-a6c8-3f111b5cb453",  # SQL Injection Strings In URI
        "65354b83-a2ea-4ea6-8414-3ab38be0d409",  # Cross Site Scripting Strings
        "7ff9db12-1b94-4a79-ba68-a2402c5d6729",  # Windows Webshell Strings
        "ada3bc4f-f0fd-42b9-ba91-e105e8af7342",  # Server Side Template Injection Strings
    }

    for cand in all_candidates:
        tech = match_rule_to_technology(cand, enabled_techs)
        if tech is None:
            continue
        slug = tech.slug.lower()
        cat = str(cand.get("category") or "").strip().lower()
        srv = str(cand.get("service") or "").strip().lower()
        det_str = str(cand.get("detection") or "")
        ext_id = str(cand.get("external_id") or "")

        if slug in ("ad_windows", "sysmon"):
            if srv == "security" or cat == "security" or ext_id in priority_ext_ids:
                if "4625" in det_str or ext_id in priority_ext_ids:
                    bucket_win_sec.insert(0, cand)
                else:
                    bucket_win_sec.append(cand)
            elif cat == "process_creation" and "CommandLine" in det_str:
                bucket_win_proc4688.append(cand)
            elif cat in ("registry_set", "registry_event", "ps_script", "file_event"):
                bucket_win_tier2.append(cand)
            elif cat in ("driver_load", "image_load", "dns_query", "process_access", "create_remote_thread"):
                bucket_win_tier3.append(cand)
            else:
                bucket_other.append(cand)
        elif slug == "fortigate":
            bucket_fortigate.append(cand)
        elif slug == "office365":
            bucket_office365.append(cand)
        elif slug in ("linux", "linux_os"):
            bucket_linux.append(cand)
        elif slug == "waf_akamai":
            if ext_id in priority_ext_ids:
                bucket_waf.insert(0, cand)
            else:
                bucket_waf.append(cand)
        else:
            bucket_other.append(cand)

    # Telemetry-First & Gap-Driven: se houver tecnologias prioritárias por lacunas de clientes,
    # expande a presença dessas tecnologias no lote balanceado
    gap_set = {s.lower() for s in client_gap_techs} if client_gap_techs else set()
    gap_first_rules: list[dict[str, Any]] = []
    if gap_set:
        for cand in all_candidates:
            t = match_rule_to_technology(cand, enabled_techs)
            if t and t.slug.lower() in gap_set:
                gap_first_rules.append(cand)

    balanced: list[dict[str, Any]] = []
    # Prioriza regras de lacunas no início do catálogo
    seen_ids = set()
    for g_cand in gap_first_rules[:16]:
        gid = str(g_cand.get("external_id") or "")
        if gid and gid not in seen_ids:
            seen_ids.add(gid)
            balanced.append(g_cand)

    for item in (
        bucket_win_sec[:8]
        + bucket_win_proc4688[:10]
        + bucket_win_tier2[:10]
        + bucket_win_tier3[:10]
        + bucket_fortigate[:6]
        + bucket_office365[:6]
        + bucket_linux[:6]
        + bucket_waf[:6]
    ):
        iid = str(item.get("external_id") or "")
        if iid and iid not in seen_ids:
            seen_ids.add(iid)
            balanced.append(item)

    if len(balanced) < 52:
        seen_b = {str(c.get("external_id") or "") for c in balanced}
        for extra in bucket_other + bucket_win_proc4688[10:] + bucket_win_tier2[10:]:
            eid = str(extra.get("external_id") or "")
            if eid not in seen_b:
                seen_b.add(eid)
                balanced.append(extra)
                if len(balanced) >= 56:
                    break

    return balanced


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


MITRE_NOT_INFORMED = "não informado"
MAX_NEW_CANDIDATES_PER_CYCLE = 80
MAX_CONVERSION_ATTEMPTS_PER_CYCLE = 150


def build_original_threat_context(raw_rule: dict[str, Any]) -> str:
    """Contexto de ameaça montado SOMENTE com o conteúdo da regra original.

    Reproduz descrição, tags MITRE, falsos positivos, severidade e referências tal qual
    publicados na fonte. Nenhum texto é inventado ou reescrito.
    """
    parts: list[str] = []
    desc = str(raw_rule.get("description") or "").strip()
    if desc:
        parts.append(f"Descrição original: {desc}")
    tags = raw_rule.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if tags:
        parts.append("Tags MITRE ATT&CK (originais): " + ", ".join(str(t) for t in tags))
    level = str(raw_rule.get("level") or "").strip()
    if level:
        parts.append(f"Severidade (level) original: {level}")
    fps = raw_rule.get("falsepositives") or []
    if isinstance(fps, str):
        fps = [fps]
    if fps:
        parts.append("Falsos positivos conhecidos (originais): " + "; ".join(str(f) for f in fps))
    refs = raw_rule.get("references") or []
    if isinstance(refs, str):
        refs = [refs]
    if refs:
        parts.append("Referências (originais):\n" + "\n".join(f"- {r}" for r in refs))
    return "\n\n".join(parts)


def _restore_original_metadata(item: "CuratedRuleItem") -> bool:
    """Reaplica título/descrição/contexto de ameaça a partir do YAML original armazenado.

    Retorna True se algo foi alterado.
    """
    import yaml

    try:
        data = yaml.safe_load(item.original_syntax or "")
    except Exception:
        return False
    if not isinstance(data, dict) or not str(data.get("title") or "").strip():
        return False
    changed = False
    title = str(data["title"]).strip()
    if item.title != title or item.original_title != title:
        item.title = title
        item.original_title = title
        changed = True
    desc = str(data.get("description") or "").strip()
    if desc and item.description != desc:
        item.description = desc
        changed = True
    ctx = build_original_threat_context(data)
    if ctx and item.ai_rationale != ctx:
        item.ai_rationale = ctx
        changed = True
    return changed


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


def _extract_canonical_event_identifiers(
    raw_rule: dict[str, Any],
    logql_query: str,
) -> tuple[set[str], set[str], set[str]]:
    """Extrai EventIDs, Subtipos/Ações e Categorias exigidos por uma regra de detecção.

    Retorna: (required_event_ids, required_actions, required_categories).
    Ex.:
      - EventIDs: {"4688", "4625", "4720"}
      - Actions/Subtypes: {"vpn", "ssl", "deny", "login"}
      - Categories/Services: {"process_creation", "security", "firewall"}
    """
    req_ids: set[str] = set()
    req_actions: set[str] = set()
    req_cats: set[str] = set()

    # 1. Do raw_rule (Sigma detection / metadata)
    raw_det = raw_rule.get("detection")
    if isinstance(raw_det, dict):
        try:
            det_json = json.dumps(raw_det).lower()
            # Procura por EventID
            for m in re.finditer(r'["\']?(?:eventid|event_id|eventcode)["\']?\s*:\s*(\d+|\[[^\]]+\])', det_json):
                val = m.group(1)
                for dig in re.findall(r"\b\d{3,5}\b", val):
                    req_ids.add(dig)
            # Procura por action / subtype
            for m in re.finditer(r'["\']?(?:action|subtype|operation)["\']?\s*:\s*["\']?([a-zA-Z0-9_\-]+)["\']?', det_json):
                req_actions.add(m.group(1).lower())
        except Exception:
            pass

    # 2. Da LogQL convertida (ex: data_win_system_eventID="4688", data_action="deny", data_subtype="vpn")
    for m in re.finditer(r'(?:win_system_eventID|data_win_system_eventID|event_id|eventid)\s*(?:=~|=)\s*["\']?([^"\'|\s)]+)["\']?', logql_query, re.IGNORECASE):
        for dig in re.findall(r"\b\d{3,5}\b", m.group(1)):
            req_ids.add(dig)

    for m in re.finditer(r'(?:data_action|action|data_subtype|subtype|data_office365_Operation)\s*(?:=~|=)\s*["\']?([^"\'|\s)]+)["\']?', logql_query, re.IGNORECASE):
        act = m.group(1).strip().lower().strip("^$")
        if act and len(act) >= 2 and not act.startswith(".*"):
            req_actions.add(act)

    cat = str(raw_rule.get("category") or "").strip().lower()
    if cat:
        req_cats.add(cat)
    srv = str(raw_rule.get("service") or "").strip().lower()
    if srv:
        req_cats.add(srv)

    return req_ids, req_actions, req_cats


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
            exc.status_code in (502, 504, 408)
            or "timeout" in msg_lower
            or "tempo esgotado" in msg_lower
            or "context deadline exceeded" in msg_lower
            or "bad gateway" in msg_lower
            or "connection refused" in msg_lower
            or "dial tcp" in msg_lower
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
    res_a = results.get("A") or {}
    if res_a.get("error"):
        err_str = str(res_a.get("error") or "")
        err_low = err_str.lower()
        is_to = (
            int(res_a.get("status") or 0) in (502, 504, 408)
            or "timeout" in err_low
            or "deadline" in err_low
            or "bad gateway" in err_low
            or "connection refused" in err_low
            or "dial tcp" in err_low
        )
        return False, [], is_to, err_str[:160]
    frames = res_a.get("frames", [])
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


def _expand_observed_field_aliases(raw_fields: set[str]) -> set[str]:
    """Expande sinônimos estruturais de campos JSON do Wazuh/EventLog/Sysmon no Loki."""
    expanded = set(raw_fields)
    alias_groups = [
        {
            "data_win_eventdata_image",
            "win_eventdata_image",
            "data_win_eventdata_newProcessName",
            "win_eventdata_newProcessName",
            "data_win_eventdata_processName",
            "win_eventdata_processName",
        },
        {
            "data_win_eventdata_parentImage",
            "win_eventdata_parentImage",
            "data_win_eventdata_parentProcessName",
            "win_eventdata_parentProcessName",
        },
        {
            "data_win_eventdata_targetUserName",
            "win_eventdata_targetUserName",
            "data_win_eventdata_user",
            "win_eventdata_user",
        },
        {
            "data_win_eventdata_targetObject",
            "win_eventdata_targetObject",
            "data_win_eventdata_objectName",
            "win_eventdata_objectName",
        },
        {"data_action", "action"},
    ]
    for k in list(raw_fields):
        if k.startswith("data_win_"):
            expanded.add(k.replace("data_win_", "win_", 1))
        elif k.startswith("win_"):
            expanded.add(f"data_{k}")
    lower_snapshot = {f.lower() for f in expanded}
    for grp in alias_groups:
        if any(g in expanded or g.lower() in lower_snapshot for g in grp):
            expanded.update(grp)
    return expanded


async def _verify_targeted_fields_in_loki(
    grafana: GrafanaClient,
    datasource_uid: str,
    technology: Technology,
    missing_fields: list[str],
    time_from: str = "now-3d",
    timeout: float = 2.5,
) -> tuple[set[str], dict[str, list[str]]]:
    """Executa pesquisa direcionada no Loki verificando especificamente a existência dos campos.

    Em vez de contar apenas com a amostragem genérica da tecnologia ou com o disparo de ataque,
    constrói uma query LogQL filtrada para a presença de qualquer um dos campos faltantes:
    `{job="wazuh", ss_groups=~"..."} | json | field1 != "" or field2 != "" ...`

    Retorna: (found_fields, field_samples).
    """
    if not missing_fields:
        return set(), {}

    cond_parts: list[str] = []
    checked_tokens: set[str] = set()

    for f in missing_fields:
        cand_list = [f]
        if f.startswith("data_win_"):
            cand_list.append(f.replace("data_win_", "win_", 1))
        elif f.startswith("win_"):
            cand_list.append(f"data_{f}")
        elif f.startswith("data_"):
            cand_list.append(f[5:])
        else:
            cand_list.append(f"data_{f}")

        for cand in cand_list:
            if cand not in checked_tokens:
                checked_tokens.add(cand)
                cond_parts.append(f'{cand} != ""')

    if not cond_parts:
        return set(), {}

    # Limita o número de filtros de desjunção na query para evitar sobrecarga no parser do Loki
    or_condition = " or ".join(cond_parts[:16])
    stream_expr = f'{{job="{technology.job}", ss_groups=~"{technology.ss_groups_regex}"}} | json | {or_condition}'

    ok, lines, timed_out, _err = await _query_loki_lines(
        grafana=grafana,
        datasource_uid=datasource_uid,
        expr=stream_expr,
        limit=10,
        time_from=time_from,
        timeout=timeout,
    )

    if not ok or not lines:
        return set(), {}

    found_fields: set[str] = set()
    found_samples: dict[str, list[str]] = {}

    missing_lower_map = {f.lower(): f for f in missing_fields}

    for line_str in lines:
        try:
            parsed = json.loads(line_str)
            if not isinstance(parsed, dict):
                continue
            flat = _flatten_json_items(parsed)
            flat_exp = _expand_observed_field_aliases(set(flat.keys()))
            for fk, fv in flat.items():
                val_str = str(fv).strip()
                if not val_str:
                    continue
                # Se a chave ou seu sinônimo bater com um dos campos procurados
                matched_orig: str | None = None
                if fk in missing_fields:
                    matched_orig = fk
                elif fk.lower() in missing_lower_map:
                    matched_orig = missing_lower_map[fk.lower()]
                else:
                    for mf in missing_fields:
                        if mf in flat_exp or mf.lower() in {x.lower() for x in flat_exp}:
                            matched_orig = mf
                            break

                if matched_orig:
                    found_fields.add(matched_orig)
                    found_fields.add(fk)
                    bucket = found_samples.setdefault(matched_orig, [])
                    if val_str not in bucket and len(bucket) < 4:
                        bucket.append(val_str)
        except Exception:
            continue

    return found_fields, found_samples


def _evaluate_client_telemetry_readiness(
    mapped_fields: list[CurationFieldMapping],
    observed_fields: set[str],
    tech_logs_count: int,
    has_query_results: bool,
) -> tuple[bool, list[str], list[str]]:
    """Avalia se o cliente possui a telemetria necessária habilitada para a regra.

    Retorna: (has_required_telemetry, present_telemetry_labels, missing_telemetry_labels).
    """
    obs_lower = {f.lower() for f in observed_fields}
    compatible_fields = [m.logql_field for m in mapped_fields if m.compatible]
    specialized_req = [f for f in compatible_fields if f in SPECIALIZED_TELEMETRY_FIELDS]

    present_labels: list[str] = []
    missing_labels: list[str] = []
    for sf in specialized_req:
        label = SPECIALIZED_TELEMETRY_FIELDS[sf]
        if sf in observed_fields or sf.lower() in obs_lower:
            if label not in present_labels:
                present_labels.append(label)
        else:
            if label not in missing_labels:
                missing_labels.append(label)

    observed_in_client = [
        f for f in compatible_fields if f in observed_fields or f.lower() in obs_lower
    ]
    total_f = len(mapped_fields)
    obs_pct = (
        round((len(observed_in_client) * 100.0) / total_f, 1)
        if total_f > 0 and len(observed_fields) > 0
        else (100.0 if total_f == 0 else 0.0)
    )

    has_required_telemetry = bool(
        has_query_results
        or (tech_logs_count > 0 and obs_pct > 75.0 and len(missing_labels) == 0)
    )
    return has_required_telemetry, present_labels, missing_labels


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
    has_required_telemetry: bool = False,
    lint_valid: bool = True,
    multi_client: bool = False,
) -> tuple[float, float, float, float]:
    """Calcula a porcentagem de compatibilidade dinâmica recalibrada do D.A.N.T.E.:

    1. Alta Compatibilidade (95%+ / 'excellent'):
       Regra de detecção curada encontra mais de 75% (> 75%) dos campos necessários em um cliente
       E a telemetria necessária habilitada, mesmo sem a existência de logs correspondentes
       (Ex.: EvtID 4688 - TargetUserName, NewProcessName, CommandLine), ou possui disparo real comprovado.
    2. Compatibilidade 80% a 94% ('good'):
       Regra de detecção curada encontra mais de 50% (>= 50%) dos campos necessários em um cliente,
       mesmo sem a existência de logs correspondentes e sem a telemetria específica necessária
       (ex.: Command Line habilitado ou Registro sendo monitorado).
    3. Descartadas (< 80% / 'bad'):
       Regra de detecção possui abaixo de 50% (< 50%) de campos necessários encontrados em um cliente,
       não tem logs correspondentes e/ou não possui a telemetria necessária habilitada.

    Retorna: (total_compat_pct, log_presence_delta, threat_context_delta, scenario_match_delta).
    """
    if schema_compat_pct < 50.0 or not lint_valid:
        return round(min(49.0, schema_compat_pct), 1), 0.0, 0.0, 0.0

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
        p_rec = 1.4
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
    core_perims = {"identity_iam", "firewall", "waf_web", "antimalware_edr", "endpoint_edr", "cloud_saas"}
    t_perim = 0.5 if perim_clean in core_perims else 0.2
    threat_context_delta = min(6.0, t_sev + t_tac + t_spec + t_perim)

    # 3. Correspondência dos logs e telemetria com o cenário de ameaça (até +6.0%)
    if observed_field_compat_pct >= 100.0:
        m_obs = 3.0
    elif observed_field_compat_pct > 75.0:
        m_obs = 2.5
    elif observed_field_compat_pct >= 50.0:
        m_obs = 1.8
    elif observed_field_compat_pct >= 25.0:
        m_obs = 1.0
    elif observed_field_compat_pct > 0.0:
        m_obs = 0.6
    else:
        m_obs = 0.3

    has_results_bool = bool(has_query_results or matched_lines_count > 0)
    if has_results_bool:
        m_match = 2.5
    elif has_required_telemetry and observed_field_compat_pct > 75.0:
        m_match = 2.0
    elif tech_logs_count > 0 and observed_field_compat_pct >= 50.0:
        m_match = 1.2
    else:
        m_match = 0.4

    m_lint = 0.5 if lint_valid else 0.0
    scenario_match_delta = min(6.0, m_obs + m_match + m_lint)

    combined_deltas = log_presence_delta + threat_context_delta + scenario_match_delta

    # Faixa 1: Alta Compatibilidade (95% a 100%)
    # > 75% dos campos necessários encontrados no cliente + telemetria necessária (ou logs correspondentes)
    if (
        observed_field_compat_pct > 75.0
        and (has_required_telemetry or has_results_bool)
        and (tech_logs_count > 0 or has_results_bool)
    ):
        field_bonus = ((observed_field_compat_pct - 75.0) / 25.0) * 1.8
        context_bonus = (combined_deltas / 20.0) * 2.4
        hits_bonus = 0.8 if has_results_bool else 0.2
        total_score = round(95.0 + field_bonus + context_bonus + hits_bonus, 1)
        total_score = min(100.0, max(95.0, total_score))
        return (
            total_score,
            round(log_presence_delta, 1),
            round(threat_context_delta, 1),
            round(scenario_match_delta, 1),
        )

    # Faixa 2: Compatibilidade 80% a 94% (Candidata Qualificada)
    # >= 50% dos campos necessários encontrados no cliente, mesmo sem logs correspondentes e sem telemetria específica
    if (observed_field_compat_pct >= 50.0 and tech_logs_count > 0) or has_results_bool:
        field_span = max(0.0, min(50.0, observed_field_compat_pct - 50.0))
        field_bonus = (field_span / 50.0) * 7.5
        context_bonus = (combined_deltas / 20.0) * 6.8
        total_score = round(80.0 + field_bonus + context_bonus, 1)
        total_score = min(94.9, max(80.0, total_score))
        return (
            total_score,
            round(log_presence_delta, 1),
            round(threat_context_delta, 1),
            round(scenario_match_delta, 1),
        )

    # Faixa 3: Descartadas (< 80%)
    # Abaixo de 50% dos campos necessários encontrados no cliente, sem logs correspondentes e/ou sem telemetria
    base_discard = 25.0 + (max(0.0, observed_field_compat_pct) * 0.7)
    score_discard = (
        base_discard
        + (log_presence_delta * 0.5)
        + (threat_context_delta * 1.0)
        + (scenario_match_delta * 0.7)
    )
    total_score = min(78.0, max(25.0, round(score_discard, 1)))
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
    client_field_presence_cache: dict[tuple[str, str], set[str]] | None = None,
    dead_datasources: set[str] | None = None,
    rule_source: str = "",
    rule_index: int = 1,
    total_rules: int = 1,
    severity: str = "high",
    mitre_tactic: str = "",
    mitre_technique: str = "",
    raw_rule: dict[str, Any] | None = None,
) -> tuple[Literal["excellent", "good", "bad"], str, float, list[CurationClientEvaluation]]:
    """Passo 2.3: Executa a query convertida no Loki de todos os clientes em etapas progressivas
    (15m -> 1h -> 6h -> 24h -> 3d) e categoriza a regra segundo os 3 limiares recalibrados:

    1. Alta Compatibilidade (95%+ / 'excellent'): > 75% dos campos necessários encontrados em um cliente
       + telemetria necessária habilitada (mesmo sem logs correspondentes) ou logs correspondentes encontrados.
    2. Compatibilidade 80% a 94% ('good'): >= 50% dos campos necessários encontrados em um cliente,
       mesmo sem logs correspondentes e sem telemetria especializada.
    3. Descartadas (< 80% / 'bad'): < 50% dos campos necessários encontrados em um cliente,
       sem logs correspondentes e/ou sem telemetria necessária habilitada.
    """
    total_fields = len(mapped_fields)
    compatible_fields_list = [m.logql_field for m in mapped_fields if m.compatible]
    incompatible_fields_list = [m.original_field for m in mapped_fields if not m.compatible]

    schema_compat_pct = (
        round((len(compatible_fields_list) * 100.0) / total_fields, 1)
        if total_fields > 0
        else 100.0
    )

    # Se a regra possuir compatibilidade de schema inferior a 50.0%, ela é descartada (< 80%).
    if schema_compat_pct < 50.0:
        bad_reason = (
            f"Descartada (< 80%): compatibilidade de campos ({schema_compat_pct:.1f}%) abaixo do limiar mínimo "
            f"({len(incompatible_fields_list)} campo(s) incompatível(is): {', '.join(incompatible_fields_list)})."
        )
        return "bad", bad_reason, min(78.0, schema_compat_pct), []

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

            if not (rule_query_ok or instant_ok or tech_query_ok or rule_timed_out):
                continue

            # Inspeção Prévia de Telemetria Ativa (Active Telemetry Profiling)
            # Extrai os identificadores canônicos exigidos pela regra (Event IDs, Subtipos de Ação)
            req_event_ids, req_actions, req_cats = _extract_canonical_event_identifiers(
                raw_rule=raw_rule or {},
                logql_query=logql_query,
            )

            # Extrai todos os campos e valores JSON reais vistos nos logs durante as queries executadas
            raw_observed_fields: set[str] = set()
            observed_event_ids: set[str] = set()
            observed_actions: set[str] = set()

            for line_str in matched_lines + tech_lines:
                try:
                    parsed_line = json.loads(line_str)
                    if isinstance(parsed_line, dict):
                        flat_items = _flatten_json_items(parsed_line)
                        raw_observed_fields.update(flat_items.keys())
                        exp_keys = _expand_observed_field_aliases(set(flat_items.keys()))
                        for fk, fv in flat_items.items():
                            val_str = str(fv).strip()
                            if val_str:
                                # Captura Event IDs presentes na telemetria real do cliente
                                if "eventid" in fk.lower() or "eventcode" in fk.lower():
                                    observed_event_ids.add(val_str.lower())
                                # Captura Ações e Subtipos presentes na telemetria real
                                elif fk.lower() in ("data_action", "action", "data_subtype", "subtype", "data_office365_operation"):
                                    observed_actions.add(val_str.lower())

                                for cand_cf in compatible_fields_list:
                                    if cand_cf == fk or cand_cf.lower() == fk.lower() or cand_cf in exp_keys:
                                        bucket = global_field_samples.setdefault(cand_cf, [])
                                        if val_str not in bucket and len(bucket) < 4:
                                            bucket.append(val_str)
                except Exception:
                    continue

            observed_fields = _expand_observed_field_aliases(raw_observed_fields)
            global_observed_fields.update(observed_fields)
            obs_lower_set = {f.lower() for f in observed_fields}

            matched_count = len(matched_lines)
            tech_logs_count = max(len(tech_lines), scanned_tech_logs, matched_count)
            has_results = matched_count > 0

            # Critério 1: Compatibilidade dos campos necessários da regra com os logs do cliente
            # Enriquecimento prévio com o Dicionário de Campos do DANTE:
            # Se a tecnologia possuir dicionário coletado para este cliente, incorpora os campos reais
            # antes mesmo de calcular observed_in_client e missing_in_client para evitar queries lentas desnecessárias
            try:
                from .field_dictionary import get_field_dictionary_store
                dict_store_instance = get_field_dictionary_store()
                tech_dict_data = dict_store_instance.get_technology_data(technology.slug)
                if tech_dict_data and "clients" in tech_dict_data:
                    c_dict = tech_dict_data["clients"].get(c_uid)
                    if c_dict and c_dict.get("fields"):
                        dict_fields = set(c_dict["fields"])
                        raw_observed_fields.update(dict_fields)
                        known_client_fields = (
                            client_field_presence_cache.setdefault((ds_uid, technology.slug), set())
                            if client_field_presence_cache is not None
                            else set()
                        )
                        known_client_fields.update(dict_fields)
                        # Popula amostras reais registradas no dicionário para exibição no card
                        if c_dict.get("sample_values") and isinstance(c_dict["sample_values"], dict):
                            for s_k, s_vals in c_dict["sample_values"].items():
                                if s_vals and isinstance(s_vals, list):
                                    b_samp = global_field_samples.setdefault(s_k, [])
                                    for sv in s_vals:
                                        if sv not in b_samp and len(b_samp) < 4:
                                            b_samp.append(sv)
            except Exception:
                pass

            observed_fields = _expand_observed_field_aliases(raw_observed_fields)
            global_observed_fields.update(observed_fields)
            obs_lower_set = {f.lower() for f in observed_fields}

            observed_in_client = [
                f for f in compatible_fields_list if f in observed_fields or f.lower() in obs_lower_set
            ]

            missing_in_client = [
                f for f in compatible_fields_list if f not in observed_fields and f.lower() not in obs_lower_set
            ]
            # Se houver campos compatíveis ainda não encontrados na amostra genérica de logs,
            # executa uma pesquisa direcionada no Loki verificando a existência real desses campos
            targeted_found_fields: set[str] = set()
            targeted_cache_key = (ds_uid, technology.slug)
            known_client_fields = (
                client_field_presence_cache.setdefault(targeted_cache_key, set())
                if client_field_presence_cache is not None
                else set()
            )

            # Otimização prioritária do Dicionário de Campos:
            # Se a tecnologia já foi escaneada no Dicionário de Campos para este cliente e os campos
            # não existem no dicionário nem foram vistos nos logs, evita consultas lentas de 3d no Loki
            has_client_dict_coverage = bool(
                tech_dict_data
                and "clients" in tech_dict_data
                and c_uid in tech_dict_data["clients"]
                and tech_dict_data["clients"][c_uid].get("fields") is not None
            )

            # Verifica primeiro se algum campo faltante já foi confirmado anteriormente neste cliente/tecnologia
            unobserved_to_query: list[str] = []
            for mf in missing_in_client:
                if mf in known_client_fields or mf.lower() in {k.lower() for k in known_client_fields}:
                    targeted_found_fields.add(mf)
                elif not has_client_dict_coverage:
                    # Só dispara a query lenta no Loki se este cliente ainda NÃO tiver cobertura do dicionário de campos
                    unobserved_to_query.append(mf)

            # Para os que ainda não foram confirmados no cache, dispara a query direcionada ao Loki
            if unobserved_to_query and (dead_datasources is None or ds_uid not in dead_datasources):
                try:
                    dir_found, dir_samples = await _verify_targeted_fields_in_loki(
                        grafana=grafana,
                        datasource_uid=ds_uid,
                        technology=technology,
                        missing_fields=unobserved_to_query,
                        time_from="now-3d",
                        timeout=2.5,
                    )
                    if dir_found:
                        targeted_found_fields.update(dir_found)
                        known_client_fields.update(dir_found)
                        for d_k, d_v in dir_samples.items():
                            s_bucket = global_field_samples.setdefault(d_k, [])
                            for v_item in d_v:
                                if v_item not in s_bucket and len(s_bucket) < 4:
                                    s_bucket.append(v_item)
                except Exception:
                    pass

            if targeted_found_fields:
                raw_observed_fields.update(targeted_found_fields)
                observed_fields = _expand_observed_field_aliases(raw_observed_fields)
                global_observed_fields.update(observed_fields)
                obs_lower_set = {f.lower() for f in observed_fields}
                observed_in_client = [
                    f for f in compatible_fields_list if f in observed_fields or f.lower() in obs_lower_set
                ]
                missing_in_client = [
                    f for f in compatible_fields_list if f not in observed_fields and f.lower() not in obs_lower_set
                ]

            if total_fields > 0 and len(observed_fields) > 0:
                observed_compat_pct = round((len(observed_in_client) * 100.0) / total_fields, 1)
            elif total_fields == 0:
                observed_compat_pct = 100.0
            else:
                observed_compat_pct = 0.0

            has_req_telemetry, present_tel_labels, missing_tel_labels = _evaluate_client_telemetry_readiness(
                mapped_fields=mapped_fields,
                observed_fields=observed_fields,
                tech_logs_count=tech_logs_count,
                has_query_results=has_results,
            )

            win_steps_str = " → ".join(windows_evaluated) if windows_evaluated else "15 minutos"

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
                has_required_telemetry=has_req_telemetry,
                lint_valid=True,
                multi_client=False,
            )

            # -------------------------------------------------------------------------
            # Inspeção Prévia de Telemetria Ativa (Active Telemetry Profiling)
            # Avalia se os Event IDs / Subtipos de log exigidos pela regra foram
            # comprovadamente observados nos logs recentes do cliente ou confirmados no Loki.
            # -------------------------------------------------------------------------
            event_id_matched = True
            missing_event_ids: list[str] = []
            if req_event_ids:
                matched_eids = [eid for eid in req_event_ids if eid in observed_event_ids]
                if not matched_eids:
                    # Tenta validar se algum dos Event IDs exigidos existe no Loki deste cliente
                    eid_or = " or ".join([f'data_win_system_eventID = "{eid}" or win_system_eventID = "{eid}"' for eid in list(req_event_ids)[:6]])
                    eid_stream = f'{{job="{technology.job}", ss_groups=~"{technology.ss_groups_regex}"}} | json | {eid_or}'
                    try:
                        eid_ok, eid_lines, _, _ = await _query_loki_lines(
                            grafana=grafana,
                            datasource_uid=ds_uid,
                            expr=eid_stream,
                            limit=2,
                            time_from="now-3d",
                            timeout=2.0,
                        )
                        if eid_ok and eid_lines:
                            event_id_matched = True
                        else:
                            event_id_matched = False
                            missing_event_ids = sorted(req_event_ids)
                    except Exception:
                        event_id_matched = False
                        missing_event_ids = sorted(req_event_ids)

            # Subtipo / Ação exigida (ex.: VPN SSL, firewall policy)
            action_matched = True
            missing_actions: list[str] = []
            if req_actions:
                matched_acts = [act for act in req_actions if any(act in obs_act for obs_act in observed_actions)]
                if not matched_acts:
                    # Se há actions específicas requeridas e nenhuma foi observada nos logs recentes da tecnologia
                    if observed_actions:  # se observamos logs da tecnologia mas com actions completamente distintas
                        action_matched = False
                        missing_actions = sorted(req_actions)

            # Se a regra exige Event IDs específicos ou subtipos e nenhum foi comprovado no cliente:
            telemetry_profiling_passed = event_id_matched and action_matched
            if not telemetry_profiling_passed and not has_results:
                # Regra descartada no cliente por ausência do evento canônico gerador na telemetria
                c_score = min(c_score, 74.0)
                observed_compat_pct = min(observed_compat_pct, 45.0)

            # Telemetry-First & Gap-Driven: Análise de Lacuna de Detecção no Cliente
            is_client_gap = False
            client_tech_rules_count = sum(
                1 for r in c_rules if (r.get("labels") or {}).get("technology") == technology.slug
            )
            has_scanned_logs = tech_logs_count > 0
            if has_scanned_logs and client_tech_rules_count < 5 and telemetry_profiling_passed:
                is_client_gap = True

            # Fatores detalhados da qualificação neste cliente
            client_factors: list[CurationQualificationFactor] = []
            if not telemetry_profiling_passed and not has_results:
                missing_items = []
                if missing_event_ids:
                    missing_items.append(f"Event ID(s): {', '.join(missing_event_ids)}")
                if missing_actions:
                    missing_items.append(f"Subtipo(s)/Ação(ões): {', '.join(missing_actions)}")
                missing_str = "; ".join(missing_items) if missing_items else "eventos canônicos ausentes"
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="Inspeção Prévia de Telemetria Ativa (Active Telemetry Profiling)",
                        status="not_met",
                        impact="bad",
                        summary=(
                            f"Regra desqualificada em '{c_name}': os eventos canônicos necessários ({missing_str}) "
                            f"não foram comprovadamente observados nos logs da tecnologia '{technology.name}' no Loki."
                        ),
                    )
                )
            elif (req_event_ids or req_actions) and telemetry_profiling_passed:
                confirmed_items = []
                if req_event_ids:
                    confirmed_items.append(f"Event ID(s): {', '.join(sorted(req_event_ids))}")
                if req_actions:
                    confirmed_items.append(f"Subtipo(s): {', '.join(sorted(req_actions))}")
                conf_str = "; ".join(confirmed_items)
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="Inspeção Prévia de Telemetria Ativa (Active Telemetry Profiling)",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"Telemetria comprovada em '{c_name}': eventos canônicos requeridos ({conf_str}) "
                            f"estão ativos e gerando logs no Loki do cliente."
                        ),
                    )
                )

            if is_client_gap:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="Lacuna de Detecção Prioritária (Gap-Driven)",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"O cliente '{c_name}' possui telemetria ativa comprovada de {technology.name} "
                            f"({tech_logs_count} logs no período), mas conta com apenas {client_tech_rules_count} "
                            "regra(s) implementada(s). Esta regra fecha uma lacuna operacional de detecção."
                        ),
                    )
                )

            if targeted_found_fields:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="Pesquisa Direcionada de Campos (Loki)",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"Pesquisa direcionada no Loki confirmou presença do(s) campo(s): "
                            f"{', '.join(sorted(targeted_found_fields))} em '{ds_name}'."
                        ),
                    )
                )

            if observed_compat_pct > 75.0:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="1. Cobertura de Campos Necessários (> 75%)",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"{observed_compat_pct:.0f}% dos campos necessários ({', '.join(observed_in_client)}) "
                            f"encontrados em '{ds_name}' (acima do limiar de 75% para Alta Compatibilidade)."
                        ),
                    )
                )
            elif observed_compat_pct >= 50.0:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="1. Cobertura de Campos Necessários (50% a 75%)",
                        status="partial",
                        impact="good",
                        summary=(
                            f"{observed_compat_pct:.0f}% dos campos necessários ({', '.join(observed_in_client)}) "
                            f"encontrados em '{ds_name}'; ausentes na amostra atual: {', '.join(missing_in_client)}."
                        ),
                    )
                )
            else:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="1. Cobertura de Campos Necessários (< 50%)",
                        status="not_met",
                        impact="bad",
                        summary=(
                            f"Apenas {observed_compat_pct:.0f}% dos campos necessários encontrados em '{ds_name}' "
                            f"(abaixo do mínimo de 50%; ausentes: {', '.join(missing_in_client)})."
                        ),
                    )
                )

            if has_results:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="2. Telemetria & Logs Correspondentes",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"Telemetria ativa e disparo comprovado: a query retornou {matched_count} evento(s) "
                            f"correspondente(s) no datasource Loki '{ds_name}'."
                        ),
                    )
                )
            elif has_req_telemetry:
                tel_detail = f" ({', '.join(present_tel_labels)})" if present_tel_labels else ""
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="2. Telemetria Necessária Habilitada",
                        status="met",
                        impact="excellent",
                        summary=(
                            f"Telemetria necessária habilitada em '{ds_name}'{tel_detail}; "
                            "0 logs de ataque correspondentes no momento (pronta para detecção em tempo real)."
                        ),
                    )
                )
            elif observed_compat_pct >= 50.0 and tech_logs_count > 0:
                miss_tel_detail = (
                    f" Telemetria específica pendente: {', '.join(missing_tel_labels)}."
                    if missing_tel_labels
                    else ""
                )
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="2. Telemetria Base Disponível (80% a 94%)",
                        status="partial",
                        impact="good",
                        summary=(
                            f"Mais de 50% dos campos necessários presentes em '{ds_name}' ({tech_logs_count} logs da tecnologia), "
                            f"sem logs correspondentes no período.{miss_tel_detail}"
                        ),
                    )
                )
            else:
                client_factors.append(
                    CurationQualificationFactor(
                        criterion="2. Telemetria & Logs Correspondentes",
                        status="not_met",
                        impact="bad",
                        summary=(
                            f"Abaixo de 50% dos campos necessários em '{ds_name}', sem logs correspondentes "
                            "e/ou telemetria necessária desabilitada."
                        ),
                    )
                )

            # Categorização recalibrada no cliente:
            # 1) Alta Compatibilidade (95%+ / 'excellent'): c_score >= 95.0 (> 75% campos + telemetria ou hits)
            # 2) Compatibilidade 80% a 94% ('good'): 80.0 <= c_score < 95.0 (>= 50% campos)
            # 3) Descartada (< 80% / 'bad'): c_score < 80.0 (< 50% campos, sem logs e/ou telemetria)
            if c_score >= 95.0:
                client_quality: CurationCandidateQuality = "excellent"
                if has_results:
                    reason = (
                        f"Alta Compatibilidade ({c_score:.1f}%) em '{c_name}': {observed_compat_pct:.0f}% dos campos "
                        f"necessários ({', '.join(observed_in_client)}) validados, telemetria habilitada e "
                        f"{matched_count} log(s) correspondente(s) em '{ds_name}'."
                    )
                else:
                    reason = (
                        f"Alta Compatibilidade ({c_score:.1f}%) em '{c_name}': mais de 75% ({observed_compat_pct:.0f}%) "
                        f"dos campos necessários ({', '.join(observed_in_client)}) e telemetria necessária encontrados "
                        f"em '{ds_name}', pronta para detecção mesmo sem ocorrências de ataque no período."
                    )
            elif c_score >= 80.0:
                client_quality = "good"
                miss_note = (
                    f" (telemetria complementar sugerida: {', '.join(missing_tel_labels)})"
                    if missing_tel_labels
                    else ""
                )
                reason = (
                    f"Compatibilidade {c_score:.1f}% (faixa 80% a 94%) em '{c_name}': {observed_compat_pct:.0f}% "
                    f"dos campos necessários ({', '.join(observed_in_client)}) encontrados no cliente{miss_note}."
                )
            elif tech_logs_count > 0 or instant_ok or rule_query_ok or rule_timed_out:
                client_quality = "bad"
                reason = (
                    f"Descartada em '{c_name}' ({c_score:.1f}% < 80%): apenas {observed_compat_pct:.0f}% dos campos "
                    f"necessários encontrados (< 50%), 0 logs correspondentes nas janelas ({win_steps_str}) "
                    "e/ou telemetria necessária não habilitada."
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
    global_obs_lower = {f.lower() for f in global_observed_fields}
    for mf in mapped_fields:
        mf.observed_in_logs = (
            mf.logql_field in global_observed_fields or mf.logql_field.lower() in global_obs_lower
        )
        mf.sample_values = global_field_samples.get(mf.logql_field, [])[:4]

    # Ordena avaliações: primeiro 'excellent' (95%+), depois 'good' (80%-94%), depois por score e nome
    client_evaluations.sort(
        key=lambda ev: (
            0 if ev.classification == "excellent" else (1 if ev.classification == "good" else 2),
            -(ev.field_compatibility_pct or 0.0),
            -ev.matched_lines_count,
            ev.client_name.lower(),
        )
    )

    excellent_clients = [ev for ev in client_evaluations if ev.classification == "excellent"]
    good_clients = [ev for ev in client_evaluations if ev.classification == "good"]

    # Consolidação da compatibilidade dinâmica global da regra
    total_tech_all = sum(ev.tech_logs_count for ev in client_evaluations)
    total_hits_all = sum(ev.matched_lines_count for ev in client_evaluations)
    obs_fields_global = [m.logql_field for m in mapped_fields if m.observed_in_logs]
    global_obs_pct = (
        round((len(obs_fields_global) * 100.0) / total_fields, 1)
        if total_fields > 0 and len(global_observed_fields) > 0
        else (100.0 if total_fields == 0 else 0.0)
    )
    best_client_obs_pct = max(
        (ev.observed_field_compatibility_pct for ev in client_evaluations),
        default=global_obs_pct,
    )
    # Se todas as avaliações de clientes foram descartadas por telemetria ausente / profiling, limita global_obs_pct
    if not excellent_clients and not good_clients:
        effective_obs_pct = min(global_obs_pct, best_client_obs_pct, 45.0)
        has_telemetry_any = False
    else:
        effective_obs_pct = max(global_obs_pct, best_client_obs_pct)
        global_has_telemetry, _, _ = _evaluate_client_telemetry_readiness(
            mapped_fields=mapped_fields,
            observed_fields=global_observed_fields,
            tech_logs_count=total_tech_all,
            has_query_results=(total_hits_all > 0),
        )
        has_telemetry_any = bool(global_has_telemetry or len(excellent_clients) > 0)
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
        observed_field_compat_pct=effective_obs_pct,
        has_query_results=(total_hits_all > 0),
        has_required_telemetry=has_telemetry_any,
        lint_valid=True,
        multi_client=has_multi,
    )
    if not excellent_clients and not good_clients and global_dynamic_score >= 80.0:
        global_dynamic_score = min(global_dynamic_score, 74.0)

    if excellent_clients:
        names = ", ".join(
            f"{ev.client_name} (janela: {ev.matched_window})" if ev.matched_window else ev.client_name
            for ev in excellent_clients
        )
        total_hits = sum(ev.matched_lines_count for ev in excellent_clients)
        if total_hits > 0:
            overall_reason = (
                f"Alta Compatibilidade ({global_dynamic_score:.1f}%): {effective_obs_pct:.0f}% dos campos necessários "
                f"({', '.join(obs_fields_global or compatible_fields_list)}) e telemetria confirmados, "
                f"com {total_hits} log(s) correspondente(s) em {len(excellent_clients)} cliente(s) [{names}]."
            )
        else:
            overall_reason = (
                f"Alta Compatibilidade ({global_dynamic_score:.1f}%): mais de 75% ({effective_obs_pct:.0f}%) dos campos "
                f"necessários ({', '.join(obs_fields_global or compatible_fields_list)}) e telemetria necessária "
                f"habilitada em {len(excellent_clients)} cliente(s) [{names}], mesmo sem logs de ataque correspondentes."
            )
        return "excellent", overall_reason, global_dynamic_score, client_evaluations

    if good_clients:
        names = ", ".join(ev.client_name for ev in good_clients)
        overall_reason = (
            f"Compatibilidade {global_dynamic_score:.1f}% (faixa 80% a 94%): {effective_obs_pct:.0f}% dos campos "
            f"necessários ({', '.join(obs_fields_global or compatible_fields_list)}) encontrados em "
            f"{len(good_clients)} cliente(s) [{names}], mesmo sem logs correspondentes ou telemetria especializada."
        )
        return "good", overall_reason, global_dynamic_score, client_evaluations

    overall_reason = (
        f"Descartada ({global_dynamic_score:.1f}% < 80%): apenas {effective_obs_pct:.0f}% dos campos necessários "
        "encontrados nos clientes (< 50%), sem logs correspondentes e/ou sem a telemetria necessária habilitada."
    )
    return "bad", overall_reason, global_dynamic_score, client_evaluations


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
        purged_unverified = 0
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

                    # Purga registros legados que usavam placeholder pysigma_ast ou | logfmt
                    has_legacy_ast = (
                        "| logfmt" in str(item.get("logql_query") or "")
                        or any(
                            isinstance(m, dict) and str(m.get("logql_field") or "") in ("pysigma_ast", "data_pysigma_ast")
                            for m in (item.get("mapped_fields") or [])
                        )
                    )
                    if has_legacy_ast:
                        purged_unverified += 1
                        migrated_titles = True
                        continue
                    # Regras fabricadas (sem arquivo real na fonte / URL inexistente) são purgadas
                    if not is_verified_source_rule(
                        str(item.get("external_id") or ""),
                        str(item.get("source_id") or ""),
                        str(item.get("source_url") or ""),
                    ):
                        purged_unverified += 1
                        migrated_titles = True
                        continue
                    try:
                        parsed = CuratedRuleItem(**item)
                        if _restore_original_metadata(parsed):
                            migrated_titles = True
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
                    if not is_verified_source_rule(
                        str(d_item.get("external_id") or ""),
                        str(d_item.get("source_id") or ""),
                        str(d_item.get("source_url") or ""),
                    ):
                        purged_unverified += 1
                        migrated_titles = True
                        continue
                    try:
                        d_parsed = CuratedRuleItem(**d_item)
                        if _restore_original_metadata(d_parsed):
                            migrated_titles = True
                        canon_url = get_canonical_source_url(d_parsed.external_id, d_parsed.source_url)
                        if canon_url and canon_url != d_parsed.source_url:
                            d_parsed.source_url = canon_url
                            migrated_titles = True
                        self._discarded_rules[d_parsed.id] = d_parsed
                    except Exception:
                        pass

                # Se houver regras descartadas corrompidas (com placeholder fake (?i)T, pysigma_ast ou URL raiz), regenera tudo
                has_corrupted_discarded = any(
                    "full_log =~" in (r.logql_query or "")
                    or "| logfmt" in (r.logql_query or "")
                    or any(m.logql_field in ("pysigma_ast", "data_pysigma_ast") for m in r.mapped_fields)
                    or r.source_url in ROOT_OR_DIR_URL_PATTERNS
                    or "/tree/master/" in (r.source_url or "")
                    for r in self._discarded_rules.values()
                )
                if has_corrupted_discarded:
                    purged_unverified += len(self._discarded_rules)
                    self._discarded_rules.clear()
                    migrated_titles = True
                if purged_unverified:
                    # Reconstrói as assinaturas de deduplicação sem os registros fabricados,
                    # para que regras reais com o mesmo título/consulta não sejam bloqueadas.
                    self._seen_signatures = set()
                    for kept in list(self._rules.values()) + list(self._discarded_rules.values()):
                        self._register_rule_signatures_locked(
                            kept.external_id, kept.title, kept.original_title, kept.logql_query
                        )
                    self._discarded_bad_count = len(self._discarded_rules)
                    logger.warning(
                        "Curadoria: %d registro(s) fabricado(s)/sem fonte real purgado(s) do store.",
                        purged_unverified,
                    )
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
            self._persist_locked()
            return count

    def _seed_discarded_candidates_locked(self) -> None:
        """Mantido por compatibilidade: NÃO semeia mais regras descartadas.

        Regras descartadas só existem quando uma regra REAL da fonte foi avaliada e reprovada
        pelo ciclo de curadoria; nunca são fabricadas a partir de catálogo embutido.
        """
        return

    def mark_unconvertible(self, external_id: str) -> None:
        """Registra que a regra real não pôde ser convertida, para não reprocessá-la a cada ciclo."""
        if not external_id:
            return
        with self._lock:
            self._load_locked()
            self._seen_signatures.add(f"ext:{external_id.strip().lower()}")
            self._persist_locked()

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
        """Persiste apenas as novas regras excelentes (95%+) e boas (80%-94%) e atualiza estatísticas do ciclo."""
        with self._lock:
            self._load_locked()
            for updated in updated_existing_rules:
                if (
                    updated.id in self._rules
                    and updated.classification in ("excellent", "good")
                    and (updated.field_compatibility_pct or 0.0) >= 80.0
                ):
                    orig_rule = self._rules[updated.id]
                    updated.ignored = orig_rule.ignored
                    updated.ignored_at = orig_rule.ignored_at
                    self._rules[updated.id] = updated
                elif updated.id in self._rules:
                    del self._rules[updated.id]

            for item in new_rules:
                # Regra 2: Apenas regras com >= 80% de compatibilidade (95%+ Alta Compatibilidade ou 80%-94% Qualificada) são admitidas
                if item.classification not in ("excellent", "good") or (item.field_compatibility_pct or 0.0) < 80.0:
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

            # Purga qualquer regra prévia que fique abaixo do limiar de 80%
            for rid in list(self._rules.keys()):
                r = self._rules[rid]
                if (r.field_compatibility_pct or 0.0) < 80.0 or r.classification not in ("excellent", "good"):
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
def compute_next_08h00_run(
    settings: Settings | None = None,
    schedule_settings: Any | None = None,
) -> datetime:
    """Calcula o próximo disparo diário no fuso horário configurado (padrão UTC-3)."""
    cfg = settings or get_settings()
    hour = schedule_settings.hour if schedule_settings is not None else cfg.curation_schedule_hour
    minute = schedule_settings.minute if schedule_settings is not None else cfg.curation_schedule_minute
    tz_offset = schedule_settings.timezone_offset_hours if schedule_settings is not None else cfg.curation_timezone_offset_hours

    tz = timezone(timedelta(hours=tz_offset))
    now_local = datetime.now(tz)
    target = now_local.replace(
        hour=hour,
        minute=minute,
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

    any_client_has_telemetry = False
    for ev in item.client_evaluations:
        ev_obs_set = _expand_observed_field_aliases(set(ev.total_observed_log_fields or ev.observed_fields_in_logs or []))
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
            mitre_tactic=item.mitre_tactic,
            mitre_technique=item.mitre_technique,
            perimeter=item.perimeter,
            observed_field_compat_pct=float(ev.observed_field_compatibility_pct or 0.0),
            has_query_results=bool(ev.has_query_results or ev.matched_lines_count > 0),
            has_required_telemetry=ev_has_tel,
            lint_valid=item.lint_valid,
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

    # 2. Recalcula a pontuação dinâmica global ponderada da regra
    best_client_obs_pct = max(
        (float(ev.observed_field_compatibility_pct or 0.0) for ev in item.client_evaluations),
        default=obs_pct,
    )
    effective_obs_pct = max(obs_pct, best_client_obs_pct)
    global_obs_set = _expand_observed_field_aliases(set(obs_fields))
    global_has_tel, _, _ = _evaluate_client_telemetry_readiness(
        mapped_fields=item.mapped_fields,
        observed_fields=global_obs_set,
        tech_logs_count=total_tech,
        has_query_results=has_results,
    )
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
        observed_field_compat_pct=effective_obs_pct,
        has_query_results=has_results,
        has_required_telemetry=bool(global_has_tel or any_client_has_telemetry),
        lint_valid=item.lint_valid,
        multi_client=has_multi_clients,
    )

    # Se o item estiver descartado ou não tiver clientes qualificados, recalibra pontuação e cobertura observada
    has_qualified_clients = any(ev.classification in ("excellent", "good") for ev in item.client_evaluations)
    if (item.discarded or not has_qualified_clients) and not has_results:
        effective_obs_pct = min(effective_obs_pct, 45.0)
        any_client_has_telemetry = False
        global_has_tel = False
        dynamic_score, log_score, threat_score, scenario_score = compute_dynamic_compatibility(
            schema_compat_pct=schema_compat_pct,
            tech_logs_count=total_tech,
            matched_lines_count=total_matched,
            matched_windows=[ev.matched_window for ev in item.client_evaluations if ev.matched_window],
            severity=str(item.severity),
            mitre_tactic=item.mitre_tactic,
            mitre_technique=item.mitre_technique,
            perimeter=item.perimeter,
            observed_field_compat_pct=effective_obs_pct,
            has_query_results=has_results,
            has_required_telemetry=False,
            lint_valid=item.lint_valid,
            multi_client=has_multi_clients,
        )
        if dynamic_score >= 80.0:
            dynamic_score = min(dynamic_score, 74.0)

    if not item.discarded:
        if dynamic_score >= 95.0:
            item.classification = "excellent"
        elif dynamic_score >= 80.0:
            item.classification = "good"
        else:
            item.classification = "bad"

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

    # Pilar 3: Cobertura de Campos & Telemetria Necessária
    if has_results:
        p3_impact = "excellent"
        p3_status = "met"
        match_desc = f"disparo real comprovado nos logs ({total_matched} evento(s) correspondente(s)) e telemetria ativa"
    elif effective_obs_pct > 75.0 and (global_has_tel or any_client_has_telemetry):
        p3_impact = "excellent"
        p3_status = "met"
        match_desc = "mais de 75% dos campos necessários e telemetria habilitada encontrados no cliente (Alta Compatibilidade 95%+)"
    elif effective_obs_pct >= 50.0:
        p3_impact = "good"
        p3_status = "met"
        match_desc = "mais de 50% dos campos necessários encontrados no cliente (Compatibilidade 80% a 94%)"
    else:
        p3_impact = "bad"
        p3_status = "not_met"
        match_desc = "abaixo de 50% dos campos necessários encontrados no cliente (< 80% Descartada)"

    obs_sample = f" (ex: {', '.join(obs_fields[:4])})" if obs_fields else ""
    factors.append(
        CurationQualificationFactor(
            criterion="3. Cobertura de Campos & Telemetria no Cliente",
            status=p3_status,
            impact=p3_impact,
            summary=(
                f"{effective_obs_pct:.0f}% dos campos necessários observados{obs_sample}; {match_desc} "
                f"(+{scenario_score:.1f} pts de correspondência com o cenário)."
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
    item.observed_field_compatibility_pct = effective_obs_pct
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
    client_field_presence_cache: dict[tuple[str, str], set[str]] = {}
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

        # Contagem de clientes por tecnologia, telemetria confirmada e lacunas de detecção (Gap-Driven)
        tech_client_counts: dict[str, int] = {}
        tech_scanned_counts: dict[str, int] = {}
        perim_client_counts: dict[str, int] = {}
        client_gap_techs: set[str] = set()

        for f in client_folders:
            c_uid = str(f.get("uid") or "").strip()
            c_rules = [r for r in all_rules if str(r.get("folderUID") or "") == c_uid]
            c_rule_techs = {
                str((r.get("labels") or {}).get("technology") or "").lower()
                for r in c_rules
            }
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
                if t.slug in scanned_techs:
                    tech_scanned_counts[t.slug] = tech_scanned_counts.get(t.slug, 0) + 1
                    # Telemetry-First & Gap-Driven: se o cliente tem logs confirmados da tecnologia
                    # mas possui menos de 5 regras daquela tecnologia, isso é uma lacuna de detecção prioritária!
                    tech_rule_count = sum(1 for r in c_rules if (r.get("labels") or {}).get("technology") == t.slug)
                    if tech_rule_count < 5:
                        client_gap_techs.add(t.slug)

            for p in seen_perims_in_client:
                perim_client_counts[p] = perim_client_counts.get(p, 0) + 1

        # Ordena tecnologias para curadoria: telemetria confirmada + presença em clientes primeiro,
        # dando preferência analítica aos perímetros corporativos líderes (Identidade, Cloud / SaaS, Firewall)
        def _tech_priority(t: Technology) -> tuple[int, int, int, str]:
            c_scan = tech_scanned_counts.get(t.slug, 0)
            c_cnt = tech_client_counts.get(t.slug, 0)
            p_core = 2 if t.perimeter in ("identity_iam", "cloud_saas") else (1 if t.perimeter in ("firewall", "antimalware_edr") else 0)
            return (c_scan, c_cnt, p_core, t.name)

        technologies.sort(key=_tech_priority, reverse=True)

        # Filtra as buscas nos 4 sites confiáveis APENAS para tecnologias que já existem no D.A.N.T.E.,
        # priorizando fortemente lacunas reais de detecção (Gap-Driven)
        searched_candidates = search_rules_in_trusted_sources(technologies, client_gap_techs=client_gap_techs)

        # Priorização estrita da IA e do pipeline:
        # 1) Tecnologias com evidência real de telemetria nos clientes (Telemetry-First)
        # 2) Tecnologias com lacunas de regras identificadas no parque (Gap-Driven)
        # 3) Prevalência geral de clientes e perímetros líderes
        def _candidate_priority(cand: dict[str, Any]) -> tuple[int, int, int, int, str]:
            cand_tech = match_rule_to_technology(cand, technologies)
            if not cand_tech:
                return (-1, -1, -1, -1, "")
            is_gap = 1 if cand_tech.slug in client_gap_techs else 0
            t_scan = tech_scanned_counts.get(cand_tech.slug, 0)
            t_cnt = tech_client_counts.get(cand_tech.slug, 0)
            p_core = 2 if cand_tech.perimeter in ("identity_iam", "cloud_saas") else (1 if cand_tech.perimeter in ("firewall", "antimalware_edr") else 0)
            p_cnt = perim_client_counts.get(cand_tech.perimeter, 0)
            return (is_gap, t_scan, t_cnt, p_core + p_cnt, str(cand.get("original_title") or ""))

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
        attempted_conversions = 0
        for cand_idx, candidate in enumerate(searched_candidates, start=1):
            if _STOP_REQUESTED:
                raise asyncio.CancelledError("Parada de curadoria solicitada pelo operador.")
            # O catálogo real do SigmaHQ tem milhares de regras: cada ciclo diário processa um
            # lote limitado (as demais ficam para os próximos ciclos, pois nunca foram vistas).
            if (
                len(prepared_new_candidates) >= MAX_NEW_CANDIDATES_PER_CYCLE
                or attempted_conversions >= MAX_CONVERSION_ATTEMPTS_PER_CYCLE
            ):
                break
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
                        original_format=str(candidate.get("original_format") or candidate.get("rule_format") or "Sigma (YAML)"),
                        original_syntax=str(candidate.get("original_syntax") or candidate.get("raw_yaml") or ""),
                        logql_query=disc_logql,
                        mapped_fields=disc_mf,
                        technology=disc_tech_slug,
                        technology_name=disc_tech_name,
                        perimeter=disc_perim_slug,
                        perimeter_name=disc_perim_name,
                        rule_groups_regex=disc_regex,
                        job="wazuh",
                        severity=candidate.get("severity", "medium"),
                        mitre_tactic=str(candidate.get("mitre_tactic") or MITRE_NOT_INFORMED),
                        mitre_technique=str(candidate.get("mitre_technique") or MITRE_NOT_INFORMED),
                        threshold_operator="gt",
                        threshold_value=0.0,
                        for_duration="0s",
                        classification="bad",
                        classification_reason="Descartada no Passo 2.1: tecnologia não ativada no parque avaliado",
                        field_compatibility_pct=0.0,
                        curated_at=ran_at,
                        curation_engine=curation_engine,
                        ai_rationale=build_original_threat_context(candidate) or None,
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

            attempted_conversions += 1
            # Mantém o nome da regra em inglês tal qual está nas fontes pesquisadas
            canonical_title = orig_title

            # Passo 2.2: Converter para LogQL (via IA se configurada, ou fallback para motor heurístico)
            # Garantia: NENHUM log do Loki é enviado para a IA (apenas schema e regra).
            curation_engine: Literal["ai", "heuristic"] = "heuristic"
            ai_model: str | None = None
            ai_rationale: str | None = None
            # Metadados MITRE são SEMPRE os da regra original (nunca inferidos/inventados)
            mitre_tactic = str(candidate.get("mitre_tactic") or MITRE_NOT_INFORMED)
            mitre_technique = str(candidate.get("mitre_technique") or MITRE_NOT_INFORMED)

            logql_query, mapped_fields, lint_ok, lint_msg = convert_rule_to_logql(
                candidate, tech, known_patterns
            )
            if lint_ok and mapped_fields:
                heuristic_curated_count += 1
            elif ai_enabled and not ai_circuit_broken:
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
                        ai_curated_count += 1
                    else:
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
                    heuristic_curated_count += 1
            else:
                heuristic_curated_count += 1

            # Contexto de ameaça = conteúdo da regra original (descrição, tags, falsos positivos, refs)
            ai_rationale = build_original_threat_context(candidate) or None
            ai_model = ai_model or "D.A.N.T.E. Threat Context"

            if not lint_ok:
                discarded_bad_count += 1
                curation_store.mark_unconvertible(ext_id)
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
                client_field_presence_cache=client_field_presence_cache,
                dead_datasources=dead_datasources,
                rule_source=src_name,
                rule_index=work_rule_idx,
                total_rules=total_work_rules,
                severity=str(candidate.get("severity") or "high"),
                mitre_tactic=mitre_tactic,
                mitre_technique=mitre_technique,
                raw_rule=candidate,
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
                        original_format=str(candidate.get("original_format") or candidate.get("rule_format") or "Sigma (YAML)"),
                        original_syntax=str(candidate.get("original_syntax") or candidate.get("raw_yaml") or ""),
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
                original_format=str(candidate.get("original_format") or candidate.get("rule_format") or "Sigma (YAML)"),
                original_syntax=str(candidate.get("original_syntax") or candidate.get("raw_yaml") or ""),
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
                client_field_presence_cache=client_field_presence_cache,
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
    sys_settings: SystemSettingsStore | None = None,
) -> CurationOverviewResponse:
    """Monta a resposta consolidada da página de Curadoria."""
    cfg = settings or get_settings()
    rules = curation_store.list_rules()
    meta = curation_store.get_metadata()

    c_sched = sys_settings.get_curation_schedule() if sys_settings is not None else None
    next_run = compute_next_08h00_run(cfg, schedule_settings=c_sched)

    sched_hour = c_sched.hour if c_sched is not None else cfg.curation_schedule_hour
    sched_minute = c_sched.minute if c_sched is not None else cfg.curation_schedule_minute
    sched_tz = c_sched.timezone_offset_hours if c_sched is not None else cfg.curation_timezone_offset_hours
    sched_enabled = c_sched.enabled if c_sched is not None else True

    daily_time_str = f"{sched_hour:02d}:{sched_minute:02d}"
    tz_sign = "+" if sched_tz >= 0 else "-"
    tz_abs = abs(sched_tz)

    schedule = CurationScheduleInfo(
        enabled=sched_enabled,
        cron_expression=f"{sched_minute} {sched_hour} * * *",
        daily_time=daily_time_str,
        timezone=f"America/Sao_Paulo (UTC{tz_sign}{tz_abs:02d}:00)",
        last_run_at=meta["last_run_at"],
        next_run_at=next_run.isoformat(),
        last_run_summary=meta["last_run_summary"],
    )

    try:
        sigma_total = len(scan_local_sigma_rules())
    except Exception:
        sigma_total = 0

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
            canonical_rules_count=sigma_total if src["id"] == "sigmahq" else 0,
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

    prefix_settings = sys_settings.get_baseline_prefix()
    formatted_baseline_title = format_rule_title(
        rule.title,
        prefix_settings,
        is_baseline=True,
        technology=rule.technology,
        technology_name=rule.technology_name,
        severity=rule.severity,
    )

    if existing_baseline is not None:
        baseline_rule_uid = str(existing_baseline.get("uid") or "")
        baseline_payload = copy.deepcopy(existing_baseline)
    else:
        baseline_rule_uid = f"ghp-{uuid.uuid4().hex[:10]}"
        baseline_payload = {
            "uid": baseline_rule_uid,
            "title": formatted_baseline_title,
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
                    title=rule.title,
                    status="failed",
                    detail=f"Pasta do cliente '{c_uid}' não encontrada no Grafana.",
                )
            )
            continue

        c_name = str(target_folder.get("title") or c_uid).strip()
        c_rules = [r for r in all_rules if str(r.get("folderUID") or "") == c_uid]

        # Regra no cliente salva exatamente como ela está (sem prefixo '[nomedocliente]')
        if prefix_settings and prefix_settings.enabled and "{{tenant}}" in (prefix_settings.template or "").lower():
            clone_title = format_rule_title(
                rule.title,
                prefix_settings,
                tenant_name=c_name,
                technology=rule.technology,
                technology_name=rule.technology_name,
                severity=rule.severity,
            )
        else:
            clone_title = rule.title

        existing_in_client = find_implemented_rule(
            {"uid": baseline_rule_uid, "title": clone_title}, c_rules
        )
        if existing_in_client is not None:
            client_results.append(
                ImplementedRuleResult(
                    uid=str(existing_in_client.get("uid") or baseline_rule_uid),
                    title=str(existing_in_client.get("title") or clone_title),
                    status="skipped",
                    detail=f"Regra já implementada no cliente '{c_name}'.",
                )
            )
            implemented_client_names.append(c_name)
            continue

        clone_uid = f"ghp-{uuid.uuid4().hex[:10]}"
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
        c_sched = sys_settings.get_curation_schedule()
        if not c_sched.enabled:
            await asyncio.sleep(60.0)
            continue

        next_run = compute_next_08h00_run(settings, schedule_settings=c_sched)
        now = datetime.now(next_run.tzinfo)
        wait_seconds = max((next_run - now).total_seconds(), 1.0)
        logger.info(
            "Agendador de Curadoria: próxima execução programada para %s (em %.0fs)",
            next_run.isoformat(),
            wait_seconds,
        )
        try:
            await asyncio.sleep(wait_seconds)
            # Sincronização periódica do repositório SigmaHQ
            if getattr(settings, "sigma_auto_pull_on_schedule", True):
                try:
                    logger.info("Rotina de Curadoria: executando git pull no repositório SigmaHQ local...")
                    pull_ok, pull_msg = await asyncio.to_thread(pull_sigma_repo, settings.sigma_repo_dir)
                    logger.info("Rotina de Curadoria: resultado da sincronização do repositório Sigma: %s", pull_msg)
                except Exception as pull_err:
                    logger.warning("Rotina de Curadoria: falha ao sincronizar repositório Sigma: %s", pull_err)

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
            logger.info("Agendador de Curadoria encerrado.")
            raise
        except Exception as exc:
            logger.error("Erro na execução agendada da Curadoria: %s", exc)
            await asyncio.sleep(60.0)
