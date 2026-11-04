"""Catálogo de tecnologias (data sources) e seu mapeamento para a label ``ss_groups``.

Contexto do SIEM:
    * O tenant/cliente é representado pelo ``grafana_folder``.
    * A tecnologia/datasource é representada pela label ``ss_groups`` no Loki,
      que é um espelho do ``rule.groups`` do Wazuh.
    * Nesta arquitetura todo log de endpoint entra por ``job="wazuh"``.

Este módulo mantém uma base persistente (arquivo JSON gravado atomicamente em um
volume Docker) que relaciona cada tecnologia a um recorte regex de ``ss_groups``.
O frontend usa essa base para renderizar o radio box de tecnologia na criação de
regras de detecção; o backend usa a mesma base para validar a segregação, ou seja,
garantir que a query de uma regra só olhe para a tecnologia selecionada.

Formato do registro (arquivo)::

    {
      "slug": "ad_windows",
      "name": "AD/Windows",
      "ss_groups_regex": ".*windows.*",
      "job": "wazuh",
      "description": "Endpoints Windows e AD",
      "icon": "🪟",
      "enabled": true
    }

A seleção LogQL correspondente é::

    ss_groups=~".*windows.*"

Regras de segurança aplicadas na escrita:
    * ``slug`` restrito a ``^[a-z0-9_]{2,32}$`` (usado em labels do Grafana e URLs).
    * ``ss_groups_regex`` precisa compilar como regex Python/RE2 (``re.compile``) e
      não pode conter ``"``, backtick, barra invertida ou quebra de linha, o que
      quebraria o literal de string do LogQL ou permitiria injeção de query.
    * Toda escrita usa arquivo temporário + ``os.replace`` (atômico) e é
      serializada por um lock de processo.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

from pydantic import BaseModel, model_validator

from .schemas import TechnologyUpsertRequest

logger = logging.getLogger("hunter_portal.technologies")

SLUG_PATTERN = re.compile(r"^[a-z0-9_]{2,32}$")

# Caracteres proibidos no regex: quebrariam o literal LogQL ou permitiriam injeção.
FORBIDDEN_REGEX_CHARS = ('"', "`", "\\", "\n", "\r")

# Matcher de grupos de regras do Wazuh (rule_groups) ou legado (ss_groups)
RULE_GROUPS_MATCHER = re.compile(
    r'\b(?:rule_groups|ss_groups)\s*(=~|!~|!=|=)\s*(?:"([^"]*)"|`([^`]*)`)'
)
SS_GROUPS_MATCHER = RULE_GROUPS_MATCHER


class TechnologyStoreError(RuntimeError):
    """Falha de leitura/escrita da base de tecnologias."""


class TechnologyNotFound(TechnologyStoreError):
    """Tecnologia inexistente na base."""


class TechnologyConflict(TechnologyStoreError):
    """Slug já cadastrado ou recurso em conflito."""


class TechnologyValidationError(TechnologyStoreError):
    """Dados inválidos para cadastro/atualização de tecnologia."""


# =============================================================================
# Catálogo Canônico de Perímetros de Detecção (Detection Perimeters)
# Amarra regras e tecnologias ao perímetro de segurança em vez do vendor fixo.
# =============================================================================
DETECTION_PERIMETERS: dict[str, dict[str, Any]] = {
    "firewall": {
        "slug": "firewall",
        "name": "Firewall",
        "icon": "local_fire_department",
        "description": "Firewalls de rede, tráfego de borda, VPNs e regras de filtragem (ex: Fortigate, Palo Alto, Check Point, pfSense, Cisco ASA).",
        "keywords": [
            "firewall", "fortigate", "fortinet", "paloalto", "panos", "checkpoint",
            "pfsense", "opnsense", "cisco_asa", "iptables", "netfilter", "sophos_xg",
            "traffic", "network_traffic", "fw", "sslvpn", "vpn", "perimeter_firewall"
        ],
    },
    "waf_web": {
        "slug": "waf_web",
        "name": "WAF / Web",
        "icon": "language",
        "description": "Web Application Firewalls e proteção HTTP (ex: Akamai WAF, Cloudflare WAF, AWS WAF, ModSecurity, F5 ASM, Nginx).",
        "keywords": [
            "waf", "web", "akamai", "cloudflare", "awswaf", "aws_waf", "modsecurity",
            "imperva", "f5_asm", "nginx_waf", "http_access", "apache", "waf_akamai"
        ],
    },
    "endpoint_edr": {
        "slug": "endpoint_edr",
        "name": "Antimalware/EDR",
        "icon": "shield",
        "description": "Detecção de endpoint, antimalware e EDR (ex: CrowdStrike, Symantec, Kaspersky, Sophos, Microsoft Defender, Wazuh EDR).",
        "keywords": [
            "edr", "endpoint", "antimalware", "antivirus", "crowdstrike", "symantec",
            "kaspersky", "sophos", "defender", "sentinelone", "carbonblack",
            "wazuh_agent", "process_creation", "malware", "sysmon", "edr_agent"
        ],
    },
    "identity_iam": {
        "slug": "identity_iam",
        "name": "Identidade",
        "icon": "badge",
        "description": "Controladores de domínio, autenticação e diretórios (ex: Active Directory, Kerberos, NTLM, Okta, Entra ID, LDAP).",
        "keywords": [
            "ad", "active_directory", "ad_windows", "windows_security", "kerberos",
            "ntlm", "ldap", "entra_id", "azuread", "okta", "iam", "authentication",
            "domain_controller", "identity"
        ],
    },
    "cloud_saas": {
        "slug": "cloud_saas",
        "name": "Cloud / SaaS",
        "icon": "cloud",
        "description": "Ambientes em nuvem e ferramentas SaaS (ex: Microsoft 365, AWS CloudTrail, Google Workspace, Azure Activity, GCP).",
        "keywords": [
            "cloud", "saas", "office365", "m365", "azure", "aws", "cloudtrail",
            "gcp", "workspace", "github", "audit_logs", "o365"
        ],
    },
    "os_host": {
        "slug": "os_host",
        "name": "Sistema Operacional",
        "icon": "terminal",
        "description": "Logs de auditoria e kernel do sistema operacional (ex: Linux Auditd, Syslog, SSHD, Windows System, macOS).",
        "keywords": [
            "linux", "syslog", "auditd", "sshd", "sudo", "system", "windows_system", "macos", "os"
        ],
    },
    "network_ids": {
        "slug": "network_ids",
        "name": "Rede / IDS / DNS",
        "icon": "hub",
        "description": "Sistemas de detecção de intrusão e sensores de rede (ex: Snort, Suricata, Zeek, DNS Query, Proxy, Cisco Umbrella).",
        "keywords": [
            "network", "ids", "ips", "snort", "suricata", "zeek", "bro", "dns",
            "proxy", "squid", "bluecoat", "cisco_umbrella"
        ],
    },
    "email_gateway": {
        "slug": "email_gateway",
        "name": "Email Gateway",
        "icon": "mail",
        "description": "Segurança de email corporativo e gateways anti-phishing (ex: Proofpoint, Mimecast, Cisco IronPort, Defender for O365).",
        "keywords": [
            "email", "mail", "proofpoint", "mimecast", "ironport", "exchange_online", "spam", "phishing"
        ],
    },
    "other": {
        "slug": "other",
        "name": "Outro",
        "icon": "category",
        "description": "Outros perímetros e fontes customizadas de telemetria.",
        "keywords": ["other", "custom", "customizado"],
    },
}


def infer_perimeter(
    slug: str, name: str = "", hints: list[str] | None = None
) -> tuple[str, str]:
    """Infere o perímetro canônico a partir de slug, nome ou hints de logsource."""
    tokens = [slug.lower().strip(), name.lower().strip()]
    if hints:
        tokens.extend([str(h).lower().strip() for h in hints if h])

    for token in tokens:
        if not token:
            continue
        if token in DETECTION_PERIMETERS:
            return token, DETECTION_PERIMETERS[token]["name"]

        for p_slug, p_meta in DETECTION_PERIMETERS.items():
            if p_slug == "other":
                continue
            for kw in p_meta.get("keywords", []):
                if kw in token or token in kw:
                    return p_slug, p_meta["name"]

    return "other", DETECTION_PERIMETERS["other"]["name"]


def normalize_perimeter(
    raw_perimeter: str | None,
    slug: str = "",
    name: str = "",
    hints: list[str] | None = None,
) -> tuple[str, str]:
    """Normaliza o perímetro garantindo que ele pertença ao catálogo oficial."""
    clean = (raw_perimeter or "").strip().lower()
    if clean in DETECTION_PERIMETERS and clean != "other":
        return clean, DETECTION_PERIMETERS[clean]["name"]
    return infer_perimeter(slug, name, hints)


class Technology(BaseModel):
    """Tecnologia/datasource mapeada para um recorte da label rule_groups do Wazuh (compatível com ss_groups)."""

    slug: str
    name: str
    rule_groups_regex: str = ""
    ss_groups_regex: str = ""
    job: str = "wazuh"
    description: str = ""
    icon: str = ""
    enabled: bool = True
    perimeter: str = "other"
    perimeter_name: str = "Outro"

    @model_validator(mode="before")
    @classmethod
    def _sync_groups(cls, data: Any) -> Any:
        if isinstance(data, dict):
            rg = data.get("rule_groups_regex") or data.get("ss_groups_regex") or ""
            if rg:
                data.setdefault("rule_groups_regex", rg)
                data.setdefault("ss_groups_regex", rg)
        return data

    @property
    def effective_groups_regex(self) -> str:
        return self.rule_groups_regex or self.ss_groups_regex or ""

    @property
    def logql_selector(self) -> str:
        """Seletor LogQL pronto para uso dentro das chaves ``{}``."""
        return build_selector(self.effective_groups_regex)


def build_selector(groups_regex: str, label_name: str = "rule_groups") -> str:
    """Monta o matcher regex para a tecnologia informada (padrão rule_groups do Wazuh)."""
    return f'{label_name}=~"{groups_regex}"'


# Janela de observação da consulta implícita de telemetria (1 minuto).
PRESENCE_WINDOW_SECONDS = 60


def validate_rule_groups_regex(regex: str) -> str:
    """Normaliza e valida o recorte de rule_groups (ou ss_groups) usado nas queries LogQL.

    Sem essa validação, um recorte malicioso poderia quebrar o literal de
    string do LogQL ou injetar estágios no pipeline.
    """
    cleaned = (regex or "").strip()
    if not cleaned:
        raise TechnologyValidationError("O recorte de ss_groups é obrigatório.")
    for bad in FORBIDDEN_REGEX_CHARS:
        if bad in cleaned:
            raise TechnologyValidationError(
                "O padrão de ss_groups não pode conter aspas, backtick, barra invertida "
                "ou quebra de linha."
            )
    try:
        re.compile(cleaned)
    except re.error as exc:
        raise TechnologyValidationError(
            f"Expressão regular inválida para ss_groups: {exc}"
        ) from exc
    return cleaned

validate_ss_groups_regex = validate_rule_groups_regex


def validate_job(job: str) -> str:
    """Normaliza e valida a label ``job`` (pipeline de ingestão do SIEM)."""
    cleaned = (job or "").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", cleaned):
        raise TechnologyValidationError(
            "A label 'job' deve conter apenas letras, números, ponto, hífen ou underscore."
        )
    return cleaned


def _range_literal(window_seconds: int) -> str:
    """Converte a janela em segundos no literal de range LogQL mais legível."""
    if window_seconds % 60 == 0:
        return f"{window_seconds // 60}m"
    return f"{window_seconds}s"


def build_log_presence_query(
    job: str,
    groups_regex: str,
    window_seconds: int = PRESENCE_WINDOW_SECONDS,
    label_name: str = "rule_groups",
) -> str:
    """Monta a query implícita de contagem de logs de uma tecnologia.

    Semântica canônica (nunca exposta ao usuário)::

        sum(count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json [1m]))

    Nota técnica: a forma curta ``count({...} | json [1m])`` **não é LogQL
    válido** — ``count`` opera sobre vetor instantâneo, e agregação de intervalo
    sobre stream de logs exige ``count_over_time`` (o Loki responde
    ``parse error ... unexpected RANGE``). A expressão acima devolve exatamente a
    mesma contagem de linhas na janela, com ``sum`` para colapsar as séries.

    Levanta ``TechnologyValidationError`` se ``job`` ou o recorte forem inválidos,
    garantindo que a string interpolada é segura antes de chegar ao Loki.
    """
    clean_job = validate_job(job)
    clean_regex = validate_rule_groups_regex(groups_regex)
    span = _range_literal(max(int(window_seconds), 30))
    inner = f'count_over_time({{job="{clean_job}", {label_name}=~"{clean_regex}"}} | json [{span}])'
    return f"sum({inner})"


def validate_technology_payload(payload: TechnologyUpsertRequest) -> Technology:
    """Valida e normaliza um payload de tecnologia.

    Levanta ``TechnologyValidationError`` com mensagem em português pronta para a UI.
    """
    slug = payload.slug.strip().lower()
    if not SLUG_PATTERN.match(slug):
        raise TechnologyValidationError(
            "O identificador (slug) deve ter de 2 a 32 caracteres, usando apenas "
            "letras minúsculas, números e underscore."
        )

    name = payload.name.strip()
    if not name:
        raise TechnologyValidationError("O nome da tecnologia é obrigatório.")

    raw_regex = payload.rule_groups_regex or payload.ss_groups_regex or ""
    regex = raw_regex.strip()
    for bad in FORBIDDEN_REGEX_CHARS:
        if bad in regex:
            raise TechnologyValidationError(
                "O padrão de ss_groups não pode conter aspas, backtick, barra invertida "
                "ou quebra de linha."
            )
    try:
        re.compile(regex)
    except re.error as exc:
        raise TechnologyValidationError(
            f"Expressão regular inválida para ss_groups: {exc}"
        ) from exc

    job = payload.job.strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", job):
        raise TechnologyValidationError(
            "A label 'job' deve conter apenas letras, números, ponto, hífen ou underscore."
        )

    perimeter_slug, perimeter_name = normalize_perimeter(
        payload.perimeter, slug=slug, name=name
    )

    return Technology(
        slug=slug,
        name=name,
        rule_groups_regex=regex,
        ss_groups_regex=regex,
        job=job,
        description=payload.description.strip(),
        icon=payload.icon.strip(),
        enabled=payload.enabled,
        perimeter=perimeter_slug,
        perimeter_name=perimeter_name,
    )


def extract_rule_groups_values(query: str) -> list[tuple[str, str]]:
    """Extrai pares ``(operador, valor)`` de ``rule_groups`` ou ``ss_groups`` em uma query LogQL."""
    return [
        (m.group(1), m.group(2) if m.group(2) is not None else m.group(3))
        for m in RULE_GROUPS_MATCHER.finditer(query)
    ]

extract_ss_groups_values = extract_rule_groups_values


def _core(pattern: str) -> str:
    """Reduz um recorte como ``.*windows.*`` ou ``(?i).*windows.*`` ao seu núcleo comparável ``windows``."""
    core = pattern.strip()
    if core.lower().startswith("(?i)"):
        core = core[4:].strip()
    while core.startswith(".*"):
        core = core[2:]
    while core.endswith(".*"):
        core = core[:-2]
    return core.strip("^$").strip().lower()


def selector_matches_technology(selector_value: str, technology: Technology) -> bool:
    """Indica se o valor de ``ss_groups`` da query pertence à tecnologia informada.

    Comparação tolerante (os recortes são do tipo ``.*windows.*``):
      1. ``re.fullmatch`` do padrão da tecnologia sobre o valor da query;
      2. sobreposição do núcleo (``windows``) em qualquer direção.
    Ignora prefixo regex case-insensitive ``(?i)`` caso presente.
    """
    value = (selector_value or "").strip()
    if not value:
        return False
    cleaned_value = value
    if cleaned_value.lower().startswith("(?i)"):
        cleaned_value = cleaned_value[4:].strip()
    try:
        eff_regex = technology.rule_groups_regex or technology.ss_groups_regex
        if (
            re.fullmatch(eff_regex, value, re.IGNORECASE)
            or re.fullmatch(eff_regex, cleaned_value, re.IGNORECASE)
        ):
            return True
    except re.error:  # pragma: no cover - padrões já validados na escrita
        pass
    tech_core = _core(technology.rule_groups_regex or technology.ss_groups_regex)
    value_core = _core(value)
    if not tech_core or not value_core:
        return False
    return tech_core in value_core or value_core in tech_core


class TechnologyStore:
    """Base persistente de tecnologias (arquivo JSON com escrita atômica)."""

    def __init__(self, store_path: str | Path, seed_path: str | Path | None = None) -> None:
        self._path = Path(store_path)
        self._seed_path = Path(seed_path) if seed_path else None
        self._lock = threading.Lock()
        self._technologies: dict[str, Technology] = {}
        self._loaded = False

    # --- carga / persistência -------------------------------------------------
    def _read_records(self, path: Path) -> list[dict[str, Any]]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TechnologyStoreError(
                f"Não foi possível ler a base de tecnologias em '{path}': {exc}"
            ) from exc
        items = raw.get("technologies") if isinstance(raw, dict) else raw
        if not isinstance(items, list):
            raise TechnologyStoreError(
                f"Formato inválido em '{path}': esperado objeto com a chave 'technologies'."
            )
        return [item for item in items if isinstance(item, dict)]

    def _load(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            if self._seed_path and self._seed_path.exists():
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._write_records(self._read_records(self._seed_path))
                logger.info("Base de tecnologias semeada a partir de %s", self._seed_path)
            else:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._write_records([])
                logger.warning("Base de tecnologias criada vazia em %s", self._path)

        records = self._read_records(self._path)
        self._technologies = {}
        for item in records:
            try:
                payload = TechnologyUpsertRequest(**item)
                tech = validate_technology_payload(payload)
            except Exception as exc:  # registro inválido não derruba o portal
                logger.error("Registro de tecnologia ignorado (%s): %s", item.get("slug"), exc)
                continue
            if tech.slug in self._technologies:
                logger.error("Slug duplicado na base de tecnologias: %s", tech.slug)
                continue
            self._technologies[tech.slug] = tech
        self._loaded = True

    def _write_records(self, records: list[dict[str, Any]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            {"version": 1, "technologies": records}, ensure_ascii=False, indent=2
        )
        fd, tmp_name = tempfile.mkstemp(dir=str(self._path.parent), prefix=".tech-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._path)
        except OSError as exc:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise TechnologyStoreError(
                f"Falha ao gravar a base de tecnologias em '{self._path}': {exc}"
            ) from exc

    def _persist(self) -> None:
        self._write_records([tech.model_dump() for tech in self._technologies.values()])

    # --- operações ------------------------------------------------------------
    def list_all(self, include_disabled: bool = True) -> list[Technology]:
        with self._lock:
            self._load()
            items = [
                tech
                for tech in sorted(
                    self._technologies.values(),
                    key=lambda t: t.name.lower(),
                )
                if include_disabled or tech.enabled
            ]
            return list(items)

    def get(self, slug: str) -> Technology:
        with self._lock:
            self._load()
            tech = self._technologies.get(slug.strip().lower())
            if tech is None:
                raise TechnologyNotFound(f"Tecnologia '{slug}' não cadastrada.")
            return tech

    def create(self, payload: TechnologyUpsertRequest) -> Technology:
        tech = validate_technology_payload(payload)
        with self._lock:
            self._load()
            if tech.slug in self._technologies:
                raise TechnologyConflict(f"Já existe uma tecnologia com o slug '{tech.slug}'.")
            for existing in self._technologies.values():
                if existing.ss_groups_regex == tech.ss_groups_regex:
                    raise TechnologyConflict(
                        f"O recorte de ss_groups '{tech.ss_groups_regex}' já está associado "
                        f"à tecnologia '{existing.name}'."
                    )
            self._technologies[tech.slug] = tech
            self._persist()
            return tech

    def update(self, slug: str, payload: TechnologyUpsertRequest) -> Technology:
        tech = validate_technology_payload(payload)
        target = slug.strip().lower()
        with self._lock:
            self._load()
            if target not in self._technologies:
                raise TechnologyNotFound(f"Tecnologia '{slug}' não cadastrada.")
            if tech.slug != target and tech.slug in self._technologies:
                raise TechnologyConflict(f"Já existe uma tecnologia com o slug '{tech.slug}'.")
            for existing in self._technologies.values():
                if existing.slug == target:
                    continue
                if existing.ss_groups_regex == tech.ss_groups_regex:
                    raise TechnologyConflict(
                        f"O recorte de ss_groups '{tech.ss_groups_regex}' já está associado "
                        f"à tecnologia '{existing.name}'."
                    )
            self._technologies.pop(target)
            self._technologies[tech.slug] = tech
            self._persist()
            return tech

    def delete(self, slug: str) -> Technology:
        target = slug.strip().lower()
        with self._lock:
            self._load()
            tech = self._technologies.pop(target, None)
            if tech is None:
                raise TechnologyNotFound(f"Tecnologia '{slug}' não cadastrada.")
            self._persist()
            return tech

    def match_query(self, query: str) -> list[Technology]:
        """Retorna todas as tecnologias compatíveis com os matchers de ``ss_groups`` da query."""
        values = [value for _op, value in extract_ss_groups_values(query)]
        with self._lock:
            self._load()
            techs = list(self._technologies.values())
        return [
            tech
            for tech in techs
            if any(selector_matches_technology(value, tech) for value in values)
        ]
