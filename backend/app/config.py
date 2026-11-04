"""Configuração do backend, carregada de variáveis de ambiente.

Todas as opções podem ser definidas via variáveis de ambiente com o mesmo nome
em maiúsculas (ex.: ``grafana_url`` -> ``GRAFANA_URL``). Valores inválidos
interrompem a inicialização (fail fast) em vez de rodar com configuração insegura.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from . import __version__

MIN_PASSWORD_LENGTH = 12


def _validate_http_url(value: str) -> str:
    """Aceita apenas URLs http(s) e remove a barra final."""
    value = value.strip()
    if not value.startswith(("http://", "https://")):
        raise ValueError("deve começar com http:// ou https://")
    return value.rstrip("/")


class Settings(BaseSettings):
    """Configurações do portal."""

    model_config = SettingsConfigDict(case_sensitive=False, extra="ignore")

    # --- Grafana -------------------------------------------------------------
    compose_profiles: str = "default"
    """Perfil do docker compose ('default' ou 'external')."""

    grafana_mode: str | None = None
    """Modo explícito do Grafana ('standalone' ou 'external'). Se omitido, deriva de compose_profiles."""

    @property
    def is_external_grafana(self) -> bool:
        """Indica se a aplicação está rodando conectada a um Grafana externo."""
        if self.grafana_mode:
            return self.grafana_mode.strip().lower() in {"external", "ext"}
        return "external" in self.compose_profiles.lower()

    grafana_url: str = "http://grafana:3000"
    """URL interna usada pelo backend para chamar a API do Grafana."""

    grafana_public_url: str = "http://localhost:3000"
    """URL do Grafana vista pelo navegador (apenas para montar links)."""

    grafana_token: SecretStr | None = None
    """Token informado diretamente (alternativa ao arquivo; útil com Grafana externo)."""

    grafana_token_file: str | None = "/run/portal-secrets/grafana_token"
    """Arquivo com o token da service account (gerado pelo grafana-bootstrap)."""

    grafana_verify_tls: bool = True
    grafana_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    # --- Catálogo de tecnologias / data sources ------------------------------
    technologies_store_path: str = "/data/technologies.json"
    """Arquivo JSON com o mapeamento ss_groups -> tecnologia (volume persistente)."""

    tenant_technologies_store_path: str = "/data/tenant-technologies.json"
    """Arquivo JSON com o inventário declarado de tecnologias por cliente.

    Alimenta o footprint usado na conformidade ao baseline: o que o cliente não
    possui no SIEM não entra no denominador das regras globais daquela
    tecnologia.
    """

    tenant_scan_store_path: str = "/data/tenant-technology-scan.json"
    """Arquivo JSON com o snapshot do último escaneamento de tecnologias por
    cliente (evidência de logs no Loki do próprio tenant). Alimenta a coluna de
    tecnologias da página Tenants sem reconsultar o Loki a cada render.
    """

    system_settings_store_path: str = "/data/system-settings.json"
    synthetic_alerts_store_path: str = "/data/synthetic-alerts.json"
    curation_store_path: str = "/data/curation-rules.json"
    curation_schedule_hour: int = Field(default=8, ge=0, le=23)
    curation_schedule_minute: int = Field(default=0, ge=0, le=59)
    curation_timezone_offset_hours: int = Field(default=-3, ge=-12, le=14)
    curation_ai_cache_path: str = "/data/curation-ai-cache.json"
    rule_evaluation_ai_cache_path: str = "/data/rules-ai-evaluation-cache.json"
    sigma_repo_dir: str = "/data/sigma-repo"
    sigma_repo_url: str = "https://github.com/SigmaHQ/sigma.git"
    sigma_auto_pull_on_schedule: bool = True
    ai_default_provider: str = "deepseek"
    ai_default_model: str = "deepseek-chat"
    deepseek_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    ai_api_base_url: str | None = None
    ai_timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    """Arquivo JSON com as configurações operacionais persistidas do portal
    (mapeamento de estágios de Contact Points e UID da pasta baseline).
    """

    loki_tenant_datasource_url: str = "http://loki:3100"
    """URL padrão do Loki usado ao criar o data source de um novo tenant.

    Cada tenant possui um data source Loki com o próprio nome; quando a URL não
    é informada no cadastro, o portal usa este endereço (o Loki da stack por
    padrão, alcançável pelo Grafana na rede ``core-net``).
    """

    # --- Autenticação do portal ---------------------------------------------
    portal_admin_user: str = Field(min_length=1, max_length=128)
    portal_admin_password: SecretStr
    session_ttl_minutes: int = Field(default=480, ge=5, le=1440)
    cookie_secure: bool = True
    login_max_attempts: int = Field(default=5, ge=1, le=100)
    login_window_seconds: int = Field(default=300, ge=10, le=86400)

    # --- Convenções de Labels e Pipelines (Customizáveis) -------------------
    default_job_label: str = "job"
    """Nome da label do Loki que identifica o pipeline de ingestão (padrão: 'job')."""

    default_job_name: str = "wazuh"
    """Valor esperado da label job para telemetria de endpoint (padrão: 'wazuh')."""

    default_technology_label: str = "rule_groups"
    """Nome da label do Loki que identifica o agrupamento de tecnologia/Wazuh (padrão: 'rule_groups')."""

    default_evaluation_group: str = "5m"
    """Intervalo padrão dos grupos de avaliação do Grafana Alerting."""

    default_baseline_folder: str = "global"
    """UID da pasta do Grafana onde reside o baseline institucional de segurança."""

    # --- Diversos ------------------------------------------------------------
    app_version: str = Field(default="")
    """Versão atual do D.A.N.T.E. (definida canonicamente em __init__.py ou via variável APP_VERSION)."""

    @field_validator("app_version", mode="before")
    @classmethod
    def _resolve_app_version(cls, v: Any) -> str:
        if not v or str(v).strip() in {"", "1.1.0"}:
            return __version__
        return str(v).strip()

    github_repo: str = "sg0luc/dante"
    """Repositório oficial no GitHub para checagem de releases e atualizações."""

    github_token: SecretStr | None = None
    """Token opcional do GitHub para autenticação de chamadas de API."""

    update_check_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    """Intervalo em segundos para cache de checagem de atualizações no GitHub."""

    updater_url: str = "http://updater:8080"
    """URL interna do serviço updater (Watchtower) para disparo in-app de atualização."""

    updater_token: SecretStr = Field(default=SecretStr("dante-updater-secret-2026"))
    """Token de autenticação compartilhado com a API HTTP do updater."""

    refresh_interval_seconds: int = Field(default=15, ge=5, le=300)
    log_level: str = "INFO"
    enable_api_docs: bool = False
    """Expõe /api/docs (Swagger). Mantenha desabilitado em produção."""

    @field_validator(
        "grafana_url",
        "grafana_public_url",
        "loki_tenant_datasource_url",
        "updater_url",
    )
    @classmethod
    def _check_urls(cls, value: str) -> str:
        return _validate_http_url(value)

    @field_validator("grafana_token", "github_token", "updater_token", mode="before")
    @classmethod
    def _check_token(cls, value: Any) -> Any:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("portal_admin_password")
    @classmethod
    def _check_password(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"PORTAL_ADMIN_PASSWORD deve ter no mínimo {MIN_PASSWORD_LENGTH} caracteres"
            )
        return value

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        value = value.upper()
        if value not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("LOG_LEVEL inválido")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retorna a instância única de configurações (carregada uma vez)."""
    return Settings()  # type: ignore[call-arg]  # campos obrigatórios vêm do ambiente
