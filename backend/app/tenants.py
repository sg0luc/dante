"""Identidade de um tenant no Grafana (pasta + data source Loki + grupo de avaliação).

Um tenant é materializado por três recursos, criados e removidos juntos:

1. **Pasta** (``grafana_folder``): regras de detecção e dashboards do cliente.
2. **Data source Loki homônimo**: fronteira lógica da telemetria do cliente.
3. **Grupo de avaliação** ``5m`` com intervalo de ``5m``: organização
   das regras do cliente no Grafana Alerting.

O Grafana **não persiste grupo de avaliação vazio** (grupos são derivados das regras
— a API de provisioning aceita o PUT mas não lista um grupo sem regras). Para que o
grupo exista no seletor "Evaluation group and interval" desde a criação do tenant, o
portal o materializa com uma **regra-âncora pausada**, marcada com a label
``portal_internal=rule_group_anchor``. Essas regras são internas do portal e ficam
fora de todas as contagens/listagens (``detection_rules``) — inclusive da regra que
proíbe excluir tenant com regras.

Além disso, cada cliente conta com um data source Loki de **SANDBOX** (``sandbox-<cliente>``),
destinado com exclusividade ao laboratório de injeção de logs sintéticos e testes
seguros de regras antes de produção.
"""

from __future__ import annotations

import uuid
from typing import Any

from .contact_points import DEFAULT_CONTACT_POINT

# Nome do grupo de avaliação dos clientes: ``5m`` (intervalo de 5m).
# pelas regras criadas pelo portal desde a primeira versão da página Tenants).
DEFAULT_TENANT_RULE_GROUP = "5m"
RULE_GROUP_PREFIX = "detections-"
# O baseline institucional usa um grupo próprio, na pasta ``global``.
BASELINE_RULE_GROUP = "global-detections"
# Intervalo obrigatório dos grupos de tenant.
RULE_GROUP_INTERVAL = "5m"
RULE_GROUP_INTERVAL_SECONDS = 300

# Marcação das regras internas do portal (nunca são detecções do cliente).
INTERNAL_LABEL = "portal_internal"
INTERNAL_ANCHOR_VALUE = "rule_group_anchor"
ANCHOR_TITLE_PREFIX = "[D.A.N.T.E.]"

# Tipos de data source Loki aceitos pelo Grafana.
LOKI_DATASOURCE_TYPES = {"loki", "grafana-loki-datasource"}
SANDBOX_DATASOURCE_PREFIX = "sandbox-"


def sandbox_datasource_name(title_or_name: str) -> str:
    """Nome do data source de sandbox de um cliente (prefixo 'sandbox-')."""
    clean = title_or_name.strip()
    if clean.lower().startswith(SANDBOX_DATASOURCE_PREFIX):
        return clean
    return f"{SANDBOX_DATASOURCE_PREFIX}{clean}"


def sandbox_datasource_uid(uid: str) -> str:
    """UID do data source de sandbox de um cliente (prefixo 'sandbox-')."""
    clean = uid.strip()
    if clean.lower().startswith(SANDBOX_DATASOURCE_PREFIX):
        return clean
    return f"{SANDBOX_DATASOURCE_PREFIX}{clean}"


def is_sandbox_datasource(name: str = "", uid: str = "") -> bool:
    """Verifica se um nome ou UID pertence a um data source de sandbox."""
    return (
        name.strip().lower().startswith(SANDBOX_DATASOURCE_PREFIX)
        or uid.strip().lower().startswith(SANDBOX_DATASOURCE_PREFIX)
    )


def find_tenant_datasource(
    title: str, uid: str, datasources: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Localiza o data source Loki de PRODUÇÃO do tenant (por UID; fallback por nome)."""
    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
    ]
    for datasource in lokis:
        ds_uid = str(datasource.get("uid") or "")
        if ds_uid in (uid, f"{uid}-loki") and not is_sandbox_datasource(uid=ds_uid):
            return datasource
    normalized = title.strip().casefold()
    for datasource in lokis:
        ds_name = str(datasource.get("name") or "").strip()
        if ds_name.casefold() == normalized and not is_sandbox_datasource(name=ds_name):
            return datasource
    return None


def find_tenant_sandbox_datasource(
    title: str, uid: str, datasources: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Localiza o data source Loki de SANDBOX do tenant (por UID; fallback por nome)."""
    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
    ]
    # 1. Busca por UID direto de sandbox
    sandbox_uids = {
        sandbox_datasource_uid(uid),
        f"{sandbox_datasource_uid(uid)}-loki",
        f"sandbox-{uid}",
        f"sandbox-{uid}-loki",
    }
    for datasource in lokis:
        ds_uid = str(datasource.get("uid") or "")
        if ds_uid in sandbox_uids:
            return datasource

    # 2. Busca por nome com o prefixo sandbox-
    prod_ds = find_tenant_datasource(title, uid, datasources)
    prod_name = str(prod_ds.get("name") or title).strip() if prod_ds else title.strip()
    target_names = {
        sandbox_datasource_name(title).casefold(),
        sandbox_datasource_name(prod_name).casefold(),
    }
    for datasource in lokis:
        ds_name = str(datasource.get("name") or "").strip().casefold()
        if ds_name in target_names:
            return datasource

    return None


def build_tenant_sandbox_datasource_payload(
    title: str, prod_datasource_uid: str, url: str
) -> dict[str, Any]:
    """Payload de criação do data source Loki de SANDBOX do tenant."""
    sb_name = sandbox_datasource_name(title)
    sb_uid = sandbox_datasource_uid(prod_datasource_uid)
    return {
        "name": sb_name,
        "uid": sb_uid,
        "type": "loki",
        "access": "proxy",
        "url": url,
        "isDefault": False,
        "editable": True,
        "jsonData": {
            "maxLines": 1000,
            "timeout": 30,
        },
    }


def resolve_baseline_loki_datasource(
    datasources: list[dict[str, Any]],
) -> dict[str, Any]:
    """Resolve o data source 'Loki' padrão para regras de detecção do baseline ('global')."""
    lokis = [
        ds
        for ds in datasources
        if str(ds.get("type") or "") in LOKI_DATASOURCE_TYPES
    ]
    for datasource in lokis:
        if str(datasource.get("uid") or "").strip().casefold() == "loki":
            return datasource
    for datasource in lokis:
        if str(datasource.get("name") or "").strip().casefold() == "loki":
            return datasource
    for datasource in lokis:
        if bool(datasource.get("isDefault", False)):
            return datasource
    if lokis:
        return lokis[0]
    return {"uid": "loki", "name": "Loki", "type": "loki"}


def get_client_datasource_uids(
    folders: list[dict[str, Any]],
    datasources: list[dict[str, Any]],
    baseline_uid: str = "global",
) -> set[str]:
    """Identifica os UIDs de datasources de PRODUÇÃO pertencentes a pastas de clientes (tenants)."""
    from .technology_insights import is_client_folder

    client_folders = [f for f in folders if is_client_folder(f, baseline_folder_uid=baseline_uid)]
    client_uids: set[str] = set()
    for folder in client_folders:
        title = str(folder.get("title") or "")
        f_uid = str(folder.get("uid") or "")
        ds = find_tenant_datasource(title, f_uid, datasources)
        if ds and ds.get("uid"):
            client_uids.add(str(ds["uid"]))
        if f_uid:
            client_uids.add(f_uid)
            client_uids.add(f"{f_uid}-loki")
    return client_uids


def get_client_sandbox_datasource_uids(
    folders: list[dict[str, Any]],
    datasources: list[dict[str, Any]],
    baseline_uid: str = "global",
) -> set[str]:
    """Identifica os UIDs de datasources de SANDBOX pertencentes a pastas de clientes (tenants)."""
    from .technology_insights import is_client_folder

    client_folders = [f for f in folders if is_client_folder(f, baseline_folder_uid=baseline_uid)]
    sandbox_uids: set[str] = set()
    for folder in client_folders:
        title = str(folder.get("title") or "")
        f_uid = str(folder.get("uid") or "")
        ds = find_tenant_sandbox_datasource(title, f_uid, datasources)
        if ds and ds.get("uid"):
            sandbox_uids.add(str(ds["uid"]))
        if f_uid:
            sandbox_uids.add(sandbox_datasource_uid(f_uid))
            sandbox_uids.add(f"{sandbox_datasource_uid(f_uid)}-loki")
    return sandbox_uids


def bind_rule_datasource(
    rule_payload: dict[str, Any], datasource: dict[str, Any]
) -> dict[str, Any]:
    """Aponta as queries de dados (não-expressão) de uma regra para o data source Loki alvo.

    Remove artefatos legados do TestData (``scenarioId``, ``stringInput``) e
    garante ``queryType = 'range'``, exigido pelo plugin Loki do Grafana Alerting.
    """
    ds_uid = str(datasource.get("uid") or "loki")
    ds_type = str(datasource.get("type") or "loki")
    if ds_type not in LOKI_DATASOURCE_TYPES:
        ds_type = "loki"

    for query in rule_payload.get("data") or []:
        if not isinstance(query, dict):
            continue
        q_ds_uid = str(query.get("datasourceUid") or "")
        model = dict(query.get("model") or {})
        model_ds_uid = str((model.get("datasource") or {}).get("uid") or "")
        if q_ds_uid == "__expr__" or model_ds_uid == "__expr__":
            continue
        query["datasourceUid"] = ds_uid
        query["queryType"] = "range"
        model["datasource"] = {"type": ds_type, "uid": ds_uid}
        model["queryType"] = "range"
        model.setdefault("editorMode", "code")
        model.setdefault("legendFormat", "__auto")
        model.pop("scenarioId", None)
        model.pop("stringInput", None)
        query["model"] = model

    return rule_payload


def tenant_slug(title: str) -> str:
    """Slug usado em nome de grupo: minúsculas e espaços -> hífen.

    Mantém exatamente a transformação original do portal (``Banco Alfa`` ->
    ``banco-alfa``) para não renomear grupos já existentes no Grafana.
    """
    slug = title.strip().lower().replace(" ", "-")
    return slug or "cliente"


def tenant_rule_group(title: str = "") -> str:
    """Nome canônico do grupo de avaliação do tenant."""
    return DEFAULT_TENANT_RULE_GROUP


def is_internal_rule(rule: dict[str, Any]) -> bool:
    """Indica se a regra é um artefato interno do portal (âncora de grupo)."""
    labels = rule.get("labels") or {}
    marker = str(labels.get(INTERNAL_LABEL) or "").strip().lower()
    if marker and marker != "false":
        return True
    return str(rule.get("title") or "").startswith(ANCHOR_TITLE_PREFIX)


def detection_rules(rules: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Somente regras de detecção reais — sem artefatos internos do portal."""
    return [rule for rule in (rules or []) if not is_internal_rule(rule)]


def anchor_rule(rules: list[dict[str, Any]] | None, folder_uid: str) -> dict[str, Any] | None:
    """Regra-âncora (materializadora do grupo) de uma pasta, se existir."""
    for rule in rules or []:
        if str(rule.get("folderUID") or "") != folder_uid:
            continue
        labels = rule.get("labels") or {}
        marker = str(labels.get(INTERNAL_LABEL) or "").strip().lower()
        if marker == INTERNAL_ANCHOR_VALUE:
            return rule
    return None


def rules_in_other_groups(
    rules: list[dict[str, Any]] | None, folder_uid: str, group: str
) -> list[dict[str, Any]]:
    """Regras de detecção da pasta que estão fora do grupo canônico do tenant.

    Serve para detectar desvio de grupo (regra criada antes do padrão, ou em
    grupo renomeado no Grafana) e para migrá-las de volta em ``5m``.
    """
    return [
        rule
        for rule in detection_rules(rules)
        if str(rule.get("folderUID") or "") == folder_uid
        and str(rule.get("ruleGroup") or "") != group
    ]


def anchor_rule_uid() -> str:
    return f"ghp-anchor-{uuid.uuid4().hex[:10]}"


def format_interval(seconds: int | float | None) -> str | None:
    """Formata o intervalo do grupo (em segundos) como ``1m``/``30s``/``2h``."""
    if seconds is None:
        return None
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return None
    if total <= 0:
        return None
    if total % 3600 == 0:
        return f"{total // 3600}h"
    if total % 60 == 0:
        return f"{total // 60}m"
    return f"{total}s"


def build_anchor_rule_payload(folder_uid: str, tenant_title: str) -> dict[str, Any]:
    """Payload da regra-âncora que materializa o grupo de avaliação do tenant.

    A regra nasce **pausada** e com um threshold inalcançável (1e9), então nunca
    avalia nem dispara: existe apenas para o Grafana registrar o grupo com o
    intervalo de ``1m`` no seletor de Evaluation group.
    """
    group = tenant_rule_group(tenant_title)
    return {
        "uid": anchor_rule_uid(),
        "title": f"{ANCHOR_TITLE_PREFIX} Grupo de avaliação — {tenant_title}",
        "folderUID": folder_uid,
        "ruleGroup": group,
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "OK",
        "for": "0s",
        "isPaused": True,
        # Regra interna do portal: pausada, portanto o estágio de deploy é
        # irrelevante — mas o Contact Point 'dev' mantém o padrão da stack.
        "notification_settings": {"receiver": DEFAULT_CONTACT_POINT},
        "labels": {
            INTERNAL_LABEL: INTERNAL_ANCHOR_VALUE,
            "tenant": tenant_title,
            "evaluation_group": group,
        },
        "annotations": {
            "summary": f"Grupo de avaliação '{group}' do tenant {tenant_title}",
            "description": (
                "Regra interna do D.A.N.T.E.: mantém o grupo de avaliação do "
                "tenant disponível no Grafana com intervalo de 5m. Pausada e fora das "
                f"contagens do portal. Não remova — use a página Tenants para excluir "
                f"o tenant {tenant_title}."
            ),
        },
        "data": [
            {
                "refId": "A",
                "queryType": "",
                "relativeTimeRange": {"from": 300, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "0",
                    "intervalMs": 1000,
                    "maxDataPoints": 100,
                    "refId": "A",
                    "type": "math",
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
                    "maxDataPoints": 100,
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
                    "conditions": [{"evaluator": {"params": [1_000_000_000], "type": "gt"}}],
                    "datasource": {"type": "__expr__", "uid": "__expr__"},
                    "expression": "B",
                    "intervalMs": 1000,
                    "maxDataPoints": 100,
                    "refId": "C",
                    "type": "threshold",
                },
            },
        ],
    }


async def ensure_tenant_sandbox_datasource(
    grafana: Any,
    folder_title: str,
    folder_uid: str,
    datasources: list[dict[str, Any]] | None = None,
    default_url: str = "http://loki:3100",
) -> dict[str, Any] | None:
    """Garante de forma idempotente que o data source 'sandbox-<cliente>' existe no Grafana."""
    import logging
    _logger = logging.getLogger("dante.tenants")

    if datasources is None:
        try:
            datasources = await grafana.list_datasources()
        except Exception as exc:
            _logger.warning("Falha ao listar datasources para validação de sandbox: %s", exc)
            datasources = []

    existing_sandbox = find_tenant_sandbox_datasource(folder_title, folder_uid, datasources)
    if existing_sandbox is not None:
        return existing_sandbox

    prod_ds = find_tenant_datasource(folder_title, folder_uid, datasources)
    prod_uid = str((prod_ds or {}).get("uid") or folder_uid)
    loki_url = str((prod_ds or {}).get("url") or default_url)

    payload = build_tenant_sandbox_datasource_payload(folder_title, prod_uid, loki_url)
    try:
        created = await grafana.create_datasource(payload)
        _logger.info(
            "Data source de sandbox '%s' criado com sucesso para o tenant '%s' (uid=%s).",
            payload["name"],
            folder_title,
            payload["uid"],
        )
        return created
    except Exception as exc:
        _logger.warning(
            "Falha ao auto-provisionar data source de sandbox para o tenant '%s': %s",
            folder_title,
            exc,
        )
        return None
