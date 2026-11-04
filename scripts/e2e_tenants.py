"""Harness E2E de Tenants com data source Loki dedicado (D.A.N.T.E.).

Cobre, contra a stack real (nginx :8080 -> FastAPI -> Grafana):
  * POST /api/tenants cria pasta (grafana_folder) E data source Loki com o nome
    do tenant, com URL padrão da stack quando nenhuma é informada;
  * o data source realmente existe no Grafana (conferido pela API com basic
    auth de admin), com type=loki e uid igual ao uid da pasta;
  * GET /api/tenants devolve o estado do data source (presente, nome, uid, url);
  * rejeições: nome duplicado (409), URL não http(s) (400), uid reservado (400);
  * DELETE /api/tenants/{uid} remove pasta E data source;
  * POST /api/tenants/{uid}/datasource recupera tenant legado (pasta sem DS) e
    devolve 409 quando o data source já existe;
  * POST /api/tenants/{uid}/evaluation-group materializa o grupo canônico em
    tenant legado, migra regras de grupo divergente e é idempotente.

Nada de dados pré-existentes é reaproveitado: todos os recursos são criados com
sufixo aleatório e removidos ao final.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import urllib.error
import urllib.request
import os
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
BASE = os.getenv("PORTAL_BASE_URL", "http://localhost:8080")
GRAFANA = os.getenv("GRAFANA_URL", "http://localhost:3000")
CSRF = {"X-Requested-With": "hunter-portal"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for raw in (REPO / ".env").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


ENV = load_env()
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
results: list[tuple[bool, str]] = []


def call(
    method: str, path: str, body=None, *, csrf: bool = False, base: str = BASE
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        for key, value in CSRF.items():
            req.add_header(key, value)
    try:
        with opener.open(req, timeout=30) as resp:
            payload = resp.read()
            return resp.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = payload.decode(errors="replace")[:400]
        return exc.code, parsed


def grafana_call(method: str, path: str, body=None) -> tuple[int, Any]:
    """Chamada ao Grafana com basic auth de admin (comprova o recurso real)."""
    creds = f"{ENV['GRAFANA_ADMIN_USER']}:{ENV['GRAFANA_ADMIN_PASSWORD']}"
    token = base64.b64encode(creds.encode()).decode()
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GRAFANA + path, data=data, method=method)
    req.add_header("Authorization", f"Basic {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = resp.read()
            return resp.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = payload.decode(errors="replace")[:400]
        return exc.code, parsed


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((condition, name))
    print(("PASS " if condition else "FAIL ") + name + (f" :: {detail}" if detail else ""))


def grafana_datasource(name: str):
    status, datasources = grafana_call("GET", "/api/datasources")
    if status != 200 or not isinstance(datasources, list):
        return None
    for ds in datasources:
        if str(ds.get("name") or "") == name:
            return ds
    return None


def grafana_rule_groups():
    status, payload = grafana_call("GET", "/api/prometheus/grafana/api/v1/rules")
    if status != 200 or not isinstance(payload, dict):
        return []
    return (payload.get("data") or {}).get("groups") or []


def grafana_group(folder_uid: str, group: str):
    for candidate in grafana_rule_groups():
        if str(candidate.get("folderUid")) == folder_uid and str(candidate.get("name")) == group:
            return candidate
    return None


def grafana_folder_rules(folder_uid: str):
    status, rules = grafana_call("GET", "/api/v1/provisioning/alert-rules")
    if status != 200 or not isinstance(rules, list):
        return []
    return [r for r in rules if str(r.get("folderUID")) == folder_uid]


def find_tenant(uid: str):
    status, tenants = call("GET", "/api/tenants")
    if status != 200 or not isinstance(tenants, list):
        return None
    return next((t for t in tenants if t.get("uid") == uid), None)


def main() -> int:
    # 0. Login ---------------------------------------------------------------
    status, _ = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("login do portal", status == 200, f"HTTP {status}")

    # 1. Criação com data source Loki dedicado -------------------------------
    suffix = uuid.uuid4().hex[:8]
    title = f"E2E Tenant {suffix}"
    uid = f"e2e-tenant-{suffix}"
    status, created = call(
        "POST",
        "/api/tenants",
        {"title": title, "uid": uid},
        csrf=True,
    )
    check("POST /api/tenants responde 200", status == 200, f"HTTP {status} {created}")
    created = created or {}
    check("tenant nasceu com uid solicitado", created.get("uid") == uid, str(created.get("uid")))
    check(
        "tenant nasceu com data source Loki marcado como presente",
        created.get("loki_datasource_present") is True,
        str(created.get("loki_datasource_present")),
    )
    check(
        "data source Loki tem o nome do tenant",
        created.get("loki_datasource_name") == title,
        str(created.get("loki_datasource_name")),
    )
    check(
        "data source Loki usa a URL padrão da stack",
        created.get("loki_datasource_url") == ENV.get("LOKI_TENANT_DATASOURCE_URL", "http://loki:3100"),
        str(created.get("loki_datasource_url")),
    )

    # Grupo de avaliação criado junto com o tenant (Evaluation group, 1m)
    expected_group = "5m"
    check(
        "tenant nasceu com o nome canônico do grupo de avaliação",
        created.get("evaluation_group") == expected_group,
        str(created.get("evaluation_group")),
    )
    check(
        "tenant nasceu com grupo de avaliação presente",
        created.get("evaluation_group_present") is True,
        str(created.get("evaluation_group_present")),
    )
    check(
        "intervalo do grupo é 5m",
        created.get("evaluation_group_interval") == "5m",
        str(created.get("evaluation_group_interval")),
    )
    group = grafana_group(uid, expected_group)
    check("grupo existe de fato no Grafana", group is not None)
    if group:
        check("intervalo real do grupo é 300s (5m)", int(group.get("interval") or 0) == 300, str(group.get("interval")))
        check("grupo contém a regra-âncora materializada", len(group.get("rules") or []) == 1, str(len(group.get("rules") or [])))

    anchor_rules = [
        r for r in grafana_folder_rules(uid)
        if str((r.get("labels") or {}).get("portal_internal") or "") == "rule_group_anchor"
    ]
    check("regra-âncora existe no Grafana", len(anchor_rules) == 1, str(len(anchor_rules)))
    if anchor_rules:
        check("regra-âncora nasce pausada", anchor_rules[0].get("isPaused") is True, str(anchor_rules[0].get("isPaused")))
        check(
            "regra-âncora nasce sem provenance (editável via GUI)",
            not str(anchor_rules[0].get("provenance") or "").strip(),
            repr(anchor_rules[0].get("provenance")),
        )
    check(
        "regra-âncora não é contada como detecção do tenant",
        created.get("rules_count") == 0,
        str(created.get("rules_count")),
    )

    ds = grafana_datasource(title)
    check("data source existe de fato no Grafana", ds is not None)
    if ds:
        check(
            "data source do tenant nasce sem provenance (editável via GUI)",
            not str(ds.get("provenance") or "").strip(),
            repr(ds.get("provenance")),
        )
        check("data source é do tipo loki", ds.get("type") == "loki", str(ds.get("type")))
        check("uid do data source acompanha o uid da pasta", ds.get("uid") == uid, str(ds.get("uid")))

    # 2. Listagem reflete o data source --------------------------------------
    listed = find_tenant(uid)
    check("GET /api/tenants lista o tenant criado", listed is not None)
    if listed:
        check(
            "listagem traz data source presente",
            listed.get("loki_datasource_present") is True,
            str(listed.get("loki_datasource_present")),
        )
        check(
            "listagem traz o nome do data source",
            listed.get("loki_datasource_name") == title,
            str(listed.get("loki_datasource_name")),
        )
        check(
            "listagem traz o grupo de avaliação",
            listed.get("evaluation_group") == expected_group
            and listed.get("evaluation_group_present") is True,
            f"{listed.get('evaluation_group')} / {listed.get('evaluation_group_present')}",
        )

    # 3. Rejeições -----------------------------------------------------------
    status, body = call("POST", "/api/tenants", {"title": title}, csrf=True)
    check("nome de data source duplicado é rejeitado (409)", status == 409, f"HTTP {status} {body}")

    status, body = call(
        "POST", "/api/tenants", {"title": f"E2E Bad Url {suffix}", "loki_url": "ftp://x"}, csrf=True
    )
    check("URL de Loki não http(s) é rejeitada (400)", status == 400, f"HTTP {status} {body}")
    check(
        "tenant inválido não deixou pasta para trás",
        next(
            (
                f
                for f in (grafana_call("GET", "/api/folders")[1] or [])
                if f.get("title") == f"E2E Bad Url {suffix}"
            ),
            None,
        )
        is None,
    )

    status, body = call(
        "POST", "/api/tenants", {"title": f"E2E Reserved {suffix}", "uid": "loki"}, csrf=True
    )
    check("uid de data source reservado é rejeitado (400)", status == 400, f"HTTP {status} {body}")

    # 3b. Pausa em lote ignora a regra-âncora (tenant continua sem regras reais)
    status, body = call("POST", f"/api/tenants/{uid}/toggle-pause", {"paused": True}, csrf=True)
    check("toggle-pause responde 200 para tenant só com âncora", status == 200, f"HTTP {status}")
    check(
        "toggle-pause não conta a âncora como regra",
        (body or {}).get("total") == 0,
        str((body or {}).get("total")),
    )
    anchor_after = [
        r for r in grafana_folder_rules(uid)
        if str((r.get("labels") or {}).get("portal_internal") or "") == "rule_group_anchor"
    ]
    check(
        "âncora permanece pausada após toggle do tenant",
        bool(anchor_after) and anchor_after[0].get("isPaused") is True,
        str(anchor_after[0].get("isPaused") if anchor_after else None),
    )

    # 4. Backfill: pasta sem data source -> POST /tenants/{uid}/datasource ----
    legacy_uid = f"e2e-legacy-{suffix}"
    legacy_title = f"E2E Legacy {suffix}"
    status, _ = call("POST", "/api/folders", {"title": legacy_title, "uid": legacy_uid}, csrf=True)
    check("pasta legada criada sem data source", status == 200, f"HTTP {status}")

    legacy = find_tenant(legacy_uid)
    check("tenant legado aparece sem data source", legacy is not None and legacy.get("loki_datasource_present") is False)
    check(
        "tenant legado (sem regra) aparece sem grupo de avaliação",
        legacy is not None and legacy.get("evaluation_group_present") is False,
        str(legacy.get("evaluation_group_present") if legacy else None),
    )

    status, ds_created = call(
        "POST", f"/api/tenants/{legacy_uid}/datasource", {}, csrf=True
    )
    check("POST /tenants/{uid}/datasource cria o data source", status == 200, f"HTTP {status} {ds_created}")
    legacy_ds = grafana_datasource(legacy_title)
    check("data source de backfill existe no Grafana com o nome do tenant", legacy_ds is not None)
    if legacy_ds:
        check("data source de backfill é loki", legacy_ds.get("type") == "loki", str(legacy_ds.get("type")))

    status, body = call("POST", f"/api/tenants/{legacy_uid}/datasource", {}, csrf=True)
    check("backfill repetido é recusado (409)", status == 409, f"HTTP {status} {body}")

    # 4c. Grupo de avaliação: desvio de padrão e correção idempotente ---------
    drift_uid = f"e2e-drift-{suffix}"
    drift_title = f"E2E Drift {suffix}"
    drift_group = "5m"
    status, _ = call("POST", "/api/folders", {"title": drift_title, "uid": drift_uid}, csrf=True)
    check("pasta de tenant desviante criada", status == 200, f"HTTP {status}")

    # Regra criada antes do padrão: vive no grupo "1m" e não há âncora na pasta.
    legacy_rule_uid = f"ghp-e2e-drift-{suffix}"
    legacy_rule = {
        "uid": legacy_rule_uid,
        "title": f"E2E Drift Rule {suffix}",
        "folderUID": drift_uid,
        "ruleGroup": "custom-legacy",
        "condition": "C",
        "noDataState": "OK",
        "execErrState": "OK",
        "for": "0s",
        "isPaused": False,
        "labels": {"team": "soc", "severity": "low"},
        "data": [
            {
                "refId": "A",
                "relativeTimeRange": {"from": 600, "to": 0},
                "datasourceUid": "__expr__",
                "model": {"expression": "1", "refId": "A", "type": "math"},
            },
            {
                "refId": "C",
                "relativeTimeRange": {"from": 0, "to": 0},
                "datasourceUid": "__expr__",
                "model": {
                    "expression": "A",
                    "refId": "C",
                    "type": "threshold",
                    "conditions": [
                        {
                            "evaluator": {"params": [0], "type": "gt"},
                            "operator": {"type": "and"},
                            "query": {"params": ["C"]},
                            "reducer": {"params": [], "type": "last"},
                            "type": "query",
                        }
                    ],
                },
            },
        ],
    }
    status, body = grafana_call("POST", "/api/v1/provisioning/alert-rules", legacy_rule)
    check("regra legada no grupo '1m' criada no Grafana", status in (200, 201), f"HTTP {status} {body}")

    drift = find_tenant(drift_uid)
    check("tenant desviante aparece na listagem", drift is not None)
    if drift:
        check(
            "tenant com regra no grupo '1m' é marcado sem grupo padrão",
            drift.get("evaluation_group_present") is False,
            str(drift.get("evaluation_group_present")),
        )
        check(
            "nome canônico do grupo é calculado mesmo com o grupo ausente",
            drift.get("evaluation_group") == drift_group,
            str(drift.get("evaluation_group")),
        )

    status, body = call(
        "POST", f"/api/tenants/{drift_uid}/evaluation-group", {"migrate_rules": True}, csrf=True
    )
    check(
        "POST /tenants/{uid}/evaluation-group corrige o desvio (200)",
        status == 200,
        f"HTTP {status} {body}",
    )
    body = body or {}
    check("resposta informa criação da regra-âncora", body.get("anchor_created") is True, str(body.get("anchor_created")))
    check(
        "resposta informa a regra migrada",
        legacy_rule_uid in (body.get("migrated_rules") or []),
        str(body.get("migrated_rules")),
    )
    check("resposta confirma grupo presente", body.get("evaluation_group_present") is True, str(body.get("evaluation_group_present")))
    check("resposta confirma intervalo 5m", body.get("evaluation_group_interval") == "5m", str(body.get("evaluation_group_interval")))
    check("resposta não registra falhas de migração", not (body.get("migration_failures") or []), str(body.get("migration_failures")))

    fixed_group = grafana_group(drift_uid, drift_group)
    check("grupo canônico existe de fato no Grafana após a correção", fixed_group is not None)
    if fixed_group:
        check("intervalo real do grupo corrigido é 300s", int(fixed_group.get("interval") or 0) == 300, str(fixed_group.get("interval")))
        check("grupo canônico tem âncora + regra migrada", len(fixed_group.get("rules") or []) == 2, str(len(fixed_group.get("rules") or [])))
    check("grupo divergente 'custom-legacy' deixou de existir", grafana_group(drift_uid, "custom-legacy") is None)

    drift_rules = {str(r.get("uid")): r for r in grafana_folder_rules(drift_uid)}
    check(
        "regra legada foi movida para o grupo canônico",
        str((drift_rules.get(legacy_rule_uid) or {}).get("ruleGroup")) == drift_group,
        str((drift_rules.get(legacy_rule_uid) or {}).get("ruleGroup")),
    )
    check(
        "regra migrada/corrigida fica sem provenance (editável via GUI)",
        not str((drift_rules.get(legacy_rule_uid) or {}).get("provenance") or "").strip(),
        repr((drift_rules.get(legacy_rule_uid) or {}).get("provenance")),
    )
    check(
        "regra migrada preservou o conteúdo (título e condição)",
        str((drift_rules.get(legacy_rule_uid) or {}).get("title")) == legacy_rule["title"],
    )

    drift_after = find_tenant(drift_uid)
    check(
        "listagem passa a mostrar o grupo presente",
        drift_after is not None and drift_after.get("evaluation_group_present") is True,
        str(drift_after.get("evaluation_group_present") if drift_after else None),
    )

    # Idempotência: repetir a correção não duplica a âncora.
    status, body = call(
        "POST", f"/api/tenants/{drift_uid}/evaluation-group", {"migrate_rules": True}, csrf=True
    )
    check("repetir a correção responde 200 (idempotente)", status == 200, f"HTTP {status}")
    check("repetição não cria nova âncora", (body or {}).get("anchor_created") is False, str((body or {}).get("anchor_created")))
    anchors = [
        r
        for r in grafana_folder_rules(drift_uid)
        if str((r.get("labels") or {}).get("portal_internal") or "") == "rule_group_anchor"
    ]
    check("existe exatamente uma regra-âncora no tenant", len(anchors) == 1, str(len(anchors)))

    # Rejeições da rota de correção.
    status, body = call("POST", "/api/tenants/global/evaluation-group", {}, csrf=True)
    check("correção de grupo no tenant global é rejeitada (400)", status == 400, f"HTTP {status} {body}")
    status, body = call("POST", "/api/tenants/e2e-nao-existe-000/evaluation-group", {}, csrf=True)
    check("correção em tenant inexistente devolve 404", status == 404, f"HTTP {status} {body}")
    status, _ = call("POST", f"/api/tenants/{drift_uid}/evaluation-group", {"migrate_rules": True})
    check("correção sem cabeçalho anti-CSRF é rejeitada", status == 403, f"HTTP {status}")


    # 5. Exclusão remove pasta e data source ---------------------------------
    status, body = call("DELETE", f"/api/tenants/{uid}", csrf=True)
    check("DELETE /api/tenants/{uid} responde 200", status == 200, f"HTTP {status} {body}")
    check("data source removido junto com o tenant", grafana_datasource(title) is None)
    check("grupo de avaliação removido junto com o tenant", grafana_group(uid, expected_group) is None)
    check("tenant sumiu da listagem", find_tenant(uid) is None)

    status, _ = call("DELETE", f"/api/tenants/{legacy_uid}", csrf=True)
    check("tenant legado removido", status == 200, f"HTTP {status}")
    check("data source do tenant legado removido", grafana_datasource(legacy_title) is None)

    # Tenant desviante: guarda de exclusão vale para a regra migrada, então ela
    # precisa sair antes de excluir o tenant.
    status, body = call("DELETE", f"/api/tenants/{drift_uid}", csrf=True)
    check(
        "tenant com regra migrada não pode ser excluído (400)",
        status == 400,
        f"HTTP {status} {body}",
    )
    status, _ = grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{legacy_rule_uid}")
    check("regra migrada removida no Grafana", status in (200, 204), f"HTTP {status}")
    status, body = call("DELETE", f"/api/tenants/{drift_uid}", csrf=True)
    check("tenant desviante removido ao final", status == 200, f"HTTP {status} {body}")
    check("grupo corrigido removido junto com o tenant", grafana_group(drift_uid, drift_group) is None)

    # 6. Sem CSRF não muta nada ---------------------------------------------
    status, _ = call("POST", "/api/tenants", {"title": f"E2E No Csrf {suffix}"})
    check("POST sem cabeçalho anti-CSRF é rejeitado", status == 403, f"HTTP {status}")

    failed = [name for ok, name in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks OK")
    if failed:
        print("Falhas:")
        for name in failed:
            print(" -", name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
