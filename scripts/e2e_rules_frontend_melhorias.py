#!/usr/bin/env python3
"""E2E Test: Regras de Detecção - Melhorias de Frontend, Labels e Pop-up.

Valida:
1. Resposta de GET /api/rules contendo o campo 'silenced_instances';
2. Criação de regra com grupo de avaliação padrão '5m';
3. Listagem confirmando persistência e remoção limpa do artefato.
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("PORTAL_BASE_URL", "http://localhost:8080")
CSRF = {"X-Requested-With": "hunter-portal"}

cookie_handler = urllib.request.HTTPCookieProcessor()
opener = urllib.request.build_opener(cookie_handler)
results: list[tuple[bool, str]] = []


def check(cond: bool, desc: str, detail: str = "") -> None:
    results.append((cond, desc))
    status = "PASS" if cond else "FAIL"
    msg = f"{status} {desc}"
    if detail:
        msg += f" :: {detail}"
    print(msg)


def call(method: str, path: str, body: dict | None = None, csrf: bool = False) -> tuple[int, dict | list | str | None]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    if csrf:
        headers.update(CSRF)
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=30) as resp:
            raw = resp.read()
            if resp.status == 204 or not raw:
                return resp.status, None
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except Exception:
            parsed = raw.decode(errors="replace")
        return exc.code, parsed


def main() -> int:
    print("=== D.A.N.T.E. E2E :: Regras de Detecção - Melhorias Frontend & API ===")

    # Limpeza prévia de regras antigas de teste se existirem
    grafana_url = os.environ.get("GRAFANA_EXTERNAL_URL", "http://localhost:3000")
    g_user = os.environ.get("GRAFANA_ADMIN_USER", "admin")
    g_pass = os.environ.get("GRAFANA_ADMIN_PASSWORD", "GrafanaAdmin@2026!Pass")
    g_auth = base64.b64encode(f"{g_user}:{g_pass}".encode()).decode()

    for stale_uid in ("ghp-c949b11186", "ghp-50a94bf688", "ghp-e47583b133"):
        try:
            req = urllib.request.Request(
                f"{grafana_url}/api/v1/provisioning/alert-rules/{stale_uid}",
                headers={"Authorization": f"Basic {g_auth}"},
                method="DELETE",
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception:
            pass

    # 1. Autenticação
    user = os.environ.get("PORTAL_ADMIN_USER", "hunter")
    password = os.environ.get("PORTAL_ADMIN_PASSWORD", "")
    status, login_res = call("POST", "/api/auth/login", {"username": user, "password": password}, csrf=True)
    check(status == 200, "1.1 Login de SecOps bem-sucedido", f"Status: {status}")

    # 2. GET /api/rules e validação de silenced_instances
    status, rules = call("GET", "/api/rules")
    check(status == 200, "2.1 GET /api/rules retorna 200 OK", f"Status: {status}")
    check(isinstance(rules, list), "2.2 Retorno é lista de regras", f"Total: {len(rules) if isinstance(rules, list) else 0}")

    if isinstance(rules, list) and rules:
        all_have_silenced_instances = all("silenced_instances" in r for r in rules)
        check(all_have_silenced_instances, "2.3 Todas as regras contêm campo 'silenced_instances'")

    # 3. Criação de nova regra com evaluation_group='5m'
    test_rule_name = "E2E Test Regra Grupo 5m"
    payload = {
        "name": test_rule_name,
        "description": "Regra temporária de validação E2E do grupo 5m",
        "scope": "baseline",
        "severity": "high",
        "mitre_tactic": "credential-access",
        "mitre_technique": "T1110",
        "logql_query": 'count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json [5m])',
        "evaluation_group": "5m",
        "technology": "ad_windows",
    }
    status, created_rule = call("POST", "/api/rules", payload, csrf=True)
    check(status in (200, 201), "3.1 POST /api/rules cria regra com grupo 5m com sucesso", f"Status: {status}")

    created_uid = None
    if isinstance(created_rule, dict):
        created_uid = created_rule.get("uid")
        check(bool(created_uid), "3.2 UID gerado para nova regra", f"UID: {created_uid}")

    if created_uid:
        status, rule_detail = call("GET", f"/api/rules/{created_uid}")
        check(status == 200, "3.3 GET /api/rules/{uid} retorna 200 OK")
        if isinstance(rule_detail, dict):
            group_name = rule_detail.get("rule_group")
            check(group_name == "5m", "3.4 Regra criada possui ruleGroup='5m'", f"Group: {group_name}")

    # 4. Limpeza via Grafana Provisioning API
    if created_uid:
        del_req = urllib.request.Request(
            f"{grafana_url}/api/v1/provisioning/alert-rules/{created_uid}",
            headers={"Authorization": f"Basic {g_auth}"},
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(del_req, timeout=10) as r:
                check(r.status in (200, 204), "4.1 Regra de teste removida no Grafana", f"Status: {r.status}")
        except Exception as e:
            check(False, "4.1 Falha ao remover regra no Grafana", str(e))

    failed = [desc for cond, desc in results if not cond]
    print(f"\nResultado final: {len(results) - len(failed)}/{len(results)} checks aprovados.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
