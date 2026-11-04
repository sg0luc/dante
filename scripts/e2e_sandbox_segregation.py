"""Harness E2E para validação de Data Sources Sandbox, Switch de Ativação/Desativação e Segregação de Ambientes no D.A.N.T.E.

Cobre contra a stack real (FastAPI + Grafana Alerting + Loki):
  1. Login + sessão + CSRF
  2. Criação de tenant e verificação do estado inicial:
     - Data source de Produção (<cliente>) criado
     - Sandbox inicialmente inativo (sandbox_datasource_present=False)
  3. Ativação do Sandbox via switch (POST /api/tenants/{uid}/sandbox):
     - Criação real no Grafana de sandbox-<cliente>
     - GET /api/tenants reflete sandbox_datasource_present=True
     - GET /api/loki/datasources discrimina can_inject=True, is_sandbox=True
  4. Proteção de Injeção (POST /api/loki/logs):
     - Bloqueio estrito (400) no data source de produção do cliente
     - Sucesso (200) com confirmação de ingestão no data source sandbox-<cliente>
  5. Consulta LogQL segregada (POST /api/rules/execute-query):
     - scope=client retorna environments=[sandbox, production]
     - "Ambiente Sandbox" exibe os logs sintéticos injetados
     - "Ambiente de Produção" sem contaminação dos logs sintéticos
  6. Desativação do Sandbox via switch (DELETE /api/tenants/{uid}/sandbox):
     - Exclusão real no Grafana do datasource sandbox-<cliente>
     - GET /api/tenants reflete sandbox_datasource_present=False
     - GET /api/loki/datasources não contém mais sandbox-<cliente>
     - execute-query reporta status inativo no sandbox_env sem erro 500
  7. Reativação do Sandbox e limpeza final do tenant.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASE = os.getenv("PORTAL_BASE_URL", "http://localhost:8080")
CSRF = {"X-Requested-With": "hunter-portal"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {
        "PORTAL_ADMIN_USER": os.getenv("PORTAL_ADMIN_USER", "admin"),
        "PORTAL_ADMIN_PASSWORD": os.getenv("PORTAL_ADMIN_PASSWORD", ""),
    }
    env_file = REPO / ".env"
    if env_file.exists():
        for raw in env_file.read_text(encoding="utf-8").splitlines():
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


def call(method: str, path: str, body=None, *, csrf: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
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


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((condition, name))
    print(("PASS " if condition else "FAIL ") + name + (f" :: {detail}" if detail else ""))


def main() -> int:
    print("Iniciando E2E: Data Sources Sandbox, Switch e Segregação de Ambientes...")

    # 1. Login
    status, body = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("1. Login autenticado com sucesso (200)", status == 200, f"{status} {body}")
    if status != 200:
        return 1

    run_id = uuid.uuid4().hex[:6]
    tenant_title = f"E2E-Client-{run_id}"
    tenant_uid = None

    try:
        # 2. Criação do tenant temporário
        status, created_tenant = call("POST", "/api/tenants", {"title": tenant_title}, csrf=True)
        check("2. Tenant criado com sucesso (200/201)", status in (200, 201), str(created_tenant))
        if status not in (200, 201):
            return 1
        tenant_uid = (created_tenant or {}).get("uid")

        # Verifica estado inicial do tenant (sandbox deve começar inativo/false)
        status, tenant_list = call("GET", "/api/tenants")
        current_tenant = next((t for t in (tenant_list or []) if t.get("uid") == tenant_uid), None)
        check("2.1. Tenant listado em GET /api/tenants", current_tenant is not None)
        check(
            "2.2. Sandbox inicialmente inativo para o novo cliente",
            current_tenant is not None and not current_tenant.get("sandbox_datasource_present"),
            str(current_tenant),
        )

        # 3. Ativação do Sandbox via Switch (POST /api/tenants/{uid}/sandbox)
        status_act, resp_act = call("POST", f"/api/tenants/{tenant_uid}/sandbox", csrf=True)
        check("3.1. POST /api/tenants/{uid}/sandbox ativa sandbox (200)", status_act == 200, str(resp_act))
        check("3.2. Retorno confirma present=True", bool(resp_act and resp_act.get("present") is True))

        # 3.3. Confere se GET /api/tenants reflete sandbox_datasource_present=True
        status, tenant_list = call("GET", "/api/tenants")
        current_tenant = next((t for t in (tenant_list or []) if t.get("uid") == tenant_uid), None)
        check(
            "3.3. GET /api/tenants reflete sandbox_datasource_present=True",
            bool(current_tenant and current_tenant.get("sandbox_datasource_present") is True),
            str(current_tenant),
        )

        # 3.4. Listagem de data sources Loki
        status, ds_list = call("GET", "/api/loki/datasources")
        check("3.4. GET /api/loki/datasources (200)", status == 200)
        ds_list = ds_list or []

        prod_ds = next((d for d in ds_list if d.get("name") == tenant_title), None)
        sandbox_ds = next((d for d in ds_list if d.get("name") == f"sandbox-{tenant_title}"), None)

        check("3.5. Data source de Produção existe", prod_ds is not None, str(prod_ds))
        check("3.6. Data source de Produção está bloqueado para injeção (can_inject=False)", bool(prod_ds and prod_ds.get("can_inject") is False))

        check("3.7. Data source de Sandbox (sandbox-<cliente>) existe no Grafana", sandbox_ds is not None, str(sandbox_ds))
        check("3.8. Data source de Sandbox está liberado para injeção (can_inject=True, is_sandbox=True)", bool(sandbox_ds and sandbox_ds.get("can_inject") is True and sandbox_ds.get("is_sandbox") is True))

        if not prod_ds or not sandbox_ds:
            return 1

        # 4. Injeção Negativa: Bloqueio estrito de injeção em Produção
        stream = {"job": "wazuh", "ss_groups": f"e2e_sb_{run_id}", "agent_name": f"agent-{run_id}"}
        lines = [
            {
                "timestamp": "2026-10-30T00:00:00Z",
                "marker": run_id,
                "data": {"srcip": "10.0.0.1", "action": "login_attempt"},
                "full_log": f"Synthetic log in sandbox for client {tenant_title}",
            }
        ]

        status_inj_prod, err_prod = call(
            "POST",
            "/api/loki/logs",
            {"datasource_uid": prod_ds["uid"], "stream": stream, "lines": lines},
            csrf=True,
        )
        check("4.1. Injeção em data source de produção é BLOQUEADA com 400", status_inj_prod == 400, f"{status_inj_prod} {err_prod}")
        check(
            "4.2. Mensagem instrui a utilizar o data source de sandbox",
            f"sandbox-{tenant_title}" in str(err_prod) or "sandbox" in str(err_prod).lower(),
            str(err_prod),
        )

        # 4.3. Injeção Positiva: Injeção com sucesso no data source de Sandbox
        status_inj_sb, resp_sb = call(
            "POST",
            "/api/loki/logs",
            {"datasource_uid": sandbox_ds["uid"], "stream": stream, "lines": lines, "spread_seconds": 60},
            csrf=True,
        )
        check("4.3. Injeção no data source de SANDBOX é ACEITA com 200", status_inj_sb == 200, f"{status_inj_sb} {resp_sb}")
        check("4.4. Ingestão verificada no sandbox", bool(resp_sb and resp_sb.get("verified") is True))

        # Aguarda 1s para o Loki indexar completamente
        time.sleep(1.0)

        # 5. Validação LogQL: Execução de Query no escopo "client" com Sandbox Ativo
        query_expr = f'{{job="wazuh", ss_groups=~".*e2e_sb_{run_id}.*"}} | json'
        status_query, query_resp = call(
            "POST",
            "/api/rules/execute-query",
            {
                "query": query_expr,
                "scope": "client",
                "client_uid": tenant_uid,
                "time_range_from": "now-1h",
                "time_range_to": "now",
                "limit": 25,
            },
            csrf=True,
        )
        check("5.1. POST /api/rules/execute-query scope=client retorna 200", status_query == 200, f"{status_query} {query_resp}")

        environments = (query_resp or {}).get("environments") or []
        check("5.2. Resposta contém a segregação de ambientes ('environments')", len(environments) == 2, f"Total envs: {len(environments)}")

        env_sb = next((e for e in environments if e.get("environment") == "sandbox"), None)
        env_prod = next((e for e in environments if e.get("environment") == "production"), None)

        check("5.3. 'Ambiente Sandbox' está presente na resposta", env_sb is not None and env_sb.get("environment_label") == "Ambiente Sandbox")
        check(
            "5.4. 'Ambiente Sandbox' contém os logs sintéticos injetados",
            bool(env_sb and env_sb.get("total_lines", 0) >= 1),
            f"Sandbox lines: {(env_sb or {}).get('total_lines')}",
        )
        check(
            "5.5. 'Ambiente Sandbox' usa o data source sandbox-<cliente>",
            bool(env_sb and env_sb.get("datasource_name") == f"sandbox-{tenant_title}"),
            str((env_sb or {}).get("datasource_name")),
        )

        check("5.6. 'Ambiente de Produção' está presente na resposta", env_prod is not None and env_prod.get("environment_label") == "Ambiente de Produção")
        check(
            "5.7. 'Ambiente de Produção' usa o data source do cliente",
            bool(env_prod and env_prod.get("datasource_name") == tenant_title),
            str((env_prod or {}).get("datasource_name")),
        )
        check(
            "5.8. 'Ambiente de Produção' não contém logs sintéticos (sem contaminação)",
            bool(env_prod and env_prod.get("total_lines") == 0),
            f"Prod lines: {(env_prod or {}).get('total_lines')}",
        )

        # 6. Desativação do Sandbox via Switch (DELETE /api/tenants/{uid}/sandbox)
        status_dis, resp_dis = call("DELETE", f"/api/tenants/{tenant_uid}/sandbox", csrf=True)
        check("6.1. DELETE /api/tenants/{uid}/sandbox desativa sandbox (200)", status_dis == 200, str(resp_dis))
        check("6.2. Retorno confirma present=False", bool(resp_dis and resp_dis.get("present") is False))

        # 6.3. Confere se GET /api/tenants reflete sandbox_datasource_present=False
        status, tenant_list = call("GET", "/api/tenants")
        current_tenant = next((t for t in (tenant_list or []) if t.get("uid") == tenant_uid), None)
        check(
            "6.3. GET /api/tenants reflete sandbox_datasource_present=False após desativação",
            bool(current_tenant and current_tenant.get("sandbox_datasource_present") is False),
            str(current_tenant),
        )

        # 6.4. Confere se sandbox-<cliente> realmente foi excluído do Grafana
        status, ds_list_after = call("GET", "/api/loki/datasources")
        sb_exists_now = any((d.get("name") == f"sandbox-{tenant_title}") for d in (ds_list_after or []))
        check("6.4. Data source sandbox-<cliente> NÃO existe mais no Grafana", not sb_exists_now)

        # 6.5. Query com sandbox desativado deve retornar informação adequada no env sandbox
        status_q_dis, resp_q_dis = call(
            "POST",
            "/api/rules/execute-query",
            {
                "query": query_expr,
                "scope": "client",
                "client_uid": tenant_uid,
                "time_range_from": "now-1h",
                "time_range_to": "now",
                "limit": 25,
            },
            csrf=True,
        )
        check("6.5. Query com sandbox desativado retorna 200 (graceful)", status_q_dis == 200)
        envs_after = (resp_q_dis or {}).get("environments") or []
        sb_env_after = next((e for e in envs_after if e.get("environment") == "sandbox"), None)
        check("6.6. Ambiente sandbox indica que está inativo/desativado", bool(sb_env_after and "desativado" in str(sb_env_after.get("error") or "").lower()))

    finally:
        # 7. Limpeza completa
        if tenant_uid:
            status_del, del_resp = call("DELETE", f"/api/tenants/{tenant_uid}", csrf=True)
            check("7. Exclusão do tenant temporário com sucesso (200)", status_del == 200, str(del_resp))

            # Verifica se ambos os datasources saíram do Grafana
            _, updated_ds = call("GET", "/api/loki/datasources")
            p_exists = any((d.get("name") == tenant_title) for d in (updated_ds or []))
            sb_exists = any((d.get("name") == f"sandbox-{tenant_title}") for d in (updated_ds or []))
            check("7.1. Data source de produção removido no Grafana", not p_exists)
            check("7.2. Data source de sandbox removido no Grafana", not sb_exists)

    # Resumo final
    total = len(results)
    passed = sum(1 for ok, _ in results if ok)
    failed = total - passed
    print(f"\nResultados do Teste: {passed}/{total} passaram ({failed} falhas).")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
