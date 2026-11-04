"""Harness E2E do laboratório de logs sintéticos (Loki) do D.A.N.T.E.

Cobre, contra a stack real (nginx :8080 -> FastAPI -> Grafana -> Loki):
  * sessão + cookie + cabeçalho anti-CSRF;
  * GET /api/loki/datasources (listagem de datasources Loki, separando internos vs clientes);
  * GET /api/loki/status (datasource provisionado, labels, readiness);
  * GET /api/loki/status?datasource_uid=loki (consulta por UID específico);
  * POST /api/loki/logs com injeção real e confirmação de ingestão em datasource interno;
  * rejeição estrita (400) de injeção de logs em data source de cliente;
  * leitura das linhas injetadas via /api/rules/execute-query (mesma rota que a
    UI usa para listar os últimos logs);
  * validações negativas: label inválida, job ausente, excesso de linhas e
    ausência do cabeçalho anti-CSRF.

As linhas injetadas ficam marcadas com synthetic="true" e são removidas pela
retenção do Loki (7 dias). Nenhum recurso do Grafana é criado.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
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


def synthetic_rows(marker: str, count: int) -> list[dict[str, object]]:
    return [
        {
            "timestamp": "2026-10-18T00:00:00Z",
            "marker": marker,
            "line_index": index,
            "rule": {"id": 5710, "level": 10, "description": "sshd: failed login"},
            "data": {"srcip": f"10.99.{index}.7", "srcuser": f"e2e{index}"},
            "full_log": f"Failed password for invalid user e2e{index} (run {marker})",
        }
        for index in range(count)
    ]


def main() -> int:
    # 0. Login ---------------------------------------------------------------
    status, body = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("login", status == 200, f"{status} {body}")
    if status != 200:
        return 1

    # 1. Listagem de datasources Loki (internos vs clientes) -----------------
    status, ds_list = call("GET", "/api/loki/datasources")
    check("GET /api/loki/datasources 200", status == 200, str(ds_list)[:200])
    if status == 200 and isinstance(ds_list, list):
        loki_internal = next((d for d in ds_list if d.get("uid") == "loki"), None)
        check("datasource 'loki' listado", loki_internal is not None)
        check("datasource 'loki' marcado como interno", bool(loki_internal and loki_internal.get("is_internal") is True))

    # 2. Status do datasource padrão e com parâmetro -------------------------
    status, state = call("GET", "/api/loki/status")
    check("GET /api/loki/status 200", status == 200, str(state)[:300])
    print("  status:", json.dumps(state, ensure_ascii=False))
    if status != 200:
        return 1
    check("datasource Loki provisionado (uid=loki)", state.get("datasource_uid") == "loki")

    # Status especificando datasource_uid
    status_param, state_param = call("GET", "/api/loki/status?datasource_uid=loki")
    check("GET /api/loki/status?datasource_uid=loki 200", status_param == 200)
    check("status com UID preserva datasource_uid", (state_param or {}).get("datasource_uid") == "loki")

    if not state.get("ready"):
        print("\nLoki não está pronto; encerrando o E2E positivo.")
        return _summary()

    # 3. Injeção positiva especificando datasource interno -------------------
    run = uuid.uuid4().hex[:8]
    stream = {"job": "wazuh", "ss_groups": "e2e_loki_lab", "agent_name": f"lab-{run}"}
    lines = synthetic_rows(run, 4)
    status, injected = call(
        "POST",
        "/api/loki/logs",
        {"datasource_uid": "loki", "stream": stream, "lines": lines, "spread_seconds": 120},
        csrf=True,
    )
    print("  inject:", status, json.dumps(injected, ensure_ascii=False)[:400])
    check("POST /api/loki/logs com datasource_uid=loki 200", status == 200, f"{status} {injected}")
    if status == 200:
        check("injeção reporta 4 linhas", injected.get("lines_sent") == 4, str(injected.get("lines_sent")))
        check("datasource_uid retornado é 'loki'", injected.get("datasource_uid") == "loki")
        check(
            "marcação synthetic aplicada ao stream",
            injected.get("stream", {}).get("synthetic") == "true",
            json.dumps(injected.get("stream")),
        )
        check("ingestão confirmada por consulta", injected.get("verified") is True, str(injected.get("verified_count")))
        check(
            "LogQL devolvida usa o seletor do stream",
            'ss_groups="e2e_loki_lab"' in str(injected.get("logql")),
            str(injected.get("logql")),
        )
        check(
            "link do Grafana Explore presente",
            str(injected.get("grafana_explore_url") or "").startswith("http"),
            str(injected.get("grafana_explore_url"))[:120],
        )

    # 4. Leitura das linhas pela rota de consulta da UI (baseline vs client) -
    status, query = call(
        "POST",
        "/api/rules/execute-query",
        {
            "query": f'{{ss_groups="e2e_loki_lab", agent_name="lab-{run}"}} | json',
            "time_range_from": "now-15m",
            "time_range_to": "now",
            "limit": 50,
            "scope": "baseline",
        },
        csrf=True,
    )
    check("POST /api/rules/execute-query scope=baseline 200", status == 200, str(status))
    total = int((query or {}).get("total_lines") or 0)
    check("consulta baseline devolve as 4 linhas injetadas", total == 4, f"total={total}")
    check("consulta baseline usou o data source Loki", (query or {}).get("datasource_name") == "Loki", (query or {}).get("datasource_name"))
    markers = [ln.get("line", "") for ln in (query or {}).get("lines", [])]
    check("linhas contêm o marcador da execução", all(run in line for line in markers) and bool(markers), markers[:1])

    # 5. Proteção de Segurança: Injeção em data source de PRODUÇÃO de cliente é RECUSADA -
    # Localiza um datasource de cliente de produção existente ou cria um tenant temporário
    client_ds = next((d for d in (ds_list or []) if d.get("is_internal") is False and not d.get("is_sandbox")), None)
    temp_tenant_uid = None
    if not client_ds:
        # Cria um tenant temporário para provar a guarda de segurança
        temp_title = f"E2E Lab Guard {run}"
        status_c, created_t = call("POST", "/api/tenants", {"title": temp_title}, csrf=True)
        if status_c in (200, 201):
            temp_tenant_uid = (created_t or {}).get("uid")
            client_ds = {"uid": temp_tenant_uid, "name": temp_title}

    if client_ds:
        c_uid = str(client_ds.get("uid"))
        status_rej, err_rej = call(
            "POST",
            "/api/loki/logs",
            {"datasource_uid": c_uid, "stream": stream, "lines": lines},
            csrf=True,
        )
        check(
            "injeção em data source de cliente recusada (400)",
            status_rej == 400,
            f"{status_rej} {err_rej}",
        )
        detail_msg = str((err_rej or {}).get("detail", "")).lower()
        check(
            "mensagem explica proibição de clientes",
            "clientes" in detail_msg and ("sandbox" in detail_msg or "internos" in detail_msg),
            str((err_rej or {}).get("detail")),
        )

        # 5.1. Prova que mesmo com cliente existente, o datasource padrão selecionado é interno
        status_def_st, state_def_st = call("GET", "/api/loki/status")
        check("status padrão com cliente existente retorna 200", status_def_st == 200)
        check(
            "status padrão escolhe datasource interno (não cliente)",
            (state_def_st or {}).get("datasource_uid") != c_uid and (state_def_st or {}).get("datasource_uid") == "loki",
            str(state_def_st),
        )

        # 5.2. Prova que injeção sem datasource_uid usa o default interno e tem sucesso
        run_def = uuid.uuid4().hex[:8]
        stream_def = {"job": "wazuh", "ss_groups": "e2e_loki_lab", "agent_name": f"lab-def-{run_def}"}
        lines_def = synthetic_rows(run_def, 2)
        status_def_inj, injected_def = call(
            "POST",
            "/api/loki/logs",
            {"stream": stream_def, "lines": lines_def, "spread_seconds": 60},
            csrf=True,
        )
        check(
            "injeção sem datasource_uid usa default interno com sucesso (200)",
            status_def_inj == 200,
            f"{status_def_inj} {injected_def}",
        )
        check(
            "injeção sem datasource_uid reporta datasource_uid interno",
            (injected_def or {}).get("datasource_uid") == "loki",
        )
    else:
        print("  [aviso] nenhum tenant/datasource de cliente disponível para teste de bloqueio")

    # Limpeza do tenant temporário se foi criado
    if temp_tenant_uid:
        call("DELETE", f"/api/tenants/{temp_tenant_uid}", csrf=True)

    # 6. Validações negativas ------------------------------------------------
    status, err = call(
        "POST",
        "/api/loki/logs",
        {"stream": {"job": "wazuh", "bad key": "x"}, "lines": lines},
        csrf=True,
    )
    check("label inválida recusada (422)", status == 422, f"{status} {err}")

    status, err = call(
        "POST",
        "/api/loki/logs",
        {"stream": {"ss_groups": "linux"}, "lines": lines},
        csrf=True,
    )
    check("job ausente recusado (422)", status == 422, f"{status} {err}")

    status, err = call(
        "POST",
        "/api/loki/logs",
        {"stream": {"job": "wazuh"}, "lines": synthetic_rows(run, 201)},
        csrf=True,
    )
    check("excesso de linhas recusado (422)", status == 422, str(status))

    status, err = call(
        "POST",
        "/api/loki/logs",
        {"stream": {"job": "wazuh"}, "lines": lines},
        csrf=False,
    )
    check("sem cabeçalho anti-CSRF recusado (403)", status == 403, str(status))

    return _summary()


def _summary() -> int:
    failed = [name for ok, name in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} verificações passaram.")
    if failed:
        print("Falhas:")
        for name in failed:
            print(" -", name)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
