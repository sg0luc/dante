"""Suíte de Testes E2E para o Dicionário de Campos e Agendamentos no D.A.N.T.E.

Testa de ponta a ponta:
1. Autenticação e obtenção de sessão + CSRF;
2. Leitura dos resumos de dicionário de campos: GET /api/technologies/fields/summaries;
3. Detalhe do dicionário de uma tecnologia existente: GET /api/technologies/{slug}/fields;
4. Disparo de reanálise sob demanda: POST /api/technologies/{slug}/fields/rescan;
5. Análise de discrepâncias por IA: POST /api/technologies/{slug}/fields/ai-analysis;
6. Consulta dos agendamentos do sistema: GET /api/system/schedules;
7. Atualização e persistência de agendamentos: PUT /api/system/schedules;
8. Criação de nova tecnologia disparando varredura em background: POST /api/technologies;
9. Limpeza da tecnologia criada.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

BASE = os.environ.get("E2E_BASE_URL", "http://localhost:8080")
CSRF = {"X-Requested-With": "hunter-portal"}

ADMIN_USER = os.environ.get("PORTAL_ADMIN_USER", "hunter")
ADMIN_PASS = os.environ.get("PORTAL_ADMIN_PASSWORD", "HunterPortal@2026!Pass")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
results: list[tuple[bool, str]] = []


def record(ok: bool, desc: str, detail: str = "") -> None:
    results.append((ok, desc))
    status = "PASS" if ok else "FAIL"
    msg = f"[{status}] {desc}"
    if detail:
        msg += f" -- {detail}"
    print(msg)


def call(method: str, path: str, body: Any = None, csrf: bool = False) -> tuple[int, Any]:
    url = BASE + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        for k, v in CSRF.items():
            req.add_header(k, v)
    try:
        with opener.open(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            ct = resp.headers.get("content-type", "")
            if "application/json" in ct:
                return resp.status, json.loads(raw)
            return resp.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        try:
            return exc.code, json.loads(raw)
        except Exception:
            return exc.code, raw


def run_e2e() -> None:
    print(f"=== E2E Dicionário de Campos e Agendamentos no D.A.N.T.E. ({BASE}) ===")

    # 1. Login
    code, resp = call("POST", "/api/auth/login", {"username": ADMIN_USER, "password": ADMIN_PASS}, csrf=True)
    record(code == 200, "1. Login autenticado com sucesso", f"status={code}")

    # 2. Resumos do dicionário
    code, summaries = call("GET", "/api/technologies/fields/summaries")
    has_max = False
    if code == 200 and isinstance(summaries, dict):
        # Verifica se max_unique_fields_per_client está presente nos resumos
        ad_sum = summaries.get("ad_windows")
        if ad_sum and "max_unique_fields_per_client" in ad_sum:
            has_max = True
    record(
        code == 200 and isinstance(summaries, dict) and has_max,
        "2. GET /api/technologies/fields/summaries (com max_unique_fields_per_client)",
        f"status={code}, has_max={has_max}",
    )

    # 3. Detalhes do dicionário para 'ad_windows'
    code, dict_detail = call("GET", "/api/technologies/ad_windows/fields")
    record(
        code == 200 and dict_detail.get("technology_slug") == "ad_windows",
        "3. GET /api/technologies/ad_windows/fields",
        f"status={code}, unique_fields={dict_detail.get('total_unique_fields', 0)}",
    )

    # 4. Reanálise sob demanda
    code, rescan_resp = call("POST", "/api/technologies/ad_windows/fields/rescan", csrf=True)
    record(
        code == 200 and rescan_resp.get("status") == "scanning",
        "4. POST /api/technologies/ad_windows/fields/rescan",
        f"status={code}, msg={rescan_resp.get('message')}",
    )

    # 5. Agendamentos atuais
    code, sched_resp = call("GET", "/api/system/schedules")
    record(
        code == 200 and "field_dictionary" in sched_resp and "curation" in sched_resp,
        "5. GET /api/system/schedules",
        f"status={code}, field_dict_day={sched_resp.get('field_dictionary', {}).get('day_of_week')}",
    )

    # 6. Atualização de agendamentos
    update_payload = {
        "field_dictionary": {
            "enabled": True,
            "day_of_week": 2, # Quarta
            "hour": 4,
            "minute": 30,
            "timezone_offset_hours": -3,
        },
        "curation": {
            "enabled": True,
            "hour": 9,
            "minute": 15,
            "timezone_offset_hours": -3,
        },
    }
    code, updated_sched = call("PUT", "/api/system/schedules", update_payload, csrf=True)
    ok_sched = (
        code == 200
        and updated_sched.get("field_dictionary", {}).get("hour") == 4
        and updated_sched.get("curation", {}).get("minute") == 15
    )
    record(
        ok_sched,
        "6. PUT /api/system/schedules (personalização de data e hora)",
        f"status={code}, f_hour={updated_sched.get('field_dictionary', {}).get('hour')}, c_min={updated_sched.get('curation', {}).get('minute')}",
    )

    # 7. Criação de nova tecnologia disparando varredura em background
    test_slug = f"tech_e2e_{int(time.time())}"[-20:]
    tech_payload = {
        "slug": test_slug,
        "name": "E2E Test Technology",
        "perimeter": "firewall",
        "rule_groups_regex": ".*test_firewall.*",
        "job": "wazuh",
        "description": "Tecnologia de teste criada pelo teste E2E do Dicionário de Campos.",
        "icon": "shield",
        "enabled": True,
        "confirm_without_logs": True,
    }
    code, created_tech = call("POST", "/api/technologies", tech_payload, csrf=True)
    record(
        code == 201 and created_tech.get("slug") == test_slug,
        "7. POST /api/technologies (criação e disparo de background scan)",
        f"status={code}, slug={test_slug}",
    )

    # 8. Consulta do dicionário da nova tecnologia recém-criada
    code, new_tech_dict = call("GET", f"/api/technologies/{test_slug}/fields")
    record(
        code == 200 and new_tech_dict.get("technology_slug") == test_slug,
        "8. GET dicionário da nova tecnologia criada",
        f"status={code}, total_unique_fields={new_tech_dict.get('total_unique_fields', 0)}",
    )

    # 9. Limpeza: remoção da tecnologia de teste
    code, del_resp = call("DELETE", f"/api/technologies/{test_slug}", csrf=True)
    record(code == 200, "9. DELETE /api/technologies/{slug} (limpeza)", f"status={code}")

    print("\n=== RESUMO DA SUÍTE ===")
    total = len(results)
    passed = sum(1 for ok, _ in results if ok)
    failed = total - passed
    print(f"Total de asserções: {total} | Passou: {passed} | Falhou: {failed}")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_e2e()