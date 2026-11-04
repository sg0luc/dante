"""Suíte de testes E2E para Silences e Exceções com contagem de alertas silenciados em tempo real.

Valida contra a stack oficial (FastAPI -> Grafana Alerting -> Loki):
1. Consulta de silences via GET /api/silences e validação do novo contrato de API:
   - Presença dos campos `silenced_alerts_count` (int) e `silenced_alerts` (list)
2. Criação de exceção de teste com critérios (matchers) específicos
3. Disparo/geração de alertas correspondentes
4. Verificação em tempo real:
   - A exceção identifica imediatamente as instâncias suprimidas (silenced_alerts_count > 0)
   - A lista detalhada `silenced_alerts` contém os metadados corretos (fingerprint, alertname, folder, severidade)
5. Exclusão e limpeza do silence e dos alertas de teste
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

BASE = os.environ.get("PORTAL_BASE_URL", "http://frontend:8080")
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


def call(method: str, path: str, body=None, csrf: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        for k, v in CSRF.items():
            req.add_header(k, v)
    try:
        with opener.open(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except Exception:
            parsed = raw.decode(errors="replace")
        return exc.code, parsed


def main() -> int:
    print("=== D.A.N.T.E. E2E :: Silences & Alertas Silenciados em Tempo Real ===")

    # 1. Autenticação
    status, login_res = call(
        "POST",
        "/api/auth/login",
        {
            "username": os.environ.get("PORTAL_ADMIN_USER", "hunter"),
            "password": os.environ.get("PORTAL_ADMIN_PASSWORD", ""),
        },
        csrf=True,
    )
    check(status == 200, "1.1 Login de SecOps bem-sucedido", f"Status: {status}")

    # 2. Consultar silences existentes
    status, silences = call("GET", "/api/silences")
    check(status == 200, "2.1 GET /api/silences retorna 200 OK", f"Status: {status}")
    check(isinstance(silences, list), "2.2 Retorno é lista de silences", f"Count: {len(silences) if isinstance(silences, list) else 'N/A'}")

    for s in silences[:5]:
        check("silenced_alerts_count" in s, f"2.3 Silence #{s.get('id', '')[:8]} possui campo 'silenced_alerts_count'", f"Count: {s.get('silenced_alerts_count')}")
        check("silenced_alerts" in s, f"2.4 Silence #{s.get('id', '')[:8]} possui campo 'silenced_alerts'", f"Tipo: {type(s.get('silenced_alerts')).__name__}")

    # 3. Criar uma exceção específica de teste
    test_alertname = "E2E - Alerta Ficticio Para Silence"
    test_folder = "global"
    ends_at = "2036-01-01T00:00:00Z"

    create_payload = {
        "matchers": [
            {"name": "alertname", "value": test_alertname, "is_equal": True, "is_regex": False},
            {"name": "grafana_folder", "value": test_folder, "is_equal": True, "is_regex": False},
        ],
        "ends_at": ends_at,
        "comment": "[e2e-test] Excecao temporaria de teste para contagem em tempo real",
        "kind": "maintenance",
    }

    status, created_silence = call("POST", "/api/silences", create_payload, csrf=True)
    check(status == 200, "3.1 POST /api/silences cria silence com sucesso", f"Status: {status}")
    created_id = (created_silence.get("silence_id") or created_silence.get("id")) if isinstance(created_silence, dict) else None
    check(bool(created_id), "3.2 Silence ID retornado", f"ID: {created_id}")

    # 4. Gerar alertas sintéticos que coincidem com esse silence
    mock_rule = {
        "uid": "e2e-silence-rule",
        "title": test_alertname,
        "folderUID": test_folder,
        "labels": {
            "technology": "linux",
            "severity": "high",
            "scope": "baseline",
            "grafana_folder": test_folder,
        },
        "annotations": {
            "summary": f"{test_alertname} em teste",
        },
    }
    status, gen_res = call(
        "POST",
        "/api/alerts/synthetic/generate",
        {"rule_uid": "e2e-silence-rule", "count": 6},
        csrf=True,
    )
    check(status in (200, 404), "4.1 Tentativa de geração de alertas sintéticos", f"Status: {status}")

    # Se a regra não existir no Grafana, gera sem rule_uid para usar regra existente
    if status != 200:
        status, gen_res = call(
            "POST",
            "/api/alerts/synthetic/generate",
            {"count": 8},
            csrf=True,
        )
        check(status == 200, "4.2 Alertas sintéticos gerados a partir de regra existente", f"Gerados: {len(gen_res) if isinstance(gen_res, list) else 0}")
        # Criamos um silence correspondente aos alertas gerados
        if gen_res and isinstance(gen_res, list):
            first_alert = gen_res[0]
            first_name = first_alert.get("alertname")
            first_folder = first_alert.get("folder_uid") or first_alert.get("labels", {}).get("grafana_folder", "global")
            # Atualiza/Cria silence para o alerta gerado
            call("DELETE", f"/api/silences/{created_id}", csrf=True)
            create_payload = {
                "matchers": [
                    {"name": "alertname", "value": first_name, "is_equal": True, "is_regex": False},
                ],
                "ends_at": ends_at,
                "comment": "[e2e-test] Silence correspondente aos alertas sintéticos ativos",
                "kind": "maintenance",
            }
            status, created_silence = call("POST", "/api/silences", create_payload, csrf=True)
            created_id = (created_silence.get("silence_id") or created_silence.get("id")) if isinstance(created_silence, dict) else None
            check(status == 200 and bool(created_id), "4.3 Silence criado com matchers do alerta gerado", f"ID: {created_id}")

    # 5. Consultar novamente os silences e checar contagem em tempo real
    status, silences_after = call("GET", "/api/silences")
    check(status == 200, "5.1 GET /api/silences após disparo de alertas", f"Status: {status}")

    matched_silence = None
    for s in silences_after:
        if s.get("id") == created_id:
            matched_silence = s
            break

    check(bool(matched_silence), "5.2 Silence de teste localizado na listagem", f"ID: {created_id}")
    if matched_silence:
        silenced_count = matched_silence.get("silenced_alerts_count", 0)
        silenced_list = matched_silence.get("silenced_alerts", [])
        check(
            silenced_count >= 1,
            "5.3 Contagem em tempo real de alertas silenciados >= 1",
            f"silenced_alerts_count={silenced_count}",
        )
        check(
            len(silenced_list) == silenced_count,
            "5.4 Tamanho da lista de alertas silenciados coincide com a contagem",
            f"len(silenced_alerts)={len(silenced_list)} vs count={silenced_count}",
        )
        if silenced_list:
            first_silenced = silenced_list[0]
            check("fingerprint" in first_silenced, "5.5 Alerta silenciado contém fingerprint", f"fp={first_silenced.get('fingerprint')}")
            check("alertname" in first_silenced, "5.6 Alerta silenciado contém alertname", f"name={first_silenced.get('alertname')}")
            check("severity" in first_silenced, "5.7 Alerta silenciado contém severidade", f"sev={first_silenced.get('severity')}")

    # 6. Limpeza do silence de teste
    if created_id:
        del_status, _ = call("DELETE", f"/api/silences/{created_id}", csrf=True)
        check(del_status in (200, 204), "6.1 Silence de teste excluído com sucesso", f"Status: {del_status}")

    # 7. Limpeza dos alertas sintéticos
    clear_status, clear_res = call("DELETE", "/api/alerts/synthetic", csrf=True)
    check(clear_status == 200, "7.1 Alertas sintéticos limpos com sucesso", f"Status: {clear_status}")

    # Resumo
    passed = sum(1 for ok, _ in results if ok)
    total = len(results)
    print(f"\nResultado final: {passed}/{total} checks aprovados.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
