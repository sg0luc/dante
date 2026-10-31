"""Harness E2E do escaneamento de tecnologias por tenant (D.A.N.T.E.).

Cobre, contra a stack real (nginx :8080 -> FastAPI -> Grafana -> Loki):

  * POST /api/tenants/{uid}/technologies/scan roda a query de presença de cada
    tecnologia do catálogo no data source Loki do tenant e devolve quais têm
    logs (semente sintética apenas para ``fortigate``);
  * o resultado é persistido e aparece em GET /api/tenants
    (``technologies_count`` / ``technologies_scanned_at``);
  * GET /api/tenants/{uid}/technologies devolve o estado de baseline de cada
    tecnologia do cliente (sem implementação => ``none``);
  * POST /api/technologies/{slug}/implement-baseline (botão "Implementar tudo")
    cria as regras com Contact Point ``dev`` no grupo do tenant e, na releitura,
    o status passa a ``complete``;
  * recusas: pasta ``global`` (400) e tenant inexistente (404);
  * DELETE do tenant limpa o snapshot de escaneamento.

Todos os recursos são criados com sufixo aleatório e removidos ao final
(inclusive a regra temporária de baseline na pasta ``global``).
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
import os
BASE = os.environ.get("PORTAL_BASE_URL", "http://localhost:8080")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000")
CSRF = {"X-Requested-With": "hunter-portal"}

# Tecnologia semeada e as que devem ficar de fora do escaneamento.
SEEDED = "fortigate"
NOT_SEEDED = ("ad_windows", "office365")


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
    method: str, path: str, body=None, *, csrf: bool = False, timeout: int = 60
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        for key, value in CSRF.items():
            req.add_header(key, value)
    try:
        with opener.open(req, timeout=timeout) as resp:
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


def find_tenant(uid: str):
    status, tenants = call("GET", "/api/tenants")
    if status != 200 or not isinstance(tenants, list):
        return None
    return next((t for t in tenants if t.get("uid") == uid), None)


def folder_rules(folder_uid: str) -> list[dict[str, Any]]:
    status, rules = grafana_call("GET", "/api/v1/provisioning/alert-rules")
    if status != 200 or not isinstance(rules, list):
        return []
    return [r for r in rules if str(r.get("folderUID")) == folder_uid]


def delete_rule(uid: str) -> None:
    grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{uid}")


def seed_logs() -> tuple[bool, str]:
    """Semeia linhas sintéticas de fortigate no Loki da stack."""
    lines = [
        {
            "rule": {"id": f"3110{i}", "description": "Fortigate traffic"},
            "srcip": f"10.0.0.{i}",
            "dstip": "8.8.8.8",
            "action": "deny",
        }
        for i in range(1, 11)
    ]
    status, payload = call(
        "POST",
        "/api/loki/logs",
        {
            "stream": {"job": "wazuh", "ss_groups": f"e2e-scan-{SEEDED}"},
            "lines": lines,
            "spread_seconds": 600,
        },
        csrf=True,
    )
    if status != 200:
        return False, f"HTTP {status} {payload}"
    # O recorte do catálogo é `.*fortigate.*`, então `e2e-scan-fortigate` casa.
    return bool((payload or {}).get("verified")), str((payload or {}).get("verified_count"))


def main() -> int:
    suffix = uuid.uuid4().hex[:8]
    title = f"E2E Scan {suffix}"
    uid = f"e2e-scan-{suffix}"
    temp_global_uid = f"e2e-scan-baseline-{suffix}"
    cloned_uid = ""
    tenant_created = False

    # 0. Login ---------------------------------------------------------------
    status, _ = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("login do portal", status == 200, f"HTTP {status}")
    if status != 200:
        return 1

    try:
        # 1. Tenant de teste --------------------------------------------------
        status, created = call(
            "POST", "/api/tenants", {"title": title, "uid": uid}, csrf=True
        )
        tenant_created = status == 200
        check("tenant de teste criado", tenant_created, f"HTTP {status} {created}")
        if not tenant_created:
            return 1

        # 2. Semente de telemetria (apenas fortigate) -------------------------
        seeded, detail = seed_logs()
        check("semente sintética de fortigate no Loki", seeded, detail)
        # Ingestão do Loki é assíncrona; a query de presença usa janela de 1h.
        time.sleep(1.5)

        # 3. Escaneamento -----------------------------------------------------
        status, scan = call(
            "POST",
            f"/api/tenants/{uid}/technologies/scan",
            {"window_seconds": 3600},
            csrf=True,
        )
        check("POST scan responde 200", status == 200, f"HTTP {status} {scan}")
        scan = scan if isinstance(scan, dict) else {}
        check("scan reporta Loki disponível", scan.get("available") is True, str(scan.get("available")))
        check(
            "scan usou o data source Loki do tenant",
            scan.get("datasource") == title,
            str(scan.get("datasource")),
        )
        by_slug = {item.get("slug"): item for item in scan.get("technologies") or []}
        check(
            "scan avalia todas as tecnologias do catálogo",
            len(by_slug) >= 3,
            str(sorted(by_slug)),
        )
        check(
            "fortigate detectado com logs",
            bool((by_slug.get(SEEDED) or {}).get("found")) is True
            and int((by_slug.get(SEEDED) or {}).get("logs_count") or 0) > 0,
            str(by_slug.get(SEEDED)),
        )
        for slug in NOT_SEEDED:
            item = by_slug.get(slug) or {}
            check(
                f"{slug} não detectado (sem logs na janela)",
                item.get("found") is False,
                str(item),
            )
        check(
            "total de detectadas = 1",
            scan.get("technologies_detected") == 1,
            str(scan.get("technologies_detected")),
        )

        # 4. Persistência na listagem ----------------------------------------
        listed = find_tenant(uid)
        check("GET /api/tenants traz o tenant", listed is not None)
        if listed:
            check(
                "coluna de tecnologias persistida",
                listed.get("technologies_count") == 1,
                str(listed.get("technologies_count")),
            )
            check(
                "timestamp do escaneamento persistido",
                bool(listed.get("technologies_scanned_at")),
                str(listed.get("technologies_scanned_at")),
            )

        # 5. Detalhe do pop-up (estado inicial: sem baseline) ------------------
        status, detail_payload = call("GET", f"/api/tenants/{uid}/technologies")
        check("GET tecnologias do tenant responde 200", status == 200, f"HTTP {status}")
        detail_payload = detail_payload if isinstance(detail_payload, dict) else {}
        techs = {
            item.get("slug"): item for item in detail_payload.get("technologies") or []
        }
        check(
            "pop-up lista a tecnologia detectada",
            SEEDED in techs,
            str(sorted(techs)),
        )
        fortigate = techs.get(SEEDED) or {}
        check(
            "tecnologia detectada está marcada como tal",
            fortigate.get("detected") is True,
            str(fortigate.get("detected")),
        )
        check(
            "tecnologia sem regra no cliente nasce com status none",
            fortigate.get("status") == "none",
            str(fortigate.get("status")),
        )
        initial_baseline_rules = int(fortigate.get("baseline_rules") or 0)

        # 6. Regra temporária de baseline na pasta global ---------------------
        status, template = grafana_call("GET", "/api/v1/provisioning/alert-rules/ghp-global-ssh-logql")
        if status != 200:
            status, template = grafana_call("GET", "/api/v1/provisioning/alert-rules/ghp-det-lab-ssh-bruteforce")
        if status != 200:
            st_all, all_rules = grafana_call("GET", "/api/v1/provisioning/alert-rules")
            if st_all == 200 and isinstance(all_rules, list):
                global_rules = [r for r in all_rules if r.get("folderUID") == "global" and r.get("data")]
                if global_rules:
                    template = global_rules[0]
                    status = 200
        check("regra global de referência disponível", status == 200, f"HTTP {status}")
        if status != 200 or not isinstance(template, dict):
            return 1
        payload = {
            "uid": temp_global_uid,
            "title": f"[Global] E2E Baseline Fortigate {suffix}",
            "folderUID": "global",
            "ruleGroup": "global-detections",
            "condition": template.get("condition"),
            "data": template.get("data"),
            "noDataState": template.get("noDataState", "NoData"),
            "execErrState": template.get("execErrState", "Error"),
            "for": template.get("for", "5m"),
            "orgID": 1,
            "labels": {
                "technology": SEEDED,
                "technology_name": "Fortigate",
                "severity": "high",
            },
            "annotations": {"summary": "Baseline temporário de E2E"},
            "isPaused": False,
        }
        status, _ = grafana_call("POST", "/api/v1/provisioning/alert-rules", payload)
        check("baseline temporário de fortigate criado", status in (201, 200), f"HTTP {status}")

        # Releitura do pop-up: agora existe baseline de 1 regra, ainda não implementada
        status, detail_payload = call("GET", f"/api/tenants/{uid}/technologies")
        techs = {
            item.get("slug"): item
            for item in (detail_payload or {}).get("technologies") or []
        }
        fortigate = techs.get(SEEDED) or {}
        expected_baseline = initial_baseline_rules + 1
        check(
            f"baseline de fortigate contabilizado ({expected_baseline} regra(s))",
            fortigate.get("baseline_rules") == expected_baseline,
            str(fortigate.get("baseline_rules")),
        )
        check(
            "baseline pendente mantém status none",
            fortigate.get("status") == "none",
            str(fortigate.get("status")),
        )

        # 7. "Implementar tudo" ----------------------------------------------
        status, implement = call(
            "POST",
            f"/api/technologies/{SEEDED}/implement-baseline",
            {
                "target_folder_uid": uid,
                "target_folder_title": title,
                "confirm_client_without_technology": True,
            },
            csrf=True,
        )
        check("implement-baseline responde 200", status == 200, f"HTTP {status} {implement}")
        implement = implement if isinstance(implement, dict) else {}
        check(
            "regras criadas no cliente",
            implement.get("created", 0) >= 1 and implement.get("failed", 0) == 0,
            f"created={implement.get('created')} failed={implement.get('failed')}",
        )

        rules = folder_rules(uid)
        detection = [
            r
            for r in rules
            if str((r.get("labels") or {}).get("portal_internal") or "")
            != "rule_group_anchor"
        ]
        check("regra(s) clonada(s) existem na pasta do tenant", len(detection) >= 1, str(len(detection)))
        cloned_target = next(
            (r for r in detection if str((r.get("annotations") or {}).get("cloned_from")) == temp_global_uid),
            detection[0] if detection else None,
        )
        if cloned_target:
            cloned = cloned_target
            cloned_uid = str(cloned.get("uid") or "")
            check(
                "clone veio do baseline global",
                str((cloned.get("annotations") or {}).get("cloned_from")) == temp_global_uid,
                str((cloned.get("annotations") or {}).get("cloned_from")),
            )
            receiver = (
                (cloned.get("notification_settings") or {}).get("receiver")
                or (cloned.get("notificationSettings") or {}).get("receiver")
                or cloned.get("contactPoint")
            )
            status_hml, hml_ov = call("GET", "/api/homologation")
            expected_stg = (
                (hml_ov.get("stage_contact_points") or {}).get("stg") or "stg"
                if isinstance(hml_ov, dict)
                else "stg"
            )
            check(
                "clone nasceu com Contact Point de homologação (stg)",
                str(receiver) == expected_stg,
                f"receiver={receiver} expected={expected_stg}",
            )
            check("clone nasceu ativo", cloned.get("isPaused") is False, str(cloned.get("isPaused")))
            check(
                "clone está no grupo de avaliação do tenant",
                str(cloned.get("ruleGroup")) == "5m",
                str(cloned.get("ruleGroup")),
            )

        # 8. Estado após a implementação -------------------------------------
        status, detail_payload = call("GET", f"/api/tenants/{uid}/technologies")
        techs = {
            item.get("slug"): item
            for item in (detail_payload or {}).get("technologies") or []
        }
        fortigate = techs.get(SEEDED) or {}
        check(
            "status do baseline passa a complete",
            fortigate.get("status") == "complete",
            str(fortigate.get("status")),
        )
        check(
            "conformidade em 100%",
            fortigate.get("compliance_pct") == 100.0,
            str(fortigate.get("compliance_pct")),
        )

        # 9. Recusas ----------------------------------------------------------
        status, _ = call("POST", "/api/tenants/global/technologies/scan", {}, csrf=True)
        check("scan na pasta global é recusado (400)", status == 400, f"HTTP {status}")
        status, _ = call(
            "POST", "/api/tenants/e2e-inexistente-xyz/technologies/scan", {}, csrf=True
        )
        check("scan de tenant inexistente responde 404", status == 404, f"HTTP {status}")
        status, _ = call("GET", "/api/tenants/e2e-inexistente-xyz/technologies")
        check("detalhe de tenant inexistente responde 404", status == 404, f"HTTP {status}")
    finally:
        # 10. Limpeza ---------------------------------------------------------
        for r in folder_rules(uid):
            if str((r.get("labels") or {}).get("portal_internal") or "") != "rule_group_anchor":
                delete_rule(str(r.get("uid") or ""))
        if tenant_created:
            status, payload = call("DELETE", f"/api/tenants/{uid}", csrf=True)
            check("tenant de teste removido", status == 200, f"HTTP {status} {payload}")
            check(
                "snapshot de escaneamento removido junto",
                find_tenant(uid) is None,
            )
        delete_rule(temp_global_uid)

    failed = [name for ok, name in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passaram")
    if failed:
        print("Falhas:")
        for name in failed:
            print(" - " + name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
