"""Harness E2E da página/APIs de Tecnologias do D.A.N.T.E.

Cobre, contra a stack real (nginx :8080 -> FastAPI -> Grafana):
  * login + cookie de sessão + header anti-CSRF;
  * GET /api/technologies/overview (métricas, distribuição, conformidade);
  * POST /api/technologies/log-presence (validação implícita no Loki);
  * POST /api/technologies (bloqueio sem logs + aceite explícito);
  * POST /api/technologies/{slug}/implement-baseline (validação prévia + lote);
  * footprint de tecnologias por cliente (escopo do baseline) — GET/PUT;
  * limpeza do que foi criado (tecnologia, regras e tenant de teste).
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO = Path(globals().get("__file__", "/app/scripts/e2e_technologies.py")).resolve().parent.parent
BASE = os.environ.get("E2E_BASE_URL", "http://localhost:8080")
GRAFANA = os.environ.get("E2E_GRAFANA_URL", "http://localhost:3000")
CSRF = {"X-Requested-With": "hunter-portal"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = dict(os.environ)
    env.setdefault("PORTAL_ADMIN_USER", "hunter")
    env.setdefault("PORTAL_ADMIN_PASSWORD", "Hunter@SecOps2026!Key")
    env.setdefault("GRAFANA_ADMIN_USER", "admin")
    env.setdefault("GRAFANA_ADMIN_PASSWORD", "GrafanaAdmin@2026!Pass")
    env_file = REPO / ".env"
    if not env_file.exists():
        return env
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


def call(method: str, path: str, body=None, *, base: str = BASE, csrf: bool = False, raw=False):
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
            if raw:
                return resp.status, payload
            return resp.status, (json.loads(payload) if payload else None)
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        try:
            parsed = json.loads(payload) if payload else None
        except json.JSONDecodeError:
            parsed = payload.decode(errors="replace")[:400]
        return exc.code, parsed


def grafana_call(method: str, path: str, body=None) -> tuple[int, Any]:
    """Chamada ao Grafana com basic auth de admin (limpeza de artefatos reais)."""
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


def purge_test_artifacts(tenant_uid: str) -> None:
    """Remove regras de teste e o tenant, deixando o laboratório limpo.

    Sem isso a segunda execução herdaria regras da primeira: o tenant já teria a
    tecnologia implementada (sem 409) e o baseline global ficaria duplicado.
    """
    status, rules = grafana_call("GET", "/api/v1/provisioning/alert-rules")
    for rule in rules or []:
        folder = str(rule.get("folderUID") or "")
        title = str(rule.get("title") or "")
        if folder == tenant_uid or title.startswith("E2E Fortigate"):
            grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{rule.get('uid')}")
    call("DELETE", f"/api/tenants/{tenant_uid}", csrf=True)


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((condition, name))
    print(("PASS " if condition else "FAIL ") + name + (f" :: {detail}" if detail else ""))


def main() -> int:
    # 1. Login ---------------------------------------------------------------
    status, body = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("login", status == 200, f"{status} {body}")
    if status != 200:
        return 1

    # 2. Overview ------------------------------------------------------------
    status, overview = call("GET", "/api/technologies/overview")
    check("GET /technologies/overview 200", status == 200, str(status))
    metrics = (overview or {}).get("metrics", {})
    print("  metrics:", json.dumps(metrics, ensure_ascii=False))
    for tech in (overview or {}).get("technologies", []):
        print(
            f"  tech {tech['slug']} (perimeter={tech.get('perimeter')}): baseline={tech['baseline_rules_count']} "
            f"clientes={tech['integrated_clients_count']} conformidade={tech['compliance_pct']}%"
        )
    check(
        "overview traz métricas obrigatórias",
        {"unique_technologies", "baseline_rules_total", "clients_total", "compliance_pct"}
        <= set(metrics),
    )

    # 2b. Perimeters ---------------------------------------------------------
    status, perims = call("GET", "/api/technologies/perimeters")
    check("GET /technologies/perimeters 200", status == 200, str(status))
    perim_slugs = {p.get("slug") for p in (perims or [])}
    check(
        "catálogo de perímetros contém escopos essenciais",
        {"firewall", "waf_web", "endpoint_edr", "identity_iam", "cloud_saas"}.issubset(perim_slugs),
        f"encontrados: {sorted(perim_slugs)}",
    )

    # 3. Presença de logs (Loki real quando disponível) ---------------------
    # Semeia telemetria de fortigate pelo laboratório de logs sintéticos: o
    # caminho positivo passa a ser comprovado de verdade, sem depender de dados
    # deixados por execuções anteriores.
    seeded, seed_body = call(
        "POST",
        "/api/loki/logs",
        {
            "stream": {"job": "wazuh", "ss_groups": "fortigate", "agent_name": "e2e-fw-01"},
            "lines": [
                {
                    "rule": {"id": 100100 + i, "level": 8, "description": "Fortigate traffic denied"},
                    "data": {"srcip": f"10.77.{i}.9", "dstip": "10.20.0.5", "action": "deny"},
                }
                for i in range(3)
            ],
            "spread_seconds": 30,
        },
        csrf=True,
    )
    print("  seed fortigate:", seeded, json.dumps(seed_body, ensure_ascii=False)[:200])

    status, presence = call(
        "POST",
        "/api/technologies/log-presence",
        {"ss_groups_regex": ".*fortigate.*", "job": "wazuh"},
        csrf=True,
    )
    check("POST /log-presence 200", status == 200, f"{status} {presence}")
    print("  presence fortigate:", json.dumps(presence, ensure_ascii=False))
    if status == 200:
        check("log-presence não expõe a query", "count_over_time" not in json.dumps(presence))
        if presence.get("available"):
            check(
                "log-presence acha telemetria de fortigate",
                bool(presence.get("found")) and int(presence.get("count") or 0) > 0,
                json.dumps(presence, ensure_ascii=False),
            )

    status, absent = call(
        "POST",
        "/api/technologies/log-presence",
        {"ss_groups_regex": ".*e2esignalnuncaexistiu.*", "job": "wazuh"},
        csrf=True,
    )
    print("  presence inexistente:", json.dumps(absent, ensure_ascii=False))
    check(
        "log-presence negativo (sem logs)",
        status == 200 and absent.get("found") is False and absent.get("count") == 0,
        json.dumps(absent, ensure_ascii=False),
    )
    loki_available = bool(presence.get("available"))

    # 4. Cadastro sem logs: bloqueio + aceite explícito ----------------------
    for slug in ("e2e_tmp_tech", "e2e_no_logs"):
        call("DELETE", f"/api/technologies/{slug}", csrf=True)

    status, created = call(
        "POST",
        "/api/technologies",
        {
            "slug": "e2e_tmp_tech",
            "name": "E2E Temp Tech",
            "ss_groups_regex": ".*e2etemplogs.*",
            "job": "wazuh",
            "description": "tecnologia temporaria de teste",
            "icon": "🧪",
            "enabled": True,
        },
        csrf=True,
    )
    print("  create sem logs:", status, json.dumps(created, ensure_ascii=False)[:300])
    if loki_available:
        check(
            "cadastro sem logs é bloqueado (409)",
            status == 409,
            f"{status} {created}",
        )
    else:
        check(
            "sem Loki consultável o cadastro é permitido",
            status == 201,
            f"{status} {created}",
        )
        call("DELETE", "/api/technologies/e2e_tmp_tech", csrf=True)

    status, blocked = call(
        "POST",
        "/api/technologies",
        {
            "slug": "e2e_no_logs",
            "name": "E2E Sem Logs",
            "ss_groups_regex": ".*e2esignalnuncaexistiu.*",
            "job": "wazuh",
            "enabled": True,
        },
        csrf=True,
    )
    print("  create sem logs (2):", status, json.dumps(blocked, ensure_ascii=False)[:300])
    if loki_available:
        check("segundo cadastro sem logs também bloqueado", status == 409, str(status))

    if not loki_available:
        # sem Loki o cadastro já foi aceito: remove para testar o aceite explícito
        call("DELETE", "/api/technologies/e2e_no_logs", csrf=True)

    status, confirmed = call(
        "POST",
        "/api/technologies",
        {
            "slug": "e2e_no_logs",
            "name": "E2E Sem Logs",
            "ss_groups_regex": ".*e2esignalnuncaexistiu.*",
            "job": "wazuh",
            "enabled": True,
            "confirm_without_logs": True,
        },
        csrf=True,
    )
    print("  create confirmado:", status, json.dumps(confirmed, ensure_ascii=False)[:300])
    check(
        "cadastro com aceite explícito permitido",
        status == 201,
        f"{status} {confirmed}",
    )

    # 6. Ciclo baseline ------------------------------------------------------
    tenant_uid = "e2e-cliente-tech"
    purge_test_artifacts(tenant_uid)  # idempotência: rodadas anteriores não podem vazar
    status, tenant = call(
        "POST", "/api/tenants", {"title": "Cliente E2E Tech", "uid": tenant_uid}, csrf=True
    )
    check("tenant de teste criado", status in (200, 201), f"{status} {tenant}")

    # baseline de fortigate
    query = '{job="wazuh", ss_groups=~".*fortigate.*"} |= "deny" | json'
    status, rule = call(
        "POST",
        "/api/rules",
        {
            "name": "E2E Fortigate - Trafego negado",
            "description": "regra baseline de teste",
            "scope": "baseline",
            "logql_query": query,
            "severity": "high",
            "mitre_tactic": "command-and-control",
            "mitre_technique": "T1071",
            "technology": "fortigate",
        },
        csrf=True,
    )
    print("  baseline rule:", status, json.dumps(rule, ensure_ascii=False)[:300])
    check("regra baseline fortigate criada", status in (200, 201), str(status))
    baseline_uid = (rule or {}).get("uid") if isinstance(rule, dict) else None

    # 7. Implementar baseline -------------------------------------------------
    status, first = call(
        "POST",
        "/api/technologies/fortigate/implement-baseline",
        {"target_folder_uid": tenant_uid, "target_folder_title": "Cliente E2E Tech"},
        csrf=True,
    )
    print("  implement (sem aceite):", status, json.dumps(first, ensure_ascii=False)[:300])
    check("implement-baseline exige validação prévia (409)", status == 409, str(status))

    status, second = call(
        "POST",
        "/api/technologies/fortigate/implement-baseline",
        {
            "target_folder_uid": tenant_uid,
            "target_folder_title": "Cliente E2E Tech",
            "confirm_client_without_technology": True,
        },
        csrf=True,
    )
    print("  implement (confirmado):", status, json.dumps(second, ensure_ascii=False)[:400])
    check("implement-baseline confirmado cria regras", status == 200, str(status))
    created_impl_uids = [
        r.get("uid")
        for r in ((second or {}).get("rules") or [])
        if r.get("status") == "created" and r.get("uid")
    ]
    if created_impl_uids:
        st_detail, impl_detail = call("GET", f"/api/rules/{created_impl_uids[0]}")
        impl_q_a = next(
            (q for q in ((impl_detail or {}).get("queries") or []) if q.get("ref_id") == "A"),
            {},
        )
        check(
            "implement-baseline aponta a regra do cliente para o data source Loki do tenant",
            st_detail == 200 and impl_q_a.get("datasource_uid") == tenant_uid,
            str(impl_q_a.get("datasource_uid")),
        )
        status_hml, hml_ov = call("GET", "/api/homologation")
        expected_stg = (
            (hml_ov.get("stage_contact_points") or {}).get("stg") or "stg"
            if isinstance(hml_ov, dict)
            else "stg"
        )
        check(
            "implement-baseline amarra a regra ao Contact Point correspondente ao estágio stg",
            st_detail == 200 and (impl_detail or {}).get("contact_point") == expected_stg,
            f"cp={(impl_detail or {}).get('contact_point')} expected={expected_stg}",
        )
        check(
            "implement-baseline response retorna o contact_point stg",
            (second or {}).get("contact_point") == expected_stg,
            str((second or {}).get("contact_point")),
        )
        check(
            "implement-baseline response retorna o evaluation_group padrão do tenant",
            (second or {}).get("evaluation_group") == "5m",
            str((second or {}).get("evaluation_group")),
        )
        check(
            "regra criada possui rule_group padrão do tenant",
            (impl_detail or {}).get("rule_group") == "5m",
            str((impl_detail or {}).get("rule_group")),
        )
        check(
            "regra criada por implement-baseline nasce sem provenance (editável via GUI)",
            not str((impl_detail or {}).get("provenance") or "").strip(),
            repr((impl_detail or {}).get("provenance")),
        )

    # 7b. Implementar baseline com evaluation_group customizado --------------
    status_custom_ten, custom_ten = call(
        "POST",
        "/api/tenants",
        {"title": "Cliente Custom Group Tech"},
        csrf=True,
    )
    if status_custom_ten == 200:
        custom_ten_uid = custom_ten["uid"]
        try:
            status_ci, custom_impl = call(
                "POST",
                "/api/technologies/fortigate/implement-baseline",
                {
                    "target_folder_uid": custom_ten_uid,
                    "target_folder_title": "Cliente Custom Group Tech",
                    "confirm_client_without_technology": True,
                    "evaluation_group": "custom-tech-eval-group",
                },
                csrf=True,
            )
            check("implement-baseline com evaluation_group customizado responde 200", status_ci == 200, str(status_ci))
            check(
                "implement-baseline response retorna o evaluation_group customizado",
                (custom_impl or {}).get("evaluation_group") == "custom-tech-eval-group",
                str((custom_impl or {}).get("evaluation_group")),
            )
            custom_created_uids = [
                r.get("uid")
                for r in ((custom_impl or {}).get("rules") or [])
                if r.get("status") == "created" and r.get("uid")
            ]
            if custom_created_uids:
                st_cd, custom_rule_detail = call("GET", f"/api/rules/{custom_created_uids[0]}")
                check(
                    "regra implementada no Grafana possui o evaluation_group customizado",
                    st_cd == 200 and (custom_rule_detail or {}).get("rule_group") == "custom-tech-eval-group",
                    str((custom_rule_detail or {}).get("rule_group")),
                )
        finally:
            call("DELETE", f"/api/tenants/{custom_ten_uid}", csrf=True)

    # 8. Reexecução deve ignorar (sem duplicar) ------------------------------
    status, third = call(
        "POST",
        "/api/technologies/fortigate/implement-baseline",
        {
            "target_folder_uid": tenant_uid,
            "target_folder_title": "Cliente E2E Tech",
            "confirm_client_without_technology": True,
        },
        csrf=True,
    )
    print("  implement (reexec):", status, json.dumps(third, ensure_ascii=False)[:300])
    check(
        "reexecução não duplica regras",
        status == 200 and (third or {}).get("created") == 0,
        str(status),
    )

    # 9. Overview reflete a implementação ------------------------------------
    status, overview2 = call("GET", "/api/technologies/overview")
    fortigate = next(
        (t for t in (overview2 or {}).get("technologies", []) if t["slug"] == "fortigate"),
        None,
    )
    print("  fortigate após implementação:", json.dumps(fortigate, ensure_ascii=False)[:500])
    client_row = next(
        (c for c in (fortigate or {}).get("clients", []) if c["client_uid"] == tenant_uid),
        None,
    )
    check(
        "distribuição/conformidade registram o cliente",
        bool(client_row and client_row["integrated"] and client_row["implemented_rules"] >= 1),
        json.dumps(client_row, ensure_ascii=False),
    )

    # 10. Footprint por cliente (escopo do baseline) -------------------------
    # O cliente que implementou a tecnologia entra no denominador; os demais
    # clientes ficam fora do escopo daquela tecnologia em vez de reprovar.
    other_client = next(
        (c for c in (fortigate or {}).get("clients", []) if c["client_uid"] != tenant_uid and not c.get("integrated")),
        None,
    )
    check(
        "cliente sem a tecnologia fica fora do escopo (not_applicable)",
        bool(
            other_client
            and other_client["applicable"] is False
            and other_client["status"] == "not_applicable"
            and other_client["footprint_source"] == "none"
        ),
        json.dumps(other_client, ensure_ascii=False)[:300],
    )
    check(
        "slots fora do escopo saem do denominador",
        bool(
            fortigate
            and fortigate["total_baseline_slots"]
            == fortigate["baseline_rules_count"] * fortigate["applicable_clients_count"]
            and int(((overview2 or {}).get("metrics") or {}).get("not_applicable_slots") or 0)
            >= 1
        ),
        json.dumps(fortigate, ensure_ascii=False)[:300],
    )

    status, footprints = call("GET", "/api/technologies/footprints")
    check("GET /technologies/footprints 200", status == 200, str(status))
    fp_row = next(
        (item for item in footprints or [] if item.get("client_uid") == tenant_uid), None
    )
    check(
        "footprint derivado traz a tecnologia implementada",
        bool(fp_row and "fortigate" in fp_row.get("derived", [])),
        json.dumps(fp_row, ensure_ascii=False)[:300],
    )

    status, declared = call(
        "PUT",
        f"/api/technologies/footprints/{tenant_uid}",
        {"technologies": ["office365"]},
        csrf=True,
    )
    check(
        "PUT footprint declara tecnologia (200)",
        status == 200 and "office365" in (declared or {}).get("declared", []),
        f"{status} {json.dumps(declared, ensure_ascii=False)[:300]}",
    )
    check(
        "declarado + derivado compõem o footprint efetivo",
        bool(
            declared
            and set(declared.get("effective", [])) == {"fortigate", "office365"}
            and "fortigate" in declared.get("derived", [])
        ),
        json.dumps(declared, ensure_ascii=False)[:300],
    )

    # Tecnologia declarada sem nenhuma regra precisa entrar no denominador do
    # baseline: é justamente a lacuna que a evidência de regra esconderia.
    status, overview3 = call("GET", "/api/technologies/overview")
    office365 = next(
        (t for t in (overview3 or {}).get("technologies", []) if t.get("slug") == "office365"),
        None,
    )
    office_row = next(
        (c for c in (office365 or {}).get("clients", []) if c.get("client_uid") == tenant_uid),
        None,
    )
    check(
        "tecnologia declarada entra no escopo da conformidade",
        bool(
            office_row
            and office_row["applicable"] is True
            and office_row["footprint_source"] == "declared"
        ),
        json.dumps(office_row, ensure_ascii=False)[:300],
    )

    status, unknown = call(
        "PUT",
        f"/api/technologies/footprints/{tenant_uid}",
        {"technologies": ["nao_existe_tech"]},
        csrf=True,
    )
    check("slug fora do catálogo é recusado (422)", status == 422, f"{status} {unknown}")

    status, missing = call(
        "PUT",
        "/api/technologies/footprints/e2e-cliente-inexistente",
        {"technologies": ["fortigate"]},
        csrf=True,
    )
    check("cliente inexistente é recusado (404)", status == 404, f"{status} {missing}")

    status, after_errors = call("GET", "/api/technologies/footprints")
    fp_after = next(
        (item for item in after_errors or [] if item.get("client_uid") == tenant_uid), None
    )
    check(
        "requisições recusadas não corrompem o footprint",
        bool(fp_after and "office365" in fp_after.get("declared", [])),
        json.dumps(fp_after, ensure_ascii=False)[:300],
    )

    # 10b. Replicação automática ao criar regra no baseline (replicate_to_clients=True)
    call(
        "PUT",
        f"/api/technologies/footprints/{tenant_uid}",
        {"technologies": ["office365", "e2e_no_logs"]},
        csrf=True,
    )
    st_auto, auto_rule = call(
        "POST",
        "/api/rules",
        {
            "name": "E2E Fortigate AutoRep - Sinal custom",
            "description": "regra baseline replicada automaticamente para clientes com a tecnologia",
            "scope": "baseline",
            "logql_query": 'count_over_time({job="wazuh", ss_groups=~".*e2esignalnuncaexistiu.*"} | json [5m])',
            "severity": "medium",
            "mitre_tactic": "discovery",
            "mitre_technique": "T1046",
            "technology": "e2e_no_logs",
            "replicate_to_clients": True,
        },
        csrf=True,
    )
    check(
        "POST /api/rules (baseline + replicate_to_clients=True) replica automaticamente para o cliente com a tecnologia",
        st_auto == 200
        and (auto_rule or {}).get("replicated_to_clients") is True
        and (auto_rule or {}).get("replicated_count") == 1,
        f"{st_auto} {json.dumps(auto_rule, ensure_ascii=False)[:300]}",
    )
    auto_replicas = (auto_rule or {}).get("replicated_rules") or []
    if auto_replicas and auto_replicas[0].get("uid"):
        st_rep, rep_detail = call("GET", f"/api/rules/{auto_replicas[0]['uid']}")
        rep_q_a = next(
            (q for q in ((rep_detail or {}).get("queries") or []) if q.get("ref_id") == "A"),
            {},
        )
        check(
            "réplica automática nasce na pasta do cliente apontando para o data source Loki do tenant",
            st_rep == 200
            and (rep_detail or {}).get("folder_uid") == tenant_uid
            and rep_q_a.get("datasource_uid") == tenant_uid,
            f"folder={((rep_detail or {}).get('folder_uid'))} ds={rep_q_a.get('datasource_uid')}",
        )

    # 11. Limpeza ------------------------------------------------------------
    cleanup = {"baseline_uid": baseline_uid, "tenant_uid": tenant_uid, "rules": []}
    status, rules = call("GET", "/api/rules")
    for rule_item in rules or []:
        if str(rule_item.get("folder_uid") or "") == tenant_uid:
            cleanup["rules"].append(rule_item.get("uid"))
    for slug in ("e2e_tmp_tech", "e2e_no_logs"):
        call("DELETE", f"/api/technologies/{slug}", csrf=True)
    purge_test_artifacts(tenant_uid)
    cleanup_dir = Path(os.environ.get("TMPDIR") or ("/tmp" if Path("/tmp").is_dir() else "."))
    cleanup_dir.joinpath("e2e-cleanup.json").write_text(
        json.dumps(cleanup, indent=2), encoding="utf-8"
    )

    failed = [name for ok, name in results if not ok]
    print("\nRESULTADO:", f"{len(results) - len(failed)}/{len(results)} checks OK")
    if failed:
        print("FALHAS:", failed)
    return 0 if not failed else 2


if __name__ == "__main__":
    sys.exit(main())
