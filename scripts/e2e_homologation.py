"""Harness E2E: página Homologação e estágio de deploy por Contact Point.

Cobre, contra a stack real (nginx :8080 -> FastAPI -> Grafana):
  * GET /api/homologation devolve métricas, contact points e o estágio de cada
    regra (active/homolog/paused/unassigned);
  * os Contact Points canônicos dev/stg/prod existem no Grafana (file provisioning);
  * regra criada pelo portal (POST /api/rules) nasce com Contact Point 'dev' —
    comprovado tanto na resposta da API quanto no objeto real do Grafana;
  * GET /api/rules passa a expor contact_point/deploy_status (coluna STATUS);
  * POST /api/homologation/rules/{uid}/contact-point promove para prod
    (deploy_status=active) e rebaixa para stg/dev (deploy_status=homolog),
    gravando notification_settings.receiver no Grafana;
  * regra pausada é 'paused' independentemente do Contact Point;
  * duplicação baseline->cliente SEMPRE nasce em 'dev', mesmo com a origem em 'prod';
  * rejeições: contact point fora do padrão (422), sem CSRF (403), regra interna (400);
  * regras-âncora dos grupos de avaliação ficam fora da contagem da página.

Todos os recursos são criados com sufixo aleatório e removidos ao final.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent if "__file__" in globals() else Path(".")
BASE = os.environ.get("PORTAL_BASE_URL", "http://localhost:8080")
GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000")
CSRF = {"X-Requested-With": "hunter-portal"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = dict(os.environ)
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


def rule_in_grafana(uid: str) -> dict[str, Any] | None:
    status, rule = grafana_call("GET", f"/api/v1/provisioning/alert-rules/{uid}")
    return rule if status == 200 and isinstance(rule, dict) else None


def grafana_receiver(uid: str) -> str | None:
    rule = rule_in_grafana(uid) or {}
    settings = rule.get("notification_settings") or {}
    receiver = settings.get("receiver")
    return str(receiver) if receiver else None


def rule_from_api(uid: str) -> dict[str, Any] | None:
    status, rules = call("GET", "/api/rules")
    if status != 200 or not isinstance(rules, list):
        return None
    return next((r for r in rules if r.get("uid") == uid), None)


def homologation() -> dict[str, Any]:
    status, payload = call("GET", "/api/homologation")
    return payload if status == 200 and isinstance(payload, dict) else {}


def main() -> int:
    # 0. Login ---------------------------------------------------------------
    status, _ = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("login do portal", status == 200, f"HTTP {status}")

    # 1. Contact Points canônicos provisionados ------------------------------
    status, cps = grafana_call("GET", "/api/v1/provisioning/contact-points")
    names = {str(cp.get("name")) for cp in cps} if isinstance(cps, list) else set()
    check("GET contact-points no Grafana responde 200", status == 200, f"HTTP {status}")
    for expected in ("dev", "stg", "prod"):
        check(f"contact point '{expected}' provisionado no Grafana", expected in names, str(sorted(names)))

    overview = homologation()
    check("GET /api/homologation responde 200", bool(overview), str(list(overview)[:4]))
    check(
        "página lista os contact points padrão sem faltantes",
        overview.get("missing_contact_points") == [],
        str(overview.get("missing_contact_points")),
    )
    check(
        "estágios possíveis aparecem nas regras",
        all(
            r.get("deploy_status") in ("active", "homolog", "paused", "unassigned")
            for r in overview.get("rules") or []
        ),
    )
    check(
        "regras-âncora internas não entram na página",
        all(
            "portal_internal" not in (r.get("labels") or {})
            and not str(r.get("uid", "")).startswith("ghp-anchor-")
            for r in overview.get("rules") or []
        ),
    )

    # 2. Criação de regra nasce em 'dev' -------------------------------------
    status, techs = call("GET", "/api/technologies")
    tech = next((t for t in techs or [] if t.get("enabled", True)), None)
    check("catálogo de tecnologias disponível para o teste", tech is not None)
    if not tech:
        return 1

    suffix = uuid.uuid4().hex[:8]
    query = (
        f'sum(count_over_time({{job="wazuh", ss_groups=~"{tech["ss_groups_regex"]}"}} '
        "| json [1m]))"
    )
    status, created = call(
        "POST",
        "/api/rules",
        {
            "name": f"E2E Homologacao {suffix}",
            "description": "Regra criada pelo harness E2E de homologação.",
            "scope": "baseline",
            "logql_query": query,
            "severity": "medium",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
            "technology": tech["slug"],
        },
        csrf=True,
    )
    check("POST /api/rules cria a regra (200)", status == 200, f"HTTP {status} {created}")
    rule_uid = (created or {}).get("uid") or ""
    check("resposta do create informa Contact Point 'dev'", (created or {}).get("contact_point") == "dev", str((created or {}).get("contact_point")))
    check("resposta do create baseline informa datasource_uid='loki'", (created or {}).get("datasource_uid") == "loki", str((created or {}).get("datasource_uid")))
    check("regra nasceu com notification_settings.receiver='dev' no Grafana", grafana_receiver(rule_uid) == "dev", str(grafana_receiver(rule_uid)))
    baseline_grafana = rule_in_grafana(rule_uid) or {}
    baseline_q_a = next((q for q in (baseline_grafana.get("data") or []) if q.get("refId") == "A"), {})
    check(
        "regra de baseline aponta para o data source 'loki' no Grafana (não testdata)",
        baseline_q_a.get("datasourceUid") == "loki"
        and ((baseline_q_a.get("model") or {}).get("datasource") or {}).get("uid") == "loki",
        str(baseline_q_a.get("datasourceUid")),
    )

    # 3. Coluna STATUS em /api/rules ----------------------------------------
    listed = rule_from_api(rule_uid) or {}
    check("GET /api/rules expõe contact_point", listed.get("contact_point") == "dev", str(listed.get("contact_point")))
    check("GET /api/rules expõe deploy_status=homolog", listed.get("deploy_status") == "homolog", str(listed.get("deploy_status")))

    overview = homologation()
    page_rule = next((r for r in overview.get("rules") or [] if r.get("uid") == rule_uid), None)
    check("regra aparece na página Homologação", page_rule is not None)
    check("regra nova entra na contagem de homologação", (overview.get("metrics") or {}).get("homolog", 0) >= 1, str((overview.get("metrics") or {}).get("homolog")))

    # 3.1 Histórico, volume e histograma da regra em homologação -------------
    status, hist = call("GET", f"/api/homologation/rules/{rule_uid}/alert-history?window_hours=24&bucket_count=12")
    check("GET /api/homologation/rules/{uid}/alert-history responde 200", status == 200, f"HTTP {status} {hist}")
    check("histórico retorna uid e deploy_status=homolog", isinstance(hist, dict) and hist.get("uid") == rule_uid and hist.get("deploy_status") == "homolog", str((hist or {}).get("deploy_status")))
    check("histórico retorna 12 buckets de histograma", isinstance((hist or {}).get("histogram"), list) and len((hist or {}).get("histogram") or []) == 12, str(len((hist or {}).get("histogram") or [])))
    check("histórico retorna lista de eventos e métricas volumétricas", isinstance((hist or {}).get("events"), list) and "firing_events_count" in (hist or {}), str(list((hist or {}).keys())[:10]))

    # 3.2 Parecer técnico da IA sobre os alertas e homologação -----------------
    ai_status, ai_eval = call("GET", f"/api/homologation/rules/{rule_uid}/ai-evaluation?window_hours=24")
    check("GET /api/homologation/rules/{uid}/ai-evaluation responde 200", ai_status == 200, f"HTTP {ai_status} {ai_eval}")
    check("parecer técnico da IA retorna verdict e threat_analysis", isinstance(ai_eval, dict) and bool(ai_eval.get("verdict")) and bool(ai_eval.get("threat_analysis")), str(list((ai_eval or {}).keys())[:8]))
    check("parecer técnico da IA retorna melhorias e ações contra falsos positivos", isinstance((ai_eval or {}).get("improvements"), list) and isinstance((ai_eval or {}).get("noise_reduction_actions"), list), str((ai_eval or {}).get("verdict")))

    # 4. Promoção e rebaixamento ---------------------------------------------
    status, promoted = call(
        "POST",
        f"/api/homologation/rules/{rule_uid}/contact-point",
        {"contact_point": "prod"},
        csrf=True,
    )
    check("promoção para prod responde 200", status == 200, f"HTTP {status} {promoted}")
    check("promoção devolve deploy_status=active", (promoted or {}).get("deploy_status") == "active", str((promoted or {}).get("deploy_status")))
    check("promoção registra o estágio anterior (homolog)", (promoted or {}).get("previous_deploy_status") == "homolog", str((promoted or {}).get("previous_deploy_status")))
    expected_prod_receiver = (overview.get("stage_contact_points") or {}).get("prod", "prod")
    check(
        "Grafana persistiu receiver='prod' (ou contact point mapeado)",
        grafana_receiver(rule_uid) in ("prod", expected_prod_receiver),
        str(grafana_receiver(rule_uid)),
    )
    check("coluna STATUS da página Regras reflete 'active'", (rule_from_api(rule_uid) or {}).get("deploy_status") == "active")

    # 4.1 Parecer técnico da IA para regra já em produção -----------------------
    ai_prod_status, ai_prod_eval = call("GET", f"/api/homologation/rules/{rule_uid}/ai-evaluation?window_hours=24")
    check("GET /api/homologation/rules/{uid}/ai-evaluation em prod responde 200", ai_prod_status == 200, f"HTTP {ai_prod_status}")
    check("parecer técnico da IA reconhece regra em produção", (ai_prod_eval or {}).get("is_in_production") is True, str((ai_prod_eval or {}).get("is_in_production")))

    status, staged = call(
        "POST",
        f"/api/homologation/rules/{rule_uid}/contact-point",
        {"contact_point": "stg"},
        csrf=True,
    )
    check("rebaixamento para stg responde 200", status == 200, f"HTTP {status}")
    check("stg devolve deploy_status=homolog", (staged or {}).get("deploy_status") == "homolog", str((staged or {}).get("deploy_status")))

    # 5. Rejeições ------------------------------------------------------------
    status, body = call(
        "POST",
        f"/api/homologation/rules/{rule_uid}/contact-point",
        {"contact_point": "sandbox"},
        csrf=True,
    )
    check("contact point fora do padrão é recusado (422)", status == 422, f"HTTP {status} {body}")

    status, _ = call(
        "POST",
        f"/api/homologation/rules/{rule_uid}/contact-point",
        {"contact_point": "prod"},
    )
    check("mudança de estágio sem CSRF é recusada (403)", status == 403, f"HTTP {status}")

    # 6. Pausa independe do Contact Point ------------------------------------
    status, _ = call("POST", f"/api/rules/{rule_uid}/toggle-pause", {"paused": True}, csrf=True)
    check("pausa da regra responde 200", status == 200, f"HTTP {status}")
    paused_rule = rule_from_api(rule_uid) or {}
    check("regra pausada fica 'paused' mesmo com CP stg", paused_rule.get("deploy_status") == "paused", str(paused_rule.get("deploy_status")))
    check("contact point é preservado ao pausar", paused_rule.get("contact_point") == "stg", str(paused_rule.get("contact_point")))
    status, _ = call("POST", f"/api/rules/{rule_uid}/toggle-pause", {"paused": False}, csrf=True)
    check("reativação volta a 'homolog'", (rule_from_api(rule_uid) or {}).get("deploy_status") == "homolog")

    # 7. Replicação baseline->cliente sempre nasce em dev --------------------
    title = f"E2E Homolog Tenant {suffix}"
    tenant_uid = f"e2e-homolog-{suffix}"
    status, tenant = call("POST", "/api/tenants", {"title": title, "uid": tenant_uid}, csrf=True)
    check("tenant de teste criado para a replicação", status == 200, f"HTTP {status} {tenant}")

    # 7.0 Regra customizada criada diretamente para o cliente aponta para o DS do cliente
    status, custom_client_rule = call(
        "POST",
        "/api/rules",
        {
            "name": f"E2E Custom Client {suffix}",
            "description": "Regra customizada de cliente criada pelo harness E2E.",
            "scope": "client",
            "target_client_uid": tenant_uid,
            "logql_query": query,
            "severity": "high",
            "mitre_tactic": "Discovery",
            "mitre_technique": "T1046",
            "technology": tech["slug"],
        },
        csrf=True,
    )
    check("POST /api/rules (scope=client) cria regra customizada (200)", status == 200, f"HTTP {status} {custom_client_rule}")
    custom_client_uid = (custom_client_rule or {}).get("uid") or ""
    custom_client_grafana = rule_in_grafana(custom_client_uid) or {}
    custom_client_q_a = next((q for q in (custom_client_grafana.get("data") or []) if q.get("refId") == "A"), {})
    check(
        "regra customizada de cliente aponta para o data source Loki do cliente no Grafana",
        custom_client_q_a.get("datasourceUid") == tenant_uid
        and ((custom_client_q_a.get("model") or {}).get("datasource") or {}).get("uid") == tenant_uid,
        str(custom_client_q_a.get("datasourceUid")),
    )
    if custom_client_uid:
        grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{custom_client_uid}")

    # 7.1 Regra interna (âncora do grupo de avaliação) não muda de estágio ---
    # A âncora é pausada, logo não aparece na API compatível com Prometheus:
    # a busca é feita na API de provisionamento.
    status, all_rules = grafana_call("GET", "/api/v1/provisioning/alert-rules")
    anchor_uid = next(
        (
            str(rule.get("uid"))
            for rule in all_rules or []
            if str(rule.get("uid") or "").startswith("ghp-anchor-")
            and (rule.get("labels") or {}).get("portal_internal")
        ),
        "",
    )
    check("regra interna (âncora) encontrada para o teste", bool(anchor_uid), anchor_uid)
    if anchor_uid:
        status, body = call(
            "POST",
            f"/api/homologation/rules/{anchor_uid}/contact-point",
            {"contact_point": "prod"},
            csrf=True,
        )
        check("regra interna (âncora) não muda de estágio (400)", status == 400, f"HTTP {status} {body}")
        status_hist, body_hist = call("GET", f"/api/homologation/rules/{anchor_uid}/alert-history")
        check("regra interna (âncora) não expõe histórico de homologação (400)", status_hist == 400, f"HTTP {status_hist} {body_hist}")

    # 8. Origem global em produção: o clone não pode herdar o estágio --------
    # Origem global em produção (o clone não pode herdar o estágio)
    call("POST", f"/api/homologation/rules/{rule_uid}/contact-point", {"contact_point": "prod"}, csrf=True)
    status, clone = call(
        "POST",
        f"/api/rules/{rule_uid}/duplicate",
        {
            "target_folder_uid": tenant_uid,
            "target_folder_title": title,
            "new_title": f"[{title}] E2E Homologacao {suffix}",
            "client_name": title,
        },
        csrf=True,
    )
    check("duplicação para o cliente responde 200", status == 200, f"HTTP {status} {clone}")
    clone_uid = (clone or {}).get("uid") or ""
    check("clone informa Contact Point 'dev'", (clone or {}).get("contact_point") == "dev", str((clone or {}).get("contact_point")))
    check(
        "clone nasceu em 'dev' mesmo com a origem em 'prod'",
        grafana_receiver(clone_uid) == "dev",
        str(grafana_receiver(clone_uid)),
    )
    check("clone aparece como homolog na página", (rule_from_api(clone_uid) or {}).get("deploy_status") == "homolog")

    overview = homologation()
    client_row = next(
        (c for c in overview.get("clients") or [] if c.get("folder_uid") == tenant_uid), None
    )
    check("cliente aparece na distribuição por estágio", client_row is not None, str(client_row))
    if client_row:
        check("cliente tem 1 regra em homologação", client_row.get("homolog") == 1, str(client_row.get("homolog")))
        check("âncora do tenant não é contada como regra", client_row.get("total") == 1, str(client_row.get("total")))

    # 8b. Nenhum clone pode herdar proveniência (estado "Provisioned") ------
    clone_detail = rule_in_grafana(clone_uid) or {}
    check(
        "clone do portal nasce sem provenance",
        not str(clone_detail.get("provenance") or "").strip(),
        repr(clone_detail.get("provenance")),
    )
    clone_q_a = next((q for q in (clone_detail.get("data") or []) if q.get("refId") == "A"), {})
    check(
        "clone replicado aponta para o data source Loki do cliente no Grafana",
        clone_q_a.get("datasourceUid") == tenant_uid
        and ((clone_q_a.get("model") or {}).get("datasource") or {}).get("uid") == tenant_uid,
        str(clone_q_a.get("datasourceUid")),
    )

    # Origem "envenenada": regra criada fora do portal (POST sem
    # X-Disable-Provenance), que é o caso que nasce com provenance 'api'.
    source_detail = rule_in_grafana(rule_uid) or {}
    poisoned = dict(source_detail)
    for field in ("id", "updated", "provenance", "orgID"):
        poisoned.pop(field, None)
    poisoned_uid = f"ghp-poison-{suffix}"
    poisoned["uid"] = poisoned_uid
    poisoned["title"] = f"E2E Poison Source {suffix}"
    poisoned["isPaused"] = False
    grafana_call("POST", "/api/v1/provisioning/alert-rules", poisoned)
    poisoned_persisted = rule_in_grafana(poisoned_uid) or {}
    check(
        "regra criada fora do portal nasce com provenance 'api'",
        str(poisoned_persisted.get("provenance") or "") == "api",
        repr(poisoned_persisted.get("provenance")),
    )

    status, poisoned_clone = call(
        "POST",
        f"/api/rules/{poisoned_uid}/duplicate",
        {
            "target_folder_uid": tenant_uid,
            "target_folder_title": title,
            "new_title": f"[{title}] E2E Clone Poison {suffix}",
            "client_name": title,
        },
        csrf=True,
    )
    check("duplicação de regra com provenance responde 200", status == 200, f"HTTP {status} {poisoned_clone}")
    poisoned_clone_uid = (poisoned_clone or {}).get("uid") or ""
    poisoned_clone_detail = rule_in_grafana(poisoned_clone_uid) or {}
    check(
        "clone NÃO herda provenance da origem (não nasce Provisioned)",
        bool(poisoned_clone_uid) and not str(poisoned_clone_detail.get("provenance") or "").strip(),
        repr(poisoned_clone_detail.get("provenance")),
    )

    # 9. Limpeza --------------------------------------------------------------
    # O tenant só pode ser excluído após remover as regras de detecção dele.
    grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{poisoned_clone_uid}")
    grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{poisoned_uid}")
    grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{clone_uid}")
    check("regra clonada removida com o tenant", rule_in_grafana(clone_uid) is None)
    status, body = call("DELETE", f"/api/tenants/{tenant_uid}", csrf=True)
    check("tenant de teste removido", status == 200, f"HTTP {status} {body}")
    grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{rule_uid}")
    check("regra de baseline do teste removida", rule_in_grafana(rule_uid) is None)
    check("regra some da página após a limpeza", rule_from_api(rule_uid) is None)

    failed = [name for ok, name in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks OK")
    if failed:
        print("Falhas:")
        for name in failed:
            print(" -", name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
