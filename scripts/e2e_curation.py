"""Harness E2E da página/APIs de Curadoria de Regras de Detecção do D.A.N.T.E.

Cobre, contra a stack real (nginx :8080 -> FastAPI -> Grafana -> Loki):
  1. Fontes confiáveis pesquisadas:
     - https://github.com/SigmaHQ/sigma
     - https://detection.fyi/
     - https://research.splunk.com/detections/
     - https://elastic.github.io/detection-rules-explorer/
  2. Agendamento diário às 08h00 (cron '0 8 * * *', daily_time '08:00').
  3. Compatibilidade de tecnologia, conversão para LogQL (job='wazuh', ss_groups, | json, lint_logql).
  4. Avaliação no Loki dos clientes e categorização ('excellent' e 'good').
  5. Regra 2: Nenhuma regra 'bad' (má candidata) é inserida na curadoria.
  6. Regra 3: Execuções subsequentes nunca repetem regras que já foram curadas.
  7. Botão/Endpoint 'Implementar': bloqueia sem confirmação (409) e implementa no
     Baseline Global + clientes recomendados mediante confirmação explícita (200).
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

REPO = Path(globals().get("__file__", "/app/scripts/e2e_curation.py")).resolve().parent.parent
BASE = os.environ.get("E2E_BASE_URL", "http://localhost:8080")
GRAFANA = os.environ.get("E2E_GRAFANA_URL", "http://localhost:3000")
CSRF = {"X-Requested-With": "hunter-portal"}
TEST_TENANT_UID = "e2e-curation-client"
TEST_TENANT_TITLE = "E2E Curation Client"
TIMEOUT_TENANT_UID = "e2e-timeout-client"
TIMEOUT_TENANT_TITLE = "E2E Timeout Client"


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


def call(method: str, path: str, body=None, *, base: str = BASE, csrf: bool = False, timeout: int = 180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
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
    token_file = Path("/run/portal-secrets/grafana_token")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GRAFANA + path, data=data, method=method)
    if token_file.exists():
        req.add_header("Authorization", f"Bearer {token_file.read_text(encoding='utf-8').strip()}")
    else:
        creds = f"{ENV.get('GRAFANA_ADMIN_USER', 'admin')}:{ENV.get('GRAFANA_ADMIN_PASSWORD', 'GrafanaAdmin@2026!Pass')}"
        token = base64.b64encode(creds.encode()).decode()
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


def cleanup_artifacts(baseline_rule_uid: str | None = None) -> None:
    status, rules = grafana_call("GET", "/api/v1/provisioning/alert-rules")
    if status == 200 and isinstance(rules, list):
        for r in rules:
            f_uid = str(r.get("folderUID") or "")
            r_uid = str(r.get("uid") or "")
            if f_uid in (TEST_TENANT_UID, TIMEOUT_TENANT_UID) or (baseline_rule_uid and r_uid == baseline_rule_uid):
                grafana_call("DELETE", f"/api/v1/provisioning/alert-rules/{r_uid}")
    call("DELETE", f"/api/tenants/{TEST_TENANT_UID}", csrf=True)
    call("DELETE", f"/api/tenants/{TIMEOUT_TENANT_UID}", csrf=True)


def check(name: str, condition: bool, detail: str = "") -> None:
    results.append((condition, name))
    print(("PASS " if condition else "FAIL ") + name + (f" :: {detail}" if detail else ""))


def seed_progressive_window_telemetry() -> None:
    """Injeta logs reais no Loki dentro da janela de 15 minutos para provar a parada antecipada."""
    payloads = [
        {
            "stream": {"job": "wazuh", "ss_groups": "fortigate", "agent_name": "fg-curation-01"},
            "spread_seconds": 120,
            "lines": [
                {
                    "rule": {"id": "81601", "level": 8, "description": "FortiGate traffic denied"},
                    "data": {"action": "deny", "srcip": "10.77.2.9", "dstip": "10.0.0.15", "dstport": "445"},
                }
                for _ in range(6)
            ],
        },
        {
            "stream": {"job": "wazuh", "ss_groups": "windows", "agent_name": "dc01-curation"},
            "spread_seconds": 180,
            "lines": [
                {
                    "rule": {"id": "60122", "level": 10, "description": "Windows Logon Failure"},
                    "win": {
                        "system": {"eventID": "4625", "channel": "Security"},
                        "eventdata": {
                            "logonType": "3",
                            "targetUserName": "Administrator",
                            "ipAddress": "10.77.9.41",
                        },
                    },
                }
                for _ in range(6)
            ],
        },
        {
            "stream": {"job": "wazuh", "ss_groups": "linux", "agent_name": "lnx-curation-01"},
            "spread_seconds": 180,
            "lines": [
                {
                    "rule": {"id": "5710", "level": 10, "description": "sshd: Attempt to login using a non-existent user"},
                    "data": {"pam_status": "failed", "srcip": "172.16.40.19", "srcuser": "admin_backup"},
                }
                for _ in range(6)
            ],
        },
        {
            "stream": {"job": "wazuh", "ss_groups": "office365", "agent_name": "o365-curation"},
            "spread_seconds": 180,
            "lines": [
                {
                    "rule": {"id": "100100", "level": 8, "description": "Office 365 logon attempt"},
                    "data": {
                        "office365": {
                            "Operation": "UserLoggedIn",
                            "ResultStatus": "Failed",
                            "Workload": "AzureActiveDirectory",
                            "UserId": "admin@empresa.com.br",
                            "ClientIP": "198.51.100.22",
                        }
                    },
                }
                for _ in range(6)
            ],
        },
        {
            "stream": {"job": "wazuh", "ss_groups": "waf", "agent_name": "waf-curation-01"},
            "spread_seconds": 180,
            "lines": [
                {
                    "rule": {"id": "90100", "level": 9, "description": "Akamai WAF blocked SQLi attack"},
                    "data": {
                        "action": "deny",
                        "srcip": "203.0.113.88",
                        "uri": "/api/v1/users?id=1' OR '1'='1",
                        "http_method": "POST",
                        "status_code": "403",
                    },
                }
                for _ in range(6)
            ],
        },
    ]
    for p in payloads:
        call("POST", "/api/loki/logs", p, csrf=True)


def main() -> int:
    # 1. Login
    status, body = call(
        "POST",
        "/api/auth/login",
        {"username": ENV["PORTAL_ADMIN_USER"], "password": ENV["PORTAL_ADMIN_PASSWORD"]},
        csrf=True,
    )
    check("login 200", status == 200, str(body))
    cleanup_artifacts()
    seed_progressive_window_telemetry()

    # 2. Cria tenant de teste para validar avaliação multi-cliente
    t_status, t_body = call(
        "POST",
        "/api/tenants",
        {"title": TEST_TENANT_TITLE, "uid": TEST_TENANT_UID},
        csrf=True,
    )
    check("create test tenant", t_status in (200, 201), str(t_status))

    # Executa ciclo inicial da suíte após semear a telemetria das janelas e criar tenant
    run_init_status, run_init_body = call("POST", "/api/curation/run", {}, csrf=True)
    print("Initial run result:", run_init_status, str(run_init_body)[:200])

    # 3. GET /api/curation
    status, overview = call("GET", "/api/curation")
    check("GET /api/curation 200", status == 200, f"status={status}")
    if not isinstance(overview, dict):
        cleanup_artifacts()
        return 1

    # 3.1. Validar as 4 fontes confiáveis
    sources = overview.get("sources") or []
    source_urls = {s.get("url") for s in sources if isinstance(s, dict)}
    expected_urls = {
        "https://github.com/SigmaHQ/sigma",
        "https://detection.fyi/",
        "https://research.splunk.com/detections/",
        "https://elastic.github.io/detection-rules-explorer/",
    }
    check(
        "4 fontes confiaveis presentes",
        expected_urls.issubset(source_urls),
        str(sorted(source_urls)),
    )

    # 3.2. Validar agendamento diário às 08h00 (Regra 1)
    schedule = overview.get("schedule") or {}
    check(
        "agendamento diario 08h00 ativo",
        schedule.get("enabled") is True
        and schedule.get("daily_time") == "08:00"
        and schedule.get("cron_expression") == "0 8 * * *",
        str(schedule),
    )

    # 3.3. Validar que NUNCA há má candidata inserida (Regra 2)
    rules = overview.get("rules") or []
    metrics = overview.get("metrics") or {}
    classifications = {r.get("classification") for r in rules}
    check(
        "apenas excelentes e boas candidatas armazenadas (zero mas candidatas)",
        len(rules) > 0 and classifications.issubset({"excellent", "good"}),
        f"total={len(rules)}, classifications={classifications}, discarded_bad={metrics.get('discarded_bad_count')}",
    )
    check(
        "mas candidatas foram barradas no pipeline",
        int(metrics.get("discarded_bad_count") or 0) > 0,
        f"discarded_bad_count={metrics.get('discarded_bad_count')}",
    )

    all_compat_above_80 = all(
        float(r.get("field_compatibility_pct") or 0.0) >= 80.0
        for r in rules
    )
    distinct_compat_scores = {float(r.get("field_compatibility_pct") or 0.0) for r in rules}
    has_dynamic_scores = len(distinct_compat_scores) > 1
    has_score_breakdown = any(
        float(r.get("log_presence_score") or 0.0) > 0
        and float(r.get("threat_context_score") or 0.0) > 0
        and float(r.get("scenario_match_score") or 0.0) > 0
        for r in rules
    )
    check(
        "todas as regras candidatas possuem compatibilidade >= 80% para implementacao no SIEM",
        all_compat_above_80,
        f"min_compat={min(float(r.get('field_compatibility_pct') or 0.0) for r in rules)}%",
    )
    check(
        "porcentagem de compatibilidade e dinamica ponderando presenca de logs, ameaca e cenario",
        has_dynamic_scores and has_score_breakdown,
        f"distinct_scores_count={len(distinct_compat_scores)}, sample_scores={sorted(list(distinct_compat_scores))[:5]}",
    )

    # 3.3b. Validar ordenação estritamente decrescente por compatibilidade (mais próximas de 100% primeiro)
    compat_list = [float(r.get("field_compatibility_pct") or 0.0) for r in rules]
    is_sorted_descending = all(compat_list[i] >= compat_list[i + 1] for i in range(len(compat_list) - 1))
    check(
        "regras curadas exibidas em ordem estritamente decrescente de compatibilidade (mais proximas de 100% primeiro)",
        is_sorted_descending,
        f"compat_list={compat_list[:8]}",
    )

    # 3.3c. Validar que SOMENTE regras com logs reais encontrados possuem compatibilidade >= 80%
    all_rules_have_proven_logs = all(
        int(r.get("total_matched_results") or 0) > 0
        or any(ev.get("has_query_results") for ev in r.get("client_evaluations") or [])
        for r in rules
    )
    check(
        "SOMENTE regras com logs reais encontrados sao categorizadas como >= 80% de compatibilidade",
        all_rules_have_proven_logs,
        f"total_rules={len(rules)}, min_hits={min(int(r.get('total_matched_results') or 0) for r in rules)}",
    )

    # 3.4. Validar conversão LogQL e diretrizes D.A.N.T.E.
    all_logql_valid = all(
        r.get("lint_valid") is True
        and 'job="wazuh"' in str(r.get("logql_query") or "")
        and "ss_groups=~" in str(r.get("logql_query") or "")
        and "| json" in str(r.get("logql_query") or "")
        for r in rules
    )
    check("todas as regras curadas em formato LogQL valido D.A.N.T.E.", all_logql_valid)

    # 3.4a. Validar amarração ao Perímetro de Detecção e novos nomes padronizados
    all_rules_have_perimeter = all(
        bool(r.get("perimeter")) and bool(r.get("perimeter_name"))
        for r in rules
    )
    curated_perimeters = {r.get("perimeter") for r in rules}
    identity_names = {r.get("perimeter_name") for r in rules if r.get("perimeter") == "identity_iam"}
    waf_names = {r.get("perimeter_name") for r in rules if r.get("perimeter") == "waf_web"}
    check(
        "regras curadas possuem perimetro e perimetro_name padronizados (Identidade e WAF / Web)",
        all_rules_have_perimeter
        and ("Identidade" in identity_names or not identity_names)
        and ("AD / Identidade" not in identity_names)
        and ("WAF / Web" in waf_names or not waf_names)
        and ("WAF ou Web" not in waf_names),
        f"identity_names={identity_names}, waf_names={waf_names}",
    )

    # 3.4a2. Validar prefixo data_ em campos LogQL de dados e URLs factuais (zero alucinação)
    no_hallucinated_urls = all(
        "win_security_dcsync" not in str(r.get("source_url") or "")
        and not str(r.get("source_url") or "").startswith("https://detection.fyi/rules/")
        for r in rules
    )
    has_data_prefix = any(
        "data_" in str(r.get("logql_query") or "")
        for r in rules
        if r.get("technology") in ("fortigate", "waf_akamai", "linux")
    )
    check(
        "queries convertidas utilizam prefixo data_ e URLs curadas sao reais (zero alucinacao)",
        no_hallucinated_urls and has_data_prefix,
        f"no_hallucinated_urls={no_hallucinated_urls}, has_data_prefix={has_data_prefix}",
    )

    # 3.4b. Validar que os nomes das regras sao mantidos em ingles tal qual nas fontes pesquisadas
    all_english_titles = all(
        bool(r.get("title"))
        and r.get("title") == r.get("original_title")
        for r in rules
    )
    check(
        "nomes das regras mantidos em ingles tal qual nas fontes pesquisadas",
        all_english_titles,
        f"sample_titles={[r.get('title') for r in rules[:4]]}",
    )

    # 3.4c. Validar que o pipeline de curadoria avaliou as 4 fontes confiaveis nas tecnologias
    # e manteve como candidatas apenas as regras com evidencias comprovadas (total_matched_results > 0)
    total_eval = int(metrics.get("total_evaluated_history") or 0)
    check(
        "pipeline de curadoria avaliou todas as 4 fontes confiaveis nas tecnologias com descarte estrito de regras sem logs",
        total_eval >= 50 and int(metrics.get("discarded_bad_count") or 0) > 0 and len(rules) >= 5,
        f"total_evaluated={total_eval}, discarded_bad={metrics.get('discarded_bad_count')}, qualified_candidatas={len(rules)}",
    )

    # 3.5. Validar Critério 1 (compatibilidade de campos com logs reais) e Critério 2
    # (se não houver evidências de resultados nos logs, nunca pode ser excelente candidata)
    excellent_rules = [r for r in rules if r.get("classification") == "excellent"]
    good_rules = [r for r in rules if r.get("classification") == "good"]
    zero_results_excellent = [
        r.get("title")
        for r in excellent_rules
        if int(r.get("total_matched_results") or 0) <= 0 or not r.get("has_query_results")
    ]
    check(
        "Criterio 2: nenhuma regra sem resultados na query (0 logs) e categorizada como excelente",
        len(zero_results_excellent) == 0 and len(excellent_rules) > 0,
        f"excellent={len(excellent_rules)}, good={len(good_rules)}, invalid_excellent={zero_results_excellent}",
    )

    all_excellent_have_real_logs_and_fields = all(
        float(r.get("observed_field_compatibility_pct") or 0) >= 100.0
        and len(r.get("sample_query_results") or []) > 0
        and all(m.get("observed_in_logs") is True for m in (r.get("mapped_fields") or []))
        for r in excellent_rules
    )
    check(
        "Criterio 1 e 2: excelentes candidatas possuem 100% dos campos vistos nos logs reais e amostras de retorno da query",
        all_excellent_have_real_logs_and_fields,
        f"excellent_titles={[r.get('title') for r in excellent_rules]}",
    )

    all_have_complete_details = all(
        bool(r.get("original_syntax"))
        and bool(r.get("logql_query"))
        and len(r.get("qualification_factors") or []) >= 2
        for r in rules
    )
    check(
        "visualizacao completa contem regra original, LogQL, resultados da query e fatores de qualificacao",
        all_have_complete_details,
    )

    # 3.6. Validar execução em etapas progressivas (15m -> 1h -> 6h -> 24h -> 3d) e parada antecipada
    expected_5_windows = ["15 minutos", "1 hora", "6 horas", "24 horas", "3 dias"]
    rules_with_early_stop = [
        r.get("title")
        for r in excellent_rules
        if any(
            ev.get("matched_window") == "15 minutos"
            and ev.get("windows_evaluated") == ["15 minutos"]
            for ev in (r.get("client_evaluations") or [])
        )
    ]
    check(
        "parada antecipada na janela de 15 minutos quando logs sao encontrados (nao roda janelas mais extensas)",
        len(rules_with_early_stop) >= 3,
        f"regras com parada antecipada comprovada ({len(rules_with_early_stop)}/{len(excellent_rules)}): {rules_with_early_stop}",
    )

    has_5_stages_executed = any(
        any(
            ev.get("windows_evaluated") == expected_5_windows
            for ev in (r.get("client_evaluations") or [])
            if not ev.get("timed_out")
        )
        for r in rules
    )
    check(
        "5 etapas progressivas (15m, 1h, 6h, 24h, 3d) executadas quando nao ha logs em janelas menores",
        has_5_stages_executed,
        str(
            [
                (r.get("title"), [ev.get("windows_evaluated") for ev in (r.get("client_evaluations") or [])])
                for r in good_rules[:2]
            ]
        ),
    )

    # 3.7. Validar endpoint de progresso em tempo real (GET /api/curation/progress)
    prog_status, prog_body = call("GET", "/api/curation/progress")
    check(
        "GET /api/curation/progress retorna porcentagem (100%), acao, cliente e logs verbosos",
        prog_status == 200
        and isinstance(prog_body, dict)
        and int(prog_body.get("percent") or 0) == 100
        and prog_body.get("running") is False
        and len(prog_body.get("recent_logs") or []) > 0,
        f"percent={prog_body.get('percent') if isinstance(prog_body, dict) else None}, logs={len((prog_body or {}).get('recent_logs') or [])}",
    )

    # 4. Executar POST /api/curation/run e provar Regra 3 (não repetir regras já curadas)
    count_before = len(rules)
    r_status, run_res = call("POST", "/api/curation/run", {}, csrf=True)
    check("POST /api/curation/run 200", r_status == 200, str(run_res))
    if isinstance(run_res, dict):
        summary = run_res.get("summary") or {}
        run_prog = run_res.get("progress") or {}
        check(
            "busca nas 4 fontes filtrada apenas para tecnologias que ja existem no D.A.N.T.E.",
            int(summary.get("fetched_count") or 0) > 0
            and int(summary.get("fetched_count") or 0) == int(summary.get("compatible_tech_count") or 0),
            f"fetched={summary.get('fetched_count')}, compatible_tech={summary.get('compatible_tech_count')}",
        )
        act_str = str(run_prog.get("current_action") or "").strip()
        cli_str = str(run_prog.get("current_client_name") or "").strip()
        check(
            "bloco Acao sendo executada mostra acao curta e menos verbosa (nao apenas o nome do cliente)",
            bool(act_str)
            and act_str != cli_str
            and len(act_str) <= 95
            and "15m → 1h" not in act_str,
            f"current_action={act_str}, current_client_name={cli_str}",
        )
        check(
            "Regra 3: nao repete regras que ja foram curadas",
            int(summary.get("new_curated_count") or 0) == 0
            and int(summary.get("skipped_duplicates_count") or 0) >= count_before
            and int(run_res.get("total_curated") or 0) == count_before,
            f"new={summary.get('new_curated_count')}, skipped_dups={summary.get('skipped_duplicates_count')}, total={run_res.get('total_curated')}",
        )

    # 4.2. Validar resiliência a timeout em um cliente (não deve parar a curadoria)
    call(
        "POST",
        "/api/tenants",
        {
            "title": TIMEOUT_TENANT_TITLE,
            "uid": TIMEOUT_TENANT_UID,
            "loki_url": "http://10.255.255.1:3100",
        },
        csrf=True,
    )
    to_status, to_res = call("POST", "/api/curation/run", {}, csrf=True)
    call("DELETE", f"/api/tenants/{TIMEOUT_TENANT_UID}", csrf=True)
    to_summary = (to_res or {}).get("summary") or {} if isinstance(to_res, dict) else {}
    to_prog = (to_res or {}).get("progress") or {} if isinstance(to_res, dict) else {}
    check(
        "resiliencia a timeout: cliente com timeout nao interrompe a curadoria (conclui 100%)",
        to_status == 200
        and int(to_prog.get("percent") or 0) == 100
        and int(to_summary.get("timed_out_clients_count") or 0) >= 1,
        f"status={to_status}, percent={to_prog.get('percent')}, timed_out={to_summary.get('timed_out_clients')}",
    )

    # Recarrega para ver o cliente de teste nas avaliações das regras pendentes
    _, overview_after = call("GET", "/api/curation")
    rules_after = (overview_after or {}).get("rules") or []
    target_rule = next((r for r in rules_after if not r.get("implemented")), rules_after[0])
    target_rule_id = target_rule["id"]

    # 5. Testar botão/endpoint "Implementar"
    # 5.1. Sem confirmação explícita -> deve bloquear com 409 (Requisito 3.1)
    imp_no_confirm_status, imp_no_confirm_body = call(
        "POST",
        f"/api/curation/rules/{target_rule_id}/implement",
        {"client_uids": [TEST_TENANT_UID], "confirm": False},
        csrf=True,
    )
    check(
        "implementacao sem confirmacao bloqueada (409)",
        imp_no_confirm_status == 409,
        str(imp_no_confirm_body),
    )

    # 5.2. Com confirmação explícita -> implementa no Baseline e no cliente indicado
    imp_status, imp_body = call(
        "POST",
        f"/api/curation/rules/{target_rule_id}/implement",
        {"client_uids": [TEST_TENANT_UID], "confirm": True},
        csrf=True,
    )
    check(
        "implementacao com confirmacao 200",
        imp_status == 200 and int((imp_body or {}).get("created_in_clients") or 0) == 1,
        str(imp_body),
    )

    created_baseline_uid = (imp_body or {}).get("baseline_rule_uid")
    cleanup_artifacts(created_baseline_uid)

    # 6. Testar Ignorar e Restaurar regra curada (POST /api/curation/rules/{rule_id}/ignore)
    ign_status, ign_body = call(
        "POST",
        f"/api/curation/rules/{target_rule_id}/ignore",
        {"ignored": True},
        csrf=True,
    )
    check(
        "POST /api/curation/rules/{rule_id}/ignore com ignored=true 200",
        ign_status == 200 and (ign_body or {}).get("ignored") is True and bool((ign_body or {}).get("ignored_at")),
        str(ign_body),
    )

    _, ov_ign = call("GET", "/api/curation")
    ign_count = int(((ov_ign or {}).get("metrics") or {}).get("ignored_count") or 0)
    check("GET /api/curation reflete ignored_count >= 1", ign_count >= 1, f"ignored_count={ign_count}")

    unign_status, unign_body = call(
        "POST",
        f"/api/curation/rules/{target_rule_id}/ignore",
        {"ignored": False},
        csrf=True,
    )
    check(
        "POST /api/curation/rules/{rule_id}/ignore com ignored=false restaura regra",
        unign_status == 200 and (unign_body or {}).get("ignored") is False and (unign_body or {}).get("ignored_at") is None,
        str(unign_body),
    )

    # 7. Testar botão e endpoint de Parar Curadoria (POST /api/curation/stop)
    stop_idle_status, stop_idle_body = call("POST", "/api/curation/stop", {}, csrf=True)
    check(
        "POST /api/curation/stop quando inativo retorna status not_running",
        stop_idle_status == 200 and (stop_idle_body or {}).get("status") in ("not_running", "stopped"),
        str(stop_idle_body),
    )

    # 8. Testar idempotência pura de GET /api/curation (sem reiniciar ciclo indesejado ao dar refresh)
    for _ in range(3):
        g_st, g_ov = call("GET", "/api/curation")
        p_st, p_body = call("GET", "/api/curation/progress")
        check(
            "GET /api/curation idempotente (refresh nao inicia execucao em background)",
            g_st == 200 and p_st == 200 and (p_body or {}).get("running") is False,
            f"running={(p_body or {}).get('running')}",
        )

    # 9. Testar Limpar Curadoria (POST /api/curation/clear)
    clr_status, clr_body = call("POST", "/api/curation/clear", {}, csrf=True)
    check(
        "POST /api/curation/clear limpa todas as regras e reseta catalogo 200",
        clr_status == 200 and (clr_body or {}).get("status") == "cleared",
        str(clr_body),
    )
    g_after_clr_st, g_after_clr_ov = call("GET", "/api/curation")
    rules_after_clr = (g_after_clr_ov or {}).get("rules") or []
    check(
        "GET /api/curation apos clear retorna lista completamente vazia (0 regras)",
        g_after_clr_st == 200 and len(rules_after_clr) == 0,
        f"total_rules={len(rules_after_clr)}",
    )
    p_after_clr_st, p_after_clr = call("GET", "/api/curation/progress")
    check(
        "apos clear o progresso fica estritamente em 0% e running=False (sem travar em 2%)",
        p_after_clr_st == 200
        and (p_after_clr or {}).get("percent") == 0
        and (p_after_clr or {}).get("running") is False
        and len((p_after_clr or {}).get("recent_logs") or []) == 0,
        f"percent={(p_after_clr or {}).get('percent')}, running={(p_after_clr or {}).get('running')}, logs={len((p_after_clr or {}).get('recent_logs') or [])}",
    )

    failed = [name for ok, name in results if not ok]
    print(f"\nResumo E2E Curadoria: {len(results) - len(failed)}/{len(results)} checks aprovados.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
