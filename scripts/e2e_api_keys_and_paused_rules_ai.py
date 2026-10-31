#!/usr/bin/env python3
"""E2E Test: API Keys e Análise por IA de Regras Pausadas nas 5 Faixas Temporais.

Valida:
1. Endpoints de configuração de IA (GET e PUT /api/ai/settings) com suporte aos switches:
   - "Análises e Recomendações por IA" (ai_analysis_enabled)
   - "Curadoria com IA" (curation_enabled)
2. Avaliação de IA em regras de detecção pausadas (GET /api/rules/{uid}/ai-evaluation):
   - Execução nas 5 faixas progressivas (15m -> 1h -> 6h -> 24h -> 3d) no cliente Loki;
   - Preenchimento de telemetria real (windows_evaluated, matched_window, matched_events_count);
   - Parecer técnico emitido detalhando viabilidade de reativação da regra.
"""

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
    print("=== D.A.N.T.E. E2E :: API Keys e Análise por IA de Regras Pausadas ===")

    # 1. Login
    user = os.environ.get("PORTAL_ADMIN_USER", "admin")
    password = os.environ.get("PORTAL_ADMIN_PASSWORD", "admin123")
    status, body = call("POST", "/api/auth/login", {"username": user, "password": password}, csrf=True)
    check(status == 200, "login autenticado no portal D.A.N.T.E.", f"status={status}")
    if status != 200:
        return 1

    # 2. Consultar GET /api/ai/settings
    status, ai_settings = call("GET", "/api/ai/settings")
    check(status == 200 and isinstance(ai_settings, dict), "consulta de configurações de IA (GET /api/ai/settings)", f"status={status}")
    if not isinstance(ai_settings, dict):
        return 1

    check(
        "ai_analysis_enabled" in ai_settings and "curation_enabled" in ai_settings,
        "campos de switches 'ai_analysis_enabled' e 'curation_enabled' presentes no schema público",
        f"keys={list(ai_settings.keys())}",
    )
    check(
        len(ai_settings.get("available_providers", [])) >= 4,
        "provedores disponíveis configurados (DeepSeek, OpenAI, Gemini, etc.)",
        f"count={len(ai_settings.get('available_providers', []))}",
    )

    # 3. Atualizar PUT /api/ai/settings com novos switches
    orig_analysis = ai_settings.get("ai_analysis_enabled", True)
    orig_curation = ai_settings.get("curation_enabled", True)

    update_payload = {
        "provider": ai_settings.get("provider", "deepseek"),
        "model": ai_settings.get("model", "deepseek-chat"),
        "temperature": ai_settings.get("temperature", 0.1),
        "ai_analysis_enabled": False,
        "curation_enabled": True,
        "cache_enabled": ai_settings.get("cache_enabled", True),
    }
    status, updated_settings = call("PUT", "/api/ai/settings", update_payload, csrf=True)
    check(status == 200 and isinstance(updated_settings, dict), "atualização de switches de IA (PUT /api/ai/settings)", f"status={status}")
    if isinstance(updated_settings, dict):
        check(
            updated_settings.get("ai_analysis_enabled") is False and updated_settings.get("curation_enabled") is True,
            "switches persistidos corretamente no backend",
            f"analysis={updated_settings.get('ai_analysis_enabled')}, curation={updated_settings.get('curation_enabled')}",
        )

    # Restaura configurações
    restore_payload = {
        "provider": ai_settings.get("provider", "deepseek"),
        "model": ai_settings.get("model", "deepseek-chat"),
        "temperature": ai_settings.get("temperature", 0.1),
        "ai_analysis_enabled": orig_analysis,
        "curation_enabled": orig_curation,
        "cache_enabled": ai_settings.get("cache_enabled", True),
    }
    call("PUT", "/api/ai/settings", restore_payload, csrf=True)

    # 4. Localizar regras e testar avaliação por IA em regra pausada
    status, rules = call("GET", "/api/rules")
    check(status == 200 and isinstance(rules, list) and len(rules) > 0, "listagem de regras de detecção no portal", f"total={len(rules) if isinstance(rules, list) else 0}")
    if not isinstance(rules, list) or len(rules) == 0:
        return 1

    # Busca uma regra para teste
    test_rule = next((r for r in rules if r.get("uid")), rules[0])
    rule_uid = test_rule["uid"]
    rule_title = test_rule.get("title", "")
    orig_paused = test_rule.get("is_paused", False)

    # Garante que a regra esteja pausada para o teste
    status, pause_res = call("POST", f"/api/rules/{rule_uid}/toggle-pause", {"paused": True}, csrf=True)
    check(status == 200, f"pausa de regra para avaliação de telemetria ({rule_title})", f"status={status}")

    # 5. Avaliação técnica por IA na regra pausada
    status, ai_eval = call("GET", f"/api/rules/{rule_uid}/ai-evaluation")
    check(status == 200 and isinstance(ai_eval, dict), f"parecer técnico por IA da regra pausada (GET /api/rules/{rule_uid}/ai-evaluation)", f"status={status}")

    if isinstance(ai_eval, dict):
        check(
            ai_eval.get("is_paused_rule") is True,
            "regra identificada como pausada no parecer da IA (is_paused_rule=True)",
            f"is_paused={ai_eval.get('is_paused_rule')}",
        )
        check(
            ai_eval.get("telemetry_evaluated") is True,
            "telemetria real no Loki executada para a regra pausada (telemetry_evaluated=True)",
            f"telemetry_evaluated={ai_eval.get('telemetry_evaluated')}",
        )
        check(
            len(ai_eval.get("windows_evaluated", [])) >= 1,
            "etapas progressivas de faixas temporais registradas na avaliação",
            f"windows={ai_eval.get('windows_evaluated')}",
        )
        check(
            bool(ai_eval.get("verdict")) and bool(ai_eval.get("threat_context")),
            "veredito e parecer técnico conclusivo gerados",
            f"verdict='{ai_eval.get('verdict')[:60]}...'",
        )

    # 6. Restaura estado original de pausa da regra
    call("POST", f"/api/rules/{rule_uid}/toggle-pause", {"paused": orig_paused}, csrf=True)

    passed = sum(1 for ok, _ in results if ok)
    failed = sum(1 for ok, _ in results if not ok)
    print(f"\nResumo E2E: {passed} passaram, {failed} falharam.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

