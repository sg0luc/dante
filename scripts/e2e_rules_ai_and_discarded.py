"""Suíte de testes E2E para avaliação de regras por IA e regras descartadas na Curadoria.

Testa contra a stack real (FastAPI -> Grafana Alerting -> Loki):
1. Curadoria:
   - Presença e integridade das regras descartadas em GET /api/curation (discarded_rules)
   - Estrutura de cada regra descartada (discarded=True, classification='bad', discard_reason)
   - Parecer técnico focado no cenário e contexto de ameaça (sem menções a conversão de sintaxe LogQL)
2. Regras de Detecção:
   - Endpoint GET /api/rules/{uid}/ai-evaluation com parecer técnico e oportunidades de melhoria
   - Endpoint POST /api/rules/{uid}/apply-ai-suggestions persistindo melhorias da IA no Grafana
   - Validação de segurança (CSRF) e linter LogQL (rejeição de query inválida com 400)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

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
    print("Iniciando suíte E2E: Regras Descartadas e Avaliação de IA em Regras de Detecção...")

    # 1. Login
    pwd = os.environ.get("PORTAL_ADMIN_PASSWORD", "HunterPortal@2026!Pass")
    st, data = call("POST", "/api/auth/login", {"username": "hunter", "password": pwd}, csrf=True)
    check(st == 200, "Login do portal com credenciais do operador", f"status={st}")

    # 2. Curadoria: visualização de regras descartadas
    st, cur_data = call("GET", "/api/curation")
    check(st == 200, "GET /api/curation responde 200", f"status={st}")

    rules = cur_data.get("rules") or []
    if not rules:
        # Se o catálogo foi resetado anteriormente, executa um ciclo rápido para popular
        call("POST", "/api/curation/run", {}, csrf=True)
        _, cur_data = call("GET", "/api/curation")
        rules = cur_data.get("rules") or []

    discarded_rules = cur_data.get("discarded_rules") or []
    check(len(rules) > 0, "Curadoria possui regras qualificadas armazenadas", f"total={len(rules)}")
    check(len(discarded_rules) > 0, "Curadoria expõe regras descartadas para visualização", f"total_descartadas={len(discarded_rules)}")

    # Valida estrutura das regras descartadas
    sample_disc = discarded_rules[0]
    check(bool(sample_disc.get("discarded")), "Regra descartada possui flag discarded=True", f"id={sample_disc.get('id')}")
    check(sample_disc.get("classification") == "bad", "Regra descartada possui classification='bad'", f"class={sample_disc.get('classification')}")
    check(bool(sample_disc.get("discard_reason")), "Regra descartada possui justificativa explícita de descarte", f"reason={sample_disc.get('discard_reason')}")

    # 3. Curadoria: parecer técnico estrito no contexto de ameaça (sem citar tradução para LogQL)
    for r in rules:
        rationale = r.get("ai_rationale") or ""
        t_name = r.get("title", "")[:35]
        check("Lógica e Reforço LogQL:" not in rationale, f"Parecer da regra '{t_name}' não menciona detalhes sintáticos de conversão", f"len={len(rationale)}")
        check("parser '| json'" not in rationale, f"Parecer da regra '{t_name}' não cita parser | json")

    # 4. Regras de Detecção: avaliação de oportunidades de melhoria por IA
    st, all_rules = call("GET", "/api/rules")
    check(st == 200 and len(all_rules) > 0, "GET /api/rules lista regras do Grafana", f"total={len(all_rules)}")

    target_rule = all_rules[0]
    target_uid = target_rule["uid"]

    st, ai_eval = call("GET", f"/api/rules/{target_uid}/ai-evaluation")
    check(st == 200, f"GET /api/rules/{target_uid}/ai-evaluation responde 200", f"status={st}")
    check(bool(ai_eval.get("verdict")), "Avaliação da IA retorna veredito estruturado", f"verdict={ai_eval.get('verdict')}")
    check(bool(ai_eval.get("threat_context")), "Avaliação da IA retorna contexto e cenário de ameaça", f"threat={ai_eval.get('threat_context')[:60]}...")
    check(isinstance(ai_eval.get("improvements"), list) and len(ai_eval.get("improvements", [])) >= 2, "Avaliação da IA retorna oportunidades de melhoria", f"count={len(ai_eval.get('improvements', []))}")
    check(isinstance(ai_eval.get("noise_reduction_actions"), list) and len(ai_eval.get("noise_reduction_actions", [])) >= 2, "Avaliação da IA retorna ações anti-ruído", f"count={len(ai_eval.get('noise_reduction_actions', []))}")
    check(bool(ai_eval.get("can_implement")), "Avaliação da IA sinaliza can_implement=True para implementar sugestões")
    check(isinstance(ai_eval.get("diff_summary"), list) and len(ai_eval.get("diff_summary", [])) >= 1, "Avaliação da IA gera diff_summary com resumo de melhorias")

    # 4.1 Validação específica de regra não-firing / silenciosa (NTDS ou regra em estado Normal)
    ntds_rules = [r for r in all_rules if "ntds" in str(r.get("title", "")).lower()]
    if ntds_rules:
        ntds_uid = ntds_rules[0]["uid"]
        st_ntds, ntds_eval = call("GET", f"/api/rules/{ntds_uid}/ai-evaluation")
        check(st_ntds == 200, f"GET /api/rules/{ntds_uid}/ai-evaluation para regra NTDS responde 200", f"status={st_ntds}")
        check("ntds" in str(ntds_eval.get("threat_context", "")).lower() or "active directory" in str(ntds_eval.get("threat_context", "")).lower(), "Regra não-firing avalia o contexto intrínseco de ameaça de Active Directory / NTDS", f"threat={ntds_eval.get('threat_context')[:70]}...")
        check(bool(ntds_eval.get("can_implement")), "Regra não-firing possui can_implement=True com botão de implementação habilitado")
        check(len(ntds_eval.get("improvements", [])) >= 3, "Regra não-firing possui melhorias técnicas detalhadas", f"count={len(ntds_eval.get('improvements', []))}")
        check(len(ntds_eval.get("noise_reduction_actions", [])) >= 2, "Regra não-firing possui ações anti-ruído detalhadas", f"count={len(ntds_eval.get('noise_reduction_actions', []))}")

    # 4.2 Validação de Cache de IA por Regra (preservação de tokens e reanálise com refresh=True)
    st_cached, ai_eval_cached = call("GET", f"/api/rules/{target_uid}/ai-evaluation")
    check(st_cached == 200, f"Segunda chamada GET /api/rules/{target_uid}/ai-evaluation responde 200", f"status={st_cached}")
    check(bool(ai_eval_cached.get("is_cached")), "Segunda chamada recupera parecer técnico do cache (is_cached=True, economizando tokens)")
    check(ai_eval_cached.get("verdict") == ai_eval.get("verdict"), "Parecer em cache é consistente com a avaliação anterior")

    # Chamada com refresh=True (botão 'Analisar') força nova avaliação e atualiza o cache
    st_refreshed, ai_eval_refreshed = call("GET", f"/api/rules/{target_uid}/ai-evaluation?refresh=true")
    check(st_refreshed == 200, f"Chamada forçada com refresh=True responde 200", f"status={st_refreshed}")
    check(bool(ai_eval_refreshed.get("verdict")), "Chamada forçada com refresh=True executa reanálise e atualiza cache")

    # 5. Aplicação de sugestões da IA na regra (POST /apply-ai-suggestions)
    # 5.1 Teste de proteção CSRF
    st_no_csrf, _ = call("POST", f"/api/rules/{target_uid}/apply-ai-suggestions", {"suggested_labels": {"test": "1"}}, csrf=False)
    check(st_no_csrf == 403, "POST /apply-ai-suggestions bloqueia requisição sem CSRF (403)", f"status={st_no_csrf}")

    # 5.2 Teste de validação LogQL (rejeição de query inválida com 400)
    st_bad_query, bad_resp = call(
        "POST",
        f"/api/rules/{target_uid}/apply-ai-suggestions",
        {"suggested_logql_query": "query invalida sem chaves nem nada"},
        csrf=True,
    )
    check(st_bad_query == 400, "POST /apply-ai-suggestions recusa query LogQL inválida com HTTP 400", f"status={st_bad_query}")

    # 5.3 Aplicação bem-sucedida de melhoria válida
    apply_payload = {
        "suggested_labels": {"mitre_ai_checked": "true", "evaluated_release": "v1.7.0"},
        "suggested_annotations": {"dante_ai_tuning": "Calibração e parecer técnico validados"}
    }
    if ai_eval.get("suggested_logql_query"):
        apply_payload["suggested_logql_query"] = ai_eval["suggested_logql_query"]

    st_ok, apply_res = call("POST", f"/api/rules/{target_uid}/apply-ai-suggestions", apply_payload, csrf=True)
    check(st_ok == 200, "POST /apply-ai-suggestions aplica melhorias com sucesso no Grafana", f"msg={apply_res.get('message')}")
    
    updated_rule = apply_res.get("rule") or {}
    check(updated_rule.get("labels", {}).get("evaluated_release") == "v1.7.0", "Regra atualizada persistiu nova label de auditoria", "evaluated_release=v1.7.0")

    passed = sum(1 for c, _ in results if c)
    total = len(results)
    print(f"\nResumo da Suíte: {passed}/{total} checks aprovados.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

