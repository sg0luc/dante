"""Harness E2E da funcionalidade de Prefixo Baseline e remoção do prefixo de cliente (D.A.N.T.E.).

Valida contra a stack real (nginx :8080 -> FastAPI -> Grafana):
1. Autenticação e sessão CSRF;
2. GET /api/system/baseline/prefix retorna configurações com valores padrão;
3. POST /api/system/baseline/prefix/preview valida substituição dinâmica e capitalização:
   - {{tenant}} no baseline vira 'Baseline';
   - {{tenant}} no cliente vira o nome do cliente capitalizado;
   - {{technology}}, {{tactic}}, {{severity}} com primeira letra maiúscula;
4. PUT /api/system/baseline/prefix atualiza configurações com proteção CSRF;
5. Importação de regra no Baseline Global aplica o prefixo configurado no Grafana;
6. Implementação/replicação de regra no cliente NÃO recebe o prefixo hardcoded '[nomedocliente]';
7. Limpeza (teardown) de regras e restauração das configurações.
"""

from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
BASE = os.getenv("PORTAL_BASE_URL", "http://localhost:8080")
GRAFANA = os.getenv("GRAFANA_URL", "http://localhost:3000")
CSRF = {"X-Requested-With": "hunter-portal"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
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


def get_env_val(key: str, default: str = "") -> str:
    return os.environ.get(key) or ENV.get(key) or default


jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
results: list[tuple[bool, str]] = []


def call(
    method: str, path: str, body: Any = None, *, csrf: bool = False, base: str = BASE
) -> tuple[int, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if csrf:
        for k, v in CSRF.items():
            req.add_header(k, v)
    try:
        with opener.open(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            parsed = json.loads(raw) if raw else None
        except Exception:
            parsed = raw.decode("utf-8", errors="replace")
        return exc.code, parsed


def grafana_get(path: str) -> tuple[int, Any]:
    user = get_env_val("GRAFANA_ADMIN_USER", "admin")
    pwd = get_env_val("GRAFANA_ADMIN_PASSWORD", "GrafanaAdmin@2026!Pass")
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req = urllib.request.Request(GRAFANA + path, method="GET")
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


def grafana_delete(path: str) -> tuple[int, Any]:
    user = get_env_val("GRAFANA_ADMIN_USER", "admin")
    pwd = get_env_val("GRAFANA_ADMIN_PASSWORD", "GrafanaAdmin@2026!Pass")
    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    req = urllib.request.Request(GRAFANA + path, method="DELETE")
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, json.loads(raw) if raw else None


def record(ok: bool, desc: str) -> None:
    results.append((ok, desc))
    status_str = "OK" if ok else "FAIL"
    print(f"[{status_str}] {desc}")


def login() -> None:
    u = get_env_val("PORTAL_ADMIN_USER", "admin")
    p = get_env_val("PORTAL_ADMIN_PASSWORD", "HunterAdmin@2026!Pass")
    status, body = call("POST", "/api/auth/login", {"username": u, "password": p}, csrf=True)
    if status != 200:
        raise RuntimeError(f"Login falhou: {status} {body}")


def main() -> int:
    print("Iniciando suite E2E de Prefixo Baseline...")
    login()

    created_uids: list[str] = []
    run_id = uuid.uuid4().hex[:6]
    orig_prefix_settings = None

    try:
        # 1. Obter configuração atual de Prefixo Baseline
        status, prefix_cfg = call("GET", "/api/system/baseline/prefix")
        record(
            status == 200 and "enabled" in prefix_cfg and "template" in prefix_cfg,
            "1. GET /api/system/baseline/prefix retorna configurações de prefixo válidas",
        )
        orig_prefix_settings = prefix_cfg

        # 2. Preview de Prefixo com variáveis dinâmicas e capitalização
        preview_payload = {
            "template": "[{{tenant}}] [{{technology_name}}] [{{tactic}}] [{{severity}}] - ",
            "title": "Ataque RDP Brute Force",
            "technology": "ad_windows",
            "technology_name": "AD/Windows",
            "tactic": "credential_access",
            "severity": "high",
            "tenant": None,  # Baseline Global
        }
        status_prev, res_prev = call("POST", "/api/system/baseline/prefix/preview", preview_payload, csrf=True)
        expected_base = "[Baseline] [AD/Windows] [Credential Access] [High] - Ataque RDP Brute Force"
        record(
            status_prev == 200 and res_prev.get("preview_title") == expected_base,
            f"2. Preview no Baseline substitui {{technology_name}} pelo nome limpo da tecnologia sem '_' ou '-': {res_prev.get('preview_title')}",
        )

        # 2.1. Compatibilidade com {{technology}} legada resolvendo nome limpo
        prev_legacy = {
            "template": "[{{technology}}] - ",
            "title": "Regra Legada",
            "technology": "ad_windows",
        }
        st_leg, res_leg = call("POST", "/api/system/baseline/prefix/preview", prev_legacy, csrf=True)
        legacy_ok = st_leg == 200 and res_leg.get("preview_title") == "[AD/Windows] - Regra Legada"
        record(legacy_ok, "2.1. Coringa {{technology}} resolve para o nome limpo da tecnologia ('AD/Windows') sem '_' ou '-'")

        # 3. Preview para tenant de cliente
        preview_client_payload = dict(preview_payload)
        preview_client_payload["tenant"] = "hospital_santa_clara"
        status_prev_c, res_prev_c = call("POST", "/api/system/baseline/prefix/preview", preview_client_payload, csrf=True)
        expected_client = "[Hospital_santa_clara] [AD/Windows] [Credential Access] [High] - Ataque RDP Brute Force"
        record(
            status_prev_c == 200 and res_prev_c.get("preview_title") == expected_client,
            f"3. Preview no Cliente substitui {{tenant}} pelo nome capitalizado do cliente: {res_prev_c.get('preview_title')}",
        )

        # 4. Configurar prefixo para 'Baseline - ' via PUT
        test_prefix_template = f"Baseline {run_id} - "
        status_put, res_put = call(
            "PUT",
            "/api/system/baseline/prefix",
            {"enabled": True, "template": test_prefix_template},
            csrf=True,
        )
        record(
            status_put == 200 and res_put.get("template") == test_prefix_template,
            f"4. PUT /api/system/baseline/prefix atualiza template com sucesso para '{test_prefix_template}'",
        )

        # 5. Importar regra no Baseline Global e validar que o título recebe o prefixo configurado
        rule_base_name = f"Regra Teste Prefixo {run_id}"
        rule_yaml = f"""
groups:
  - name: e2e_prefix_group
    rules:
      - alert: "{rule_base_name}"
        expr: 'sum(count_over_time({{job="wazuh", ss_groups=~".*windows.*"}} | json | win_system_eventID=~"4728" [5m])) > 0'
        for: 0s
        labels:
          severity: critical
          mitre_tactic: persistence
          mitre_technique: T1098
        annotations:
          summary: "Teste de prefixo baseline"
"""
        status_pv, res_pv = call("POST", "/api/rules/import/preview", {"content": rule_yaml}, csrf=True)
        import_item = res_pv["items"][0]
        status_imp, res_imp = call("POST", "/api/rules/import", {"rules": [import_item]}, csrf=True)
        import_ok = status_imp == 200 and res_imp.get("imported_count") == 1
        record(import_ok, "5. Importação de regra de baseline executada com sucesso")

        if import_ok:
            rule_uid = res_imp["imported_uids"][0]
            created_uids.append(rule_uid)
            g_st, g_rule = grafana_get(f"/api/v1/provisioning/alert-rules/{rule_uid}")
            expected_title = f"{test_prefix_template}{rule_base_name}"
            has_prefix = g_st == 200 and g_rule.get("title") == expected_title
            record(
                has_prefix,
                f"6. Título da regra instalada no Grafana possui o prefixo baseline configurado ('{g_rule.get('title')}')",
            )

        # 6. Validar que ao implementar regra em um cliente, ela NÃO recebe o prefixo '[nomedocliente]'
        # Primeiro, listamos os folders para encontrar um tenant de cliente
        g_folders_st, folders = grafana_get("/api/folders")
        client_folders = [f for f in (folders or []) if str(f.get("uid") or "").lower() not in ("global", "general")]
        if client_folders:
            target_client = client_folders[0]
            c_uid = target_client.get("uid")
            c_title = target_client.get("title") or c_uid

            # Implementa o baseline da tecnologia no cliente
            status_impl, res_impl = call(
                "POST",
                "/api/technologies/ad_windows/implement-baseline",
                {
                    "target_folder_uid": c_uid,
                    "confirm_client_without_technology": True,
                },
                csrf=True,
            )
            impl_ok = status_impl == 200 and (res_impl.get("created", 0) >= 1 or res_impl.get("skipped", 0) >= 1)
            record(
                impl_ok,
                f"7. Replicação de baseline da tecnologia executada para o cliente '{c_title}' (created={res_impl.get('created')}, skipped={res_impl.get('skipped')})",
            )

            # Verifica o título da regra replicada no Grafana
            # O título da regra no cliente NÃO pode começar com '[c_title]'
            g_all_st, all_rules = grafana_get("/api/v1/provisioning/alert-rules")
            client_rule = next(
                (r for r in (all_rules or []) if r.get("folderUID") == c_uid and (rule_base_name in str(r.get("title") or ""))),
                None,
            )
            if client_rule:
                c_rule_uid = client_rule.get("uid")
                created_uids.append(c_rule_uid)
                c_rule_title = str(client_rule.get("title") or "")
                # NÃO deve conter [c_title]
                not_has_bracket_client = not c_rule_title.startswith(f"[{c_title}]")
                record(
                    not_has_bracket_client,
                    f"8. Regra replicada para o cliente NÃO possui o prefixo '[nomedocliente]': '{c_rule_title}'",
                )
            else:
                record(False, "8. Regra replicada não encontrada no cliente para conferência de título")
        else:
            record(True, "7 e 8. Pulado (nenhum tenant cliente cadastrado no ambiente)")

    finally:
        # Teardown de limpeza
        print("Executando limpeza (teardown)...")
        for uid in created_uids:
            st, _ = grafana_delete(f"/api/v1/provisioning/alert-rules/{uid}")
            print(f"Limpeza de regra {uid}: status {st}")

        # Restaura configuração original de prefixo
        if orig_prefix_settings:
            call("PUT", "/api/system/baseline/prefix", orig_prefix_settings, csrf=True)
            print("Configuração original de prefixo restaurada.")

    failed = [desc for ok, desc in results if not ok]
    if failed:
        print(f"\nFALHA: {len(failed)} testes falharam:")
        for f in failed:
            print(f"  - {f}")
        return 1

    print(f"\nSUCESSO: Todos os {len(results)} testes passaram com perfeição!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
