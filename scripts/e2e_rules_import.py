"""Harness E2E da funcionalidade de importaÃ§Ã£o de regras em formato Loki Ruler (D.A.N.T.E.).

Valida contra a stack real (nginx :8080 -> FastAPI -> Grafana):
1. Preview / ValidaÃ§Ã£o de JSON malformado (rejeiÃ§Ã£o com general_error);
2. Preview de regra vÃ¡lida em formato Loki Ruler (infeÃ§Ã£o de tecnologia, severidade, MITRE);
3. Preview de regras invÃ¡lidas (LogQL invÃ¡lido, ss_groups ausente/desconhecido, falta de MITRE);
4. RejeiÃ§Ã£o estrita no backend de importaÃ§Ã£o contendo regras invÃ¡lidas (400 Bad Request);
5. ExecuÃ§Ã£o de importaÃ§Ã£o de regra vÃ¡lida:
   - GravaÃ§Ã£o garantida na pasta global ('global' / baseline);
   - Contact Point verificado como 'stg' (HomologaÃ§Ã£o);
   - Data source Loki sistÃªmico ('loki');
   - Grupo de avaliaÃ§Ã£o 'global-detections';
   - Labels de governanÃ§a (scope: baseline, client: global, siem_tier: global, source: dante);
6. Limpeza (teardown) da regra criada no Grafana.
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
    print("Iniciando suite E2E de Importacao de Regras...")
    login()

    created_uids: list[str] = []
    run_id = uuid.uuid4().hex[:6]

    try:
        # 1. Preview de JSON malformado
        bad_json = "{ rules: [ invalid json"
        status, res = call("POST", "/api/rules/import/preview", {"content": bad_json}, csrf=True)
        record(
            status == 200 and res.get("general_error") is not None and res.get("total_rules") == 0,
            "1. JSON malformado retorna general_error amigÃ¡vel sem quebrar o backend",
        )

        # 1.1 Preview de YAML malformado
        bad_yaml = "groups:\n  - name: test\n    rules:\n      - alert: [invalid yaml"
        status, res = call("POST", "/api/rules/import/preview", {"content": bad_yaml}, csrf=True)
        record(
            status == 200 and res.get("general_error") is not None and res.get("total_rules") == 0,
            "1.1. YAML malformado retorna general_error amigÃ¡vel sem quebrar o backend",
        )

        # 2. Preview de regra vÃ¡lida em formato Loki Ruler
        valid_ruler_json = json.dumps({
            "groups": [
                {
                    "name": "e2e_group",
                    "rules": [
                        {
                            "alert": f"E2E Test Rule {run_id}",
                            "expr": 'sum(count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json | win_system_eventID=~"4728" [5m])) > 0',
                            "for": "0s",
                            "labels": {
                                "severity": "critical",
                                "mitre_tactic": "persistence",
                                "mitre_technique": "T1098"
                            },
                            "annotations": {
                                "summary": "Teste de importaÃ§Ã£o de regra E2E",
                                "description": "DescriÃ§Ã£o detalhada do teste E2E"
                            }
                        }
                    ]
                }
            ]
        })
        status, res = call("POST", "/api/rules/import/preview", {"content": valid_ruler_json}, csrf=True)
        is_preview_ok = (
            status == 200
            and res.get("total_rules") == 1
            and res.get("valid_count") == 1
            and res.get("invalid_count") == 0
        )
        if is_preview_ok:
            item = res["items"][0]
            is_preview_ok = (
                item.get("valid") is True
                and item.get("technology") == "ad_windows"
                and item.get("severity") == "critical"
                and item.get("mitre_tactic") == "persistence"
                and item.get("mitre_technique") == "T1098"
            )
        record(is_preview_ok, "2. Preview de regra vÃ¡lida no formato Loki Ruler extrai metadados e tecnologia")

        # 3. Preview de regras invÃ¡lidas (LogQL invÃ¡lido, ss_groups ausente, falta de MITRE)
        invalid_rules_json = json.dumps([
            {
                "alert": "Regra com LogQL InvÃ¡lido",
                "expr": "count({job=\"wazuh\"}[1m])",  # sintaxe invÃ¡lida no LogQL (unexpected RANGE)
                "labels": {"severity": "high", "mitre_tactic": "initial_access", "mitre_technique": "T1190"}
            },
            {
                "alert": "Regra com ss_groups desconhecido",
                "expr": "sum(count_over_time({job=\"wazuh\", ss_groups=\"tech_desconhecida_xyz\"} [5m])) > 0",
                "labels": {"severity": "high", "mitre_tactic": "execution", "mitre_technique": "T1059"}
            },
            {
                "alert": "Regra sem MITRE",
                "expr": "sum(count_over_time({job=\"wazuh\", ss_groups=~\".*fortigate.*\"} [5m])) > 0",
                "labels": {"severity": "medium"}  # sem mitre_tactic nem mitre_technique
            }
        ])
        status, res = call("POST", "/api/rules/import/preview", {"content": invalid_rules_json}, csrf=True)
        all_invalid = (
            status == 200
            and res.get("total_rules") == 3
            and res.get("valid_count") == 0
            and res.get("invalid_count") == 3
            and all(not it.get("valid") and len(it.get("errors", [])) > 0 for it in res.get("items", []))
        )
        record(all_invalid, "3. Preview identifica e lista erros ponta a ponta em regras invÃ¡lidas")

        # 4. RejeiÃ§Ã£o no endpoint de importaÃ§Ã£o contendo apenas regras invÃ¡lidas
        invalid_items = res.get("items", [])
        status, res_import = call("POST", "/api/rules/import", {"rules": invalid_items}, csrf=True)
        record(
            status == 400,
            "4. Endpoint /api/rules/import rejeita com 400 tentativa de importar regras invÃ¡lidas",
        )

        # 5. ExecuÃ§Ã£o de importaÃ§Ã£o de regra vÃ¡lida
        status, preview_valid = call("POST", "/api/rules/import/preview", {"content": valid_ruler_json}, csrf=True)
        valid_items = preview_valid.get("items", [])
        status, exec_res = call("POST", "/api/rules/import", {"rules": valid_items}, csrf=True)
        import_ok = (
            status == 200
            and exec_res.get("imported_count") == 1
            and len(exec_res.get("imported_uids", [])) == 1
        )
        record(import_ok, "5. ImportaÃ§Ã£o de regra vÃ¡lida executada com sucesso")

        if import_ok:
            rule_uid = exec_res["imported_uids"][0]
            created_uids.append(rule_uid)

            # 6. ConferÃªncia direta no Grafana das invariantes
            g_status, g_rule = grafana_get(f"/api/v1/provisioning/alert-rules/{rule_uid}")
            record(
                g_status == 200,
                f"6. Regra realmente existe no Grafana ({rule_uid})",
            )
            if g_status == 200:
                # Invariante 1: Pasta SEMPRE global
                folder_ok = g_rule.get("folderUID") == "global"
                record(folder_ok, "7. Invariante: Regra importada SEMPRE na pasta global (baseline)")

                # Invariante 2: Contact point SEMPRE stg
                notif = g_rule.get("notification_settings") or {}
                cp_ok = notif.get("receiver") == "stg"
                record(cp_ok, "8. Invariante: Contact Point SEMPRE 'stg' (HomologaÃ§Ã£o)")

                # Invariante 3: Data source SEMPRE loki
                queries = g_rule.get("data") or []
                loki_q = next((q for q in queries if q.get("refId") == "A"), {})
                ds_ok = loki_q.get("datasourceUid") == "loki"
                record(ds_ok, "9. Invariante: Data source de consulta Ã© o Loki sistÃªmico ('loki')")

                # Invariante 4: Labels de governanÃ§a
                labels = g_rule.get("labels") or {}
                labels_ok = (
                    labels.get("scope") == "baseline"
                    and labels.get("client") == "global"
                    and labels.get("siem_tier") == "global"
                    and labels.get("source") == "dante"
                    and labels.get("technology") == "ad_windows"
                )
                record(labels_ok, "10. Invariante: Labels de governanÃ§a (baseline, global, soc) aplicadas")

        # 11. ValidaÃ§Ã£o de importaÃ§Ã£o com especificaÃ§Ã£o YAML nativa do Loki Ruler
        valid_ruler_yaml = f"""
groups:
  - name: e2e_yaml_group
    rules:
      - alert: E2E YAML Fortigate Rule {run_id}
        expr: 'sum(count_over_time({{job="wazuh", ss_groups=~".*fortigate.*"}} | json [5m])) > 0'
        for: 0s
        labels:
          severity: high
          mitre_tactic: initial_access
          mitre_technique: T1190
        annotations:
          summary: Teste de importaÃ§Ã£o de regra YAML E2E
          description: Regra importada com sucesso via arquivo/payload YAML
"""
        status, res_yaml = call("POST", "/api/rules/import/preview", {"content": valid_ruler_yaml}, csrf=True)
        is_yaml_preview_ok = (
            status == 200
            and res_yaml.get("total_rules") == 1
            and res_yaml.get("valid_count") == 1
            and res_yaml["items"][0].get("technology") == "fortigate"
            and res_yaml["items"][0].get("mitre_technique") == "T1190"
        )
        record(is_yaml_preview_ok, "11. Preview de especificaÃ§Ã£o Loki Ruler em formato YAML processado com sucesso")

        if is_yaml_preview_ok:
            valid_yaml_items = res_yaml.get("items", [])
            status, exec_yaml_res = call("POST", "/api/rules/import", {"rules": valid_yaml_items}, csrf=True)
            yaml_import_ok = (
                status == 200
                and exec_yaml_res.get("imported_count") == 1
                and len(exec_yaml_res.get("imported_uids", [])) == 1
            )
            record(yaml_import_ok, "12. ExecuÃ§Ã£o da importaÃ§Ã£o originada de arquivo YAML concluÃ­da")
            if yaml_import_ok:
                yaml_rule_uid = exec_yaml_res["imported_uids"][0]
                created_uids.append(yaml_rule_uid)
                g_st, g_yaml_rule = grafana_get(f"/api/v1/provisioning/alert-rules/{yaml_rule_uid}")
                yaml_invariants_ok = (
                    g_st == 200
                    and g_yaml_rule.get("folderUID") == "global"
                    and (g_yaml_rule.get("notification_settings") or {}).get("receiver") == "stg"
                    and (g_yaml_rule.get("labels") or {}).get("technology") == "fortigate"
                )
                record(yaml_invariants_ok, "13. Invariantes confirmadas no Grafana para regra importada via YAML")

        # 14. Preview de arquivo YAML com mÃºltiplos documentos (separados por ---)
        multi_doc_yaml = f"""
groups:
  - name: multi_doc_1
    rules:
      - alert: MultiDoc Rule 1 {run_id}
        expr: 'sum(count_over_time({{job="wazuh", ss_groups=~".*windows.*"}} | json [5m])) > 0'
        labels:
          severity: medium
          mitre_tactic: persistence
          mitre_technique: T1098
---
groups:
  - name: multi_doc_2
    rules:
      - alert: MultiDoc Rule 2 {run_id}
        expr: 'sum(count_over_time({{job="wazuh", ss_groups=~".*fortigate.*"}} | json [5m])) > 0'
        labels:
          severity: critical
          mitre_tactic: initial_access
          mitre_technique: T1190
"""
        status, res_multi_doc = call("POST", "/api/rules/import/preview", {"content": multi_doc_yaml}, csrf=True)
        multi_doc_ok = (
            status == 200
            and res_multi_doc.get("total_rules") == 2
            and res_multi_doc.get("valid_count") == 2
        )
        record(multi_doc_ok, "14. Preview de YAML multi-documento (separado por ---) processa todos os documentos")

        # 15. Preview com mÃºltiplos arquivos simultÃ¢neos (drag & drop mÃºltiplo)
        file1_content = f"""
groups:
  - name: file1_group
    rules:
      - alert: MultiFile Rule Win {run_id}
        expr: 'sum(count_over_time({{job="wazuh", ss_groups=~".*windows.*"}} | json [5m])) > 0'
        labels:
          severity: high
          mitre_tactic: privilege_escalation
          mitre_technique: T1078
"""
        file2_content = json.dumps([
            {
                "alert": f"MultiFile Rule Fortigate {run_id}",
                "expr": 'sum(count_over_time({job="wazuh", ss_groups=~".*fortigate.*"} | json [5m])) > 0',
                "labels": {
                    "severity": "critical",
                    "mitre_tactic": "initial_access",
                    "mitre_technique": "T1190"
                }
            }
        ])
        file3_bad = "invalid: yaml: syntax: [unclosed"

        multi_payload = {
            "files": [
                {"filename": "regras_windows.yaml", "content": file1_content},
                {"filename": "regras_fortigate.json", "content": file2_content},
                {"filename": "arquivo_corrompido.yaml", "content": file3_bad},
            ]
        }
        status, res_multi = call("POST", "/api/rules/import/preview", multi_payload, csrf=True)
        multi_ok = (
            status == 200
            and res_multi.get("files_count") == 3
            and res_multi.get("total_rules") == 3
            and res_multi.get("valid_count") == 2
            and res_multi.get("invalid_count") == 1
        )
        record(multi_ok, "15. Preview com mÃºltiplos arquivos simultÃ¢neos (YAML, JSON e arquivo com erro)")

        # 16. Rastreabilidade de arquivo (filename em cada item validado)
        items = res_multi.get("items", [])
        filenames_tracked = (
            len(items) == 3
            and items[0].get("filename") == "regras_windows.yaml"
            and items[0].get("valid") is True
            and items[1].get("filename") == "regras_fortigate.json"
            and items[1].get("valid") is True
            and items[2].get("filename") == "arquivo_corrompido.yaml"
            and items[2].get("valid") is False
            and "Erro de sintaxe" in items[2].get("title", "")
        )
        record(filenames_tracked, "16. Metadado de origem (filename) preservado por regra e erros isolados por arquivo")

        # 17. ImportaÃ§Ã£o executada apenas com as regras vÃ¡lidas dos mÃºltiplos arquivos
        valid_multi_items = [it for it in items if it.get("valid")]
        status, exec_multi_res = call("POST", "/api/rules/import", {"rules": valid_multi_items}, csrf=True)
        exec_multi_ok = (
            status == 200
            and exec_multi_res.get("imported_count") == 2
            and len(exec_multi_res.get("imported_uids", [])) == 2
        )
        record(exec_multi_ok, "17. ExecuÃ§Ã£o de importaÃ§Ã£o em lote das regras vÃ¡lidas provenientes de mÃºltiplos arquivos")

        if exec_multi_ok:
            for uid in exec_multi_res.get("imported_uids", []):
                created_uids.append(uid)
                g_st, g_rule = grafana_get(f"/api/v1/provisioning/alert-rules/{uid}")
                rule_ok = (
                    g_st == 200
                    and g_rule.get("folderUID") == "global"
                    and (g_rule.get("notification_settings") or {}).get("receiver") == "stg"
                )
                record(rule_ok, f"18. Invariantes de baseline confirmadas no Grafana para regra multi-arquivo ({uid})")

        # 19. Regra OK mas com tecnologia não cadastrada: tecnologia pendente (chip amarelo, sem erros)
        new_tech_slug = f"e2e_pfsense_{run_id}"
        rule_missing_tech_json = json.dumps({
            "groups": [
                {
                    "name": "pfsense_group",
                    "rules": [
                        {
                            "alert": f"E2E PfSense Rule {run_id}",
                            "expr": f'sum(count_over_time({{job="wazuh", ss_groups=~".*{new_tech_slug}.*"}} | json [5m])) > 0',
                            "for": "0s",
                            "labels": {
                                "severity": "high",
                                "mitre_tactic": "initial_access",
                                "mitre_technique": "T1190"
                            },
                            "annotations": {
                                "summary": "Regra PfSense com tecnologia ainda não cadastrada",
                            }
                        }
                    ]
                }
            ]
        })
        status, res_tech_missing = call("POST", "/api/rules/import/preview", {"content": rule_missing_tech_json}, csrf=True)
        missing_tech_ok = (
            status == 200
            and res_tech_missing.get("total_rules") == 1
            and res_tech_missing.get("valid_count") == 0
            and res_tech_missing.get("missing_tech_count") == 1
            and res_tech_missing.get("invalid_count") == 0
        )
        if missing_tech_ok:
            item_missing = res_tech_missing["items"][0]
            missing_tech_ok = (
                item_missing.get("technology_missing") is True
                and item_missing.get("valid") is False
                and len(item_missing.get("errors", [])) == 0
                and item_missing.get("suggested_technology_slug") == new_tech_slug
            )
        record(missing_tech_ok, "19. Regra OK sem tecnologia no catálogo tem technology_missing=True, chip amarelo e 0 erros")

        # 20. Criação da tecnologia pendente via POST /api/technologies
        tech_payload = {
            "slug": new_tech_slug,
            "name": f"E2E PfSense {run_id}",
            "ss_groups_regex": f".*{new_tech_slug}.*",
            "job": "wazuh",
            "description": "Tecnologia criada para suportar importação de regra",
            "confirm_without_logs": True,
        }
        st_tech, res_created_tech = call("POST", "/api/technologies", tech_payload, csrf=True)
        created_tech_ok = st_tech == 201 and res_created_tech.get("slug") == new_tech_slug
        record(created_tech_ok, "20. Criação de nova tecnologia no catálogo com sucesso")

        # 21. Revalidação após tecnologia cadastrada: regra transiciona para válida (verde)
        status, res_revalidated = call("POST", "/api/rules/import/preview", {"content": rule_missing_tech_json}, csrf=True)
        revalidated_ok = (
            status == 200
            and res_revalidated.get("total_rules") == 1
            and res_revalidated.get("valid_count") == 1
            and res_revalidated.get("missing_tech_count") == 0
            and res_revalidated["items"][0].get("valid") is True
            and res_revalidated["items"][0].get("technology") == new_tech_slug
        )
        record(revalidated_ok, "21. Revalidação após criação da tecnologia torna a regra válida (chip verde)")

        # 22. Importação especificando data source Loki interno
        rules_to_import = res_revalidated.get("items", [])
        status, exec_ds_res = call(
            "POST",
            "/api/rules/import",
            {"rules": rules_to_import, "datasource_uid": "loki"},
            csrf=True,
        )
        exec_ds_ok = (
            status == 200
            and exec_ds_res.get("imported_count") == 1
            and len(exec_ds_res.get("imported_uids", [])) == 1
        )
        record(exec_ds_ok, "22. Importação com seleção de data source Loki interno bem-sucedida")
        if exec_ds_ok:
            ds_rule_uid = exec_ds_res["imported_uids"][0]
            created_uids.append(ds_rule_uid)
            g_st, g_ds_rule = grafana_get(f"/api/v1/provisioning/alert-rules/{ds_rule_uid}")
            queries = g_ds_rule.get("data") or []
            loki_q = next((q for q in queries if q.get("refId") == "A"), {})
            ds_pointed_ok = g_st == 200 and loki_q.get("datasourceUid") == "loki"
            record(ds_pointed_ok, "23. Invariante: Regra no Grafana aponta para o datasourceUid interno informado")

        # 24. Bloqueio de importação em data source de cliente
        # Cria um tenant de teste temporário para obter seu datasource de cliente
        tenant_title = f"Tenant Client DS Test {run_id}"
        st_t, res_t = call("POST", "/api/tenants", {"title": tenant_title}, csrf=True)
        client_ds_uid = None
        created_tenant_uid = None
        if st_t == 201:
            created_tenant_uid = res_t.get("uid")
            client_ds_uid = res_t.get("datasource", {}).get("uid") or f"{created_tenant_uid}-loki"

        if client_ds_uid:
            status_blocked, res_blocked = call(
                "POST",
                "/api/rules/import",
                {"rules": rules_to_import, "datasource_uid": client_ds_uid},
                csrf=True,
            )
            blocked_ok = (
                status_blocked == 400
                and "Data sources de clientes não podem ser selecionados" in str(res_blocked)
            )
            record(blocked_ok, "24. Bloqueio estrito de importação com data source de cliente (400 Bad Request)")

            # Limpa tenant temporário
            if created_tenant_uid:
                call("DELETE", f"/api/tenants/{created_tenant_uid}", csrf=True)

        # 25. Regra com (?i) em ss_groups para tecnologia existente (fortigate)
        rule_qi_existing = json.dumps({
            "groups": [
                {
                    "name": "qi_group_existing",
                    "rules": [
                        {
                            "alert": f"E2E Regex Case Insensitive Fortigate {run_id}",
                            "expr": 'sum(count_over_time({job="wazuh", ss_groups=~"(?i).*fortigate.*"} | json [5m])) > 0',
                            "for": "0s",
                            "labels": {
                                "severity": "medium",
                                "mitre_tactic": "initial_access",
                                "mitre_technique": "T1190"
                            },
                            "annotations": {
                                "summary": "Teste de seletor com prefixo (?i) casando tecnologia existente"
                            }
                        }
                    ]
                }
            ]
        })
        status, res_qi_exist = call("POST", "/api/rules/import/preview", {"content": rule_qi_existing}, csrf=True)
        qi_exist_ok = (
            status == 200
            and res_qi_exist.get("total_rules") == 1
            and res_qi_exist.get("valid_count") == 1
            and res_qi_exist.get("items")[0].get("technology") == "fortigate"
            and res_qi_exist.get("items")[0].get("valid") is True
        )
        record(qi_exist_ok, "25. Regra com (?i) em ss_groups casa com tecnologia existente e ignora o prefixo (?i)")

        # 26. Regra com (?i) em ss_groups para tecnologia inexistente extrai apenas o nome limpo
        new_qi_slug = f"suricata_{run_id}"
        rule_qi_new = json.dumps({
            "groups": [
                {
                    "name": "qi_group_new",
                    "rules": [
                        {
                            "alert": f"E2E Regex Case Insensitive Suricata {run_id}",
                            "expr": f'sum(count_over_time({{job="wazuh", ss_groups=~"(?i).*{new_qi_slug}.*"}} | json [5m])) > 0',
                            "for": "0s",
                            "labels": {
                                "severity": "high",
                                "mitre_tactic": "execution",
                                "mitre_technique": "T1059"
                            },
                            "annotations": {
                                "summary": "Teste de seletor com prefixo (?i) sugerindo tecnologia inexistente limpa"
                            }
                        }
                    ]
                }
            ]
        })
        status, res_qi_new = call("POST", "/api/rules/import/preview", {"content": rule_qi_new}, csrf=True)
        qi_new_ok = (
            status == 200
            and res_qi_new.get("total_rules") == 1
            and res_qi_new.get("missing_tech_count") == 1
            and res_qi_new.get("items")[0].get("suggested_technology_slug") == new_qi_slug
            and "(?i)" not in (res_qi_new.get("items")[0].get("suggested_ss_groups_regex") or "")
        )
        record(qi_new_ok, "26. Regra com (?i) para tecnologia inexistente gera slug/nome limpo sem (?i)")

        # 27. Contact Point dinamicamente amarrado ao estágio 'stg' da tela de homologação
        # Altera temporariamente o estágio 'stg' para mapear no Contact Point 'dev'
        st_cp_up, _ = call(
            "PUT",
            "/api/homologation/stage-contact-points",
            {"stage_contact_points": {"stg": "dev"}},
            csrf=True,
        )
        if st_cp_up == 200:
            # Importa regra com o novo mapeamento ativo
            status_dyn, res_dyn = call("POST", "/api/rules/import", {"rules": [res_qi_exist["items"][0]]}, csrf=True)
            dyn_import_ok = status_dyn == 200 and res_dyn.get("imported_count") == 1
            if dyn_import_ok:
                dyn_uid = res_dyn["imported_uids"][0]
                created_uids.append(dyn_uid)
                g_st_dyn, g_rule_dyn = grafana_get(f"/api/v1/provisioning/alert-rules/{dyn_uid}")
                dyn_receiver_ok = (
                    g_st_dyn == 200
                    and (g_rule_dyn.get("notification_settings") or {}).get("receiver") == "dev"
                )
                record(dyn_receiver_ok, "27. Regra importada herda dinamicamente o Contact Point mapeado para 'stg'")
            else:
                record(False, "27. Falha na importação de regra com Contact Point dinâmico")
            # Restaura estágio 'stg' para 'stg'
            call(
                "PUT",
                "/api/homologation/stage-contact-points",
                {"stage_contact_points": {"stg": "stg"}},
                csrf=True,
            )
        else:
            record(False, "27. Falha ao configurar mapeamento de estágio de homologação")

        # 28. Listagem de grupos de avaliação (Evaluation Groups) via GET /api/rules/evaluation-groups
        status_eg, res_eg = call("GET", "/api/rules/evaluation-groups")
        eg_list_ok = (
            status_eg == 200
            and isinstance(res_eg, list)
            and len(res_eg) > 0
            and "global-detections" in res_eg
        )
        record(eg_list_ok, "28. GET /api/rules/evaluation-groups lista grupos com 'global-detections'")

        # 29. Importação de regra especificando evaluation_group personalizado
        custom_eval_group = f"eval-group-{run_id}"
        status_eval, res_eval = call(
            "POST",
            "/api/rules/import",
            {
                "rules": [res_qi_exist["items"][0]],
                "evaluation_group": custom_eval_group,
            },
            csrf=True,
        )
        eval_import_ok = status_eval == 200 and res_eval.get("imported_count") == 1
        record(eval_import_ok, "29. Importação especificando evaluation_group personalizado aceita com sucesso")
        if eval_import_ok:
            custom_rule_uid = res_eval["imported_uids"][0]
            created_uids.append(custom_rule_uid)
            g_st_custom, g_rule_custom = grafana_get(f"/api/v1/provisioning/alert-rules/{custom_rule_uid}")
            custom_group_ok = (
                g_st_custom == 200
                and g_rule_custom.get("ruleGroup") == custom_eval_group
            )
            record(custom_group_ok, f"30. Regra importada no Grafana possui ruleGroup='{custom_eval_group}'")

        # 31. Validação de Análise, Curadoria e Parecer Técnico por IA no Preview
        curation_rule_json = json.dumps({
            "groups": [
                {
                    "name": "e2e_curation_group",
                    "rules": [
                        {
                            "alert": f"E2E AI Curation Rule {run_id}",
                            "expr": 'sum(count_over_time({job="wazuh", ss_groups=~".*windows.*"} | json | win_system_eventID=~"4728" | win_eventdata_targetUserName!="" [5m])) > 0',
                            "for": "0s",
                            "labels": {
                                "severity": "high",
                                "mitre_tactic": "persistence",
                                "mitre_technique": "T1098"
                            },
                            "annotations": {
                                "summary": "Teste de Curadoria com Parecer Técnico por IA E2E",
                                "description": "Valida parecer de IA e compatibilidade de campos na importação"
                            }
                        }
                    ]
                }
            ]
        })
        status_cur, res_cur = call("POST", "/api/rules/import/preview", {"content": curation_rule_json}, csrf=True)
        cur_preview_ok = status_cur == 200 and res_cur.get("total_rules") == 1 and res_cur.get("valid_count") == 1
        if cur_preview_ok:
            cur_item = res_cur["items"][0]
            has_curation = (
                cur_item.get("classification") in ["excellent", "good", "neutral", "bad"]
                and isinstance(cur_item.get("field_compatibility_pct"), (int, float))
                and cur_item.get("field_compatibility_pct") > 0
                and isinstance(cur_item.get("mapped_fields"), list)
                and len(cur_item.get("mapped_fields")) > 0
                and bool(cur_item.get("ai_rationale"))
                and isinstance(cur_item.get("qualification_factors"), list)
                and res_cur.get("qualified_count", 0) >= 0
            )
            record(
                has_curation,
                "31. Preview de importação enriquece regra com curadoria, compatibilidade de campos e Parecer Técnico por IA",
            )
        else:
            record(False, "31. Falha no preview de regra para validação de curadoria IA")

        # 32. Validação da persistência de metadados de curadoria/IA ao importar regra no Grafana
        if cur_preview_ok:
            status_import_cur, exec_cur_res = call("POST", "/api/rules/import", {"rules": [cur_item]}, csrf=True)
            import_cur_ok = status_import_cur == 200 and exec_cur_res.get("imported_count") == 1
            record(import_cur_ok, "32. Importação de regra curada com parecer de IA executada com sucesso")
            if import_cur_ok:
                cur_uid = exec_cur_res["imported_uids"][0]
                created_uids.append(cur_uid)
                g_st_cur, g_cur_rule = grafana_get(f"/api/v1/provisioning/alert-rules/{cur_uid}")
                annot = g_cur_rule.get("annotations") or {}
                labels = g_cur_rule.get("labels") or {}
                cur_persisted_ok = (
                    g_st_cur == 200
                    and "ai_rationale" in annot
                    and "field_compatibility_pct" in annot
                    and "field_compatibility" in labels
                )
                record(
                    cur_persisted_ok,
                    "33. Regra gravada no Grafana preserva parecer técnico da IA e percentual de compatibilidade",
                )

    finally:
        # Teardown de limpeza
        print("Executando limpeza (teardown)...")
        for uid in created_uids:
            st, _ = grafana_delete(f"/api/v1/provisioning/alert-rules/{uid}")
            print(f"Limpeza de regra {uid}: status {st}")

        # Limpeza da tecnologia criada no teste
        if "new_tech_slug" in locals():
            st_del, _ = call("DELETE", f"/api/technologies/{new_tech_slug}", csrf=True)
            print(f"Limpeza de tecnologia {new_tech_slug}: status {st_del}")

    failed = [desc for ok, desc in results if not ok]
    if failed:
        print(f"\nFALHA: {len(failed)} testes falharam:")
        for f in failed:
            print(f"  - {f}")
        return 1

    print(f"\nSUCESSO: Todos os {len(results)} testes passaram com perfeiÃ§Ã£o!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
