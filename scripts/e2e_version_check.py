#!/usr/bin/env python3
"""Teste E2E de checagem de versão e endpoints de release do D.A.N.T.E.

Testa:
1. Comparação de versão semântica e parsing de tags;
2. Autenticação e consulta a /api/config (verificando app_version);
3. Endpoint autenticado GET /api/system/version;
4. Endpoint autenticado POST /api/system/version/check (com cabeçalho anti-CSRF).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
import http.cookiejar

BASE_URL = os.environ.get("PORTAL_URL", "http://localhost:8080")
CSRF_HEADER = "hunter-portal"


def parse_semver(version_str: str) -> tuple[int, int, int]:
    clean = version_str.strip().lstrip("vV")
    parts = clean.split(".")
    major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
    minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
    return (major, minor, patch)


def is_newer_version(current_ver: str, candidate_ver: str) -> bool:
    return parse_semver(candidate_ver) > parse_semver(current_ver)


def test_semver_logic() -> None:
    print("[1/4] Testando logica de Semantic Versioning...")
    assert parse_semver("v0.1.0") == (0, 1, 0)
    assert parse_semver("1.2.3") == (1, 2, 3)
    assert parse_semver("v2.0.0-rc1") == (2, 0, 0)
    assert is_newer_version("0.1.0", "v0.2.0") is True
    assert is_newer_version("1.0.0", "v0.9.9") is False
    assert is_newer_version("0.1.0", "0.1.0") is False
    assert is_newer_version("0.1.0", "v1.0.0") is True
    print("  -> Logica de semver OK!")


def run_api_tests() -> None:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def api_call(path: str, method: str = "GET", data: dict | None = None, csrf: bool = False):
        url = f"{BASE_URL}{path}"
        body_bytes = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(url, data=body_bytes, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if csrf:
            req.add_header("X-Requested-With", CSRF_HEADER)
        with opener.open(req, timeout=15) as resp:
            content = resp.read()
            return resp.status, json.loads(content.decode("utf-8")) if content else None

    # Ler credenciais do ambiente ou .env
    user = os.environ.get("PORTAL_ADMIN_USER")
    pwd = os.environ.get("PORTAL_ADMIN_PASSWORD")

    if not user or not pwd:
        # Tenta carregar do .env local
        env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("PORTAL_ADMIN_USER="):
                        user = line.split("=", 1)[1].strip()
                    elif line.startswith("PORTAL_ADMIN_PASSWORD="):
                        pwd = line.split("=", 1)[1].strip()

    if not user or not pwd:
        print("  [WARN] PORTAL_ADMIN_USER ou PORTAL_ADMIN_PASSWORD nao configurados. Pulando testes autenticados.")
        return

    print("[2/4] Realizando login na API...")
    status, login_res = api_call("/api/auth/login", method="POST", data={"username": user, "password": pwd}, csrf=True)
    assert status == 200, f"Falha no login: HTTP {status}"
    print(f"  -> Login efetuado com sucesso como '{login_res.get('username')}'")

    print("[3/4] Testando GET /api/config...")
    status, config_res = api_call("/api/config")
    assert status == 200, f"Falha no config: HTTP {status}"
    assert "app_version" in config_res, "Campo 'app_version' ausente em /api/config"
    print(f"  -> Config OK! app_version='{config_res['app_version']}'")

    print("[4/4] Testando endpoints de versao (/api/system/version)...")
    status, ver_res = api_call("/api/system/version")
    assert status == 200, f"Falha no GET version: HTTP {status}"
    assert "current_version" in ver_res, "Campo 'current_version' ausente"
    assert "update_available" in ver_res, "Campo 'update_available' ausente"
    print(f"  -> GET /api/system/version OK: versao={ver_res['current_version']}, update_available={ver_res['update_available']}")

    status, check_res = api_call("/api/system/version/check", method="POST", csrf=True)
    assert status == 200, f"Falha no POST version/check: HTTP {status}"
    assert "current_version" in check_res
    print(f"  -> POST /api/system/version/check OK: checado com sucesso")


def main() -> int:
    try:
        test_semver_logic()
        run_api_tests()
        print("\nTodos os testes de versao e release passaram com sucesso!")
        return 0
    except Exception as exc:
        print(f"\n[ERRO NO TESTE]: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

