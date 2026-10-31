"""Script para geração de sequência cronológica de alertas fictícios no D.A.N.T.E.

Uso:
    python scripts/generate_synthetic_alerts.py [--rule-uid UID] [--count N] [--clear]

Comprova o funcionamento dos buckets temporais no histograma da Visão Geral
(janelas de 1h, 6h, 12h, 24h, 3d e 7d).
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASE = os.getenv("PORTAL_BASE_URL", "http://localhost:8080")
CSRF = {"X-Requested-With": "hunter-portal"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {
        "PORTAL_ADMIN_USER": os.getenv("PORTAL_ADMIN_USER", "admin"),
        "PORTAL_ADMIN_PASSWORD": os.getenv("PORTAL_ADMIN_PASSWORD", ""),
    }
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


def call(method: str, path: str, body=None, *, csrf: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
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


def login() -> bool:
    user = ENV.get("PORTAL_ADMIN_USER", "admin")
    password = ENV.get("PORTAL_ADMIN_PASSWORD", "")
    status, body = call(
        "POST",
        "/api/auth/login",
        {"username": user, "password": password},
        csrf=True,
    )
    if status == 200:
        print(f"[OK] Login realizado com sucesso como '{user}'.")
        return True
    print(f"[ERRO] Falha no login ({status}): {body}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Gera sequência cronológica de alertas fictícios")
    parser.add_argument("--rule-uid", type=str, default=None, help="UID da regra base (opcional)")
    parser.add_argument("--count", type=int, default=15, help="Quantidade de alertas a gerar (padrão: 15)")
    parser.add_argument("--clear", action="store_true", help="Limpa alertas fictícios em vez de gerar")
    args = parser.parse_args()

    if not login():
        sys.exit(1)

    if args.clear:
        status, body = call("DELETE", "/api/alerts/synthetic", csrf=True)
        print(f"Limpeza de alertas sintéticos: status={status}, resposta={body}")
        return

    print(f"\nGerando sequência de {args.count} alertas fictícios...")
    payload = {"count": args.count}
    if args.rule_uid:
        payload["rule_uid"] = args.rule_uid

    status, generated = call("POST", "/api/alerts/synthetic/generate", payload, csrf=True)
    if status != 200:
        print(f"[ERRO] Falha ao gerar alertas ({status}): {generated}")
        sys.exit(1)

    print(f"[OK] {len(generated)} alertas fictícios gerados!")

    # Busca lista consolidada de alertas para demonstrar a distribuição temporal
    status, all_alerts = call("GET", "/api/alerts")
    if status != 200:
        print(f"[ERRO] Falha ao consultar /api/alerts ({status})")
        sys.exit(1)

    now = datetime.now(timezone.utc)
    now_ms = now.timestamp() * 1000

    print("\n--- DISTRIBUIÇÃO CRONOLÓGICA GERADA ---")
    print(f"{'#':<3} {'StartsAt (UTC)':<22} {'Idade':<14} {'Estado':<10} {'Host / Ativo':<20} {'Janelas Alcançadas'}")
    print("-" * 95)

    window_counts = {
        "1h": 0,
        "6h": 0,
        "12h": 0,
        "24h": 0,
        "3d": 0,
        "7d": 0,
    }

    windows_ms = {
        "1h": 1 * 3600 * 1000,
        "6h": 6 * 3600 * 1000,
        "12h": 12 * 3600 * 1000,
        "24h": 24 * 3600 * 1000,
        "3d": 3 * 24 * 3600 * 1000,
        "7d": 7 * 24 * 3600 * 1000,
    }

    for i, alert in enumerate(all_alerts):
        starts_at = alert.get("starts_at") or ""
        state = alert.get("state") or ""
        labels = alert.get("labels") or {}
        host = labels.get("host") or labels.get("client") or "-"

        if starts_at:
            dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
            age_s = int((now - dt).total_seconds())
            if age_s < 3600:
                age_str = f"{age_s // 60}m atrás"
            elif age_s < 86400:
                age_str = f"{age_s // 3600}h {(age_s % 3600) // 60}m atrás"
            else:
                age_str = f"{age_s // 86400}d {(age_s % 86400) // 3600}h atrás"

            alert_ms = dt.timestamp() * 1000
            diff_ms = now_ms - alert_ms

            matched_windows = []
            for win_name, win_span in windows_ms.items():
                if diff_ms <= win_span:
                    matched_windows.append(win_name)
                    window_counts[win_name] += 1

            windows_str = ", ".join(matched_windows) if matched_windows else "(> 7d)"
        else:
            age_str = "-"
            windows_str = "-"

        print(f"{i+1:<3} {starts_at:<22} {age_str:<14} {state:<10} {host:<20} {windows_str}")

    print("\n--- VOLUMETRIA POR JANELA TEMPORAL ---")
    for win, count in window_counts.items():
        print(f"  • Janela {win:<4}: {count} alertas ativos no período")
    print("\nHistograma temporal pronto para validação visual na tela Visão Geral.")


if __name__ == "__main__":
    main()

