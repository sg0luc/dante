#!/usr/bin/env python3
"""Upsert de regras de alerta do Grafana a partir de arquivos JSON (seed ou bundle).

Uso (da raiz do repo dante-portal, com o stack no ar):
    python scripts/upsert_baseline_rules.py grafana/bootstrap/seed/rules/1*.json
    python scripts/upsert_baseline_rules.py --group global-detections --verify <arquivo...>

- Lê GRAFANA_ADMIN_USER/GRAFANA_ADMIN_PASSWORD do ambiente ou do .env.
- Envia X-Disable-Provenance: true (regra continua editável no portal).
- POST quando o uid não existe, PUT quando existe (idempotente, não duplica).
- --verify lê o ruler e imprime o estado de cada regra do grupo (firing/health/lastError).
"""
from __future__ import annotations

import base64
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

GRAFANA = os.environ.get("GRAFANA_URL", "http://localhost:3000")


def env(name: str) -> str:
    if os.environ.get(name):
        return os.environ[name]
    with open(".env", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("defina %s no ambiente ou no .env" % name)


AUTH = base64.b64encode(
    ("%s:%s" % (env("GRAFANA_ADMIN_USER"), env("GRAFANA_ADMIN_PASSWORD"))).encode()
).decode()


def api(method: str, path: str):
    req = urllib.request.Request(
        GRAFANA + path,
        headers={
            "Authorization": "Basic " + AUTH,
            "Content-Type": "application/json",
            "X-Disable-Provenance": "true",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return res.status, json.loads(res.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:400]


def upsert(path: str) -> int:
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    uid = payload["uid"]
    status, _ = api("GET", "/api/v1/provisioning/alert-rules/%s" % uid)
    method = "PUT" if status == 200 else "POST"
    target = (
        "/api/v1/provisioning/alert-rules/%s" % uid
        if method == "PUT"
        else "/api/v1/provisioning/alert-rules"
    )
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        GRAFANA + target,
        data=data,
        headers={
            "Authorization": "Basic " + AUTH,
            "Content-Type": "application/json",
            "X-Disable-Provenance": "true",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            print("%-3s %-32s %s" % (method, uid, res.status))
            return 0
    except urllib.error.HTTPError as exc:
        print("%-3s %-32s ERRO %s %s" % (method, uid, exc.code, exc.read().decode()[:300]))
        return 1


def verify(group: str, wait_seconds: int) -> int:
    if wait_seconds:
        time.sleep(wait_seconds)  # um ciclo do ruler (interval do grupo = 60s)
    status, body = api("GET", "/api/prometheus/grafana/api/v1/rules")
    if status != 200:
        print("falha ao ler o ruler:", status, body)
        return 1
    rows = [
        (r.get("name"), r.get("state"), r.get("health"), (r.get("lastError") or "")[:80])
        for g in body.get("data", {}).get("groups", [])
        if g.get("name") == group
        for r in g.get("rules", [])
    ]
    for name, state, health, err in rows:
        print("%-9s health=%-4s %s%s" % (state, health, name, (" | " + err) if err else ""))
    firing = sum(1 for _n, s, _h, _e in rows if s == "firing")
    print("firing: %d/%d" % (firing, len(rows)))
    return 0


def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    files: list[str] = []
    for pattern in args:
        files.extend(sorted(glob.glob(pattern)) or [pattern])
    if not files:
        print(__doc__)
        return 2
    do_verify = "--verify" in argv
    group = "global-detections"
    if "--group" in argv:
        group = argv[argv.index("--group") + 1]
    rc = 0
    for path in files:
        rc |= upsert(path)
    if do_verify:
        rc |= verify(group, wait_seconds=80)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
