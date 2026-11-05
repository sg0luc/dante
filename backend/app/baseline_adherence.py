"""Mapa de Adesao ao Baseline: conformidade dos clientes as regras da pasta baseline.

Modulo puro (sem I/O). Reaproveita as mesmas definicoes de ``technology_insights``:

* cliente = pasta do Grafana que nao e a baseline e **nao esta Oculta**;
* aplicabilidade = footprint do cliente (regra derivada ou tecnologia declarada);
* regra implementada = clone rastreado por ``cloned_from`` (ou titulo-base).

Cliente sem a tecnologia vira ``not_applicable`` e sai do denominador.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .schemas import (
    AdherenceBucket,
    AdherenceClient,
    AdherenceClientCell,
    AdherenceClientTechnology,
    AdherenceMetrics,
    AdherenceRule,
    AdherenceTechnology,
    BaselineAdherenceResponse,
)
from .technologies import Technology
from .technology_insights import (
    _compliance_status,
    _pct,
    client_footprint,
    find_implemented_rule,
    is_client_folder,
    resolve_rule_technology,
    rule_query,
    strip_scope_prefix,
)

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _is_baseline_rule(rule: dict[str, Any], baseline_uid: str) -> bool:
    folder = str(rule.get("folderUID") or "").strip().lower()
    return folder == baseline_uid or folder == "global"


def build_adherence(
    technologies: list[Technology],
    rules: list[dict[str, Any]],
    folders: list[dict[str, Any]],
    declared: dict[str, list[str]] | None = None,
    baseline_folder_uid: str = "global",
    hidden_uids: set[str] | None = None,
) -> BaselineAdherenceResponse:
    b_uid = (baseline_folder_uid or "global").strip().lower()
    declared = declared or {}
    hidden_uids = hidden_uids or set()

    clients = [f for f in folders if is_client_folder(f, baseline_folder_uid=b_uid, include_hidden=True)]
    hidden_total = sum(1 for f in clients if str(f.get("uid") or "") in hidden_uids)
    clients = [f for f in clients if str(f.get("uid") or "") not in hidden_uids]
    client_by_uid = {str(f.get("uid") or ""): str(f.get("title") or "") for f in clients}

    baseline_title = baseline_folder_uid
    for f in folders:
        if str(f.get("uid") or "").strip().lower() == b_uid:
            baseline_title = str(f.get("title") or baseline_folder_uid)
            break

    baseline_rules = [r for r in rules if _is_baseline_rule(r, b_uid)]
    rules_by_client: dict[str, list[dict[str, Any]]] = {uid: [] for uid in client_by_uid}
    for rule in rules:
        uid = str(rule.get("folderUID") or "")
        if uid in rules_by_client:
            rules_by_client[uid].append(rule)

    footprints = {
        uid: client_footprint(rules_by_client[uid], technologies, declared.get(uid, []))
        for uid in client_by_uid
    }

    out_rules: list[AdherenceRule] = []
    rule_uids_by_tech: dict[str, list[str]] = {t.slug: [] for t in technologies}
    unmapped = 0
    sev_counter: dict[str, int] = {}

    # cliente -> slug -> [implemented, total]
    per_client_tech: dict[str, dict[str, list[int]]] = {uid: {} for uid in client_by_uid}
    # tecnologia -> [implemented_slots, total_slots]
    tech_slots: dict[str, list[int]] = {t.slug: [0, 0] for t in technologies}

    for rule in sorted(baseline_rules, key=lambda r: str(r.get("title") or "").lower()):
        tech = resolve_rule_technology(rule, technologies)
        labels = dict(rule.get("labels") or {})
        title = str(rule.get("title") or "")
        severity = str(labels.get("severity") or "").strip().lower()
        sev_counter[severity or "info"] = sev_counter.get(severity or "info", 0) + 1
        counted = tech is not None
        if tech is None:
            unmapped += 1
        else:
            rule_uids_by_tech[tech.slug].append(str(rule.get("uid") or ""))

        cells: list[AdherenceClientCell] = []
        active = paused = applicable_n = 0
        for uid, name in client_by_uid.items():
            applicable = True if tech is None else tech.slug in footprints[uid]
            replica = find_implemented_rule(rule, rules_by_client[uid]) if applicable else None
            if not applicable:
                cells.append(AdherenceClientCell(client_uid=uid, client_name=name, applicable=False, status="not_applicable"))
                continue
            applicable_n += 1
            if replica is None:
                status = "not_implemented"
            elif replica.get("isPaused"):
                status = "paused"
                paused += 1
            else:
                status = "active"
                active += 1
            cells.append(
                AdherenceClientCell(
                    client_uid=uid,
                    client_name=name,
                    applicable=True,
                    status=status,  # type: ignore[arg-type]
                    rule_uid=str(replica.get("uid") or "") if replica else None,
                    rule_title=str(replica.get("title") or "") if replica else None,
                )
            )
            if tech is not None:
                acc = per_client_tech[uid].setdefault(tech.slug, [0, 0])
                acc[1] += 1
                tech_slots[tech.slug][1] += 1
                if replica is not None:
                    acc[0] += 1
                    tech_slots[tech.slug][0] += 1

        implemented = active + paused
        out_rules.append(
            AdherenceRule(
                uid=str(rule.get("uid") or ""),
                title=title,
                base_title=strip_scope_prefix(title) or title,
                technology_slug=tech.slug if tech else None,
                technology_name=tech.name if tech else None,
                severity=severity,
                mitre_tactic=str(labels.get("mitre_tactic") or ""),
                rule_group=str(rule.get("ruleGroup") or ""),
                is_paused=bool(rule.get("isPaused")),
                logql=rule_query(rule),
                counted=counted,
                applicable_clients=applicable_n,
                implemented_clients=implemented,
                active_clients=active,
                paused_clients=paused,
                missing_clients=applicable_n - implemented,
                compliance_pct=_pct(implemented, applicable_n),
                clients=cells,
            )
        )

    # --- clientes ---
    out_clients: list[AdherenceClient] = []
    for uid, name in client_by_uid.items():
        techs: list[AdherenceClientTechnology] = []
        impl_total = slots_total = 0
        for tech in sorted(technologies, key=lambda t: t.name.lower()):
            baseline_n = len(rule_uids_by_tech[tech.slug])
            if baseline_n == 0:
                continue
            applicable = tech.slug in footprints[uid]
            impl, tot = per_client_tech[uid].get(tech.slug, [0, 0]) if applicable else (0, 0)
            techs.append(
                AdherenceClientTechnology(
                    slug=tech.slug,
                    name=tech.name,
                    applicable=applicable,
                    implemented=impl,
                    total=tot,
                    missing=tot - impl,
                    compliance_pct=_pct(impl, tot) if applicable else 0.0,
                    status=_compliance_status(impl, tot) if applicable else "not_applicable",
                )
            )
            impl_total += impl
            slots_total += tot
        out_clients.append(
            AdherenceClient(
                client_uid=uid,
                client_name=name,
                applicable_slots=slots_total,
                implemented_slots=impl_total,
                missing_slots=slots_total - impl_total,
                compliance_pct=_pct(impl_total, slots_total),
                status=_compliance_status(impl_total, slots_total) if slots_total else "not_applicable",
                technologies=techs,
            )
        )
    out_clients.sort(key=lambda c: (c.status == "not_applicable", c.compliance_pct, c.client_name.lower()))

    # --- tecnologias ---
    out_techs: list[AdherenceTechnology] = []
    for tech in technologies:
        uids = rule_uids_by_tech[tech.slug]
        if not uids:
            continue
        impl, tot = tech_slots[tech.slug]
        applicable_clients = [c for c in clients if tech.slug in footprints[str(c.get("uid") or "")]]
        full = sum(
            1
            for c in applicable_clients
            if per_client_tech[str(c.get("uid") or "")].get(tech.slug, [0, 0])[0]
            >= per_client_tech[str(c.get("uid") or "")].get(tech.slug, [0, 0])[1]
            > 0
        )
        out_techs.append(
            AdherenceTechnology(
                slug=tech.slug,
                name=tech.name,
                icon=tech.icon,
                baseline_rules_count=len(uids),
                applicable_clients_count=len(applicable_clients),
                fully_compliant_clients=full,
                implemented_slots=impl,
                total_slots=tot,
                missing_slots=tot - impl,
                compliance_pct=_pct(impl, tot),
                rule_uids=uids,
            )
        )
    out_techs.sort(key=lambda t: t.name.lower())

    applicable_slots = sum(c.applicable_slots for c in out_clients)
    implemented_slots = sum(c.implemented_slots for c in out_clients)
    not_applicable_slots = sum(
        len(rule_uids_by_tech[t.slug]) * (len(client_by_uid) - sum(1 for u in client_by_uid if t.slug in footprints[u]))
        for t in technologies
    )

    distribution = [
        AdherenceBucket(label="100%", count=sum(1 for c in out_clients if c.status == "complete")),
        AdherenceBucket(label="50-99%", count=sum(1 for c in out_clients if c.status == "partial" and c.compliance_pct >= 50)),
        AdherenceBucket(label="1-49%", count=sum(1 for c in out_clients if c.status == "partial" and c.compliance_pct < 50)),
        AdherenceBucket(label="0%", count=sum(1 for c in out_clients if c.status == "none")),
        AdherenceBucket(label="N/A", count=sum(1 for c in out_clients if c.status == "not_applicable")),
    ]
    sev_rows = [
        AdherenceBucket(label=s, count=sev_counter[s]) for s in _SEVERITY_ORDER if s in sev_counter
    ] + [
        AdherenceBucket(label=s, count=n) for s, n in sev_counter.items() if s not in _SEVERITY_ORDER
    ]

    metrics = AdherenceMetrics(
        clients_total=len(client_by_uid),
        hidden_clients_total=hidden_total,
        technologies_total=len(out_techs),
        baseline_rules_total=len(baseline_rules),
        baseline_rules_unmapped=unmapped,
        applicable_slots=applicable_slots,
        implemented_slots=implemented_slots,
        missing_slots=applicable_slots - implemented_slots,
        not_applicable_slots=not_applicable_slots,
        compliance_pct=_pct(implemented_slots, applicable_slots),
        clients_complete=sum(1 for c in out_clients if c.status == "complete"),
        clients_partial=sum(1 for c in out_clients if c.status == "partial"),
        clients_none=sum(1 for c in out_clients if c.status == "none"),
        clients_not_applicable=sum(1 for c in out_clients if c.status == "not_applicable"),
    )
    return BaselineAdherenceResponse(
        generated_at=datetime.now(timezone.utc).isoformat(),
        baseline_folder_uid=baseline_folder_uid,
        baseline_folder_title=baseline_title,
        metrics=metrics,
        distribution=distribution,
        severity_breakdown=sev_rows,
        technologies=out_techs,
        clients=out_clients,
        rules=out_rules,
    )
