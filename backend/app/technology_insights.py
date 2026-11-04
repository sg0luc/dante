"""Insights do catálogo de tecnologias: distribuição e conformidade de baseline.

Modelo de negócio (SIEM da D.A.N.T.E.):

    * ``grafana_folder`` -> cliente/tenant (a pasta ``global`` é o baseline).
    * ``ss_groups``      -> tecnologia/data source (espelho de ``rule.groups``).
    * ``job``            -> pipeline de ingestão, sempre ``wazuh``.

Duas leituras derivam deste módulo:

1. **Distribuição de tecnologias por cliente** — quantos clientes consomem cada
   tecnologia, medido pelas regras de detecção já implementadas nas pastas dos
   clientes (labels ``technology``/``technology_name``). O Loki não carrega a
   label de tenant nesta arquitetura, então a evidência de integração por
   cliente é justamente a regra implementada na pasta daquele cliente.

2. **Mapa de conformidade ao baseline** — para cada tecnologia, quais regras da
   pasta ``global`` já foram replicadas em cada cliente. O vínculo é
   ``annotations.cloned_from`` (rastreabilidade gravada na replicação) com
   fallback para o título-base (sem o prefixo ``[Global]``/``[Cliente]``), que é
   o mesmo critério usado pela matriz global existente.

Este módulo é puro (sem I/O): recebe as regras/pastas já obtidas do Grafana e o
catálogo de tecnologias, e devolve as estruturas tipadas da API.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .schemas import (
    TechnologyClientCompliance,
    TechnologyComplianceStatus,
    TechnologyFootprintSource,
    TechnologyOverviewItem,
    TechnologyOverviewMetrics,
    TechnologyOverviewResponse,
)
from .technologies import Technology

# Prefixo de escopo do título de regra: "[Global] ", "[Cliente X] "...
_TITLE_SCOPE_RE = re.compile(r"^\[.*?\]\s*")


def normalize_rule_title(title: str) -> str:
    """Remove o prefixo de escopo e normaliza o título para comparação."""
    return _TITLE_SCOPE_RE.sub("", str(title or "")).strip().lower()


def strip_scope_prefix(title: str) -> str:
    """Remove o prefixo de escopo preservando a caixa original do título."""
    return _TITLE_SCOPE_RE.sub("", str(title or "")).strip()


def rule_query(rule: dict[str, Any]) -> str:
    """Query LogQL efetiva da regra (annotations ou modelo de query)."""
    annotations = rule.get("annotations") or {}
    query = annotations.get("logql_query")
    if isinstance(query, str) and query.strip():
        return query.strip()
    for entry in rule.get("data") or []:
        expr = (entry.get("model") or {}).get("expr")
        if isinstance(expr, str) and ("rule_groups" in expr or "ss_groups" in expr):
            return expr.strip()
    return ""


def rule_cloned_from(rule: dict[str, Any]) -> str:
    """UID da regra global de origem (quando a regra é uma replicação)."""
    annotations = rule.get("annotations") or {}
    return str(annotations.get("cloned_from") or "").strip()


def resolve_rule_technology(
    rule: dict[str, Any], technologies: Iterable[Technology]
) -> Technology | None:
    """Resolve a tecnologia de uma regra.

    Ordem de precedência:
      1. label ``technology`` (gravada pelo portal na criação/replicação), aceita
         como slug ou como nome exibido (rótulos legados gravavam "AD/Windows");
      2. recorte de ``ss_groups`` da query, quando resolve para exatamente uma
         tecnologia do catálogo (cobre regras antigas/semeadas sem a label).

    Uma label fora do catálogo NÃO encerra a resolução: sem o fallback, uma regra
    antiga com ``technology: "AD/Windows"`` ficava sempre "sem tecnologia mapeada"
    e sumia do baseline. Regras ambíguas (duas tecnologias possíveis) continuam
    retornando ``None`` para não contabilizar conformidade no balde errado.
    """
    catalog = list(technologies)
    slug = str((rule.get("labels") or {}).get("technology") or "").strip().lower()
    if slug:
        for tech in catalog:
            if tech.slug == slug:
                return tech
        for tech in catalog:
            if tech.name.strip().lower() == slug:
                return tech

    query = rule_query(rule)
    if not query:
        return None
    from .technologies import (  # import tardio: evita ciclo em tempo de módulo
        extract_rule_groups_values,
        extract_ss_groups_values,
        selector_matches_technology,
    )

    values = [value for _op, value in extract_rule_groups_values(query)]
    if not values:
        return None
    matched = [
        tech
        for tech in catalog
        if any(selector_matches_technology(value, tech) for value in values)
    ]
    return matched[0] if len(matched) == 1 else None


def is_client_folder(folder: dict[str, Any], baseline_folder_uid: str = "global") -> bool:
    """Indica se a pasta representa um cliente (tudo menos a pasta arbitrada como baseline)."""
    uid = str(folder.get("uid") or "").strip().lower()
    title = str(folder.get("title") or "").strip().lower()
    b_uid = (baseline_folder_uid or "global").strip().lower()
    return uid != b_uid and uid != "global" and title != b_uid and title != "global"


def client_footprint(
    client_rules: list[dict[str, Any]],
    technologies: Iterable[Technology],
    declared: Iterable[str] = (),
) -> dict[str, TechnologyFootprintSource]:
    """Tecnologias que um cliente possui no SIEM, com a origem da evidência.

    União de ``derived`` (regra de detecção já existente na pasta do cliente) com
    ``declared`` (inventário informado pelo operador). O valor devolvido é a
    origem: ``derived``, ``declared`` ou ``both``.
    """
    catalog = {tech.slug: tech for tech in technologies}
    derived = {
        tech.slug
        for tech in (resolve_rule_technology(rule, catalog.values()) for rule in client_rules)
        if tech is not None
    }
    declared_set = {
        str(slug).strip().lower() for slug in declared if str(slug or "").strip()
    } & set(catalog)

    footprint: dict[str, TechnologyFootprintSource] = {}
    for slug in derived | declared_set:
        if slug in derived and slug in declared_set:
            footprint[slug] = "both"
        elif slug in derived:
            footprint[slug] = "derived"
        else:
            footprint[slug] = "declared"
    return footprint


def client_has_technology(
    client_rules: list[dict[str, Any]],
    technology: Technology,
    declared: Iterable[str] = (),
) -> bool:
    """True quando a tecnologia faz parte do footprint do cliente."""
    return technology.slug in client_footprint(client_rules, [technology], declared)


def _pct(part: int, total: int) -> float:
    """Percentual com uma casa decimal e proteção contra divisão por zero."""
    if total <= 0:
        return 0.0
    return round(part * 100.0 / total, 1)


def _compliance_status(implemented: int, total: int) -> TechnologyComplianceStatus:
    if total > 0 and implemented >= total:
        return "complete"
    if implemented > 0:
        return "partial"
    return "none"


def find_implemented_rule(
    baseline_rule: dict[str, Any], client_rules: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Localiza, na pasta do cliente, a replicação de uma regra de baseline."""
    baseline_uid = str(baseline_rule.get("uid") or "")
    base_title = normalize_rule_title(str(baseline_rule.get("title") or ""))

    for candidate in client_rules:
        if baseline_uid and rule_cloned_from(candidate) == baseline_uid:
            return candidate

    for candidate in client_rules:
        candidate_title = normalize_rule_title(str(candidate.get("title") or ""))
        if base_title and candidate_title == base_title:
            return candidate
    return None


def build_overview(
    technologies: list[Technology],
    rules: list[dict[str, Any]],
    folders: list[dict[str, Any]],
    declared: dict[str, list[str]] | None = None,
    baseline_folder_uid: str = "global",
) -> TechnologyOverviewResponse:
    """Consolida métricas, distribuição por cliente e conformidade de baseline.

    Conformidade é calculada apenas sobre o **footprint** de cada cliente: as
    regras do baseline ``global`` de uma tecnologia só entram no denominador dos
    clientes que possuem aquela tecnologia no SIEM (evidência derivada das regras
    da pasta ou inventário declarado). Cliente sem a tecnologia recebe
    ``not_applicable`` e a célula é excluída do percentual — não ter Office365
    integrado não pode reprovar o cliente no baseline de Office365.
    """
    b_uid = (baseline_folder_uid or "global").strip().lower()
    declared = declared or {}
    clients = [folder for folder in folders if is_client_folder(folder, baseline_folder_uid=b_uid)]
    client_by_uid = {
        str(folder.get("uid") or ""): str(folder.get("title") or "") for folder in clients
    }

    global_rules = [
        rule
        for rule in rules
        if str(rule.get("folderUID") or "").strip().lower() == b_uid
        or str(rule.get("folderUID") or "").strip().lower() == "global"
    ]
    client_rules = [
        rule
        for rule in rules
        if str(rule.get("folderUID") or "").strip().lower() != b_uid
        and str(rule.get("folderUID") or "").strip().lower() != "global"
    ]

    rules_by_client: dict[str, list[dict[str, Any]]] = {}
    for rule in client_rules:
        rules_by_client.setdefault(str(rule.get("folderUID") or ""), []).append(rule)

    # Footprint de cada cliente (tecnologia -> origem da evidência).
    footprints = {
        client_uid: client_footprint(
            rules_by_client.get(client_uid, []), technologies, declared.get(client_uid, [])
        )
        for client_uid in client_by_uid
    }

    technology_uuids = {tech.slug for tech in technologies}
    baseline_by_technology: dict[str, list[dict[str, Any]]] = {
        slug: [] for slug in technology_uuids
    }
    unmapped_baseline = 0
    for rule in global_rules:
        tech = resolve_rule_technology(rule, technologies)
        if tech is None:
            unmapped_baseline += 1
            continue
        baseline_by_technology[tech.slug].append(rule)

    # Distribuição: cada regra de cliente é atribuída a no máximo uma
    # tecnologia (resolução contra o catálogo completo evita dupla contagem).
    tech_of_client_rule: dict[int, str] = {}
    for rule in client_rules:
        tech = resolve_rule_technology(rule, technologies)
        if tech is not None:
            tech_of_client_rule[id(rule)] = tech.slug

    client_rules_by_technology: dict[str, list[dict[str, Any]]] = {
        slug: [] for slug in technology_uuids
    }
    for rule in client_rules:
        slug = tech_of_client_rule.get(id(rule))
        if slug is not None:
            client_rules_by_technology[slug].append(rule)

    items: list[TechnologyOverviewItem] = []
    implemented_total = 0
    slots_total = 0
    excluded_slots_total = 0

    for tech in technologies:
        baseline_rules = baseline_by_technology[tech.slug]
        tech_client_rules = client_rules_by_technology[tech.slug]

        client_rows: list[TechnologyClientCompliance] = []
        implemented_for_tech = 0
        integrated_count = 0

        for client_uid, client_name in client_by_uid.items():
            folder_rules = rules_by_client.get(client_uid, [])
            footprint = footprints.get(client_uid, {})
            source = footprint.get(tech.slug)
            applicable = source is not None

            implemented = 0
            paused = 0
            if applicable:
                for baseline_rule in baseline_rules:
                    replica = find_implemented_rule(baseline_rule, folder_rules)
                    if replica is not None:
                        implemented += 1
                        if replica.get("isPaused"):
                            paused += 1
                integrated_count += 1

            total_baseline = len(baseline_rules)
            client_rows.append(
                TechnologyClientCompliance(
                    client_uid=client_uid,
                    client_name=client_name,
                    # "integrated" acompanha o footprint: cliente que declarou a
                    # tecnologia integra a distribuição mesmo sem regra ainda.
                    integrated=applicable,
                    applicable=applicable,
                    footprint_source=source or "none",
                    implemented_rules=implemented,
                    paused_rules=paused,
                    total_baseline_rules=total_baseline,
                    compliance_pct=(
                        _pct(implemented, total_baseline) if applicable else 0.0
                    ),
                    status=(
                        _compliance_status(implemented, total_baseline)
                        if applicable
                        else "not_applicable"
                    ),
                )
            )

            implemented_for_tech += implemented

        slots_for_tech = len(baseline_rules) * integrated_count
        excluded_slots = len(baseline_rules) * (len(client_by_uid) - integrated_count)
        implemented_total += implemented_for_tech
        slots_total += slots_for_tech
        excluded_slots_total += excluded_slots

        items.append(
            TechnologyOverviewItem(
                slug=tech.slug,
                name=tech.name,
                icon=tech.icon,
                description=tech.description,
                rule_groups_regex=tech.rule_groups_regex or tech.ss_groups_regex,
                ss_groups_regex=tech.ss_groups_regex,
                job=tech.job,
                enabled=tech.enabled,
                perimeter=tech.perimeter,
                perimeter_name=tech.perimeter_name,
                baseline_rules_count=len(baseline_rules),
                client_rules_count=len(tech_client_rules),
                integrated_clients_count=integrated_count,
                applicable_clients_count=integrated_count,
                excluded_clients_count=len(client_by_uid) - integrated_count,
                implemented_baseline_rules=implemented_for_tech,
                total_baseline_slots=slots_for_tech,
                compliance_pct=_pct(implemented_for_tech, slots_for_tech),
                clients=client_rows,
            )
        )

    # Footprint (regras ou inventário declarado) define "cliente com tecnologia".
    clients_with_technology = sum(1 for footprint in footprints.values() if footprint)

    metrics = TechnologyOverviewMetrics(
        unique_technologies=len(technologies),
        enabled_technologies=sum(1 for tech in technologies if tech.enabled),
        baseline_rules_total=len(global_rules),
        baseline_rules_unmapped=unmapped_baseline,
        clients_total=len(client_by_uid),
        clients_with_technology=clients_with_technology,
        client_rules_total=len(client_rules),
        implemented_baseline_rules=implemented_total,
        total_baseline_slots=slots_total,
        not_applicable_slots=excluded_slots_total,
        compliance_pct=_pct(implemented_total, slots_total),
    )

    return TechnologyOverviewResponse(
        metrics=metrics,
        technologies=sorted(items, key=lambda item: item.name.lower()),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def baseline_rules_for_technology(
    technology: Technology, global_rules: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Regras da pasta ``global`` que compõem o baseline de uma tecnologia."""
    catalog = [technology]
    return [
        rule
        for rule in global_rules
        if resolve_rule_technology(rule, catalog) is technology
    ]


__all__ = [
    "baseline_rules_for_technology",
    "build_overview",
    "client_footprint",
    "client_has_technology",
    "find_implemented_rule",
    "is_client_folder",
    "normalize_rule_title",
    "resolve_rule_technology",
    "rule_cloned_from",
    "rule_query",
]
