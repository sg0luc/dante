"""CRUD do catálogo de tecnologias (data sources), telemetria e baseline.

Segregação de escopo:
    * ``grafana_folder`` = cliente/tenant.
    * ``ss_groups``      = tecnologia/datasource (espelho de ``rule.groups`` do Wazuh).
    * ``job``            = pipeline de ingestão, sempre ``wazuh`` nesta arquitetura.

Além do CRUD, este router concentra:

    * a validação implícita de telemetria no Loki antes do cadastro
      (``POST /technologies/log-presence``), cuja query nunca é exposta;
    * a visão consolidada da página de Tecnologias -- métricas, distribuição por
      cliente e mapa de conformidade ao baseline (``GET /technologies/overview``);
    * a implementação automática de todo o baseline de uma tecnologia em um
      cliente, com validação prévia de integração e confirmação de segurança
      (``POST /technologies/{slug}/implement-baseline``).

Todas as rotas exigem sessão autenticada; as mutações exigem o cabeçalho anti-CSRF.
"""

from __future__ import annotations

import asyncio
import copy
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, status
from pydantic import BaseModel, Field

from ..contact_points import apply_contact_point, resolve_stage_receiver
from ..grafana_client import GrafanaClient, GrafanaError
from ..loki_presence import check_technology_logs
from ..schemas import (
    DetectionPerimeterOut,
    ImplementBaselineRequest,
    ImplementBaselineResponse,
    ImplementedRuleResult,
    TechnologyDeleteResponse,
    TechnologyLogCheckRequest,
    TechnologyLogCheckResult,
    TechnologyOut,
    TechnologyOverviewResponse,
    TechnologyUpsertRequest,
    TenantTechnologyFootprintOut,
    TenantTechnologyFootprintRequest,
)
from ..security import get_current_user, require_csrf_header
from ..technologies import (
    DETECTION_PERIMETERS,
    Technology,
    TechnologyConflict,
    TechnologyNotFound,
    TechnologyStore,
    TechnologyStoreError,
    TechnologyValidationError,
    validate_technology_payload,
)
from ..technology_insights import (
    baseline_rules_for_technology,
    build_overview,
    client_footprint,
    client_has_technology,
    find_implemented_rule,
    is_client_folder,
    strip_scope_prefix,
)
from ..technology_store import (
    get_system_settings_store,
    get_technology_store,
    get_tenant_technology_store,
)
from ..system_settings_store import SystemSettingsStore
from ..tenant_technologies import TenantTechnologyStore, TenantTechnologyStoreError
from ..tenants import (
    RULE_GROUP_INTERVAL_SECONDS,
    bind_rule_datasource,
    detection_rules,
    find_tenant_datasource,
    resolve_baseline_loki_datasource,
    tenant_rule_group,
)
from .deps import get_grafana

router = APIRouter(dependencies=[Depends(get_current_user)])

SLUG_PATTERN = r"^[a-z0-9_]{2,32}$"


class ResolveQueryRequest(BaseModel):
    """Consulta para descobrir quais tecnologias uma query LogQL referencia."""

    query: str = Field(min_length=1, max_length=4000)


def _to_out(tech: Technology) -> TechnologyOut:
    """Converte o registro interno no modelo exposto pela API."""
    return TechnologyOut(**tech.model_dump(), logql_selector=tech.logql_selector)


def _handle_store_error(exc: TechnologyStoreError, slug: str | None = None) -> HTTPException:
    """Traduz as exceções do catálogo em respostas HTTP seguras."""
    if isinstance(exc, TechnologyNotFound):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, TechnologyConflict):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=str(exc),
    )


async def _load_rules_and_folders(
    grafana: GrafanaClient,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Carrega regras e pastas do Grafana em paralelo."""
    rules, folders = await asyncio.gather(
        grafana.list_alert_rules(), grafana.list_folders()
    )
    # Artefatos internos (âncora do grupo de avaliação) não são detecções e não
    # podem contar como cobertura de tecnologia/baseline.
    return detection_rules(rules), list(folders or [])


# --- Catálogo de Perímetros de Detecção -------------------------------------
@router.get(
    "/technologies/perimeters",
    response_model=list[DetectionPerimeterOut],
    tags=["technologies"],
)
def list_perimeters(
    store: TechnologyStore = Depends(get_technology_store),
) -> list[DetectionPerimeterOut]:
    """Lista os perímetros canônicos de segurança e a quantidade de tecnologias cadastradas em cada um."""
    try:
        techs = store.list_all(include_disabled=True)
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc) from exc

    counts: dict[str, int] = {}
    for t in techs:
        counts[t.perimeter] = counts.get(t.perimeter, 0) + 1

    return [
        DetectionPerimeterOut(
            slug=slug,
            name=data["name"],
            icon=data.get("icon", "category"),
            description=data.get("description", ""),
            keywords=data.get("keywords", []),
            technologies_count=counts.get(slug, 0),
        )
        for slug, data in DETECTION_PERIMETERS.items()
    ]


# --- Visão consolidada (declarada antes de /technologies/{slug}) -------------
@router.get(
    "/technologies/overview",
    response_model=TechnologyOverviewResponse,
    tags=["technologies"],
)
async def technologies_overview(
    store: TechnologyStore = Depends(get_technology_store),
    footprint_store: TenantTechnologyStore = Depends(get_tenant_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> TechnologyOverviewResponse:
    """Métricas, distribuição por cliente e mapa de conformidade ao baseline.

    Fonte de verdade: regras de detecção do Grafana + catálogo do portal + o
    inventário declarado de tecnologias por cliente. A pasta baseline (arbitrada ou 'global') é o
    baseline; as demais pastas são clientes. A conformidade de cada tecnologia
    considera apenas os clientes que possuem aquela tecnologia no SIEM
    (footprint derivado das regras ou declarado pelo operador).
    """
    try:
        technologies = store.list_all()
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc) from exc

    try:
        declared = footprint_store.declared_map()
    except TenantTechnologyStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        rules, folders = await _load_rules_and_folders(grafana)
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    return build_overview(
        technologies,
        rules,
        folders,
        declared,
        baseline_folder_uid=sys_settings.get_baseline_folder_uid(),
    )


def _client_folders(folders: list[dict[str, Any]], baseline_folder_uid: str = "global") -> dict[str, dict[str, Any]]:
    """Indexa as pastas de clientes por ``uid``."""
    return {
        str(folder.get("uid") or ""): folder
        for folder in folders
        if is_client_folder(folder, baseline_folder_uid=baseline_folder_uid)
    }


def _footprint_out(
    folder: dict[str, Any],
    rules: list[dict[str, Any]],
    technologies: list[Any],
    declared: list[str],
) -> TenantTechnologyFootprintOut:
    """Monta o footprint efetivo (derivado + declarado) de um cliente."""
    client_uid = str(folder.get("uid") or "")
    client_rules = [
        rule
        for rule in rules
        if str(rule.get("folderUID") or "") == client_uid
    ]
    effective = client_footprint(client_rules, technologies, declared)
    derived = sorted(
        slug for slug, source in effective.items() if source in ("derived", "both")
    )
    declared_sorted = sorted({str(slug).strip().lower() for slug in declared if slug})
    return TenantTechnologyFootprintOut(
        client_uid=client_uid,
        client_name=str(folder.get("title") or client_uid),
        derived=derived,
        declared=declared_sorted,
        effective=sorted(effective),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/technologies/footprints",
    response_model=list[TenantTechnologyFootprintOut],
    tags=["technologies"],
)
async def list_technology_footprints(
    store: TechnologyStore = Depends(get_technology_store),
    footprint_store: TenantTechnologyStore = Depends(get_tenant_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
) -> list[TenantTechnologyFootprintOut]:
    """Footprint de tecnologias de cada cliente (derivado das regras + declarado)."""
    try:
        technologies = store.list_all()
        declared_map = footprint_store.declared_map()
    except (TechnologyStoreError, TenantTechnologyStoreError) as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        rules, folders = await _load_rules_and_folders(grafana)
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    return [
        _footprint_out(folder, rules, technologies, declared_map.get(uid, []))
        for uid, folder in sorted(
            _client_folders(folders).items(),
            key=lambda item: str(item[1].get("title") or item[0]).lower(),
        )
    ]


@router.put(
    "/technologies/footprints/{client_uid}",
    response_model=TenantTechnologyFootprintOut,
    dependencies=[Depends(require_csrf_header)],
    tags=["technologies"],
)
async def set_technology_footprint(
    payload: TenantTechnologyFootprintRequest,
    client_uid: str = Path(min_length=1, max_length=40),
    store: TechnologyStore = Depends(get_technology_store),
    footprint_store: TenantTechnologyStore = Depends(get_tenant_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
) -> TenantTechnologyFootprintOut:
    """Declara o inventário de tecnologias de um cliente (substituição total).

    Valida no servidor: o cliente precisa existir no Grafana e todo slug precisa
    estar no catálogo. O que foi derivado das regras da pasta permanece no
    footprint mesmo que não seja reenviado — a evidência de regra é imutável por
    esta rota.
    """
    try:
        technologies = store.list_all()
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc) from exc

    catalog = {tech.slug for tech in technologies}
    requested = sorted({str(slug).strip().lower() for slug in payload.technologies if slug})
    unknown = [slug for slug in requested if slug not in catalog]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Tecnologias não cadastradas no catálogo: "
                + ", ".join(sorted(unknown))
                + ". Cadastre-as antes de declará-las para o cliente."
            ),
        )

    try:
        rules, folders = await _load_rules_and_folders(grafana)
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    folder = _client_folders(folders).get(client_uid.strip())
    if folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Cliente não encontrado: a pasta '{client_uid}' não existe no Grafana. "
                "Cadastre o tenant antes de declarar suas tecnologias."
            ),
        )

    try:
        footprint_store.set_declared(client_uid, requested)
        declared = footprint_store.declared_for(client_uid)
    except TenantTechnologyStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return _footprint_out(folder, rules, technologies, declared)


@router.get("/technologies", response_model=list[TechnologyOut], tags=["technologies"])
async def list_technologies(
    store: TechnologyStore = Depends(get_technology_store),
) -> list[TechnologyOut]:
    """Lista todas as tecnologias cadastradas (fonte do radio box na criação de regras)."""
    try:
        return [_to_out(tech) for tech in store.list_all()]
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc) from exc


@router.post(
    "/technologies/resolve",
    response_model=list[TechnologyOut],
    tags=["technologies"],
)
async def resolve_technologies(
    payload: ResolveQueryRequest,
    store: TechnologyStore = Depends(get_technology_store),
) -> list[TechnologyOut]:
    """Retorna as tecnologias compatíveis com o matcher ``ss_groups`` da query."""
    try:
        return [_to_out(tech) for tech in store.match_query(payload.query)]
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc) from exc


@router.post(
    "/technologies/log-presence",
    response_model=TechnologyLogCheckResult,
    dependencies=[Depends(require_csrf_header)],
    tags=["technologies"],
)
async def technology_log_presence(
    payload: TechnologyLogCheckRequest,
    store: TechnologyStore = Depends(get_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
) -> TechnologyLogCheckResult:
    """Verifica implicitamente no Loki se o recorte de ``ss_groups`` tem logs.

    A query (``sum(count_over_time({job="wazuh", ss_groups=~".*<tecnologia>.*"} | json [1m]))``)
    é montada no backend e não é devolvida na resposta. Pode receber ``slug``
    (tecnologia já cadastrada) ou ``ss_groups_regex`` (cadastro em andamento).
    """
    regex = (payload.rule_groups_regex or payload.ss_groups_regex or "").strip()
    job = (payload.job or "").strip()

    if payload.slug:
        try:
            tech = store.get(payload.slug)
        except TechnologyStoreError as exc:
            raise _handle_store_error(exc, payload.slug) from exc
        regex = regex or tech.rule_groups_regex or tech.ss_groups_regex
        job = job or tech.job

    if not regex:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Informe o slug da tecnologia ou o recorte de ss_groups a validar.",
        )

    try:
        return await check_technology_logs(
            grafana,
            rule_groups_regex=regex,
            ss_groups_regex=regex,
            job=job or "wazuh",
            window_seconds=payload.window_seconds,
        )
    except TechnologyValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.get(
    "/technologies/{slug}/baseline",
    response_model=list[dict[str, Any]],
    tags=["technologies"],
)
async def technology_baseline(
    slug: str = Path(pattern=SLUG_PATTERN),
    store: TechnologyStore = Depends(get_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> list[dict[str, Any]]:
    """Regras da pasta baseline que compõem o baseline da tecnologia."""
    baseline_uid = sys_settings.get_baseline_folder_uid()
    try:
        tech = store.get(slug)
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc, slug) from exc

    try:
        rules, _folders = await _load_rules_and_folders(grafana)
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    global_rules = [
        rule
        for rule in rules
        if str(rule.get("folderUID") or "").strip().lower() == baseline_uid.lower()
        or str(rule.get("folderUID") or "").strip().lower() == "global"
    ]
    return [
        {
            "uid": str(rule.get("uid") or ""),
            "title": str(rule.get("title") or ""),
            "severity": str((rule.get("labels") or {}).get("severity") or ""),
            "mitre_technique": str(
                (rule.get("labels") or {}).get("mitre_technique") or ""
            ),
            "rule_group": str(rule.get("ruleGroup") or ""),
            "is_paused": bool(rule.get("isPaused")),
        }
        for rule in baseline_rules_for_technology(tech, global_rules)
    ]


@router.post(
    "/technologies/{slug}/implement-baseline",
    response_model=ImplementBaselineResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["technologies"],
)
async def implement_technology_baseline(
    payload: ImplementBaselineRequest,
    slug: str = Path(pattern=SLUG_PATTERN),
    store: TechnologyStore = Depends(get_technology_store),
    footprint_store: TenantTechnologyStore = Depends(get_tenant_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
) -> ImplementBaselineResponse:
    """Implementa em um cliente todas as regras de baseline da tecnologia.

    Validações de segurança (no servidor, não apenas na UI):
      1. A tecnologia precisa existir no catálogo.
      2. A pasta de destino precisa existir e não pode ser a pasta baseline ('global' ou arbitrada).
      3. Integração prévia: o cliente só recebe o baseline automaticamente se já
         houver evidência da tecnologia naquele tenant (regra de detecção
         implementada). Sem essa evidência o endpoint exige
         ``confirm_client_without_technology`` (pop-up de segurança do front) --
         caso contrário responde 409.
      4. Regras já replicadas (``cloned_from``/título-base) são ignoradas, sem
         duplicar alertas e sem tocar no que o cliente já tem.
    """
    baseline_uid = sys_settings.get_baseline_folder_uid()
    try:
        tech = store.get(slug)
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc, slug) from exc

    target_uid = payload.target_folder_uid.strip()
    if target_uid.lower() == baseline_uid.lower() or target_uid.lower() == "global":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "A pasta de baseline não pode receber regras de cliente: escolha a pasta de um cliente "
                "para implementar as regras."
            ),
        )

    try:
        rules, folders = await _load_rules_and_folders(grafana)
    except GrafanaError as exc:
        raise HTTPException(status_code=502, detail=exc.message) from exc

    folder_map = {str(f.get("uid") or ""): f for f in folders}
    target_folder = folder_map.get(target_uid)
    if target_folder is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Cliente não encontrado: a pasta '{target_uid}' não existe no Grafana. "
                "Cadastre o tenant antes de implementar o baseline."
            ),
        )
    if not is_client_folder(target_folder, baseline_folder_uid=baseline_uid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A pasta informada não representa um cliente.",
        )

    client_name = str(target_folder.get("title") or target_uid)
    global_rules = [
        rule
        for rule in rules
        if str(rule.get("folderUID") or "").strip().lower() == baseline_uid.lower()
        or str(rule.get("folderUID") or "").strip().lower() == "global"
    ]
    baseline = baseline_rules_for_technology(tech, global_rules)
    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"A tecnologia '{tech.name}' não possui regras de baseline na pasta "
                "'global'. Cadastre as regras globais antes de implementá-las no cliente."
            ),
        )

    client_rules = [
        rule for rule in rules if str(rule.get("folderUID") or "") == target_uid
    ]
    # "Integrado" = footprint do cliente (evidência de regra ou inventário
    # declarado). Declarar Office365 no footprint já libera a implementação do
    # baseline sem o pop-up de confirmação.
    try:
        declared_for_client = footprint_store.declared_for(target_uid)
    except TenantTechnologyStoreError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    integrated = client_has_technology(client_rules, tech, declared_for_client)
    if not integrated and not payload.confirm_client_without_technology:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Validação prévia de integração: o cliente '{client_name}' ainda não "
                f"possui regra de detecção da tecnologia '{tech.name}'. Confirme "
                "explicitamente a implementação do baseline para prosseguir."
            ),
        )

    raw_datasources, raw_contact_points = await asyncio.gather(
        grafana.list_datasources(),
        grafana.list_contact_points(),
    )
    client_ds = find_tenant_datasource(client_name, target_uid, raw_datasources)
    if not client_ds:
        client_ds = resolve_baseline_loki_datasource(raw_datasources)

    # Resolução dinâmica do Contact Point real correspondente ao estágio 'stg' (Homologação)
    stage_mapping = sys_settings.get_stage_contact_points()
    stg_contact_point = resolve_stage_receiver(
        "stg",
        stage_mapping=stage_mapping,
        available_contact_points=raw_contact_points,
    )

    target_evaluation_group = (
        payload.evaluation_group.strip()
        if payload.evaluation_group and payload.evaluation_group.strip()
        else tenant_rule_group(client_name)
    )

    results: list[ImplementedRuleResult] = []

    for source_rule in baseline:
        source_uid = str(source_rule.get("uid") or "")
        source_title = str(source_rule.get("title") or "")
        base_title = strip_scope_prefix(source_title)

        existing = find_implemented_rule(source_rule, client_rules)
        if existing is not None:
            results.append(
                ImplementedRuleResult(
                    uid=str(existing.get("uid") or source_uid),
                    title=str(existing.get("title") or source_title),
                    status="skipped",
                    detail="Regra já implementada neste cliente.",
                )
            )
            continue

        new_title = (
            f"[{client_name}] {base_title}" if base_title else source_title
        )
        new_uid = f"ghp-{uuid.uuid4().hex[:10]}"
        rule_copy = copy.deepcopy(source_rule)
        rule_copy.pop("id", None)
        rule_copy.pop("updated", None)
        # Proveniência da origem não é herdada: provenance 'api' no corpo faz o
        # clone nascer "Provisioned"/read-only no Grafana.
        rule_copy.pop("provenance", None)
        rule_copy.pop("readOnly", None)
        rule_copy.pop("orgID", None)
        rule_copy["uid"] = new_uid
        rule_copy["folderUID"] = target_uid
        rule_copy["title"] = new_title
        # Grupo de avaliação no cliente: utiliza o grupo selecionado pelo operador
        # ou recorre ao padrão canônico '5m' do tenant.
        rule_copy["ruleGroup"] = target_evaluation_group
        rule_copy["isPaused"] = False

        labels = dict(rule_copy.get("labels") or {})
        labels.update(
            {
                "client": client_name,
                "siem_tier": "client",
                "technology": tech.slug,
                "technology_name": tech.name,
            }
        )
        rule_copy["labels"] = labels

        annotations = dict(rule_copy.get("annotations") or {})
        annotations["cloned_from"] = source_uid
        annotations["client_name"] = client_name
        annotations["baseline_technology"] = tech.slug
        rule_copy["annotations"] = annotations

        # Direciona a query da regra replicada para o data source Loki do cliente
        bind_rule_datasource(rule_copy, client_ds)

        # REGRA DE NEGÓCIO: baseline replicado nasce no estágio Homologação
        # amarrado dinamicamente ao Contact Point do estágio 'stg' configurado
        # na seção Homologação (a origem global pode estar em 'prod' e não deve
        # ser herdada — a promoção é decisão explícita por cliente).
        apply_contact_point(rule_copy, contact_point=stg_contact_point)

        try:
            await grafana.create_alert_rule(rule_copy)
            results.append(
                ImplementedRuleResult(uid=new_uid, title=new_title, status="created")
            )
        except GrafanaError as exc:
            results.append(
                ImplementedRuleResult(
                    uid=new_uid,
                    title=new_title,
                    status="failed",
                    detail=exc.message,
                )
            )

    created = sum(1 for item in results if item.status == "created")
    skipped = sum(1 for item in results if item.status == "skipped")
    failed = sum(1 for item in results if item.status == "failed")

    if created > 0:
        await grafana.set_rule_group_interval(
            target_uid,
            target_evaluation_group,
            RULE_GROUP_INTERVAL_SECONDS,
        )

    message = (
        f"Baseline da tecnologia '{tech.name}' processado no cliente '{client_name}': "
        f"{created} regra(s) criada(s), {skipped} já existente(s), {failed} falha(s)."
    )
    if failed:
        message += " Revise as regras com falha antes de confiar na cobertura total."

    return ImplementBaselineResponse(
        message=message,
        technology=tech.slug,
        technology_name=tech.name,
        client_uid=target_uid,
        client_name=client_name,
        total=len(results),
        created=created,
        skipped=skipped,
        failed=failed,
        contact_point=stg_contact_point,
        rules=results,
        evaluation_group=target_evaluation_group,
    )


@router.get(
    "/technologies/{slug}",
    response_model=TechnologyOut,
    tags=["technologies"],
)
async def get_technology(
    slug: str = Path(pattern=SLUG_PATTERN),
    store: TechnologyStore = Depends(get_technology_store),
) -> TechnologyOut:
    """Detalhe de uma tecnologia pelo slug."""
    try:
        return _to_out(store.get(slug))
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc, slug) from exc


@router.post(
    "/technologies",
    response_model=TechnologyOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf_header)],
    tags=["technologies"],
)
async def create_technology(
    payload: TechnologyUpsertRequest,
    store: TechnologyStore = Depends(get_technology_store),
    grafana: GrafanaClient = Depends(get_grafana),
) -> TechnologyOut:
    """Cadastra uma nova tecnologia (nome + recorte de ``ss_groups``).

    Validação implícita de telemetria: quando o Loki é consultável e o recorte
    não possui logs, a criação é recusada (409) até o operador confirmar
    explicitamente (``confirm_without_logs``), aceite coletado no pop-up de
    segurança do frontend.
    """
    # Valida o payload antes de qualquer consulta (a query é interpolada).
    try:
        validate_technology_payload(payload)
    except TechnologyValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    if not payload.confirm_without_logs:
        presence = await check_technology_logs(
            grafana,
            rule_groups_regex=payload.effective_groups_regex,
            ss_groups_regex=payload.effective_groups_regex,
            job=payload.job,
        )
        if presence.available and not presence.found:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"{presence.message} Confirme a criação de uma tecnologia sem logs "
                    "existentes para prosseguir."
                ),
            )

    try:
        return _to_out(store.create(payload))
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc) from exc


@router.put(
    "/technologies/{slug}",
    response_model=TechnologyOut,
    dependencies=[Depends(require_csrf_header)],
    tags=["technologies"],
)
async def update_technology(
    payload: TechnologyUpsertRequest,
    slug: str = Path(pattern=SLUG_PATTERN),
    store: TechnologyStore = Depends(get_technology_store),
) -> TechnologyOut:
    """Atualiza uma tecnologia existente."""
    try:
        return _to_out(store.update(slug, payload))
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc, slug) from exc


@router.delete(
    "/technologies/{slug}",
    response_model=TechnologyDeleteResponse,
    dependencies=[Depends(require_csrf_header)],
    tags=["technologies"],
)
async def delete_technology(
    slug: str = Path(pattern=SLUG_PATTERN),
    store: TechnologyStore = Depends(get_technology_store),
) -> TechnologyDeleteResponse:
    """Remove uma tecnologia do catálogo.

    A remoção é apenas do catálogo do portal: regras já criadas no Grafana mantêm
    suas labels ``technology`` e continuam operando normalmente.
    """
    try:
        removed = store.delete(slug)
    except TechnologyStoreError as exc:
        raise _handle_store_error(exc, slug) from exc
    return TechnologyDeleteResponse(
        message=f"Tecnologia '{removed.name}' removida do catálogo.",
        slug=removed.slug,
    )
