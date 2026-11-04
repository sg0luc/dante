"""Rotas da funcionalidade de Curadoria de Regras de Detecção.

Endpoints:
    GET  /api/curation                         visão geral (fontes, métricas, agendamento 08h00, regras curadas, progresso)
    GET  /api/curation/progress                estado em tempo real da execução da curadoria (% concluído, cliente, janela)
    POST /api/curation/run                     executa ciclo de curadoria sob demanda (síncrono ou assíncrono em background)
    POST /api/curation/rules/{rule_id}/implement implementa regra no Baseline e clientes recomendados
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from ..config import Settings
from ..curation import (
    CurationStore,
    build_curation_overview,
    compute_next_08h00_run,
    get_curation_progress,
    has_unprocessed_compatible_rules,
    implement_curated_rule,
    request_stop_curation_cycle,
    _reset_to_idle_progress,
    run_curation_cycle,
    start_curation_cycle_background,
)
from ..grafana_client import GrafanaClient, GrafanaError
from ..schemas import (
    CurationClearResponse,
    CurationIgnoreRequest,
    CurationOverviewResponse,
    CurationProgressState,
    CurationRunResponse,
    CurationStopResponse,
    CuratedRuleItem,
    ImplementCuratedRuleRequest,
    ImplementCuratedRuleResponse,
)
from ..security import get_current_user, require_csrf_header
from ..system_settings_store import SystemSettingsStore
from ..technologies import TechnologyStore
from ..technology_store import (
    get_curation_store,
    get_system_settings_store,
    get_technology_store,
    get_tenant_scan_store,
    get_tenant_technology_store,
)
from ..tenant_scan import TenantScanStore
from ..tenant_technologies import TenantTechnologyStore
from .deps import get_app_settings, get_grafana

router = APIRouter(dependencies=[Depends(get_current_user)], tags=["curation"])


@router.get("/curation/progress", response_model=CurationProgressState)
async def get_curation_progress_endpoint() -> CurationProgressState:
    """Retorna o estado detalhado em tempo real da curadoria (porcentagem, ação, cliente, etapa temporal e logs)."""
    return get_curation_progress()


@router.get("/curation", response_model=CurationOverviewResponse)
async def get_curation_overview(
    settings: Settings = Depends(get_app_settings),
    curation_store: CurationStore = Depends(get_curation_store),
) -> CurationOverviewResponse:
    """Retorna o estado da curadoria, agendamento diário das 08h00 e regras candidatas (excelentes e boas)."""
    return build_curation_overview(curation_store, settings)


@router.post(
    "/curation/stop",
    response_model=CurationStopResponse,
    dependencies=[Depends(require_csrf_header)],
)
async def stop_curation_endpoint() -> CurationStopResponse:
    """Interrompe imediatamente o ciclo de curadoria em execução."""
    stopped = request_stop_curation_cycle()
    prog = get_curation_progress()
    if stopped:
        return CurationStopResponse(
            status="stopped",
            message="Ciclo de curadoria interrompido com sucesso pelo operador.",
            progress=prog,
        )
    return CurationStopResponse(
        status="not_running",
        message="Nenhum ciclo de curadoria está em execução no momento.",
        progress=prog,
    )


@router.post(
    "/curation/run",
    response_model=CurationRunResponse,
    dependencies=[Depends(require_csrf_header)],
)
async def trigger_curation_run(
    async_run: bool = Query(
        default=False,
        description="Se true, inicia o ciclo de curadoria em background e retorna imediatamente para evitar HTTP 504.",
    ),
    settings: Settings = Depends(get_app_settings),
    grafana: GrafanaClient = Depends(get_grafana),
    tech_store: TechnologyStore = Depends(get_technology_store),
    footprint_store: TenantTechnologyStore = Depends(get_tenant_technology_store),
    scan_store: TenantScanStore = Depends(get_tenant_scan_store),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    curation_store: CurationStore = Depends(get_curation_store),
) -> CurationRunResponse:
    """Executa um ciclo completo de curadoria (pesquisa, validação, conversão LogQL e execução em etapas no Loki)."""
    next_run = compute_next_08h00_run(settings)
    if async_run:
        prog = start_curation_cycle_background(
            grafana=grafana,
            technology_store=tech_store,
            footprint_store=footprint_store,
            scan_store=scan_store,
            sys_settings=sys_settings,
            curation_store=curation_store,
            trigger="manual",
        )
        rules = curation_store.list_rules()
        return CurationRunResponse(
            message="Execução da curadoria iniciada em segundo plano nas etapas progressivas (15m → 1h → 6h → 24h → 3d).",
            summary=None,
            total_curated=len(rules),
            next_run_at=next_run.isoformat(),
            progress=prog,
        )

    try:
        summary = await run_curation_cycle(
            grafana=grafana,
            technology_store=tech_store,
            footprint_store=footprint_store,
            scan_store=scan_store,
            sys_settings=sys_settings,
            curation_store=curation_store,
            trigger="manual",
        )
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Falha na execução da curadoria: {exc}",
        ) from exc

    rules = curation_store.list_rules()
    if summary.new_curated_count > 0:
        msg = (
            f"Curadoria executada com sucesso: {summary.new_curated_count} nova(s) regra(s) "
            f"adicionada(s) ({summary.excellent_added} excelente(s), {summary.good_added} boa(s)). "
            f"{summary.discarded_bad_count} má(s) candidata(s) descartada(s)."
        )
    else:
        msg = (
            f"Curadoria executada: {summary.fetched_count} regra(s) avaliada(s) nas 4 fontes confiáveis. "
            f"Nenhuma regra nova inédita ({summary.skipped_duplicates_count} já curada(s)/existente(s), "
            f"{summary.discarded_bad_count} má(s) candidata(s) descartada(s)). Avaliações de clientes atualizadas."
        )

    try:
        return CurationRunResponse(
            message=msg,
            summary=summary,
            total_curated=len(rules),
            next_run_at=next_run.isoformat(),
            progress=get_curation_progress(),
        )
    except Exception as exc:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Falha ao serializar resposta da curadoria: {exc}",
        ) from exc


@router.post(
    "/curation/rules/{rule_id}/implement",
    response_model=ImplementCuratedRuleResponse,
    dependencies=[Depends(require_csrf_header)],
)
async def implement_curation_rule_endpoint(
    payload: ImplementCuratedRuleRequest,
    rule_id: str = Path(pattern=r"^[A-Za-z0-9_-]{3,40}$"),
    grafana: GrafanaClient = Depends(get_grafana),
    tech_store: TechnologyStore = Depends(get_technology_store),
    sys_settings: SystemSettingsStore = Depends(get_system_settings_store),
    curation_store: CurationStore = Depends(get_curation_store),
) -> ImplementCuratedRuleResponse:
    """Implementa uma regra curada no Baseline Global e nos clientes recomendados."""
    if not payload.confirm:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Confirmação obrigatória: confirme explicitamente no pop-up a implementação "
                "da regra nos clientes indicados antes de prosseguir."
            ),
        )

    try:
        return await implement_curated_rule(
            rule_id=rule_id,
            payload=payload,
            grafana=grafana,
            technology_store=tech_store,
            sys_settings=sys_settings,
            curation_store=curation_store,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except GrafanaError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


@router.post(
    "/curation/rules/{rule_id}/ignore",
    response_model=CuratedRuleItem,
    dependencies=[Depends(require_csrf_header)],
)
async def ignore_curated_rule_endpoint(
    payload: CurationIgnoreRequest,
    rule_id: str = Path(pattern=r"^[A-Za-z0-9_-]{3,40}$"),
    curation_store: CurationStore = Depends(get_curation_store),
) -> CuratedRuleItem:
    """Marca ou desmarca uma regra curada como ignorada."""
    updated = curation_store.ignore_rule(rule_id, ignored=payload.ignored)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Regra curada '{rule_id}' não encontrada.",
        )
    return updated


@router.post(
    "/curation/clear",
    response_model=CurationClearResponse,
    dependencies=[Depends(require_csrf_header)],
)
async def clear_curation_endpoint(
    curation_store: CurationStore = Depends(get_curation_store),
) -> CurationClearResponse:
    """Limpa e reseta completamente todas as regras curadas e histórico da curadoria."""
    request_stop_curation_cycle()
    cleared = curation_store.clear_all()
    _reset_to_idle_progress()
    return CurationClearResponse(
        status="cleared",
        message=f"Curadoria limpa e resetada com sucesso ({cleared} regra(s) removida(s)).",
        cleared_count=cleared,
    )

