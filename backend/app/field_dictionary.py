"""Módulo do Dicionário de Campos do D.A.N.T.E.

Responsabilidades:
1. Mapear e indexar em background os campos de telemetria reais em todos os clientes
   para cada tecnologia cadastrada (`rule_groups`).
2. Armazenar o dicionário de campos com persistência atômica em `/data/field-dictionary.json`.
3. Atualizar automaticamente o dicionário 1x por semana no dia e horário configurados.
4. Fornecer reanálise sob demanda por tecnologia.
5. Análise de Inteligência Artificial evidenciando discrepâncias entre clientes
   (versões de log, formato do schema, idioma e recomendações de compatibilidade).
6. Servir como fonte de verdade para a Curadoria de Regras validar assertividade.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .ai import AIService, AIUniversalClient
from .config import Settings, get_settings
from .grafana_client import GrafanaClient
from .schemas import (
    FieldDictionaryAIAnalysisOut,
    FieldDictionaryClientItem,
    FieldDictionaryDetailOut,
    FieldDictionaryDiscrepancyItem,
    FieldDictionarySummaryOut,
)
from .system_settings_store import SystemSettingsStore
from .technologies import Technology, TechnologyStore
from .technology_insights import is_client_folder
from .tenants import find_tenant_datasource, resolve_baseline_loki_datasource

logger = logging.getLogger("hunter_portal.field_dictionary")

DEFAULT_FIELD_DICTIONARY_STORE_PATH = "/data/field-dictionary.json"


def _flatten_json_items(obj: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Extrai recursivamente campos planos e seus valores do objeto JSON."""
    items: dict[str, Any] = {}
    for k, v in obj.items():
        key_str = str(k).strip()
        if not key_str:
            continue
        compound_key = f"{prefix}.{key_str}" if prefix else key_str
        if isinstance(v, dict):
            items.update(_flatten_json_items(v, compound_key))
        else:
            items[compound_key] = v
    return items


def _normalize_field_name(name: str) -> str:
    """Padroniza o nome do campo com prefixo data_ para o ecossistema Wazuh/Loki do DANTE."""
    clean = str(name or "").strip()
    if not clean:
        return ""
    if clean.startswith("data_"):
        return clean
    if clean.startswith("data."):
        return "data_" + clean[5:].replace(".", "_")
    return f"data_{clean.replace('.', '_')}"


class FieldDictionaryStore:
    """Gerenciador de persistência atômica do dicionário de campos."""

    def __init__(self, store_path: str | Path | None = None) -> None:
        self._path = Path(store_path or DEFAULT_FIELD_DICTIONARY_STORE_PATH)
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {}
        self._loaded = False

    def _load_locked(self) -> None:
        if self._loaded:
            return
        if not self._path.exists():
            self._data = {}
            self._loaded = True
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._data = raw
            else:
                self._data = {}
        except Exception as exc:
            logger.warning("Falha ao ler %s (%s); iniciando dicionário vazio", self._path, exc)
            self._data = {}
        self._loaded = True

    def _persist_locked(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self._data, indent=2, ensure_ascii=False) + "\n"
        tmp_fd, tmp_path = tempfile.mkstemp(
            prefix="field-dict-",
            suffix=".tmp",
            dir=str(self._path.parent),
        )
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(tmp_path, self._path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def get_technology_data(self, slug: str) -> dict[str, Any] | None:
        with self._lock:
            self._load_locked()
            item = self._data.get(slug.lower())
            if item and isinstance(item, dict):
                return json.loads(json.dumps(item))
            return None

    def get_all_summaries(self) -> dict[str, FieldDictionarySummaryOut]:
        with self._lock:
            self._load_locked()
            summaries: dict[str, FieldDictionarySummaryOut] = {}
            for slug, item in self._data.items():
                if not isinstance(item, dict):
                    continue
                unique_fields = item.get("total_unique_fields", 0)
                clients = item.get("clients", {})
                active_clients = sum(1 for c in clients.values() if int(c.get("total_fields", 0)) > 0)
                client_totals = [
                    int(c.get("total_fields", 0) or len(c.get("fields", [])))
                    for c in clients.values()
                    if isinstance(c, dict)
                ]
                max_fields = max(client_totals, default=0) if client_totals else unique_fields
                summaries[slug] = FieldDictionarySummaryOut(
                    technology_slug=slug,
                    total_unique_fields=unique_fields,
                    max_unique_fields_per_client=max_fields,
                    client_count_with_telemetry=active_clients,
                    last_updated_at=item.get("last_updated_at"),
                    is_scanning=bool(item.get("is_scanning", False)),
                    last_error=item.get("last_error"),
                )
            return summaries

    def set_technology_fields(
        self,
        slug: str,
        *,
        technology_name: str,
        rule_groups_regex: str,
        client_data: list[dict[str, Any]],
        ai_analysis: dict[str, Any] | None = None,
        last_error: str | None = None,
    ) -> None:
        slug_clean = slug.strip().lower()
        unique_all: set[str] = set()
        clients_dict: dict[str, Any] = {}

        for c in client_data:
            c_uid = str(c.get("client_uid") or "").strip()
            c_name = str(c.get("client_name") or c_uid).strip()
            fields = sorted(list(set(c.get("fields") or [])))
            unique_all.update(fields)
            clients_dict[c_uid] = {
                "client_uid": c_uid,
                "client_name": c_name,
                "total_fields": len(fields),
                "fields": fields,
                "sample_values": c.get("sample_values") or {},
                "last_scanned_at": c.get("last_scanned_at") or datetime.now(timezone.utc).isoformat(),
            }

        with self._lock:
            self._load_locked()
            existing = self._data.get(slug_clean) or {}
            saved_ai = ai_analysis or existing.get("ai_analysis")
            self._data[slug_clean] = {
                "technology_slug": slug_clean,
                "technology_name": technology_name,
                "rule_groups_regex": rule_groups_regex,
                "total_unique_fields": len(unique_all),
                "all_fields": sorted(list(unique_all)),
                "clients": clients_dict,
                "last_updated_at": datetime.now(timezone.utc).isoformat(),
                "is_scanning": False,
                "last_error": last_error,
                "ai_analysis": saved_ai,
            }
            self._persist_locked()

    def set_scanning(self, slug: str, is_scanning: bool) -> None:
        slug_clean = slug.strip().lower()
        with self._lock:
            self._load_locked()
            if slug_clean in self._data:
                self._data[slug_clean]["is_scanning"] = is_scanning
                self._persist_locked()

    def set_error(self, slug: str, error_msg: str) -> None:
        slug_clean = slug.strip().lower()
        with self._lock:
            self._load_locked()
            if slug_clean in self._data:
                self._data[slug_clean]["is_scanning"] = False
                self._data[slug_clean]["last_error"] = error_msg
                self._persist_locked()
            else:
                self._data[slug_clean] = {
                    "technology_slug": slug_clean,
                    "technology_name": slug_clean,
                    "rule_groups_regex": "",
                    "total_unique_fields": 0,
                    "all_fields": [],
                    "clients": {},
                    "last_updated_at": datetime.now(timezone.utc).isoformat(),
                    "is_scanning": False,
                    "last_error": error_msg,
                    "ai_analysis": None,
                }
                self._persist_locked()

    def save_ai_analysis(self, slug: str, analysis: dict[str, Any]) -> None:
        slug_clean = slug.strip().lower()
        with self._lock:
            self._load_locked()
            if slug_clean in self._data:
                self._data[slug_clean]["ai_analysis"] = analysis
                self._persist_locked()


_store_instance: FieldDictionaryStore | None = None
_store_lock = threading.Lock()


def get_field_dictionary_store(settings: Settings | None = None) -> FieldDictionaryStore:
    global _store_instance
    if _store_instance is None:
        with _store_lock:
            if _store_instance is None:
                store_path = getattr(settings, "field_dictionary_store_path", DEFAULT_FIELD_DICTIONARY_STORE_PATH)
                _store_instance = FieldDictionaryStore(store_path)
    return _store_instance


async def _query_loki_lines_direct(
    grafana: GrafanaClient,
    datasource_uid: str,
    expr: str,
    limit: int = 40,
    time_from: str = "now-24h",
    timeout: float = 4.5,
) -> list[str]:
    """Consulta o Loki diretamente para amostragem de telemetria."""
    body = {
        "queries": [
            {
                "refId": "A",
                "datasource": {"uid": datasource_uid, "type": "loki"},
                "expr": expr,
                "queryType": "range",
                "lines": limit,
                "maxLines": limit,
            }
        ],
        "from": time_from,
        "to": "now",
    }
    try:
        res = await asyncio.wait_for(
            grafana._request("POST", "/api/ds/query", json=body),
            timeout=timeout,
        )
        lines: list[str] = []
        results = (res or {}).get("results", {})
        res_a = results.get("A") or {}
        frames = res_a.get("frames", [])
        for frame in frames:
            fields = (frame.get("schema") or {}).get("fields", [])
            data_values = (frame.get("data") or {}).get("values", [])
            line_idx = next(
                (
                    i
                    for i, f in enumerate(fields)
                    if str(f.get("name", "")).lower() in ("body", "line", "message", "value", "raw_message")
                ),
                -1,
            )
            if line_idx != -1 and len(data_values) > line_idx:
                for item in data_values[line_idx]:
                    val_str = str(item or "").strip()
                    if val_str:
                        lines.append(val_str)
        return lines
    except Exception as exc:
        logger.debug("Falha na consulta Loki para amostragem (ds: %s): %s", datasource_uid, exc)
        return []


async def scan_technology_fields_across_clients(
    technology: Technology,
    grafana: GrafanaClient,
    store: FieldDictionaryStore,
    sys_settings: SystemSettingsStore,
    ai_service: AIService | None = None,
) -> FieldDictionaryDetailOut:
    """Executa a coleta em background no Loki de todos os clientes para a tecnologia."""
    slug = technology.slug.lower()
    store.set_scanning(slug, True)

    try:
        baseline_uid = sys_settings.get_baseline_folder_uid()
        folders = await grafana.list_folders()
        datasources = await grafana.list_datasources()
        baseline_ds = resolve_baseline_loki_datasource(datasources)

        client_folders = sorted(
            [f for f in folders if is_client_folder(f, baseline_folder_uid=baseline_uid)],
            key=lambda f: str(f.get("title") or "").lower(),
        )

        regex_part = technology.effective_groups_regex
        query_expr = f'{{job="{technology.job}", ss_groups=~"{regex_part}"}} | json'

        client_results: list[dict[str, Any]] = []
        all_unique_fields: set[str] = set()

        for folder in client_folders:
            c_uid = str(folder.get("uid") or "").strip()
            c_name = str(folder.get("title") or c_uid).strip()
            if not c_uid:
                continue

            c_ds = find_tenant_datasource(c_name, c_uid, datasources) or baseline_ds
            ds_uid = str(c_ds.get("uid") or "loki")

            lines = await _query_loki_lines_direct(
                grafana, ds_uid, query_expr, limit=35, time_from="now-24h", timeout=4.5
            )
            if not lines:
                # Tenta janela mais ampla se não houver nas últimas 24h
                lines = await _query_loki_lines_direct(
                    grafana, ds_uid, query_expr, limit=35, time_from="now-7d", timeout=4.5
                )

            client_fields: set[str] = set()
            sample_values: dict[str, list[str]] = {}

            for line in lines:
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        flat = _flatten_json_items(obj)
                        for raw_k, v in flat.items():
                            norm_k = _normalize_field_name(raw_k)
                            if norm_k:
                                client_fields.add(norm_k)
                                all_unique_fields.add(norm_k)
                                if str(v).strip() and len(sample_values.get(norm_k, [])) < 3:
                                    sample_values.setdefault(norm_k, []).append(str(v)[:80])
                except Exception:
                    continue

            client_results.append({
                "client_uid": c_uid,
                "client_name": c_name,
                "fields": sorted(list(client_fields)),
                "sample_values": sample_values,
                "last_scanned_at": datetime.now(timezone.utc).isoformat(),
            })

        # Salva o resultado básico
        store.set_technology_fields(
            slug,
            technology_name=technology.name,
            rule_groups_regex=technology.effective_groups_regex,
            client_data=client_results,
        )

        # Se houver serviço de IA disponível, executa a análise de discrepâncias
        ai_out = None
        if ai_service and ai_service.is_configured():
            try:
                ai_out = await analyze_technology_discrepancies_with_ai(
                    technology=technology,
                    client_data=client_results,
                    ai_service=ai_service,
                )
                if ai_out:
                    store.save_ai_analysis(slug, ai_out.model_dump())
            except Exception as ai_exc:
                logger.warning("Falha ao executar análise de IA para dicionário de %s: %s", slug, ai_exc)

        raw_data = store.get_technology_data(slug) or {}
        return _build_detail_out_from_dict(raw_data, technology)
    except Exception as exc:
        err_msg = f"Falha na varredura de telemetria da tecnologia '{technology.name}': {exc}"
        logger.error(err_msg, exc_info=True)
        store.set_error(slug, str(exc))
        raw_data = store.get_technology_data(slug) or {}
        return _build_detail_out_from_dict(raw_data, technology)
    finally:
        store.set_scanning(slug, False)


def _build_detail_out_from_dict(raw: dict[str, Any], technology: Technology) -> FieldDictionaryDetailOut:
    clients_dict = raw.get("clients", {})
    client_items: list[FieldDictionaryClientItem] = []
    for c_id, c_val in clients_dict.items():
        client_items.append(
            FieldDictionaryClientItem(
                client_uid=str(c_val.get("client_uid") or c_id),
                client_name=str(c_val.get("client_name") or c_id),
                total_fields=int(c_val.get("total_fields") or 0),
                fields=c_val.get("fields") or [],
                sample_values=c_val.get("sample_values") or {},
                last_scanned_at=c_val.get("last_scanned_at"),
            )
        )
    client_items.sort(key=lambda x: x.client_name.lower())

    ai_dict = raw.get("ai_analysis")
    ai_analysis_obj = FieldDictionaryAIAnalysisOut(**ai_dict) if ai_dict else None

    return FieldDictionaryDetailOut(
        technology_slug=technology.slug,
        technology_name=technology.name,
        rule_groups_regex=raw.get("rule_groups_regex") or technology.effective_groups_regex,
        total_unique_fields=raw.get("total_unique_fields", 0),
        all_fields=raw.get("all_fields", []),
        client_count=len(client_items),
        clients=client_items,
        last_updated_at=raw.get("last_updated_at"),
        is_scanning=bool(raw.get("is_scanning", False)),
        last_error=raw.get("last_error"),
        ai_analysis=ai_analysis_obj,
    )


async def analyze_technology_discrepancies_with_ai(
    technology: Technology,
    client_data: list[dict[str, Any]],
    ai_service: AIService,
) -> FieldDictionaryAIAnalysisOut:
    """Utiliza IA para avaliar discrepâncias de campos entre clientes na mesma tecnologia."""
    active_clients = [c for c in client_data if len(c.get("fields", [])) > 0]
    all_fields_map: dict[str, list[str]] = {}

    for c in client_data:
        c_name = str(c.get("client_name") or c.get("client_uid"))
        for f in c.get("fields", []):
            all_fields_map.setdefault(f, []).append(c_name)

    all_client_names = [str(c.get("client_name") or c.get("client_uid")) for c in client_data]
    total_active = len(active_clients)

    discrepancies: list[FieldDictionaryDiscrepancyItem] = []
    for f, present_clients in sorted(all_fields_map.items()):
        if len(present_clients) < total_active and total_active > 1:
            missing_clients = [c for c in all_client_names if c not in present_clients]
            impact = "high" if any(k in f.lower() for k in ("eventid", "id", "action", "ip", "user", "src")) else "medium"
            discrepancies.append(
                FieldDictionaryDiscrepancyItem(
                    field=f,
                    present_in_clients=present_clients,
                    missing_in_clients=missing_clients,
                    category="telemetry_gap",
                    impact=impact,
                    notes=f"Ausente em {len(missing_clients)} cliente(s)",
                )
            )

    # Prepara prompt resumido para a IA
    client_field_summary = {
        str(c.get("client_name") or c.get("client_uid")): {
            "total_fields": len(c.get("fields", [])),
            "sample_fields": c.get("fields", [])[:25],
        }
        for c in client_data
    }

    prompt_content = f"""Você é o Engenheiro Especialista em Detecção e Telemetria do SIEM D.A.N.T.E.
Analise a telemetria da tecnologia '{technology.name}' (slug: {technology.slug}, rule_groups: {technology.effective_groups_regex}) nos clientes atendidos.

Dados dos clientes:
{json.dumps(client_field_summary, indent=2, ensure_ascii=False)}

Discrepâncias de campos detectadas ({len(discrepancies)} campos):
{json.dumps([d.model_dump() for d in discrepancies[:30]], indent=2, ensure_ascii=False)}

Forneça um parecer técnico estruturado em JSON com as chaves:
- "summary": Resumo executivo da consistência de schema e telemetria da tecnologia.
- "version_analysis": Avaliação de possíveis versões diferentes de produto/agente/OS gerando os logs entre os clientes.
- "format_and_schema_analysis": Avaliação se o formato do log é idêntico (ex: JSON estruturado, syslog raw, Wazuh data_* mapping) ou se há divergência de pipeline.
- "language_and_localization": Análise sobre idioma do log ou localização do sistema (ex: EventIDs em inglês vs português, descrições traduzidas).
- "recommendations": Lista de recomendações para padronização e garantia de cobertura das regras de detecção.
"""

    sys_prompt = "Você é um especialista em telemetria Wazuh, Grafana Loki, Windows Event Logs, Sysmon, Firewalls e WAFs. Responda estritamente em JSON válido."

    try:
        cfg = ai_service.get_raw_settings()
        client = AIUniversalClient(
            provider=cfg.provider,
            model=cfg.model,
            api_key=cfg.api_key,
            api_base_url=cfg.api_base_url,
            timeout_seconds=ai_service.app_settings.ai_timeout_seconds,
            temperature=cfg.temperature,
        )
        raw_resp = await client.generate_json(
            system_prompt=sys_prompt,
            user_prompt=prompt_content,
        )
        model_name = getattr(client, "model", "DeepSeek")
        return FieldDictionaryAIAnalysisOut(
            technology_slug=technology.slug,
            technology_name=technology.name,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            ai_model_used=model_name,
            summary=str(raw_resp.get("summary") or "Telemetria consolidada entre os clientes."),
            version_analysis=str(raw_resp.get("version_analysis") or "Versões consistentes ou diferenças menores de compilação."),
            format_and_schema_analysis=str(raw_resp.get("format_and_schema_analysis") or "Schema formatado com prefixo padronizado data_*."),
            language_and_localization=str(raw_resp.get("language_and_localization") or "Padrão de mensagens e eventos homogêneo."),
            recommendations=list(raw_resp.get("recommendations") or []),
            discrepancies=discrepancies[:40],
        )
    except Exception as exc:
        logger.warning("Falha na chamada ao modelo de IA para discrepâncias: %s", exc)
        # Fallback heurístico inteligente
        return FieldDictionaryAIAnalysisOut(
            technology_slug=technology.slug,
            technology_name=technology.name,
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            ai_model_used="Heurística D.A.N.T.E.",
            summary=f"Mapeamento concluído com {len(discrepancies)} discrepância(s) de campos identificada(s) entre os clientes.",
            version_analysis="Possível diferença nas fontes de eventos ativas ou níveis de auditoria configurados entre os tenants.",
            format_and_schema_analysis="Schema processado via decoders Wazuh com extração de chaves JSON planas.",
            language_and_localization="Recomenda-se validar se os canais de evento operam no mesmo locale para campos de texto livre.",
            recommendations=[
                "Verificar se todos os clientes possuem os mesmos módulos/canais de auditoria habilitados.",
                "Padronizar decoders Wazuh para enriquecer campos comuns faltantes.",
            ],
            discrepancies=discrepancies[:40],
        )


def compute_next_weekly_run(
    day_of_week: int = 0,
    hour: int = 3,
    minute: int = 0,
    tz_offset: int = -3,
) -> datetime:
    """Calcula o próximo disparo semanal (0=Segunda, 6=Domingo)."""
    tz = timezone(timedelta(hours=tz_offset))
    now_local = datetime.now(tz)
    target = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)

    # Dias até o próximo day_of_week
    days_ahead = (day_of_week - now_local.weekday()) % 7
    if days_ahead == 0 and target <= now_local:
        days_ahead = 7
    target = target + timedelta(days=days_ahead)
    return target


async def weekly_field_dictionary_scheduler_loop(
    grafana: GrafanaClient,
    tech_store: TechnologyStore,
    dict_store: FieldDictionaryStore,
    sys_settings: SystemSettingsStore,
    ai_service: AIService | None = None,
) -> None:
    """Loop assíncrono em background que executa a coleta do dicionário semanalmente."""
    logger.info("Scheduler do Dicionário de Campos semanal inicializado.")
    while True:
        try:
            sched = sys_settings.get_field_dictionary_schedule()
            if not sched.enabled:
                await asyncio.sleep(60)
                continue

            next_run = compute_next_weekly_run(
                day_of_week=sched.day_of_week,
                hour=sched.hour,
                minute=sched.minute,
                tz_offset=sched.timezone_offset_hours,
            )
            tz = timezone(timedelta(hours=sched.timezone_offset_hours))
            now_local = datetime.now(tz)
            wait_seconds = max((next_run - now_local).total_seconds(), 5.0)

            logger.info(
                "Dicionário de Campos: próxima varredura semanal agendada para %s (espera de %.1fs)",
                next_run.isoformat(),
                wait_seconds,
            )
            await asyncio.sleep(wait_seconds)

            # Executa a coleta para todas as tecnologias ativas
            techs = tech_store.list_all()
            for tech in techs:
                if tech.enabled:
                    logger.info("Dicionário de Campos: iniciando varredura semanal para '%s'...", tech.slug)
                    try:
                        await scan_technology_fields_across_clients(
                            technology=tech,
                            grafana=grafana,
                            store=dict_store,
                            sys_settings=sys_settings,
                            ai_service=ai_service,
                        )
                    except Exception as t_exc:
                        logger.error("Erro na varredura semanal da tecnologia %s: %s", tech.slug, t_exc)
                    await asyncio.sleep(2.0)

        except asyncio.CancelledError:
            logger.info("Scheduler do Dicionário de Campos cancelado.")
            break
        except Exception as exc:
            logger.error("Erro inesperado no scheduler do Dicionário de Campos: %s", exc)
            await asyncio.sleep(60)

