"""Cliente assíncrono da API HTTP do Grafana.

Encapsula todas as chamadas ao Grafana. Pontos de segurança:
  * O token da service account é lido do arquivo (ou variável) apenas aqui e
    enviado somente ao Grafana; nunca é logado nem devolvido ao frontend.
  * Redirecionamentos NÃO são seguidos (evita vazar o token para outro host).
  * Erros do Grafana são convertidos em mensagens genéricas; detalhes vão
    apenas para o log do backend.

Endpoints utilizados (documentação oficial do Grafana):
  * Regras (configuração):  GET /api/v1/provisioning/alert-rules[/{uid}]
    https://grafana.com/docs/grafana/latest/developers/http_api/alerting_provisioning/
  * Regras (estado atual):  GET /api/prometheus/grafana/api/v1/rules
  * Alertas (instâncias):   GET /api/alertmanager/grafana/api/v2/alerts
  * Silences:               GET /api/alertmanager/grafana/api/v2/silences
  * Pastas:                 GET /api/search?type=dash-folder
  * Saúde:                  GET /api/health
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from . import __version__
from .config import Settings

logger = logging.getLogger(__name__)


class GrafanaError(Exception):
    """Falha ao comunicar com o Grafana, com mensagem segura para o cliente."""

    def __init__(self, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class GrafanaClient:
    """Cliente HTTP compartilhado (pool de conexões) para a API do Grafana."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._token_cache: tuple[float, str] | None = None
        self._http = httpx.AsyncClient(
            base_url=settings.grafana_url,
            timeout=settings.grafana_timeout_seconds,
            verify=settings.grafana_verify_tls,
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "User-Agent": f"grafana-hunter-portal/{__version__}",
            },
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Token
    # ------------------------------------------------------------------
    def _token(self) -> str:
        """Obtém o token; relê o arquivo somente quando ele muda (mtime)."""
        if self._settings.is_external_grafana and self._settings.grafana_token is not None:
            return self._settings.grafana_token.get_secret_value()

        path = self._settings.grafana_token_file
        if path and os.path.isfile(path):
            try:
                mtime = os.stat(path).st_mtime
                if self._token_cache and self._token_cache[0] == mtime:
                    return self._token_cache[1]
                with open(path, encoding="utf-8") as handle:
                    token = handle.read().strip()
                if token:
                    self._token_cache = (mtime, token)
                    return token
            except OSError as exc:
                logger.error("Não foi possível ler o token do Grafana em %s: %s", path, exc.strerror)

        if self._settings.grafana_token is not None:
            return self._settings.grafana_token.get_secret_value()

        if not path:
            raise GrafanaError("Token do Grafana não configurado", 503)
        raise GrafanaError("Token do Grafana indisponível", 503)

    def has_token(self) -> bool:
        try:
            self._token()
            return True
        except GrafanaError:
            return False

    # ------------------------------------------------------------------
    # Requisição genérica
    # ------------------------------------------------------------------
    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        headers = {"Authorization": f"Bearer {self._token()}"}
        if extra_headers:
            headers.update(extra_headers)
        try:
            response = await self._http.request(
                method, path, params=params, json=json, headers=headers
            )
        except httpx.TimeoutException as exc:
            logger.warning("Timeout em %s %s", method, path)
            raise GrafanaError("Tempo esgotado ao consultar o Grafana", 504) from exc
        except httpx.HTTPError as exc:
            logger.warning("Erro de conexão em %s %s: %s", method, path, type(exc).__name__)
            raise GrafanaError("Grafana indisponível", 502) from exc

        if response.status_code in (401, 403):
            logger.error(
                "Grafana recusou o token do portal (%s) em %s %s",
                response.status_code, method, path,
            )
            raise GrafanaError("O Grafana recusou as credenciais do portal", 502)
        if response.status_code == 404:
            raise GrafanaError("Recurso não encontrado no Grafana", 404)
        if response.status_code >= 400:
            detail = (response.text or "").strip().replace("\n", " ")[:200]
            logger.warning(
                "Grafana respondeu %s em %s %s: %.500s",
                response.status_code, method, path, response.text,
            )
            raise GrafanaError(
                f"Erro retornado pelo Grafana (HTTP {response.status_code})"
                + (f": {detail}" if detail else ""),
                502,
            )

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            logger.warning("Resposta não-JSON do Grafana em %s %s", method, path)
            raise GrafanaError("Resposta inválida do Grafana", 502) from exc

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------
    async def is_healthy(self) -> bool:
        """Verifica /api/health (não requer autenticação)."""
        try:
            response = await self._http.get("/api/health")
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def list_alert_rules(self) -> list[dict[str, Any]]:
        """Configuração de todas as regras (Grafana-managed)."""
        return await self._request("GET", "/api/v1/provisioning/alert-rules") or []

    async def get_alert_rule(self, uid: str) -> dict[str, Any]:
        """Configuração de uma regra específica. ``uid`` já validado pelo router."""
        return await self._request("GET", f"/api/v1/provisioning/alert-rules/{uid}")

    async def list_contact_points(self) -> list[dict[str, Any]]:
        """Contact Points configurados no Grafana (rotas de notificação das regras).

        É a rota para a qual ``notification_settings.receiver`` da regra aponta;
        o portal usa o nome para derivar o estágio de deploy (dev/stg/prod).
        """
        return await self._request("GET", "/api/v1/provisioning/contact-points") or []

    async def list_rule_groups(self) -> list[dict[str, Any]]:
        """Estado de avaliação das regras (API compatível com Prometheus)."""
        payload = await self._request("GET", "/api/prometheus/grafana/api/v1/rules") or {}
        return (payload.get("data") or {}).get("groups") or []

    async def list_folders(self) -> list[dict[str, Any]]:
        """Todas as pastas (inclusive aninhadas), para resolver UID -> título."""
        return await self._request(
            "GET", "/api/search", params={"type": "dash-folder", "limit": 5000}
        ) or []

    async def list_alerts(self) -> list[dict[str, Any]]:
        """Instâncias de alerta atuais no Alertmanager interno do Grafana."""
        return await self._request(
            "GET",
            "/api/alertmanager/grafana/api/v2/alerts",
            params={"active": "true", "silenced": "true", "inhibited": "true"},
        ) or []

    async def list_annotations(
        self,
        *,
        alert_uid: str | None = None,
        type: str = "alert",
        time_from_ms: int | None = None,
        time_to_ms: int | None = None,
        limit: int = 5000,
    ) -> list[dict[str, Any]]:
        """Anotações de transições de alertas no Grafana via ``GET /api/annotations``."""
        params: dict[str, Any] = {"limit": limit}
        if type:
            params["type"] = type
        if alert_uid:
            params["alertUID"] = alert_uid
        if time_from_ms is not None:
            params["from"] = time_from_ms
        if time_to_ms is not None:
            params["to"] = time_to_ms
        data = await self._request("GET", "/api/annotations", params=params)
        return data if isinstance(data, list) else []

    async def list_rule_annotations(
        self,
        rule_uid: str,
        *,
        time_from_ms: int | None = None,
        time_to_ms: int | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Histórico de transições de estado de uma regra via ``GET /api/annotations``.

        O Grafana Unified Alerting registra cada transição (``Normal -> Alerting``,
        ``Alerting -> Normal``, ``NoData``, ``Paused`` etc.) como anotação amarrada ao
        ``alertUID`` da regra, preservando labels e valores avaliados (``data.values``).
        """
        params: dict[str, Any] = {"alertUID": rule_uid, "limit": limit}
        if time_from_ms is not None:
            params["from"] = time_from_ms
        if time_to_ms is not None:
            params["to"] = time_to_ms
        data = await self._request("GET", "/api/annotations", params=params)
        return data if isinstance(data, list) else []

    async def list_silences(self) -> list[dict[str, Any]]:
        """Todos os silences (ativos, pendentes e expirados recentemente)."""
        return await self._request("GET", "/api/alertmanager/grafana/api/v2/silences") or []

    async def get_silence(self, silence_id: str) -> dict[str, Any]:
        """Obtém os detalhes de um silence específico no Alertmanager."""
        return await self._request("GET", f"/api/alertmanager/grafana/api/v2/silence/{silence_id}")

    async def create_silence(self, payload: dict[str, Any]) -> str:
        """Cria um novo silence no Alertmanager interno do Grafana."""
        data = await self._request(
            "POST",
            "/api/alertmanager/grafana/api/v2/silences",
            json=payload,
        )
        return str(data.get("silenceID", ""))

    async def extend_silence(
        self, silence_id: str, new_ends_at: str, user_name: str
    ) -> str:
        """Prolonga o término de um silence existente no Alertmanager."""
        current = await self.get_silence(silence_id)
        payload = {
            "id": silence_id,
            "matchers": current.get("matchers") or [],
            "startsAt": current.get("startsAt"),
            "endsAt": new_ends_at,
            "createdBy": user_name or current.get("createdBy", "hunter"),
            "comment": f"{current.get('comment', '')} (prolongado por {user_name})".strip(),
        }
        data = await self._request(
            "POST",
            "/api/alertmanager/grafana/api/v2/silences",
            json=payload,
        )
        return str(data.get("silenceID", silence_id))

    async def delete_silence(self, silence_id: str) -> None:
        """Expira/deleta um silence existente pelo seu ID."""
        await self._request(
            "DELETE",
            f"/api/alertmanager/grafana/api/v2/silence/{silence_id}",
        )

    async def toggle_rule_pause(self, uid: str, paused: bool) -> dict[str, Any]:
        """Altera o status de pausa (isPaused) de uma regra de alerta."""
        rule = await self.get_alert_rule(uid)
        rule["isPaused"] = paused
        return await self.update_alert_rule(uid, rule)

    async def create_folder(self, title: str, uid: str | None = None) -> dict[str, Any]:
        """Cria uma nova pasta no Grafana (equivalente a um cliente SIEM)."""
        payload: dict[str, Any] = {"title": title}
        if uid:
            payload["uid"] = uid
        return await self._request(
            "POST",
            "/api/folders",
            json=payload,
            extra_headers={"X-Disable-Provenance": "true"},
        )

    async def delete_folder(self, uid: str, force_delete_rules: bool = False) -> dict[str, Any]:
        """Exclui uma pasta no Grafana pelo seu UID via ``/api/folders/{uid}``.

        ``force_delete_rules`` é necessário quando a pasta contém regras (o Grafana
        responde 400 ``folder.not-empty`` sem ele) — usado na exclusão de tenant,
        que só chega aqui após confirmar que não há regras de detecção reais.
        """
        params = {"forceDeleteRules": "true"} if force_delete_rules else None
        return await self._request(
            "DELETE",
            f"/api/folders/{uid}",
            params=params,
            extra_headers={"X-Disable-Provenance": "true"},
        )


    async def create_alert_rule(self, rule_payload: dict[str, Any]) -> dict[str, Any]:
        """Cria uma nova regra de alerta via API de Provisioning do Grafana.

        O payload é saneado antes do POST: campos que identificam o recurso de
        origem (``id``, ``orgID``, ``updated``) e, principalmente, ``provenance``
        e ``readOnly`` são removidos. O Grafana **honra** ``provenance`` vindo no corpo e, quando
        ele é ``api``, a regra nasce "Provisioned" (read-only) — clonar uma regra
        copiando o dicionário de origem fazia o clone herdar esse estado. O header
        ``X-Disable-Provenance`` só vale para o corpo sem proveniência, então os
        dois mecanismos são aplicados juntos.
        """
        payload = dict(rule_payload)
        for field in ("id", "orgID", "updated", "provenance", "readOnly"):
            payload.pop(field, None)
        return await self._request(
            "POST",
            "/api/v1/provisioning/alert-rules",
            json=payload,
            extra_headers={"X-Disable-Provenance": "true"},
        )

    async def update_alert_rule(
        self,
        uid: str,
        rule_payload: dict[str, Any],
        *,
        disable_provenance: bool | None = None,
    ) -> dict[str, Any]:
        """Atualiza uma regra de alerta existente via API de Provisioning do Grafana.

        O header ``X-Disable-Provenance`` só é aceito em regras **sem** proveniência
        gravada. Em regras com ``provenance`` (ex.: ``api``, criadas fora do portal),
        enviá-lo faz o Grafana responder 500 ``cannot change provenance from 'api'
        to ''``. Por isso o header é omitido automaticamente quando o payload traz
        ``provenance`` preenchido (caso dos objetos devolvidos por ``get_alert_rule``).
        """
        if disable_provenance is None:
            disable_provenance = not str(rule_payload.get("provenance") or "").strip()
        payload = dict(rule_payload)
        if disable_provenance:
            payload.pop("provenance", None)
            payload.pop("readOnly", None)
        extra_headers = {"X-Disable-Provenance": "true"} if disable_provenance else None
        return await self._request(
            "PUT",
            f"/api/v1/provisioning/alert-rules/{uid}",
            json=payload,
            extra_headers=extra_headers,
        )

    # ------------------------------------------------------------------
    async def set_rule_group_interval(
        self,
        folder_uid: str,
        group_name: str,
        interval_seconds: int = 300,
        *,
        force: bool = False,
    ) -> None:
        """Garante o intervalo de avaliação de um rule group e que nenhuma regra fique Provisioned.

        O Grafana Provisioning API, ao atualizar um rule group via PUT, marca todas as regras
        do grupo como 'provenance: api' caso o cabeçalho 'X-Disable-Provenance: true' não seja enviado.
        Sempre removemos 'provenance' e 'readOnly' das regras do grupo e enviamos o cabeçalho
        para que todos os objetos criados/ajustados continuem 100% editáveis pela GUI do Grafana.
        """
        try:
            current = await self._request(
                "GET", f"/api/v1/provisioning/folder/{folder_uid}/rule-groups/{group_name}"
            )
            if not isinstance(current, dict):
                return

            rules = current.get("rules") or []
            has_prov_or_readonly = any(
                isinstance(r, dict) and bool(r.get("provenance") or r.get("readOnly"))
                for r in rules
            )
            interval_differs = current.get("interval") != interval_seconds

            if interval_differs or has_prov_or_readonly or force:
                current["interval"] = interval_seconds
                for rule in rules:
                    if isinstance(rule, dict):
                        rule.pop("provenance", None)
                        rule.pop("readOnly", None)
                await self._request(
                    "PUT",
                    f"/api/v1/provisioning/folder/{folder_uid}/rule-groups/{group_name}",
                    json=current,
                    extra_headers={"X-Disable-Provenance": "true"},
                )
        except Exception as exc:
            logger.warning(
                "Não foi possível ajustar o intervalo do grupo '%s' na pasta '%s': %s",
                group_name,
                folder_uid,
                exc,
            )

    # Data sources — cada tenant possui um Loki próprio (segregação lógica)
    # ------------------------------------------------------------------
    async def list_datasources(self) -> list[dict[str, Any]]:
        """Lista todos os data sources configurados no Grafana."""
        return await self._request("GET", "/api/datasources") or []

    async def create_datasource(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Cria um data source via ``POST /api/datasources``.

        O payload é montado pelo chamador (tipo, uid, url, jsonData), pois cada
        integração tem requisitos próprios. Campos de estado/proveniência são
        removidos: ``provenance``/``readOnly`` no corpo fazem o data source
        aparecer como *Provisioned* (read-only) na UI do Grafana.
        """
        clean = {
            key: value
            for key, value in payload.items()
            if key not in ("provenance", "readOnly", "id", "version")
        }
        return await self._request(
            "POST",
            "/api/datasources",
            json=clean,
            extra_headers={"X-Disable-Provenance": "true"},
        ) or {}

    async def delete_datasource(self, uid: str) -> None:
        """Exclui um data source pelo UID (``DELETE /api/datasources/uid/{uid}``)."""
        await self._request(
            "DELETE",
            f"/api/datasources/uid/{uid}",
            extra_headers={"X-Disable-Provenance": "true"},
        )

    async def datasource_health(self, uid: str) -> bool:
        """Testa a conectividade de um data source (``.../health``).

        Retorna ``False`` em qualquer falha: a saúde é informativa, nunca deve
        derrubar a listagem de tenants quando a fonte está momentaneamente fora.
        """
        try:
            payload = await self._request("GET", f"/api/datasources/uid/{uid}/health")
        except GrafanaError:
            return False
        return str((payload or {}).get("status") or "").upper() == "OK"

    # ------------------------------------------------------------------
    # Loki (telemetria) — usado na validação implícita de tecnologias
    # ------------------------------------------------------------------
    async def find_loki_datasource(self) -> dict[str, Any] | None:
        """Localiza o datasource Loki configurado no Grafana.

        Preferência de seleção:
            1. o datasource provisionado pelo portal (``uid == "loki"``);
            2. qualquer Loki com URL configurada (funcional);
            3. o primeiro Loki encontrado.

        Retorna ``None`` quando o Grafana não possui datasource Loki — situação
        em que a presença de logs não pode ser comprovada e o portal não deve
        bloquear o cadastro de tecnologias.
        """
        datasources = await self._request("GET", "/api/datasources") or []
        lokis = [
            ds for ds in datasources
            if str(ds.get("type") or "") in ("loki", "grafana-loki-datasource")
        ]
        if not lokis:
            return None
        for datasource in lokis:
            if str(datasource.get("uid") or "").strip().casefold() == "loki":
                return datasource
        for datasource in lokis:
            if bool(datasource.get("isDefault", False)):
                return datasource
        for datasource in lokis:
            if str(datasource.get("name") or "").strip().casefold() == "loki":
                return datasource
        for datasource in lokis:
            if str(datasource.get("url") or "").strip():
                return datasource
        return lokis[0]

    async def loki_instant_query(self, datasource_uid: str, query: str) -> dict[str, Any]:
        """Executa uma query instantânea no Loki via proxy do datasource.

        Endpoint: ``GET /api/datasources/proxy/uid/{uid}/loki/api/v1/query``.
        Devolve o JSON bruto do Loki (``data.result`` vetorial/matricial).
        """
        payload = await self._request(
            "GET",
            f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/query",
            params={"query": query, "time": int(time.time()), "limit": 1},
        )
        return payload or {}

    async def loki_labels(self, datasource_uid: str) -> list[str]:
        """Lista os nomes de labels existentes no Loki (prova de conectividade).

        Endpoint: ``GET /api/datasources/proxy/uid/{uid}/loki/api/v1/labels``.
        """
        payload = await self._request(
            "GET",
            f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/labels",
        )
        data = (payload or {}).get("data") or []
        return [str(item) for item in data if isinstance(item, str)]

    async def loki_push(self, datasource_uid: str, payload: dict[str, Any]) -> None:
        """Envia linhas ao Loki via proxy do datasource (JSON, sem protobuf).

        Endpoint: ``POST /api/datasources/proxy/uid/{uid}/loki/api/v1/push``.
        O Loki responde 204 sem corpo em caso de sucesso.
        """
        await self._request(
            "POST",
            f"/api/datasources/proxy/uid/{datasource_uid}/loki/api/v1/push",
            json=payload,
        )
