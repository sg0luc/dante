"""Cliente HTTP assíncrono universal para chamadas de IA no D.A.N.T.E.

Suporta:
- DeepSeek (Padrão inicial - compatível com OpenAI API)
- OpenAI (gpt-4o-mini, gpt-4o)
- Google Gemini (API REST nativa v1beta)
- Anthropic Claude (Messages API)
- Ollama / Local (OpenAI-compatible)

Zero dependências externas pesadas (utiliza httpx.AsyncClient já incluído no projeto).
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from .providers import AVAILABLE_AI_PROVIDERS

logger = logging.getLogger("hunter_portal.ai.client")


class AIClientError(Exception):
    """Exceção levantada quando uma chamada de IA falha."""

    def __init__(self, message: str, status_code: int | None = None, detail: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail


def _extract_json_payload(text: str) -> dict[str, Any]:
    """Extrai e faz o parse de JSON mesmo se o modelo envolver a resposta em markdown codeblock."""
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("Resposta da IA vazia.")

    # Remove code blocks markdown ```json ... ``` se presentes
    code_block_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
    if code_block_match:
        cleaned = code_block_match.group(1).strip()

    # Se ainda houver texto antes ou depois das chaves externas
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1]

    return json.loads(cleaned)


class AIUniversalClient:
    """Cliente agnóstico e assíncrono para múltiplos provedores de LLM."""

    def __init__(
        self,
        provider: str = "deepseek",
        model: str = "deepseek-chat",
        api_key: str = "",
        api_base_url: str | None = None,
        timeout_seconds: float = 30.0,
        temperature: float = 0.1,
    ) -> None:
        self.provider = provider.strip().lower()
        self.model = model.strip()
        self.api_key = api_key.strip()
        self.api_base_url = api_base_url.strip() if api_base_url else None
        self.timeout_seconds = timeout_seconds
        self.temperature = max(0.0, min(2.0, temperature))

    def _resolve_base_url(self) -> str:
        if self.api_base_url:
            return self.api_base_url.rstrip("/")

        for p in AVAILABLE_AI_PROVIDERS:
            if p["id"] == self.provider:
                return str(p.get("default_base_url", "")).rstrip("/")

        return "https://api.deepseek.com"

    async def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Envia os prompts para o provedor de IA e retorna o JSON estruturado."""
        if self.provider in ("deepseek", "openai", "ollama"):
            return await self._call_openai_compatible(system_prompt, user_prompt)
        elif self.provider == "gemini":
            return await self._call_gemini(system_prompt, user_prompt)
        elif self.provider == "anthropic":
            return await self._call_anthropic(system_prompt, user_prompt)
        else:
            # Fallback para endpoint compatível com OpenAI
            return await self._call_openai_compatible(system_prompt, user_prompt)

    async def _call_openai_compatible(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Suporta DeepSeek, OpenAI e Ollama via endpoint /chat/completions."""
        base_url = self._resolve_base_url()
        url = f"{base_url}/chat/completions" if not base_url.endswith("/chat/completions") else base_url

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        model_lower = self.model.lower()
        is_reasoner = (
            "reasoner" in model_lower
            or "r1" in model_lower
            or "o1" in model_lower
            or "o3" in model_lower
        )

        body: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        # Modelos reasoner (como deepseek-reasoner e OpenAI o1/o3) não suportam response_format json_object nem temperature
        if not is_reasoner:
            body["temperature"] = self.temperature
            if self.provider != "ollama":
                body["response_format"] = {"type": "json_object"}
        elif self.provider == "ollama":
            body["format"] = "json"

        timeout_cfg = httpx.Timeout(
            timeout=self.timeout_seconds,
            connect=10.0,
            read=self.timeout_seconds,
            write=10.0,
            pool=5.0,
        )

        async with httpx.AsyncClient(timeout=timeout_cfg) as client:
            try:
                resp = await client.post(url, headers=headers, json=body)
            except httpx.TimeoutException as exc:
                raise AIClientError(
                    f"Timeout ({self.timeout_seconds:.0f}s) ao comunicar com a API do {self.provider.title()}.",
                    detail=str(exc),
                ) from exc
            except Exception as exc:
                raise AIClientError(
                    f"Erro de conexão com o provedor {self.provider.title()}: {str(exc)}",
                    detail=str(exc),
                ) from exc

        if resp.status_code >= 400:
            err_text = resp.text[:400]
            raise AIClientError(
                f"Erro na API {self.provider.title()} (HTTP {resp.status_code}): {err_text}",
                status_code=resp.status_code,
                detail=err_text,
            )

        try:
            res_json = resp.json()
            choices = res_json.get("choices") or []
            if not choices:
                raise ValueError("Nenhuma resposta retornada pelo modelo.")
            msg = choices[0].get("message") or {}
            content_str = msg.get("content") or msg.get("reasoning_content") or ""
            return _extract_json_payload(content_str)
        except Exception as exc:
            raise AIClientError(
                f"Falha ao interpretar JSON retornado pelo {self.provider.title()}: {str(exc)}",
                detail=resp.text[:300],
            ) from exc

    async def _call_gemini(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Chama a API REST nativa do Google Gemini."""
        base_url = self._resolve_base_url()
        url = f"{base_url}/models/{self.model}:generateContent"

        headers = {"Content-Type": "application/json"}
        params = {"key": self.api_key} if self.api_key else {}

        full_prompt = f"{system_prompt}\n\n---\n\n{user_prompt}"
        body = {
            "contents": [
                {
                    "parts": [{"text": full_prompt}],
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "responseMimeType": "application/json",
            },
        }

        timeout_cfg = httpx.Timeout(
            timeout=self.timeout_seconds,
            connect=10.0,
            read=self.timeout_seconds,
            write=10.0,
            pool=5.0,
        )

        async with httpx.AsyncClient(timeout=timeout_cfg) as client:
            try:
                resp = await client.post(url, headers=headers, params=params, json=body)
            except httpx.TimeoutException as exc:
                raise AIClientError(
                    f"Timeout ({self.timeout_seconds:.0f}s) ao comunicar com a API do Google Gemini.",
                    detail=str(exc),
                ) from exc
            except Exception as exc:
                raise AIClientError(
                    f"Erro de conexão com a API do Google Gemini: {str(exc)}",
                    detail=str(exc),
                ) from exc

        if resp.status_code >= 400:
            err_text = resp.text[:400]
            raise AIClientError(
                f"Erro na API Google Gemini (HTTP {resp.status_code}): {err_text}",
                status_code=resp.status_code,
                detail=err_text,
            )

        try:
            res_json = resp.json()
            candidates = res_json.get("candidates") or []
            if not candidates:
                raise ValueError("Nenhum candidato retornado pelo Gemini.")
            parts = candidates[0].get("content", {}).get("parts") or []
            content_str = parts[0].get("text", "") if parts else ""
            return _extract_json_payload(content_str)
        except Exception as exc:
            raise AIClientError(
                f"Falha ao interpretar JSON retornado pelo Google Gemini: {str(exc)}",
                detail=resp.text[:300],
            ) from exc

    async def _call_anthropic(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Chama a Messages API do Anthropic Claude."""
        base_url = self._resolve_base_url()
        url = f"{base_url}/messages"

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }

        body = {
            "model": self.model,
            "max_tokens": 2048,
            "temperature": self.temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

        timeout_cfg = httpx.Timeout(
            timeout=self.timeout_seconds,
            connect=10.0,
            read=self.timeout_seconds,
            write=10.0,
            pool=5.0,
        )

        async with httpx.AsyncClient(timeout=timeout_cfg) as client:
            try:
                resp = await client.post(url, headers=headers, json=body)
            except httpx.TimeoutException as exc:
                raise AIClientError(
                    f"Timeout ({self.timeout_seconds:.0f}s) ao comunicar com a API da Anthropic.",
                    detail=str(exc),
                ) from exc
            except Exception as exc:
                raise AIClientError(
                    f"Erro de conexão com a API da Anthropic: {str(exc)}",
                    detail=str(exc),
                ) from exc

        if resp.status_code >= 400:
            err_text = resp.text[:400]
            raise AIClientError(
                f"Erro na API Anthropic (HTTP {resp.status_code}): {err_text}",
                status_code=resp.status_code,
                detail=err_text,
            )

        try:
            res_json = resp.json()
            content_blocks = res_json.get("content") or []
            text_block = next((b.get("text", "") for b in content_blocks if b.get("type") == "text"), "")
            return _extract_json_payload(text_block)
        except Exception as exc:
            raise AIClientError(
                f"Falha ao interpretar JSON retornado pela Anthropic: {str(exc)}",
                detail=resp.text[:300],
            ) from exc

    async def test_connection(self) -> tuple[bool, str, int]:
        """Testa conectividade real com a API do provedor selecionado.

        Retorna: (success: bool, message: str, latency_ms: int)
        """
        t0 = time.perf_counter()
        test_system = "Você é um validador de conectividade. Responda estritamente em JSON com {\"status\": \"ok\", \"message\": \"conectado\"}."
        test_user = "Validação de ping do D.A.N.T.E. SIEM."

        try:
            res = await self.generate_json(test_system, test_user)
            latency_ms = int((time.perf_counter() - t0) * 1000)
            if isinstance(res, dict):
                return True, f"Conexão com {self.provider.title()} ({self.model}) estabelecida com sucesso!", latency_ms
            return False, f"Resposta inesperada do provedor: {str(res)[:100]}", latency_ms
        except AIClientError as exc:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return False, exc.message, latency_ms
        except Exception as exc:
            latency_ms = int((time.perf_counter() - t0) * 1000)
            return False, f"Erro inesperado ao conectar com {self.provider.title()}: {str(exc)[:160]}", latency_ms

