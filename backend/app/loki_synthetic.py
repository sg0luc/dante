"""Injeção de logs sintéticos no Loki (laboratório de detecção).

Este módulo concentra a **lógica pura** (sem I/O) do laboratório de logs do
portal: validação de labels, montagem do payload de push, geração das queries
LogQL auxiliares e do link do Grafana Explore. O router apenas orquestra essas
funções com o cliente do Grafana.

Regras de segurança (o Loki aceita escritas sem autenticação na rede interna,
então a validação é a fronteira):

  * Labels com nome no padrão Prometheus (``^[a-zA-Z_][a-zA-Z0-9_]{0,63}$``) e
    prefixo ``__`` reservado / proibido.
  * Valores de label restritos a um charset seguro (sem aspas, barra invertida,
    backtick ou newline) — evita quebra/quebra de contexto na LogQL gerada.
  * ``job`` é obrigatório: sem ele a linha não é alcançável pelas regras do
    baseline (a arquitetura usa ``job="wazuh"`` para todo o pipeline).
  * Teto de 200 linhas, 64 KiB por linha e 256 KiB por requisição.
  * Toda linha recebe ``synthetic="true"`` (e ``synthetic_source="portal"`` por
    padrão), permitindo filtrar/purgar dados de laboratório no Explore.

Formato aceito pelo Loki (JSON, sem protobuf/snappy):

    POST /loki/api/v1/push
    {
      "streams": [
        {"stream": {"job": "wazuh", "...": "..."},
         "values": [["<nanossegundos>", "<linha JSON>"], ...]}
      ]
    }
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import quote

MAX_LINES = 200
MAX_LINE_BYTES = 64 * 1024
MAX_PAYLOAD_BYTES = 256 * 1024
MAX_LABELS = 20
MAX_SPREAD_SECONDS = 86_400
MANDATORY_LABEL = "job"

SYNTHETIC_LABEL = "synthetic"
SYNTHETIC_SOURCE_LABEL = "synthetic_source"
SYNTHETIC_SOURCE_VALUE = "portal"

_LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$")
# Charset seguro para valores de label e para interpolação em LogQL.
_LABEL_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,200}$")


class SyntheticLogError(ValueError):
    """Entrada inválida para o laboratório de logs (mensagem exposta ao usuário)."""


def validate_stream(stream: dict[str, str], *, mark_synthetic: bool = True) -> dict[str, str]:
    """Valida e normaliza o conjunto de labels do stream.

    Devolve o dicionário final (incluindo as labels de marcação) pronto para o
    Loki. Levanta ``SyntheticLogError`` com mensagem acionável em caso de erro.
    """
    if not isinstance(stream, dict) or not stream:
        raise SyntheticLogError("Informe ao menos uma label para o stream.")
    if len(stream) > MAX_LABELS:
        raise SyntheticLogError(f"Máximo de {MAX_LABELS} labels por stream.")

    normalized: dict[str, str] = {}
    for raw_key, raw_value in stream.items():
        key = str(raw_key).strip()
        if not _LABEL_NAME_RE.match(key):
            raise SyntheticLogError(
                f"Label inválida: {key!r}. Use letras, números e '_' "
                "(começando por letra ou '_')."
            )
        if key.startswith("__"):
            raise SyntheticLogError(f"A label {key!r} usa o prefixo reservado '__'.")
        if isinstance(raw_value, bool) or raw_value is None:
            raise SyntheticLogError(f"Label {key!r} precisa de um valor textual.")
        value = str(raw_value).strip()
        if not value:
            raise SyntheticLogError(f"A label {key!r} está vazia.")
        if not _LABEL_VALUE_RE.match(value):
            raise SyntheticLogError(
                f"Valor inválido para a label {key!r}: use até 200 caracteres "
                "entre letras, números e _ . : / @ + -"
            )
        normalized[key] = value

    if MANDATORY_LABEL not in normalized:
        raise SyntheticLogError(
            "A label 'job' é obrigatória (a arquitetura usa job=\"wazuh\"); "
            "sem ela a linha não é alcançável pelas regras do baseline."
        )

    if mark_synthetic:
        normalized[SYNTHETIC_LABEL] = "true"
        # Não sobrescreve uma origem informada pelo usuário.
        normalized.setdefault(SYNTHETIC_SOURCE_LABEL, SYNTHETIC_SOURCE_VALUE)

    return normalized


def build_values(lines: list[dict[str, Any]], spread_seconds: int) -> tuple[list[list[str]], int]:
    """Serializa as linhas JSON e distribui os timestamps na janela informada.

    Os timestamps são nanossegundos (como exige o Loki) e ficam sempre no
    passado, em ordem crescente — o Loki rejeita séries fora de ordem.
    Devolve ``(values, total_bytes)``.
    """
    if not lines:
        raise SyntheticLogError("Envie ao menos uma linha de log.")
    if len(lines) > MAX_LINES:
        raise SyntheticLogError(f"Máximo de {MAX_LINES} linhas por requisição.")
    if spread_seconds < 0 or spread_seconds > MAX_SPREAD_SECONDS:
        raise SyntheticLogError(
            f"A janela de distribuição deve ficar entre 0 e {MAX_SPREAD_SECONDS} segundos."
        )

    total = 0
    serialized: list[str] = []
    for index, line in enumerate(lines, start=1):
        if not isinstance(line, dict):
            raise SyntheticLogError(f"A linha {index} precisa ser um objeto JSON.")
        try:
            text = json.dumps(line, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise SyntheticLogError(f"A linha {index} não é serializável em JSON.") from exc
        size = len(text.encode("utf-8"))
        if size > MAX_LINE_BYTES:
            raise SyntheticLogError(f"A linha {index} excede {MAX_LINE_BYTES} bytes.")
        total += size
        if total > MAX_PAYLOAD_BYTES:
            raise SyntheticLogError(
                f"O conjunto de linhas excede {MAX_PAYLOAD_BYTES} bytes; reduza o volume."
            )
        serialized.append(text)

    count = len(serialized)
    window_ns = max(spread_seconds, 1) * 1_000_000_000
    step = max(window_ns // count, 1_000_000)  # no mínimo 1 ms entre linhas
    now_ns = time.time_ns()
    first_ns = now_ns - count * step

    values = [
        [str(first_ns + index * step), text]
        for index, text in enumerate(serialized)
    ]
    return values, total


def build_push_payload(
    stream: dict[str, str], lines: list[dict[str, Any]], spread_seconds: int
) -> tuple[dict[str, Any], int]:
    """Monta o corpo aceito por ``POST /loki/api/v1/push`` e o tamanho em bytes."""
    values, total_bytes = build_values(lines, spread_seconds)
    return {"streams": [{"stream": stream, "values": values}]}, total_bytes


def stream_selector(stream: dict[str, str]) -> str:
    """Converte as labels em um seletor LogQL ``{k="v", ...}`` (chaves ordenadas)."""
    pairs = ", ".join(f"{key}={json.dumps(value)}" for key, value in sorted(stream.items()))
    return "{" + pairs + "}"


def build_count_query(selector: str, window_seconds: int) -> str:
    """Query instantânea que conta as linhas do seletor na janela informada."""
    window = max(int(window_seconds), 60)
    return f"sum(count_over_time({selector} [{window}s]))"


def build_explore_url(
    grafana_public_url: str,
    query: str,
    *,
    datasource: str = "loki",
    minutes: int = 15,
) -> str | None:
    """Monta o link do Grafana Explore já posicionado na query injetada."""
    if not grafana_public_url:
        return None
    left = {
        "datasource": datasource,
        "queries": [{"refId": "A", "expr": query, "queryType": "range"}],
        "range": {"from": f"now-{minutes}m", "to": "now"},
    }
    encoded = quote(json.dumps(left, separators=(",", ":")), safe="")
    return f"{grafana_public_url.rstrip('/')}/explore?left={encoded}"
