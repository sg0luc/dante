"""Definições e catálogo de provedores de Inteligência Artificial suportados pelo D.A.N.T.E.

Suporta:
- DeepSeek (Padrão inicial - deepseek-chat / deepseek-reasoner)
- OpenAI (gpt-4o-mini / gpt-4o)
- Google Gemini (gemini-2.0-flash / gemini-1.5-flash)
- Anthropic Claude (claude-3-5-haiku / claude-3-5-sonnet)
- Ollama / Local (deepseek-r1:8b / qwen2.5-coder:7b / etc.)
"""

from __future__ import annotations

from typing import Any

AVAILABLE_AI_PROVIDERS: list[dict[str, Any]] = [
    {
        "id": "deepseek",
        "name": "DeepSeek",
        "badge": "Recomendado",
        "description": "Modelo de alto desempenho e baixíssimo custo para engenharia de detecção e raciocínio analítico.",
        "default_model": "deepseek-chat",
        "models": [
            {
                "id": "deepseek-chat",
                "name": "DeepSeek-V3 (deepseek-chat)",
                "description": "Excelente para tradução de regras, síntese LogQL e análise de cibersegurança.",
            },
            {
                "id": "deepseek-reasoner",
                "name": "DeepSeek-R1 (deepseek-reasoner)",
                "description": "Modo de raciocínio profundo para cadeias complexas de ataque e correlações MITRE.",
            },
        ],
        "requires_api_key": True,
        "default_base_url": "https://api.deepseek.com",
        "api_key_placeholder": "sk-...",
        "help_url": "https://platform.deepseek.com/api_keys",
    },
    {
        "id": "openai",
        "name": "OpenAI",
        "badge": "Popular",
        "description": "Modelos GPT para geração estruturada de código com alta fidelidade de sintaxe.",
        "default_model": "gpt-4o-mini",
        "models": [
            {
                "id": "gpt-4o-mini",
                "name": "GPT-4o mini",
                "description": "Rápido, econômico e eficiente para geração de queries LogQL.",
            },
            {
                "id": "gpt-4o",
                "name": "GPT-4o",
                "description": "Maior capacidade analítica para regras e técnicas avançadas.",
            },
        ],
        "requires_api_key": True,
        "default_base_url": "https://api.openai.com/v1",
        "api_key_placeholder": "sk-...",
        "help_url": "https://platform.openai.com/api-keys",
    },
    {
        "id": "gemini",
        "name": "Google Gemini",
        "badge": "Rápido",
        "description": "Modelos Gemini da Google com contexto amplo e alta velocidade de resposta.",
        "default_model": "gemini-2.0-flash",
        "models": [
            {
                "id": "gemini-2.0-flash",
                "name": "Gemini 2.0 Flash",
                "description": "Nova geração de modelos da Google com velocidade extrema e suporte a JSON.",
            },
            {
                "id": "gemini-1.5-flash",
                "name": "Gemini 1.5 Flash",
                "description": "Baixíssima latência e consumo mínimo de recursos.",
            },
            {
                "id": "gemini-1.5-pro",
                "name": "Gemini 1.5 Pro",
                "description": "Capacidade ampliada de raciocínio e análise tecnológica.",
            },
        ],
        "requires_api_key": True,
        "default_base_url": "https://generativelanguage.googleapis.com/v1beta",
        "api_key_placeholder": "AIzaSy...",
        "help_url": "https://aistudio.google.com/app/apikey",
    },
    {
        "id": "anthropic",
        "name": "Anthropic Claude",
        "badge": "Analítico",
        "description": "Modelos Claude focados em segurança, mitigação de ameaças e redução de alucinações.",
        "default_model": "claude-3-5-haiku-20241022",
        "models": [
            {
                "id": "claude-3-5-haiku-20241022",
                "name": "Claude 3.5 Haiku",
                "description": "Ágil e econômico para tradução de queries.",
            },
            {
                "id": "claude-3-5-sonnet-20241022",
                "name": "Claude 3.5 Sonnet",
                "description": "Referência em raciocínio de segurança e Threat Intelligence.",
            },
        ],
        "requires_api_key": True,
        "default_base_url": "https://api.anthropic.com/v1",
        "api_key_placeholder": "sk-ant-...",
        "help_url": "https://console.anthropic.com/settings/keys",
    },
    {
        "id": "ollama",
        "name": "Ollama / Local (On-Premise)",
        "badge": "100% Privado",
        "description": "Execução local sem envio de dados para serviços externos em nuvem (Air-gapped).",
        "default_model": "deepseek-r1:8b",
        "models": [
            {
                "id": "deepseek-r1:8b",
                "name": "DeepSeek-R1 (Local)",
                "description": "Modelo de raciocínio executado na sua infraestrutura local.",
            },
            {
                "id": "qwen2.5-coder:7b",
                "name": "Qwen 2.5 Coder 7B",
                "description": "Especialista em geração e validação de código/queries.",
            },
            {
                "id": "llama3.1:8b",
                "name": "Llama 3.1 8B",
                "description": "Modelo versátil para tarefas gerais de cibersegurança.",
            },
        ],
        "requires_api_key": False,
        "default_base_url": "http://host.docker.internal:11434/v1",
        "api_key_placeholder": "(Não obrigatório)",
        "help_url": "https://ollama.com",
    },
]

