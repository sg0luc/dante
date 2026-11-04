# .agents — pacote de skills, subagents e regras (Antigravity)

Este diretório é descoberto automaticamente pelo Antigravity (App, CLI e IDE) e pode ser
versionado junto com o repositório. Nada aqui depende do Hermes: são arquivos Markdown com
frontmatter YAML no padrão aberto de skills (`agentskills.io`).

## Estrutura

```
.agents/
├── AGENTS.md                     # contexto always-on do projeto (sem frontmatter)
├── rules/                        # regras modulares (frontmatter obrigatório)
│   ├── backend-fastapi.md        # trigger: glob  → arquivos *.py
│   ├── frontend-react.md         # trigger: glob  → *.tsx, *.ts, *.css
│   ├── docker-grafana-loki.md    # trigger: glob  → compose, Dockerfile, grafana/, loki/
│   └── deteccao-logql.md         # trigger: model_decision → regras de detecção/telemetria
├── skills/
│   ├── dante-companion/          # arquitetura, regras de negócio, LogQL, pitfalls de API
│   │   ├── SKILL.md
│   │   ├── references/*.md
│   │   └── scripts/upsert_baseline_rules.py
│   ├── dante-entrega-git/        # gate de validação (build/E2E/screenshot) + git e PR
│   │   ├── SKILL.md
│   │   └── references/validacao-e-entrega.md
└── agents/                       # subagents customizados
    ├── dante-backend.md
    ├── dante-frontend.md
    ├── dante-detection.md
    ├── dante-e2e-qa.md
    └── dante-reviewer.md
```

## Como o Antigravity consome cada parte

- **Skills** (`skills/<nome>/SKILL.md`): descobertas no início da conversa pelo `name` +
  `description`; o agente lê o `SKILL.md` quando a tarefa casa (progressive disclosure).
  No CLI viram slash command: `/dante-companion`, `/dante-entrega-git`.
  Também é possível invocar explicitamente `@`-mencionando o nome.
- **Subagents** (`agents/<nome>.md`): o agente principal chama `invoke_subagent` quando a
  `description` casa com a tarefa; aparecem no painel `/agents`. `mainAgent: true` permite
  escolher o agente como principal.
- **Regras** (`rules/*.md`): `glob` ativa ao tocar arquivos do padrão; `model_decision` injeta
  só path + description e carrega o corpo sob demanda. `AGENTS.md` (na raiz de `.agents/`) é
  `always_on`: não usa frontmatter e entra inteiro no prompt a cada turno.
- **Referências e scripts** dentro de uma skill: lidos/executados apenas quando a skill pede,
  mantendo o contexto enxuto (`scripts/upsert_baseline_rules.py --help` antes de ler o código).

## Como usar em outra máquina / outro clone

1. Copie a pasta `.agents/` para a raiz do workspace (ou use `.agents/rules.json` com `entries`
   apontando para este diretório, se ele ficar fora do repo).
2. Alternativa global (todos os projetos): copie `skills/` para `~/.gemini/config/skills/` e
   `agents/` para `~/.gemini/config/agents/`.
3. Abra o painel **Customizations** do Antigravity para confirmar que skills, agentes e regras
   foram indexados.

## Manutenção

- Cada arquivo de regra precisa de frontmatter com `trigger` válido (`always_on`,
  `model_decision`, `glob`, `manual`); `description` é obrigatória em `model_decision` e
  `globs` em `glob`. Limite de 24 KB por arquivo.
- Nome de ferramenta em `tools` de um subagent precisa existir (`view_file`,
  `replace_file_content`, `grep_search`, `run_command`, ...): nome inválido pode travar o
  subagent.
- Mantenha a regra de negócio na skill (`references/arquitetura-e-regras-de-negocio.md`) e a
  receita operacional na skill de entrega — evite duplicar texto entre regra e skill.
