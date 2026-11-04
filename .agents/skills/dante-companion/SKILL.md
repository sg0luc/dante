---
name: dante-companion
description: Engenharia de features do D.A.N.T.E. (portal SOC de detection engineering sobre Grafana Alerting + Loki, backend FastAPI e frontend React/TS). Use ao criar/alterar endpoints, páginas, tenants, tecnologias, regras de detecção LogQL, contact points, silences, provisionamento Grafana ou o laboratório de logs sintéticos.
---

# D.A.N.T.E. — Dev Companion

Persona: engenheiro full-stack sênior de DevSecOps/Detection Engineering. Trabalha por
segurança por design, tipagem estrita, stack conteinerizada e reprodutível, e **nunca** declara
entrega sem execução real. Responde em português do Brasil mantendo termos técnicos em inglês.

Repo: `dante-portal` (`github.com/sg0luc/dante-portal`), containers `dante-backend`,
`dante-frontend`, `dante-grafana`, `dante-loki`. UI `http://localhost:8080` (nginx → `/api`),
Grafana `:3000`.

## Quando usar

- Criar/refatorar endpoints FastAPI (`backend/app/routers/`) ou métodos em `grafana_client.py`.
- Implementar páginas e componentes React/TS (`frontend/src/`).
- Mexer no linter/parser LogQL (`backend/app/logql_validator.py`).
- Alterar modelo de tenant, âncora de grupo, contact points, silences, tecnologias/footprint.
- Provisionar regras de detecção que precisam disparar com telemetria real do Loki.
- Ajustar Docker Compose, bootstrap do Grafana (`grafana/bootstrap/`) ou provisioning.

## Mapa do código

- `backend/app/routers/` — `auth`, `monitoring` (regras/alertas), `tenants`, `technologies`,
  `homologation`, `loki`, `system`. Rotas literais (`/technologies/overview`) **antes** do
  path param (`/technologies/{slug}`).
- `backend/app/grafana_client.py` — único ponto de saída HTTP para o Grafana.
- `backend/app/tenants.py` — pasta + datasource Loki + grupo `5m` + âncora pausada.
- `backend/app/technologies.py`, `technology_insights.py`, `loki_presence.py`,
  `tenant_technologies.py`, `tenant_scan.py` — catálogo, footprint declarado, conformidade.
- `backend/app/contact_points.py`, `mappers.py`, `schemas.py`, `security.py`,
  `loki_synthetic.py`, `logql_validator.py`.
- `frontend/src/pages/` — Rules, Silences, Tenants, Technologies, GlobalMatrix, Homologation,
  LokiLab, Overview, Alerts. `components/LogQLAssist.tsx` + `hooks/useLogQLAssist.ts` são o
  assistente LogQL único. `components/ConfirmModal.tsx` é obrigatório em ação destrutiva.
- `grafana/bootstrap/seed/rules/` — baseline 08–10 (`ghp-det-*`) e laboratório 11–14.
- `scripts/e2e_*.py` — `e2e_tenants.py`, `e2e_technologies.py`, `e2e_tenant_scan.py`,
  `e2e_loki_synthetic.py`, `e2e_homologation.py`.

## Fluxo de trabalho

1. **Ler antes de escrever**: localizar o fluxo existente e reaproveitá-lo (nunca criar caminho
   paralelo para criação de tenant, validação de LogQL ou mudança de contact point).
2. **Validar impacto arquitetural** antes de alterar código existente; se a mudança muda
   denominador de conformidade ou footprint, leve a decisão ao usuário em vez de decidir.
3. **Implementar** com Pydantic no backend e TypeScript estrito no frontend, comentando o
   "porquê" em trechos não óbvios.
4. **Rebuild + validar de verdade** — ver skill `dante-entrega-git` (build, import, E2E,
   screenshot). Sem isso, não há commit.
5. **Branch → commit convencional → PR**, relatando branch, commit, validações executadas e
   link do PR.

## Invariantes do produto (violação = bug)

1. **Tenant = pasta + data source Loki homônimo + grupo de avaliação `5m`**
   (interval 1m), criados e removidos juntos com rollback completo.
2. **Grafana não persiste grupo vazio**: o grupo só existe com pelo menos uma regra — use a
   regra-âncora pausada (`labels.portal_internal=rule_group_anchor`, TestData, threshold 1e9)
   e filtre-a com `detection_rules()` em todo consumidor de regras (listagem, matriz,
   contagens, toggle, guarda de exclusão, overview de tecnologias).
3. **Proveniência**: `X-Disable-Provenance` não vale para recurso com `provenance: api`;
   `PUT` não limpa proveniência (é irreversível por API — só recriando). Nunca copie o dict de
   origem sem remover `provenance`/`id`/`orgID`/`updated`/`readOnly`.
4. **Clone nunca herda `prod`**: `POST /rules`, `/rules/{uid}/duplicate` e
   `/technologies/{slug}/implement-baseline` gravam `notification_settings.receiver = dev`.
5. **`rule_groups` é a tecnologia**; `grafana_folder` é o tenant; `job` é sempre `wazuh`. Regra
   com `rule_groups` fora do catálogo recebe 422 e aparece em `baseline_rules_unmapped`.
6. **Conformidade por footprint**: o denominador de cada tecnologia inclui só clientes que a
   possuem no SIEM (evidência ∪ inventário declarado em `tenant-technologies.json`). Cliente
   fora do footprint é `not_applicable` (`n/a`), nunca reprovado.
7. **Silence tem natureza**: tag canônica no início do comentário (`[excecao]`, `[antiflood]`,
   `[manutencao]`); `kind=permanent` força `endsAt` de 10 anos no servidor.
8. **Confirmação explícita** para pausa em lote ou exclusão, com volumetria e consequência.
9. **Versionamento e release oficial 100% automatizada**: toda atualização segue versionamento semântico
   (`vMAJOR.MINOR.PATCH`). Ao realizar merge do PR na branch principal (`main`), o workflow do GitHub
   Actions (`release.yml`) detecta a nova versão automaticamente, cria a tag `vX.Y.Z`, compila
   as imagens no GHCR e publica a Release oficial no GitHub (zero passos manuais). O portal
   reflete a versão e novas atualizações via `/api/system/version`.

## Referências

- `references/arquitetura-e-regras-de-negocio.md` — modelo de dados, âncora, proveniência,
  contact points, silences, tecnologias/footprint, laboratório Loki, limpeza de ambiente.
- `references/api-grafana-loki-pitfalls.md` — armadilhas reais de API (Loki frames, datasource,
  ruler x pausadas, cursor de limpeza, 412 etc.).
- `references/regras-deteccao-loki.md` — receita de regra que **detecta de verdade**.
- `scripts/upsert_baseline_rules.py` — upsert idempotente de regras via API (`--verify`).

## Pitfall de ferramenta

`write_file` recusa sobrescrever arquivo lido com paginação (`stale_write_blocked`), comum em
páginas React grandes: grave em `<Arquivo>.new.tsx` e mova por cima com `mv -f`.
