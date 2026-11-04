# D.A.N.T.E. — regras permanentes do workspace

**Detection & Alerting Navigator for Threat Engineering**: portal web de detection engineering sobre
Grafana Alerting + Grafana Loki, com Wazuh como fonte de telemetria (Vector → Kafka → Loki,
label `job=wazuh`). Pastas do Grafana são tenants; `rule_groups` identifica a tecnologia (grupos de regras do Wazuh).

Repo: `dante-portal` (`github.com/sg0luc/dante-portal`). Stack local em Docker Compose:
containers `dante-backend`, `dante-frontend`, `dante-grafana`, `dante-loki`.
UI em `http://localhost:8080` (nginx do frontend faz proxy de `/api`), Grafana em `:3000`.

## Mapa do código

- `backend/app/` — FastAPI. `routers/` (`auth`, `monitoring`, `tenants`, `technologies`,
  `homologation`, `loki`, `system`), `grafana_client.py` (único ponto de contato com a API do
  Grafana), `logql_validator.py` (linter + compliance de labels), `tenants.py` (pasta + data
  source Loki + grupo de avaliação + âncora pausada), `technologies.py` /
  `technology_insights.py` / `loki_presence.py` (catálogo, conformidade, footprint),
  `contact_points.py` (estágio de deploy), `loki_synthetic.py` (laboratório de logs),
  `security.py` (sessão + CSRF).
- `frontend/src/` — React 18 + TypeScript + Vite. `pages/` (Rules, Silences, Tenants,
  Technologies, GlobalMatrix, Homologation, LokiLab, Overview, Alerts),
  `components/LogQLAssist.tsx` + `hooks/useLogQLAssist.ts` (assistente LogQL único e
  compartilhado por todos os fluxos que persistem regra), `ConfirmModal.tsx` (confirmação
  obrigatória de ações destrutivas).
- `grafana/bootstrap/` — seeding idempotente (pasta `global` + regras de baseline).
  `grafana/provisioning/` — datasources e contact points (aplicados só no boot).
- `scripts/e2e_*.py` — suítes E2E: `e2e_tenants.py`, `e2e_technologies.py`,
  `e2e_tenant_scan.py`, `e2e_loki_synthetic.py`, `e2e_homologation.py`.

## Invariantes (valem sempre)

1. **Nada está pronto sem execução real.** Build, import do app, E2E e screenshot quando
   houver UI. Nunca relate validação que não rodou nem invente saída de comando.
2. **Toda alteração de código exige rebuild**: `docker compose build backend frontend` e
   depois `docker compose up -d`. Frontend rebuildado precisa de
   `docker compose up -d --force-recreate frontend` e conferência do digest
   (`docker compose images frontend` x `docker inspect dante-frontend --format '{{.Image}}'`),
   senão a UI testada é o bundle antigo.
3. **Toda entrega vira branch + commit convencional + git push + PR automático**,
   sem o usuário pedir. Ao concluir uma alteração, envie a branch para a origem e abra o Pull
   Request no repositório oficial (`github.com/sg0luc/dante`). Commitar apenas os arquivos da
   feature; alterações alheias no working tree ficam fora do `git add` e são mencionadas no retorno.
4. **Ação destrutiva ou massiva** (pausar/excluir regras em lote, revogar exceção permanente,
   apagar tenant) exige `ConfirmModal` com volumetria impactada e consequência operacional
   explícitas.
5. **Regra de detecção nunca é persistida sem passar pelo linter LogQL** — valide no servidor
   (`lint_logql`), não só na tela.
6. **Segredos** nunca em log, resposta de API ou commit; `.env` fica fora do versionamento.
7. **Tenant = pasta + data source Loki homônimo + grupo `5m`.** Todo fluxo de
   criação/remoção mantém os três (com rollback); não crie caminho que pule um deles.
8. **Clone não herda `provenance` nem `notification_settings.receiver = prod`** da origem:
   remova `provenance`/`id`/`orgID` do payload e grave `dev`.
9. **Fluxo de releases oficiais e versionamento semântico**: toda nova funcionalidade ou
   correção no projeto deve seguir versionamento semântico (`vMAJOR.MINOR.PATCH`) e o fluxo
   de release oficial. A versão canônica fica em `VERSION` e `backend/app/__init__.py`. Toda
   entrega passa pelo ciclo branch + commit convencional + PR automático para `main`. No
   momento em que o PR é mergeado na `main`, o workflow `.github/workflows/release.yml` detecta
   automaticamente a nova versão, cria a tag `vX.Y.Z`, constrói as imagens no GHCR e publica
   a release oficial no GitHub com changelog automático (zero passos manuais pós-merge). O
   portal checa atualizações via `/api/system/version`.

## Ferramentas do workspace

- Skills: `.agents/skills/dante-companion` (arquitetura, regras de negócio, LogQL,
  pitfalls de API) e `.agents/skills/dante-entrega-git` (gate de validação, git e PR).
- Subagents: `dante-backend`, `dante-frontend`, `dante-detection`, `dante-e2e-qa`,
  `dante-reviewer`.
- Regras modulares por escopo de arquivo: `.agents/rules/*.md`.

Idioma: responder, comentar código e escrever docs em **português do Brasil**, mantendo
termos técnicos em inglês (rule group, provisioning, contact point, datasource).
