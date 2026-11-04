# Arquitetura e regras de negócio

## 1. Modelo de dados

- **Pasta do Grafana = tenant**. A pasta `global` é o baseline institucional.
- **`rule_groups` = tecnologia** (espelho de `rule.groups` do Wazuh). `job` é sempre `wazuh`.
- **Tenant completo** = pasta + data source Loki homônimo (uid do DS = uid da pasta) + grupo de
  avaliação `5m` (interval 5m). Criados juntos em `POST /api/tenants` com
  rollback se qualquer etapa falhar; removidos em `DELETE /api/tenants/{uid}`.
  `LOKI_TENANT_DATASOURCE_URL` define a URL padrão, sobrescrevível por `loki_url` no payload.
  `POST /api/tenants/{uid}/datasource` faz backfill de tenant legado (409 se já existe).
- **Catálogo de tecnologias**: `backend/app/technologies.py` +
  `backend/app/data/technologies.seed.json`, persistido em `TECHNOLOGIES_STORE_PATH`
  (`/data/technologies.json`, volume `portal-data`). Escrita atômica; slug `^[a-z0-9_]{2,32}$`;
  regex compilável e sem `"`, backtick, `\` ou newline.
- **Inventário declarado de tecnologias por cliente**: `TENANT_TECHNOLOGIES_STORE_PATH`
  (`/data/tenant-technologies.json`), editado por `GET/PUT /api/technologies/footprints[/{client_uid}]`.

## 2. Regra-âncora e grupo de avaliação

- O Grafana **descarta grupo vazio**: `PUT /api/v1/provisioning/folder/{uid}/rule-groups/{group}`
  com `rules: []` responde 200 e não persiste (`no changes detected`). Por isso o grupo é
  materializado por uma regra-âncora pausada (TestData + threshold 1e9, título `[D.A.N.T.E.] ...`,
  label `portal_internal=rule_group_anchor`) em `backend/app/tenants.py`.
- A âncora precisa ser filtrada em **todo** consumidor de regras (`/api/rules`, matriz global,
  contagens de tenants, toggle-pause, guarda de exclusão, overview de tecnologias).
- Backfill: `POST /api/tenants/{uid}/evaluation-group` (`{"migrate_rules": true}`) materializa a
  âncora, realinha âncora em grupo divergente e move regras para `5m`.
  Idempotente (`anchor_created=false` na repetição). É o caminho para corrigir
  `⚠ grupo padrão ausente`.
- Com âncora a pasta nunca está vazia: `DELETE /api/folders/{uid}` devolve 400
  `folder.not-empty` sem `?forceDeleteRules=true`.
- Nome do grupo tem fonte única (`tenant_rule_group`): a replicação baseline→cliente **não**
  pode herdar `ruleGroup` da origem, senão a regra nasce em `global-detections`.

## 3. Proveniência (provisioning)

- `X-Disable-Provenance` só vale para recurso **sem** proveniência. Em recurso com
  `provenance: api`, `PUT` com o header responde 500
  `cannot change provenance from 'api' to ''`.
- **O corpo vence o header**: `POST` grava `provenance` recebido no JSON. Clone que monta
  payload com `dict(source_rule)`/`deepcopy` propaga `provenance: api` e o recurso nasce
  read-only (sem lápis de edição na UI).
- **Proveniência é irreversível por API**: `PUT` com `provenance: ""` responde 200 mas mantém
  `api`. Único reparo: recriar com o mesmo uid e payload sem provenance (comparar labels,
  annotations, data e notification_settings antes/depois). Sinal visual: tag `Provisioned` em
  `/alerting/list` e ícone de edição ausente.

## 4. Validação estrita de LogQL

- Regra nunca é persistida sem `lint_logql` no **servidor** (sintaxe + compliance de labels
  `job`, `rule_groups`, funções de extração `| json` / `| logfmt`).
- Paridade obrigatória entre fluxos que persistem regra: `useLogQLAssist` + `LogQLAssist.tsx`
  no front, `lint_logql` no `POST /rules`, `POST /rules/{uid}/duplicate` e
  `POST /technologies/{slug}/implement-baseline` (422 antes de criar qualquer recurso).
- `sum(count_over_time({job="wazuh", rule_groups=~".*x.*"} | json [1m]))` é a query correta de
  presença; `count({...}[1m])` é inválido (`unexpected RANGE`).
- Teste prévio contra logs sintéticos (`/loki`) ou execução real contra o datasource.

## 5. Silences

- Matchers sempre bem definidos (`alertname`, `grafana_folder`).
- O Alertmanager não tem campo livre de metadados: a natureza do silence é classificada no
  backend (`mappers.classify_silence`) e o portal grava tag canônica no início do comentário
  (`[excecao]`, `[antiflood]`, `[manutencao]`).
- Precedência: tag `[excecao]`/`[permanente]` → vigência >= `PERMANENT_MIN_SPAN_DAYS` (365d) ou
  `endsAt` ausente/data zero → `[antiflood]`/`createdBy` antiflood → `[manutencao]`/maintenance
  → `manual`.
- `POST /api/silences` aceita `kind`; para `permanent` força `endsAt` de 10 anos no servidor.
- UI: duas visões (`Exceções permanentes` / `Silences temporários`); exceção permanente só
  oferece `Revogar exceção` com confirmação explícita, nunca `Prolongar`.

## 6. Tecnologias e conformidade

- Cadastro só passa depois da consulta implícita de telemetria (`technology_insights.py` +
  `loki_presence.py`): sem logs o backend responde 409 e o aceite vem de `ConfirmModal`
  (`confirm_without_logs`). Se não existe datasource Loki, `available=false` e o cadastro
  **não** é bloqueado (indisponível ≠ "sem logs").
- Distribuição/conformidade derivam das regras do Grafana (o Loki não tem label de tenant):
  cliente integra a tecnologia quando tem regra dela na pasta; baseline = regras da pasta
  `global`; vínculo por `annotations.cloned_from` com fallback de título-base.
- **Conformidade por footprint**: denominador por tecnologia = clientes com evidência (regra,
  label `technology`, recorte de `rule_groups`) ∪ inventário declarado. Fora do footprint →
  `status: not_applicable`, célula `n/a`, slot em `metrics.not_applicable_slots`.
  Sem o inventário declarado, cliente que integrou a tecnologia e não tem regra sairia do
  denominador (lacuna mascarada) em vez de reprovar.
- `resolve_rule_technology` aceita a label `technology` como slug **ou** nome exibido e cai
  para o recorte de `rule_groups` da query quando a label não está no catálogo (senão regra
  legada com `technology: "AD/Windows"` fica eternamente "sem tecnologia mapeada").
- Implementação automática de baseline é idempotente (pula `cloned_from`/título-base) e exige
  `confirm_client_without_technology=true` quando o cliente ainda não tem regra da tecnologia.
- Página Tecnologias alimenta também `tenant_scan.py` (scan de tecnologias por tenant) e a
  matriz de cobertura de `GlobalMatrixPage`.

## 7. Contact points como estágio de deploy

- O receiver vive em `notification_settings.receiver` (snake_case) na API de Provisioning;
  `GET /api/v1/provisioning/alert-rules` devolve `notification_settings: null` sem receiver.
  `extract_contact_point` tolera `notification_settings` / `notificationSettings` /
  `contactPoint` na raiz — aceite os três em verificação (falso negativo é comum).
- `derive_deploy_status`: pausada → `paused`; ativa + `prod` → `active`; ativa + `dev`/`stg` →
  `homolog`; ativa sem receiver → `unassigned` (bug operacional: alerta não chega a ninguém).
  Exposto em `contact_point`/`deploy_status` no `RuleSummary` e na coluna STATUS de Regras.
- Contact points padrão em `grafana/provisioning/alerting/contact-points.yml` (`dev`/`stg`/`prod`,
  email placeholder). File provisioning de alerting só aplica no **boot**:
  `docker compose restart grafana` e conferir `GET /api/v1/provisioning/contact-points`
  (provenance `file`).
- `POST /api/homologation/rules/{uid}/contact-point` valida contra os CPs existentes (409 se
  faltar) e bloqueia regras internas/recording (400). O PUT reenvia o objeto completo da regra.
- `PUT` com `notification_settings: null` volta a regra para `unassigned`.

## 8. Laboratório de logs sintéticos (Loki real)

- Serviço `loki` (`grafana/loki:3.4.2`, `loki/loki-config.yml`), datasource provisionado
  `uid=loki`; porta publicada só em 127.0.0.1, acesso interno pela `core-net`.
- Página `/loki` (`LokiLabPage.tsx`) → `POST /api/loki/logs` (sessão + CSRF) e
  `GET /api/loki/status`. Presets de ataque na própria página; tokens
  `{{i}}/{{ip}}/{{user}}/{{rand}}/{{rlen}}/{{iso}}` substituídos antes do `JSON.parse`
  (tokens numéricos sem aspas).
- Validação em `loki_synthetic.py` é a fronteira de confiança: labels no padrão Prometheus,
  prefixo `__` proibido, `job` obrigatório, 200 linhas / 64 KiB por linha / 256 KiB por request,
  timestamps ns ordenados no passado.
- Toda linha recebe `synthetic="true"` / `synthetic_source="portal"`; sem purge pela UI
  (retenção 7 dias ou reset do volume `loki-data`).
- `verified_count` é a contagem do **stream** na janela de verificação, não o total enviado —
  nunca rotular como "linhas confirmadas".

## 9. Limpeza e seeds

- Classifique antes de apagar: `datasourceUid: testdata` + `csv_metric_values` é demo/teste;
  preserve `ghp-det-*`, réplicas com `datasourceUid: loki` e regras com `labels.portal_internal`.
- Ordem: excluir regras da pasta → `DELETE /api/tenants/{uid}` → apagar silence de exemplo
  (`comment` iniciando com `[seed]`).
- Excluir por API não é durável: o bootstrap recria o que estiver em `grafana/bootstrap/seed/`
  a cada `docker compose up`. Para remover de vez, apagar os seeds, o bloco correspondente do
  `bootstrap.sh` e `SEED_SAMPLE_DATA` do compose/.env/docs — mantendo a garantia da pasta
  `global`, da qual a criação de baseline depende.
- `DELETE /api/tenants/{uid}` responde 400 enquanto houver regra de detecção na pasta (âncora
  não conta) e **412** em `POST /api/tenants` com uid já existente (não 409).
- Tenant que perdeu todas as regras perde o grupo (o Grafana não persiste grupo vazio) e o
  portal exibe o aviso de segregação com `Corrigir todos (N)`: comportamento esperado.
