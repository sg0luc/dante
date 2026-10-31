# API — D.A.N.T.E.

Referência dos endpoints expostos pelo backend FastAPI. Base: `http://<host>:8080/api` (o Nginx do frontend faz proxy de `/api` para o backend).

## Convenções

- **Autenticação**: cookie de sessão `ghp_session` (`HttpOnly`, `SameSite=Strict`, `Secure` conforme `COOKIE_SECURE`). O endpoint de login é o único que dispensa sessão, junto de `/health` e `/health/ready`.
- **Anti-CSRF**: toda mutação (`POST`, `PUT`, `DELETE`) exige o cabeçalho `X-Requested-With: hunter-portal`. Ausência/invalidade → `403`.
- **Formato de erro**: `{"detail": "<mensagem>"}`. Erros do Grafana são convertidos para JSON sem expor URL/token (tipicamente `502`, `504` em timeout).
- **Timestamps**: strings ISO-8601 em UTC.
- **Documentação interativa**: desabilitada por padrão; `ENABLE_API_DOCS=true` habilita `/api/docs` e `/api/openapi.json`.

Códigos comuns: `401` sessão ausente/expirada · `403` CSRF inválido ou regra de negócio violada · `404` recurso inexistente · `409` conflito no catálogo · `422` validação de payload/LogQL · `429` rate limit de login · `502`/`504` falha/timeout no Grafana.

---

## Sistema

### `GET /health`
Liveness sem autenticação. Resposta: `{"status": "ok"}`. Usado pelo healthcheck do container.

### `GET /health/ready`
Readiness sem autenticação; expõe apenas booleanos.

```json
{ "status": "ok", "grafana_reachable": true, "grafana_token_configured": true }
```

`status` é `degraded` quando o Grafana não responde ou não há token.

### `GET /config` 🔒
Configurações não sensíveis para a UI.

```json
{ "grafana_public_url": "http://localhost:3000", "refresh_interval_seconds": 15 }
```

---

## Autenticação

### `POST /auth/login` (CSRF)
```json
{ "username": "hunter", "password": "********" }
```
`200` → `{"username": "hunter"}` + `Set-Cookie` da sessão.
`401` credenciais inválidas · `429` excesso de tentativas por IP (`LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_SECONDS`).

### `POST /auth/logout` (CSRF)
Revoga a sessão no servidor e remove o cookie. `204`.

### `GET /auth/me` 🔒
`200` → `{"username": "hunter"}` · `401` se não autenticado.

---

## Regras de detecção

### `GET /rules` 🔒
Lista todas as regras visíveis no Grafana, já normalizadas.

```json
[{
  "uid": "ghp-1a2b3c4d5e",
  "title": "SSH - Detecção de Força Bruta",
  "folder_uid": "global",
  "folder_title": "Global Baseline",
  "rule_group": "global-detections",
  "rule_type": "alerting",
  "labels": { "severity": "high", "technology": "ad_windows", "...": "..." },
  "annotations": { "description": "...", "logql_query": "..." },
  "is_paused": false,
  "for_duration": "5m",
  "state": "normal",
  "health": "ok",
  "last_evaluation": "2026-10-18T12:00:00Z",
  "last_error": null,
  "active_instances": 0,
  "updated": "2026-10-18T11:00:00Z",
  "contact_point": "dev",
  "deploy_status": "homolog"
}]
```

`state` ∈ `firing | pending | recovering | normal | paused | error | nodata | unknown`.
`deploy_status` ∈ `active | homolog | paused | unassigned` (derivado do Contact
Point — ver seção [Homologação](#homologação--estágio-de-deploy-por-contact-point)).

### `GET /rules/global-matrix` 🔒
Matriz de cobertura das regras da pasta `global` por cliente.

```json
[{
  "global_uid": "ghp-...",
  "global_title": "Ransomware - Renomeação em Massa",
  "labels": { "...": "..." },
  "annotations": { "...": "..." },
  "total_clients": 3,
  "implemented_clients_count": 2,
  "active_clients_count": 1,
  "paused_clients_count": 1,
  "not_implemented_clients_count": 1,
  "clients": [
    { "client_uid": "cliente-alpha", "client_name": "Cliente Alpha",
      "status": "active", "rule_uid": "ghp-...", "rule_title": "..." }
  ]
}]
```

`status` ∈ `active | paused | not_implemented`.

### `GET /rules/{uid}` 🔒
Detalhe da regra: todos os campos de `RuleSummary` + `condition`, `no_data_state`, `exec_err_state`, `provenance` e `queries[]` (`ref_id`, `datasource_uid`, `relative_time_range`, `model`).

### `POST /rules` (CSRF) 🔒
Cria regra de detecção. **Falha com 422 se o LogQL não passar no linter** — antes de qualquer escrita no Grafana.

```json
{
  "name": "PowerShell Encoded Command",
  "description": "Execução de PowerShell com comando codificado em base64",
  "scope": "client",
  "target_client_uid": "cliente-alpha",
  "logql_query": "{job=\"wazuh\", rule_groups=~\".*windows.*\"} |= \"-enc\" | json",
  "severity": "high",
  "mitre_tactic": "execution",
  "mitre_technique": "T1059.001",
  "technology": "ad_windows"
}
```

Regras de negócio aplicadas pelo servidor:

1. Lint obrigatório (`lint_logql`) contra o catálogo de tecnologias.
2. `technology` explícita ou inferida pelo matcher `rule_groups` da query. Sem tecnologia resolvível → `422`; mais de uma tecnologia possível → `422`.
3. O `rule_groups` da query precisa corresponder à tecnologia escolhida → `422` caso contrário.
4. `scope=baseline` → pasta `global`, grupo `global-detections`, `client=global`, `siem_tier=global`.
   `scope=client` → `target_client_uid` obrigatório, grupo `5m`, `siem_tier=client`.
5. Labels gravadas: `severity`, `mitre_tactic`, `mitre_technique`, `scope`, `client`, `siem_tier`, `technology`, `technology_name`, `team=soc`.

Resposta `201`:

```json
{ "message": "Regra criada com sucesso", "uid": "ghp-...", "title": "...",
  "folder_uid": "cliente-alpha", "folder_title": "Cliente Alpha",
  "scope": "client", "severity": "high",
  "technology": "ad_windows", "technology_name": "AD/Windows", "labels": { "...": "..." } }
```

### `POST /rules/{uid}/duplicate` (CSRF) 🔒
Replica uma regra **da pasta `global`** para um cliente.

```json
{
  "target_folder_uid": "cliente-alpha",
  "target_folder_title": "Cliente Alpha",
  "new_title": "PowerShell Encoded Command (Cliente Alpha)",
  "new_rule_group": "5m",
  "client_name": "Cliente Alpha",
  "custom_logql": "{job=\"wazuh\", rule_groups=~\".*windows.*\"} |= \"-enc\" | json"
}
```

- `403` se a regra de origem não está em `global`.
- `422` se a query efetiva (custom ou herdada) não passar no linter — a checagem ocorre **antes** de criar pasta/regra.
- Cria a pasta de destino se não existir, gera novo UID `ghp-<hex10>`, desbloqueia (`isPaused=false`), atualiza labels `client`/`siem_tier` + `technology` resolvida e grava `annotations.cloned_from` / `client_name`.

Resposta:

```json
{ "message": "Regra duplicada com sucesso para o cliente 'Cliente Alpha'",
  "uid": "ghp-...", "title": "...", "folder_uid": "cliente-alpha", "client": "Cliente Alpha" }
```

### `POST /rules/{uid}/toggle-pause` (CSRF) 🔒
```json
{ "paused": true }
```
Retorna a regra atualizada.

### `POST /rules/batch-pause` (CSRF) 🔒
Pausa/reativa até 500 regras em paralelo, com resultado por UID.

```json
{ "uids": ["ghp-1", "ghp-2"], "paused": true }
```
```json
{ "message": "2 regra(s) pausada(s) com sucesso.", "total": 2,
  "succeeded": ["ghp-1", "ghp-2"], "failed": [] }
```

### `POST /rules/lint-logql` (CSRF) 🔒
Valida a query sem persistir nada. Corpo: `{"query": "{job=\"wazuh\", rule_groups=~\".*windows.*\"} |= \"x\" | json"}`.

```json
{
  "is_valid": true,
  "query": "...",
  "normalized_query": "...",
  "stream_selector": "{job=\"wazuh\", rule_groups=~\".*windows.*\"}",
  "metric_function": null,
  "pipeline_stages": ["|= \"x\"", "| json"],
  "issues": [{ "level": "warning", "message": "...", "field": "rule_groups" }],
  "message": "Query LogQL válida.",
  "rule_groups_values": [".*windows.*"],
  "job_value": "wazuh",
  "technologies": ["ad_windows"]
}
```

`issues[].level` ∈ `error | warning | info`. `is_valid=false` sempre que houver `error`.

### `POST /rules/execute-query` (CSRF) 🔒
Executa a query no datasource (Loki) com timeout de 8 s.

```json
{ "query": "...", "time_range_from": "now-1h", "time_range_to": "now", "limit": 50 }
```

```json
{ "success": true, "query": "...", "total_lines": 12,
  "lines": [{ "timestamp": "2026-10-18T12:00:00Z", "line": "...", "labels": { "job": "wazuh" } }],
  "duration_ms": 143.2, "is_timeout": false, "error": null }
```

Timeout retorna `success=false`, `is_timeout=true` e mensagem explícita (a UI sinaliza ao operador).

### `POST /rules/test-logql` (CSRF) 🔒
Avalia uma linha de log sintética contra a query (sem tocar no Grafana).

```json
{
  "logql_query": "{job=\"wazuh\"} | json | attempts >= 5",
  "log_line": "{\"message\":\"Failed password\",\"attempts\":7}",
  "stream_labels": { "job": "wazuh", "rule_groups": "windows" }
}
```

```json
{ "is_compatible": true, "logql_query": "...", "message": "Log compatível com a query.",
  "extracted_fields": { "attempts": 7 }, "stages": [{ "stage": "| json", "status": "ok", "detail": "..." }] }
```

---

## Silences

### `GET /silences` 🔒
Silences do Alertmanager com natureza classificada e contagem de alertas suprimidos.

```json
[{
  "id": "8f2c...", "state": "active", "kind": "permanent",
  "matchers": [{ "name": "alertname", "value": "SSH Brute Force", "is_regex": false, "is_equal": true }],
  "starts_at": "2026-10-01T10:00:00Z", "ends_at": "2036-10-01T10:00:00Z",
  "updated_at": "2026-10-01T10:00:00Z",
  "created_by": "hunter", "comment": "[excecao] Servidor de laboratório",
  "silenced_alerts_count": 2
}]
```

`state` ∈ `active | pending | expired`; `kind` ∈ `permanent | antiflood | maintenance | manual`.

### `POST /silences` (CSRF) 🔒
```json
{
  "matchers": [
    { "name": "alertname", "value": "SSH Brute Force", "is_regex": false, "is_equal": true },
    { "name": "grafana_folder", "value": "cliente-alpha", "is_regex": false, "is_equal": true }
  ],
  "starts_at": null,
  "ends_at": "2026-10-19T00:00:00Z",
  "comment": "Janela de manutenção do servidor",
  "kind": "maintenance"
}
```

- `ends_at` é obrigatório na API; ignorado e substituído por **now + 10 anos** quando `kind=permanent`.
- O comentário recebe a tag canônica no início (`[excecao]`, `[antiflood]`, `[manutencao]`); tags antigas são removidas.
- `createdBy` é o usuário da sessão.

Resposta: `{"silence_id": "..."}`.

### `POST /silences/{silence_id}/extend` (CSRF) 🔒
```json
{ "duration": "24h" }
```
`duration` ∈ `2h | 4h | 8h | 24h | 3d | 10y`. A extensão soma ao `endsAt` vigente (ou a `now`, se já expirado). `10y` converte o silence em exceção permanente. Resposta: `{"silence_id": "..."}`.

### `DELETE /silences/{silence_id}` (CSRF) 🔒
Expira o silence (usado como "Revogar exceção"). `204`.

---

## Pastas e tenants

### `GET /folders` 🔒
`[{"id": 3, "uid": "cliente-alpha", "title": "Cliente Alpha"}]`

### `POST /folders` (CSRF) 🔒
```json
{ "title": "Cliente Beta", "uid": "cliente-beta" }
```
`uid` é opcional (Grafana gera se omitido). Retorna `FolderItem`.

### `GET /tenants` 🔒
Pastas **exceto `global`** (os tenants), com contagem de regras **e o data source Loki
dedicado** de cada cliente.

```json
[{
  "id": 3, "uid": "cliente-alpha", "title": "Cliente Alpha",
  "rules_count": 12, "active_rules_count": 10, "paused_rules_count": 2,
  "rules_uids": ["ghp-1", "ghp-2"],
  "loki_datasource_name": "Cliente Alpha",
  "loki_datasource_uid": "cliente-alpha",
  "loki_datasource_url": "http://loki:3100",
  "loki_datasource_present": true,
  "loki_datasource_url_matches": true,
  "evaluation_group": "5m",
  "evaluation_group_interval": "5m",
  "evaluation_group_present": true,
  "technologies_count": 2,
  "technologies_scanned_at": "2026-10-18T16:55:31Z"
}]
```

`loki_datasource_present: false` marca tenant legado (pasta sem data source) — a UI mostra
`⚠ Ausente` e o botão **Criar DS Loki**.

`technologies_count` vem do snapshot do último escaneamento
(`POST /tenants/{uid}/technologies/scan`), não de uma reconsulta ao Loki por render.
`technologies_scanned_at: null` = tenant nunca escaneado (a UI desabilita a abertura do
pop-up de tecnologias).

### `POST /tenants/{uid}/technologies/scan` (CSRF) 🔒
Roda a query canônica de presença de logs **de cada tecnologia do catálogo** contra o data
source Loki do próprio tenant e persiste o snapshot em `TENANT_SCAN_STORE_PATH`
(`/data/tenant-technology-scan.json`).

```json
{ "window_seconds": 3600 }
```

`window_seconds` é opcional (`60..86400`, padrão `3600`). Resposta:

```json
{
  "message": "Escaneamento concluído em 'Cliente Alpha': 2 de 3 tecnologia(s) ...",
  "tenant_uid": "cliente-alpha", "client_name": "Cliente Alpha",
  "datasource": "Cliente Alpha", "datasource_uid": "cliente-alpha",
  "window_seconds": 3600, "scanned_at": "2026-10-18T16:55:31Z",
  "available": true, "technologies_detected": 2, "technologies_total": 3,
  "technologies": [
    { "slug": "fortigate", "name": "Fortigate", "icon": "🧱",
      "description": "...", "logs_count": 22, "found": true }
  ]
}
```

- A query é montada só no backend e nunca é devolvida ao usuário.
- Consultas rodam em paralelo (limite de 6) contra o data source do tenant; sem data source
  dedicado (tenant legado) cai para o Loki padrão da stack.
- `available: false` = Loki não respondeu: nada é marcado como ausente e o snapshot anterior
  é preservado.
- `400` para a pasta `global`, `404` para tenant inexistente, `409` quando não há catálogo
  ou nenhum data source Loki.

### `GET /tenants/{uid}/technologies` 🔒
Tecnologias do cliente com o estado do baseline de cada uma. A lista é a união de
tecnologias com logs no último escaneamento, com regras já na pasta do cliente e as
declaradas no footprint.

```json
{
  "tenant_uid": "cliente-alpha", "client_name": "Cliente Alpha",
  "scanned_at": "2026-10-18T16:55:31Z", "window_seconds": 3600,
  "datasource": "Cliente Alpha", "available": true,
  "technologies_detected": 2, "technologies_total": 3,
  "technologies": [{
    "slug": "ad_windows", "name": "AD/Windows", "icon": "🪟", "description": "...",
    "detected": false, "logs_count": 0,
    "baseline_rules": 1, "implemented_rules": 0, "paused_rules": 0,
    "existing_rules": 0, "compliance_pct": 0.0, "status": "none"
  }]
}
```

`status` deriva do baseline da pasta `global` para aquela tecnologia: `complete` (todas as
regras replicadas), `partial` ou `none`. É o que o pop-up da coluna **Tecnologias** da página
Tenants exibe, com o botão **Implementar tudo** por tecnologia (chama
`POST /technologies/{slug}/implement-baseline` com Contact Point dinâmico correspondente ao estágio `stg` de Homologação).

### `POST /tenants` (CSRF) 🔒
```json
{ "title": "Cliente Beta", "uid": "cliente-beta", "loki_url": "http://loki-cliente-beta:3100" }
```

Cria **a pasta, o data source Loki homônimo e o grupo de avaliação** `5m`
com intervalo de `5m` (uid do data source = uid da pasta). `loki_url` é opcional: vazio usa `LOKI_TENANT_DATASOURCE_URL` (padrão
`http://loki:3100`, o Loki da stack). A operação é transacional: se o data source falhar,
a pasta recém-criada é removida (`502` com o motivo).

`400` para título vazio, título/UID `global`, UID de data source reservado (`loki`,
`grafana`, `portal`) ou URL não `http(s)`. `409` quando já existe data source
com o mesmo nome no Grafana.

O Grafana não persiste grupo de avaliação vazio, então o grupo é materializado por uma
**regra-âncora pausada** (`labels.portal_internal = rule_group_anchor`, título
`[D.A.N.T.E.] Grupo de avaliação — <tenant>`). Ela nunca avalia, não dispara e é excluída
das contagens/listagens do portal (inclusive da checagem que bloqueia excluir tenant com
regras). A exclusão do tenant remove os três recursos (`forceDeleteRules=true` na pasta).

### `POST /tenants/{uid}/datasource` (CSRF) 🔒
Cria o data source Loki de um tenant já existente (backfill de tenant legado ou correção
após remoção manual no Grafana).

```json
{ "loki_url": "http://loki:3100" }
```

`404` tenant inexistente; `409` quando o tenant já possui data source Loki; `400` para
`global` ou URL inválida.

### `POST /tenants/{uid}/evaluation-group` (CSRF) 🔒
Garante o **grupo de avaliação canônico** `5m` (intervalo `5m`) de um tenant
— backfill de tenant legado ou correção de desvio (tenant sem grupo, ou com regras em
grupo divergente, ex.: `1m`).

```json
{ "migrate_rules": true }
```

A rota é idempotente e executa, nesta ordem: (1) cria a regra-âncora pausada se o grupo não
existe; (2) realinha a âncora se ela estiver em grupo divergente; (3) com `migrate_rules`,
move para o grupo canônico as regras de detecção da pasta que estejam em outro grupo (a
query, os labels e a severidade não mudam). A resposta é o estado **relido do Grafana**:

```json
{
  "message": "Grupo de avaliação '5m' criado com intervalo 5m. 1 regra(s) migrada(s) para o grupo canônico.",
  "uid": "cliente-alfa",
  "evaluation_group": "5m",
  "evaluation_group_interval": "5m",
  "evaluation_group_present": true,
  "anchor_created": true,
  "anchor_rule_uid": "ghp-anchor-1a2b3c4d5e",
  "migrated_rules": ["ghp-..."],
  "migration_failures": []
}
```

`400` para `global`; `404` tenant inexistente; `502` quando o Grafana recusa a criação da
âncora/realinhamento (o tenant continua reportado como fora do padrão).

> **Provenance**: `PUT /api/v1/provisioning/alert-rules/{uid}` só aceita o header
> `X-Disable-Provenance` quando a regra **não** tem proveniência gravada. Em regras com
> `provenance: api` (criadas fora do portal) o Grafana responde
> `500 cannot change provenance from 'api' to ''`; o cliente do portal omite o header
> automaticamente nesses casos.
>
> Na **criação** (`POST /api/v1/provisioning/alert-rules` e `POST /api/datasources`) o
> `GrafanaClient` remove `provenance`, `readOnly`, `id`, `orgID` e `updated` do payload
> antes de enviar. O Grafana honra `provenance` do corpo mesmo com o header
> `X-Disable-Provenance`, e o resultado é um recurso marcado *Provisioned* (read-only) na
> UI — foi assim que clones de regras herdaram `provenance: api`. Nunca monte payload de
> criação copiando o dicionário de um recurso existente sem esse saneamento.
> Proveniência **não** pode ser limpa depois (o `PUT` ignora `provenance: ""`); o único
> reparo é recriar o recurso (mesmo `uid`, payload sem provenance).

### `DELETE /tenants/{uid}` (CSRF) 🔒
`400` para o tenant `global` ou quando existem regras na pasta (mensagem informa a
quantidade). Sucesso: remove a pasta **e o data source Loki** e devolve
`{"message": "Tenant excluído com sucesso (data source Loki: removido).", "uid": "..."}`.

### `POST /tenants/{uid}/toggle-pause` (CSRF) 🔒
Pausa/reativa todas as regras do tenant.

```json
{ "paused": true }
```
Resposta no formato de `batch-pause`; tenant sem regras retorna `total=0` com mensagem informativa.

---

## Alertas

### `GET /alerts` 🔒
Instâncias atuais do Alertmanager.

```json
[{
  "fingerprint": "abc123", "alertname": "SSH Brute Force", "rule_uid": "ghp-...",
  "state": "active", "silenced_by": [], "inhibited_by": [],
  "labels": { "severity": "high", "client": "Cliente Alpha" },
  "annotations": { "summary": "..." },
  "starts_at": "2026-10-18T11:59:00Z", "updated_at": "2026-10-18T12:00:00Z"
}]
```

`state` ∈ `active | suppressed | unprocessed`.

---

## Tecnologias (`rule_groups` → data source)

### `GET /technologies` 🔒
```json
[{
  "slug": "ad_windows", "name": "AD/Windows",
  "rule_groups_regex": ".*windows.*", "job": "wazuh",
  "description": "Endpoints Windows e Controladores de Domínio...",
  "icon": "🪟", "enabled": true,
  "logql_selector": "{job=\"wazuh\", rule_groups=~\".*windows.*\"}"
}]
```

### `GET /technologies/{slug}` 🔒
Detalhe; `404` se o slug não existe.

### `POST /technologies` (CSRF) 🔒
```json
{
  "slug": "palo_alto", "name": "Palo Alto",
  "rule_groups_regex": ".*paloalto.*", "job": "wazuh",
  "description": "Firewalls PAN-OS (tráfego, threat, URL filtering).",
  "icon": "🔥", "enabled": true,
  "confirm_without_logs": false
}
```
`201` com o registro criado. Validações: slug `^[a-z0-9_]{2,32}$`; regex compilável, sem `"`, backtick, `\` ou newline; slug e recorte duplicados → `409`.

**Validação implícita de telemetria (Loki).** Antes de gravar, o backend consulta:

```logql
sum(count_over_time({job="wazuh", rule_groups=~".*<tecnologia>.*"} | json [1m]))
```

A query é montada no servidor, nunca é devolvida ao cliente e não aparece na UI.

- Contagem > 0 → cadastro liberado.
- Loki consultável e contagem = 0 → `409` com mensagem de "sem logs"; o front
  exibe o aviso e só reenvia com `confirm_without_logs: true` após o pop-up de
  confirmação.
- Loki não configurado/indisponível (sem datasource, timeout ou erro) → o
  cadastro não é bloqueado, pois a ausência de logs não pode ser comprovada.

> Nota técnica: `count({...} | json [1m])` não é LogQL válido (`parse error ...
> unexpected RANGE`). `count_over_time` é a função correta para agregar linhas em
> um intervalo de logs; `sum(...)` colapsa as séries em um único escalar.

### `POST /technologies/log-presence` (CSRF) 🔒
Pré-checagem isolada da mesma consulta (usada pela tela antes do submit).

```json
{ "rule_groups_regex": ".*fortigate.*", "job": "wazuh", "window_seconds": 60 }
```

```json
{
  "available": true, "found": true, "count": 3, "window_seconds": 60,
  "datasource": "Loki", "checked_at": "2026-10-18T11:43:24Z",
  "message": "Telemetria confirmada: 3 log(s) encontrados no Loki..."
}
```

`available=false` indica que a telemetria não pôde ser consultada (sem
datasource Loki, timeout ou erro no Loki) — nunca confundir com "sem logs".

### `GET /technologies/overview` 🔒
Visão consolidada da página de Tecnologias (métricas + distribuição por cliente +
mapa de conformidade). Fontes: catálogo do portal, regras do Grafana e pastas
(`global` = baseline; demais = clientes).

```json
{
  "metrics": {
    "unique_technologies": 3, "enabled_technologies": 3,
    "baseline_rules_total": 8, "baseline_rules_unmapped": 7,
    "clients_total": 5, "clients_with_technology": 1,
    "client_rules_total": 14, "implemented_baseline_rules": 1,
    "total_baseline_slots": 5, "compliance_pct": 20.0
  },
  "technologies": [{
    "slug": "fortigate", "name": "Fortigate", "icon": "🧱",
    "rule_groups_regex": ".*fortigate.*", "job": "wazuh", "enabled": true,
    "baseline_rules_count": 1, "client_rules_count": 1,
    "integrated_clients_count": 1, "implemented_baseline_rules": 1,
    "total_baseline_slots": 5, "compliance_pct": 20.0,
    "clients": [{
      "client_uid": "cliente-banco-alfa", "client_name": "Banco Alfa",
      "integrated": false, "implemented_rules": 0, "paused_rules": 0,
      "total_baseline_rules": 1, "compliance_pct": 0.0, "status": "none"
    }]
  }],
  "generated_at": "2026-10-18T11:43:24Z"
}
```

- **Distribuição de tecnologias por clientes**: `integrated_clients_count` e as
  regras de cliente atribuídas à tecnologia. A evidência de integração por
  cliente é a regra implementada na pasta daquele cliente — o Loki não carrega
  label de tenant nesta arquitetura.
- **Mapa de conformidade**: `implemented_rules / total_baseline_rules` por
  cliente. Vínculo por `annotations.cloned_from` com fallback para o título-base.
- Regras `global` cuja tecnologia não é resolvível (nem pela label `technology`,
  nem pelo `rule_groups` da query) contam em `baseline_rules_unmapped`.

### `GET /technologies/{slug}/baseline` 🔒
Lista as regras da pasta `global` que compõem o baseline da tecnologia
(`uid`, `title`, `severity`, `mitre_technique`, `rule_group`, `is_paused`).

### `POST /technologies/{slug}/implement-baseline` (CSRF) 🔒
Replica **todas** as regras de baseline da tecnologia na pasta do cliente.

```json
{
  "target_folder_uid": "cliente-banco-alfa",
  "target_folder_title": "Banco Alfa",
  "confirm_client_without_technology": false,
  "evaluation_group": "5m"
}
```

Resposta `200`:

```json
{
  "message": "Baseline da tecnologia 'Fortigate' processado no cliente 'Banco Alfa': 3 criada(s), 1 já existente(s), 0 falha(s).",
  "technology": "fortigate", "technology_name": "Fortigate",
  "client_uid": "cliente-banco-alfa", "client_name": "Banco Alfa",
  "total": 4, "created": 3, "skipped": 1, "failed": 0,
  "contact_point": "stg",
  "evaluation_group": "5m",
  "rules": [{
    "uid": "ghp-1b7ce162dd", "title": "[Banco Alfa] E2E Fortigate - Trafego negado",
    "status": "created", "detail": null
  }]
}
```

Validações de segurança (servidor):

1. Tecnologia inexistente → `404`; pasta inexistente → `404`; pasta `global` → `400`.
2. Tecnologia sem regras na pasta `global` → `409`.
3. **Validação prévia de integração**: se o cliente ainda não tem nenhuma regra
   daquela tecnologia, o endpoint responde `409` até receber
   `confirm_client_without_technology: true` (aceite coletado no pop-up de
   confirmação de segurança da UI).
4. Regras já replicadas (mesmo `cloned_from` ou mesmo título-base) retornam
   `status: skipped` — reexecutar a operação nunca duplica alertas.

Cada regra criada recebe labels `client`, `siem_tier=client`, `technology`,
`technology_name` e annotations `cloned_from`, `client_name`,
`baseline_technology`.

### `PUT /technologies/{slug}` (CSRF) 🔒
Mesmo payload do `POST` (upsert do registro existente). `404` se o slug não existe.

### `DELETE /technologies/{slug}` (CSRF) 🔒
Remove apenas do catálogo do portal; regras já criadas no Grafana mantêm as labels `technology`/`technology_name` e seguem operando.

```json
{ "message": "Tecnologia 'Palo Alto' removida do catálogo.", "slug": "palo_alto" }
```

### `POST /technologies/resolve` 🔒
Descobre quais tecnologias o matcher `rule_groups` da query referencia.

```json
{ "query": "{job=\"wazuh\", rule_groups=~\".*windows.*\"} | json" }
```
Resposta: lista de `TechnologyOut` compatíveis (vazia quando nada corresponde).

---

## Homologação — estágio de deploy por Contact Point

O Contact Point amarrado à regra (`notification_settings.receiver`) é interpretado
como **estágio de deploy**. A derivação é pura (`backend/app/contact_points.py`):

| Condição | `deploy_status` | Rótulo na UI |
|---|---|---|
| `isPaused = true` | `paused` | Pausada (independente do Contact Point) |
| ativa + CP `prod` | `active` | Ativa |
| ativa + CP `dev`/`stg` | `homolog` | Homologação |
| ativa + sem CP conhecido | `unassigned` | Sem Contact Point (o alerta não chega a ninguém) |

`contact_point` e `deploy_status` aparecem em todas as respostas de regra
(`GET /rules` e `GET /rules/{uid}`) e são a base da coluna **STATUS** da página
`/rules`.

**Regra de negócio**: `POST /rules` e `POST /rules/{uid}/duplicate` gravam
`notification_settings.receiver = "dev"`. A implementação e importação de baseline
(`POST /technologies/{slug}/implement-baseline` e `POST /rules/import/execute`)
gravam dinamicamente o Contact Point mapeado para o estágio `"stg"` nas configurações
de Homologação. O clone jamais herda `prod` da origem — a promoção é decisão explícita do operador.

### `GET /homologation` 🔒

Visão consolidada da página Homologação.

```json
{
  "generated_at": "2026-10-18T14:52:41+00:00",
  "contact_points": [
    {"name": "dev",  "uid": "dante-contact-dev",  "type": "email", "tier": "homolog", "standard": true},
    {"name": "prod", "uid": "dante-contact-prod", "type": "email", "tier": "prod",    "standard": true},
    {"name": "stg",  "uid": "dante-contact-stg",  "type": "email", "tier": "homolog", "standard": true}
  ],
  "missing_contact_points": [],
  "metrics": {"total_rules": 22, "active": 1, "homolog": 0, "paused": 8, "unassigned": 13},
  "clients": [
    {"folder_uid": "cliente-banco-beta", "folder_title": "Banco Beta",
     "total": 3, "active": 1, "homolog": 0, "paused": 0, "unassigned": 2}
  ],
  "rules": [
    {"uid": "ghp-d68b9103bb", "title": "Baseline - AD - Possible Brute Force",
     "folder_uid": "cliente-banco-beta", "folder_title": "Banco Beta",
     "state": "normal", "is_paused": false,
     "contact_point": "prod", "deploy_status": "active", "...": "demais campos de RuleSummary"}
  ]
}
```

- Regras internas (`portal_internal=rule_group_anchor`) **não** entram em
  `rules`/`metrics`/`clients` — mesmo filtro de `/rules` e da matriz.
- Se a API de provisionamento não responder, `contact_points` volta vazio e a
  página continua funcional (o operador vê o CP real de cada regra).
- `missing_contact_points` lista os CPs canônicos ausentes (`dev`/`stg`/`prod`).

### `POST /homologation/rules/{uid}/contact-point` (CSRF) 🔒

Promove/rebaixa o estágio de deploy da regra alterando o receiver no Grafana.

```json
{"contact_point": "prod"}
```

```json
{
  "message": "Regra 'Baseline - AD - Possible Brute Force' movida para o estágio Ativa (Contact Point 'prod').",
  "uid": "ghp-d68b9103bb",
  "title": "Baseline - AD - Possible Brute Force",
  "contact_point": "prod",
  "deploy_status": "active",
  "previous_contact_point": "dev",
  "previous_deploy_status": "homolog"
}
```

- **422** — `contact_point` fora de `dev`/`stg`/`prod`.
- **409** — Contact Point não provisionado no Grafana (apontar para um receiver
  inexistente silenciaria o alerta): aplique
  `grafana/provisioning/alerting/contact-points.yml` e reinicie o Grafana.
- **400** — regra interna do portal (âncora de grupo de avaliação) ou recording
  rule: não possuem estágio de deploy.
- O `PUT` reenvia o objeto completo da regra (mesmo padrão de `toggle-pause`);
  apenas `notification_settings` é alterado.

---

## Loki — laboratório de logs sintéticos

Todas as rotas exigem sessão (`ghp_session`); a injeção também exige o cabeçalho
anti-CSRF `X-Requested-With: hunter-portal`. O portal nunca fala com o Loki
diretamente: tudo passa pelo proxy do datasource `loki` no Grafana.

### `GET /loki/status` 🔒

Estado do datasource Loki e labels existentes (usado para habilitar o formulário).

```json
{
  "available": true, "ready": true,
  "datasource": "Loki", "datasource_uid": "loki", "url": "http://loki:3100",
  "labels": ["agent_name", "job", "rule_groups", "synthetic", "synthetic_source"],
  "message": "Loki disponível via datasource 'Loki'."
}
```

- `available=true, ready=false` → o datasource existe mas não respondeu à consulta de
  labels; a UI mantém o botão de injeção desabilitado.
- `available=false` → nenhum datasource Loki no Grafana; a mensagem orienta a subir o
  serviço `loki` do compose.

### `POST /loki/logs` (CSRF) 🔒

Injeta linhas JSON no Loki e confirma a ingestão consultando o próprio datasource.

```json
{
  "stream": {"job": "wazuh", "rule_groups": "linux", "agent_name": "lab-linux-01"},
  "lines": [
    {"rule": {"id": 5710, "level": 10}, "data": {"srcip": "10.10.0.11"}},
    {"rule": {"id": 5710, "level": 10}, "data": {"srcip": "10.10.0.12"}}
  ],
  "spread_seconds": 300,
  "mark_synthetic": true
}
```

- `stream`: labels do stream. `job` é **obrigatório**; nomes no padrão
  `^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`, prefixo `__` proibido, valores até 200 caracteres
  (`A-Za-z0-9_.:/@+-`), no máximo 20 labels.
- `lines`: 1 a 200 objetos JSON (serializados compactos). Teto de 64 KiB por linha e
  256 KiB por requisição.
- `spread_seconds` (0–86400, padrão `300`): distribui os timestamps no passado, em
  ordem crescente (o Loki rejeita série fora de ordem); o último fica no mínimo 1 ms
  antes de "agora".
- `mark_synthetic` (padrão `true`): adiciona `synthetic="true"` e
  `synthetic_source="portal"` às labels.

Resposta `200`:

```json
{
  "status": "ok", "datasource": "Loki", "datasource_uid": "loki",
  "stream": {"job": "wazuh", "rule_groups": "linux", "agent_name": "lab-linux-01",
             "synthetic": "true", "synthetic_source": "portal"},
  "lines_sent": 2, "bytes_sent": 210,
  "logql": "{agent_name=\"lab-linux-01\", job=\"wazuh\", ss_groups=\"linux\", synthetic=\"true\", synthetic_source=\"portal\"} | json",
  "verified_count": 2, "verified": true,
  "grafana_explore_url": "http://localhost:3000/explore?left=...",
  "message": "2 linha(s) injetada(s). O stream agora tem 2 entrada(s) consultável(is) na janela de verificação."
}
```

Erros:

| Código | Situação |
|---|---|
| `422` | label inválida, `job` ausente, linha que não é objeto JSON, volumes acima do teto |
| `403` | cabeçalho anti-CSRF ausente |
| `502` | o Loki recusou o push (serviço fora do ar ou payload rejeitado) |
| `503` | nenhum datasource Loki configurado |
| `504` | push excedeu o tempo limite (8 s) |

`verified_count` conta as entradas **do stream** na janela de verificação
(`spread_seconds + 120 s`), não apenas as desta requisição — é a prova de que o dado
está consultável, e não um contador do que foi enviado.

### Consulta das linhas de laboratório

`POST /rules/execute-query` com `{"query": "{synthetic=\"true\"} | json"}` devolve as
linhas mais recentes (ordenadas por timestamp, limite do payload). É a mesma rota usada
pelo painel "Últimas linhas sintéticas" da página `/loki`.

---

## Exemplo rápido (curl)

```bash
BASE=http://localhost:8080/api
H='-H Content-Type:application/json -H X-Requested-With:hunter-portal'

# login (guarda o cookie)
curl -s -c /tmp/dante.jar $H -d '{"username":"hunter","password":"<senha>"}' $BASE/auth/login

# consulta autenticada
curl -s -b /tmp/dante.jar $BASE/rules | head -40

# lint de LogQL
curl -s -b /tmp/dante.jar $H \
  -d '{"query":"{job=\"wazuh\", rule_groups=~\".*windows.*\"} |= \"Failed\" | json"}' \
  $BASE/rules/lint-logql
```
