# Pitfalls reais de API — Grafana 12 / Loki 3

## Loki

- `POST /api/datasources` devolve só um subconjunto (`id`, `message`, `name`, `uid`), **sem
  `url`**: monte o resumo com fallback para o payload enviado, senão a resposta fica com
  `loki_datasource_url: null` (falso verde de E2E já observado).
- Nome de data source é único no Grafana: pré-cheque na listagem e devolva 409 **antes** de
  criar a pasta, para não deixar pasta órfã quando o nome do DS colidir.
- `GET /api/ds/query` com datasource Loki exige `"queryType": "range"`; string vazia devolve
  `client: failed to query data: invalid queryType: ` (HTTP 500). Com TestData mantenha `""`.
- O plugin devolve **um frame por stream**, em ordem arbitrária, e aplica `maxLines` por
  consulta. Para "últimas N linhas": pedir margem (`limit*5`, teto 1000), ordenar por timestamp
  no backend e só então cortar — senão linhas novas somem atrás de outro stream.
- O campo de log no frame chama-se `Line` (maiúsculo): casar por `lower()` em
  `body|line|message|value`.
- Nunca deixe fallback que inventa linha de log quando a consulta volta vazia: mascara
  "sem logs" e já enganou E2E.
- Data source Loki antigo de teste (nome minúsculo, `url` vazio) vem primeiro em
  `GET /api/datasources`: `find_loki_datasource` deve preferir `uid == "loki"`, depois qualquer
  um com `url` não vazia.
- Push JSON pelo proxy:
  `POST /api/datasources/proxy/uid/loki/loki/api/v1/push` com
  `{"streams":[{"stream":{...},"values":[["<ns>","<linha>"]]}]}` → 204, sem protobuf.
- `limits_config.reject_old_samples_max_age` (168h no config atual) limita quão no passado o
  laboratório pode espalhar timestamps.
- E2E de presença: o Loki novo começa vazio. Semeie pela API de logs sintéticos
  (`POST /api/loki/logs` com `rule_groups` alvo) em vez de depender de execuções antigas.

## Grafana Alerting

- `GET /api/prometheus/grafana/api/v1/rules` **não** lista regras pausadas: a âncora do tenant
  (`isPaused: true`) não aparece. Para achá-la use `GET /api/v1/provisioning/alert-rules` e
  filtre `uid` com prefixo `ghp-anchor-` + label `portal_internal`.
- Grupo cujo único membro é a âncora pausada aparece no ruler com `rules: [anchor]` (verificado
  no Grafana 12.4) — mas não confie nisso como fonte única.
- `GET /api/v1/provisioning/alert-rules` devolve `notification_settings: null` quando não há
  receiver; o receiver está em **snake_case** nessa API (aceite camelCase também).
- O PUT do provisioning reenvia o objeto completo: para alterar um campo, leia a regra, altere
  e envie tudo (padrão usado por toggle-pause e promoção de contact point).
- 412 (não 409) em `POST /api/tenants` com `uid` existente.

## Ordem de limpeza em E2E

1. `DELETE /api/v1/provisioning/alert-rules/{clone}`
2. `DELETE /api/tenants/{uid}` (portal)
3. `DELETE /api/v1/provisioning/alert-rules/{origem}`

Se o tenant ainda tiver regra de detecção, o passo 2 devolve 400. Para apagar regras que ficaram
(ou a pasta em si) use basic auth admin do Grafana e, se necessário,
`DELETE /api/folders/{uid}?forceDeleteRules=true`.

## Stack local

- Provisionamento de datasource/contact point só aplica no boot do Grafana:
  `docker compose restart grafana` depois de editar o YAML.
- `up -d` após `build` mantém o digest antigo do frontend: conferir e usar
  `docker compose up -d --force-recreate frontend`.
