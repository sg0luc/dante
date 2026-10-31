---
trigger: glob
globs: "*.py, backend/**/*.py"
description: "Regras de backend FastAPI do D.A.N.T.E.: contratos de API, cliente Grafana, LogQL, tipagem e segurança."
---

# Backend FastAPI — D.A.N.T.E.

## Contratos e tipagem
- Pydantic para entrada e saída; nada de `dict` solto em rota. Schemas em `backend/app/schemas.py`.
- Toda rota nova em `routers/technologies.py` deve ser declarada **antes** de
  `GET /technologies/{slug}`, senão o path param captura a rota.
- Erros com status coerente: 409 para conflito de recurso existente, 422 para violação de
  regra de negócio/validação, 400 para operação inválida no estado atual.

## Cliente Grafana (`grafana_client.py`)
- Único ponto de saída HTTP para o Grafana. Nada de `httpx` espalhado em router.
- `create_alert_rule` / `create_datasource` **removem** `provenance`, `id`, `orgID`, `updated`
  e `readOnly` do payload antes do POST: o corpo vence o header e o recurso nasceria
  Provisioned (read-only).
- `update_alert_rule` omite `X-Disable-Provenance` quando o payload traz `provenance`
  preenchido — senão o Grafana responde 500 (`cannot change provenance from 'api' to ''`).
- Filtre a regra-âncora (`labels.portal_internal=rule_group_anchor`) em **todo** consumidor
  de regras via `detection_rules()`.

## LogQL
- Validação sempre pelo `logql_validator.lint_logql` no servidor, em qualquer fluxo que
  persista regra (criação, duplicação, replicação de baseline, implement-baseline).
- Query de presença de telemetria: `sum(count_over_time({job="wazuh", rule_groups=~".*x.*"} | json [1m]))`.
  `count({...} | json [1m])` é LogQL inválido (`unexpected RANGE`).
- `POST /api/rules` monta a query com `datasourceUid: testdata` + `csv_metric_values` — a
  LogQL vira apenas anotação e a regra não lê o Loki. Para detecção real, provisione com
  `datasourceUid: "loki"` e `queryType: "range"` (ver skill `dante-companion`).

## Segurança
- Sessão via cookie `ghp_session` + header anti-CSRF `X-Requested-With: hunter-portal` em todo
  POST/DELETE/PUT.
- Nunca logar token, senha, cookie ou corpo de login. Comparações de segredo em tempo
  constante.
- A validação de entrada do laboratório de logs (`loki_synthetic.py`) é a fronteira de
  confiança: labels no padrão Prometheus, prefixo `__` proibido, `job` obrigatório, limites de
  200 linhas / 64 KiB por linha / 256 KiB por request.

## Teste de sanidade
`python -m compileall` **falha** na imagem (camada read-only). O teste válido é o import:

```bash
docker exec dante-backend python -c "import app.main, app.mappers, app.schemas, app.routers.monitoring"
```
