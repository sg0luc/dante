---
trigger: glob
globs: "docker-compose.yml, Dockerfile, **/Dockerfile, grafana/**, loki/**"
description: "Regras da stack Docker, provisionamento Grafana e Loki do D.A.N.T.E.: rebuild, boot-only provisioning e ordem de limpeza."
---

# Stack Docker / Grafana / Loki

## Ciclo de build
1. `docker compose build backend frontend`
2. `docker compose up -d`
3. `docker compose ps` + `docker compose logs <svc> --tail 20`
4. Frontend alterado: `docker compose up -d --force-recreate frontend` e conferir digest.

`up -d` em foreground é recusado por runtimes que classificam comando longo como processo
persistente: rode em background e verifique em chamada separada. Evite `down` completo — ele
derruba o Grafana sem necessidade.

## Provisioning só no boot
- `grafana/provisioning/datasources/*.yml` e `grafana/provisioning/alerting/contact-points.yml`
  são aplicados **apenas no boot**: depois de criar/editar, `docker compose restart grafana` e
  conferir por API (`GET /api/datasources`, `GET /api/v1/provisioning/contact-points`).
- Seed de regras em `grafana/bootstrap/seed/rules/` é seguro: `seed_rules()` pula uid
  existente, então não sobrescreve edição feita no portal.

## Loki
- Config em `loki/loki-config.yml`, datasource provisionado com `uid: loki` e
  `url: http://loki:3100`. `limits_config.reject_old_samples_max_age` limita timestamps no
  passado.
- Não habilite `query_range.results_cache` em laboratório: consulta terminando em `now` é
  servida do cache e a linha recém-injetada fica invisível.
- Push pelo proxy do datasource:
  `POST /api/datasources/proxy/uid/loki/loki/api/v1/push`.

## Limpeza de ambiente
Ordem obrigatória: excluir regras da pasta (`DELETE /api/v1/provisioning/alert-rules/{uid}`)
→ `DELETE /api/tenants/{uid}` no portal → apagar silences de exemplo. Nunca apague regra com
`labels.portal_internal` (âncora) nem réplica legítima com `datasourceUid: loki`.
Excluir pela API não é durável enquanto existirem seeds de demonstração.
