# Operação — D.A.N.T.E.

Guia de execução, manutenção e diagnóstico. Configuração detalhada de variáveis está no [`README`](../README.md#-7-implantação).

---

## 1. Comandos essenciais

```bash
docker compose ps                 # status + healthchecks
docker compose logs -f backend    # logs do backend (LOG_LEVEL)
docker compose logs -f frontend   # acesso do Nginx
docker compose stop               # pausa sem remover
docker compose start              # retoma
docker compose down               # remove containers (volumes permanecem)
docker compose down -v            # DESTRUTIVO: remove volumes (Grafana + catálogo + token)
```

`docker compose up/build` pode ser classificado como processo longo pelo runtime do agente: nesses casos rode em background e valide em chamada separada com `docker compose ps` e `logs --tail 20`.

---

## 2. Ciclo de alteração de código

```bash
# 1. rebuild apenas do que mudou
docker compose build backend frontend

# 2. recriar containers
docker compose up -d

# 3. o frontend precisa ser forçado a recriar quando há novo bundle
docker compose up -d --force-recreate frontend
docker inspect dante-frontend --format '{{.Image}}'      # deve casar com:
docker images -q grafana-hunter-portal-frontend
```

Motivo: `up -d` pode manter o container antigo mesmo após `build`, servindo bundle velho — o teste de UI passaria a validar código antigo. Se o cache do build mascarar assets, use `docker compose build --no-cache frontend`.

### Gates de validação reais

| Camada | Validação |
|---|---|
| Backend | `docker exec dante-backend python -c "import app.main, app.mappers, app.routers.monitoring"` e conferir o log de startup (rotas + catálogo de tecnologias). |
| Backend (alternativa) | `curl -s localhost:8080/api/health` e `/api/health/ready`. |
| Frontend | `docker compose build frontend` já executa `tsc --noEmit && vite build` — build verde é o gate de tipagem. |
| Funcional | Fluxo criar → listar → remover via API, conferindo os campos do JSON (ex.: `technology`, `labels`). |

> `python -m compileall` **não** funciona dentro do backend: a imagem roda com `read_only: true`. Use import do módulo.

---

## 3. Healthchecks

| Serviço | Endpoint/variante | Interpretação |
|---|---|---|
| `dante-backend` | `GET /api/health` | Liveness. `ok` = processo sadio. |
| `dante-backend` | `GET /api/health/ready` | `status=ok` só com Grafana acessível **e** token configurado. |
| `dante-grafana` | `/api/health` | Readiness interna do Grafana. |
| `dante-frontend` | `GET /` (Nginx) | Sem healthcheck Docker; valide por `curl -I localhost:8080`. |

```bash
curl -s localhost:8080/api/health/ready | jq
# { "status": "ok", "grafana_reachable": true, "grafana_token_configured": true }
```

`status=degraded` significa: Grafana inalcançável a partir do backend ou token ausente/inválido.

---

## 4. Backups

O que importa preservar:

1. **`grafana-data`** — pastas, regras, silences, datasources (fonte de verdade da detecção).
2. **`portal-data`** — catálogo de tecnologias (`technologies.json`).
3. **`.env`** — credenciais do portal e do Grafana (guarde fora do repositório).

```bash
# Snapshot lógico do Grafana
docker exec -u 0 dante-grafana tar -czf /tmp/grafana-data.tgz -C /var/lib/grafana .
docker cp dante-grafana:/tmp/grafana-data.tgz ./backup-grafana-$(date +%F).tgz

# Catálogo de tecnologias
docker cp dante-backend:/data/technologies.json ./backup-technologies-$(date +%F).json
```

Restore: pare o stack, restaure os arquivos/volumes e suba novamente. Para reverter apenas o catálogo, basta substituir `technologies.json` no volume `portal-data` e reiniciar o backend (o store é carregado no startup).

> O token do Grafana é regenerável: se `portal-secrets` for perdido, rode o bootstrap novamente (`docker compose up -d grafana-bootstrap` com o perfil `default`) ou defina `GRAFANA_TOKEN`.

---

## 5. Pasta do baseline (`global`)

O bootstrap não cria mais dados de exemplo: ele garante apenas a pasta `global`, onde vivem as regras do baseline institucional (seed versionado em `grafana/bootstrap/seed/rules/`), e nada mais. As regras são criadas pelo portal (*+ Nova Regra* → abrangência *Baseline*) ou replicadas para os clientes a partir dela.

> Não há mais `SEED_SAMPLE_DATA`: pasta de demonstração, regras de exemplo e silence de exemplo deixaram de existir. Para popular um ambiente novo, use o seed de regras do baseline ou o próprio portal.

---

## 6. Manutenção do catálogo de tecnologias

- **Pela UI**: *Regras → + Nova Regra → ⚙️ Gerenciar Tecnologias* (criar, editar, remover).
- **Pela API**: ver [`docs/API.md`](API.md#tecnologias-ss_groups--data-source).
- Diretrizes ao cadastrar:
  - `rule_groups_regex` deve ser um recorte estável do `rule.groups` do Wazuh (ex.: `.*windows.*`, `.*fortigate.*`).
  - `job` permanece `wazuh` nesta arquitetura.
  - Evite regex sobrepostos entre tecnologias — a resolução de query passa a ser ambígua e a criação de regra exige seleção explícita.
  - Remover uma tecnologia **não** altera regras existentes no Grafana; apenas impede novas regras com aquele recorte.

---

## 7. Troubleshooting

| Sintoma | Causa provável | Ação |
|---|---|---|
| `/api/health/ready` = `degraded` | Grafana inalcançável ou token ausente | `docker compose logs --tail 50 backend`; validar `GRAFANA_URL` e `GRAFANA_TOKEN`/volume `portal-secrets`; `curl` no `/api/health` do Grafana. |
| Login retorna `401` mesmo com senha correta | `PORTAL_ADMIN_PASSWORD` diferente do `.env` em uso | O backend falha no boot se a senha tiver < 12 caracteres; confirme o `.env` efetivamente carregado e recrie o backend. |
| Login `429` | Rate limit por IP (5/300 s) | Aguarde a janela ou ajuste `LOGIN_MAX_ATTEMPTS` / `LOGIN_WINDOW_SECONDS` e recrie o backend. |
| Sessão cai após login em HTTP não-localhost | Cookie `Secure` rejeitado pelo navegador | `COOKIE_SECURE=false` no ambiente de desenvolvimento (nunca em produção). |
| Mutações retornam `403 Cabeçalho anti-CSRF ausente` | Chamada sem `X-Requested-With: hunter-portal` | O front já envia; em scripts/curl, inclua o cabeçalho. |
| Criação de regra `422` | LogQL inválido, tecnologia ausente/ambígua ou `ss_groups` fora do recorte | Ler `detail` da resposta, rodar `POST /api/rules/lint-logql` e ajustar o seletor. |
| Implementação no cliente `403` | Regra de origem fora da pasta `global` | Só baseline é replicável; crie a regra direto no cliente. |
| UI não reflete o último build | `up -d` reaproveitou o container | `docker compose up -d --force-recreate frontend` e conferir o digest da imagem. |
| Detalhes de regra falham com `502` | Grafana sem a API de provisioning habilitada / SA sem role Admin | Verifique a service account (`Admin` no OSS) e a versão do Grafana. |
| Silences criados fora do portal aparecem como `manual` | Sem tag canônica no comentário | Comportamento esperado; recrie pelo portal para obter a classificação correta. |
| Consulta real sem dados | Datasource Loki ausente ou inalcançável | No modo embutido o serviço `loki` já é provisionado: confira `docker compose ps loki` (`healthy`) e `curl http://localhost:3100/ready`; em `external`, registre um datasource `type=loki` no Grafana alvo. |
| Página Logs Sintéticos bloqueada (`indisponível`) | Loki fora do ar ou datasource sem URL | `docker compose up -d loki` e `GET /api/loki/status`; a injeção fica desabilitada enquanto o datasource não responder à consulta de labels. |
| Linhas injetadas não aparecem | Janela do Explore menor que `spread_seconds` | A injeção distribui os timestamps no passado (`Distribuir em`); consulte uma janela igual ou maior. |
| Resetar o laboratório | Dados de teste acumulados | `docker compose down` + `docker volume rm grafana-hunter-portal_loki-data` (remove só os logs; Grafana e catálogo ficam intactos). |
| `docker compose` recusa variável obrigatória | `PORTAL_ADMIN_USER`/`PORTAL_ADMIN_PASSWORD` ou senha do Grafana vazios | Preencha o `.env` (senhas ≥ 12 caracteres no portal). |

### Diagnóstico rápido

```bash
docker compose ps
docker compose logs --tail 100 backend
docker inspect dante-backend --format '{{.State.Health.Status}}'
docker exec dante-backend python -c "import app.main; print('ok')"
curl -s localhost:8080/api/health/ready | jq
curl -s -o /dev/null -w '%{http_code}\n' localhost:8080/
```

---

## 8. Exposição e rede

- `BIND_ADDRESS=0.0.0.0` publica o portal em todas as interfaces; em host com IP público, restrinja no firewall ou use `BIND_ADDRESS=127.0.0.1` atrás de um reverse proxy com TLS.
- O backend **não** publica porta: só é acessível por `edge-net`/`core-net`. Nunca o exponha diretamente — ele confia no `X-Forwarded-For` do Nginx para o rate limit.
- O Grafana embutido publica `${GRAFANA_PORT}` no host. Em produção com perfil `default`, limite o acesso ou use `external` apontando para o Grafana gerenciado.
- TLS: terminar em um proxy na frente do `dante-frontend` e manter `COOKIE_SECURE=true`.
