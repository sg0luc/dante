# Arquitetura — D.A.N.T.E.

Documento de referência sobre componentes, fluxos e decisões de projeto do portal. Para o uso funcional, veja o [`README`](../README.md); para contratos de API, [`API.md`](API.md).

---

## 1. Princípios

1. **O navegador nunca fala com o Engine de Alertas.** O backend é o único cliente da API do Engine de Alertas/Alertmanager e detém o token da service account.
2. **O frontend depende apenas dos modelos do portal**, nunca do JSON bruto do Engine de Alertas. Isso isola a UI de mudanças entre versões do Engine de Alertas (`backend/app/mappers.py` + `frontend/src/types.ts`).
3. **Regras de negócio são aplicadas no servidor.** O linting de LogQL, a segregação por tecnologia e a conversão de exceção permanente em `endsAt` de 10 anos não são "validações de UI": são invariantes do backend, válidas também para chamadas diretas à API.
4. **Falha rápida na configuração.** `Settings` (pydantic-settings) valida URL, senha mínima de 12 caracteres e `LOG_LEVEL` no boot; configuração inválida derruba o processo em vez de rodar insegura.
5. **Container descartável.** Backend roda com `read_only: true`, `/tmp` em `tmpfs`, usuário não-root (UID 10001), `cap_drop: [ALL]`; estado próprio vive em volumes.

---

## 2. Componentes

| Componente | Container | Tecnologia | Responsabilidade |
|---|---|---|---|
| Frontend | `dante-frontend` | React 18 + TS + Vite, servido por `nginx-unprivileged:1.27-alpine` | SPA, sessão via cookie, proxy `/api` → `backend:8000`, cabeçalhos de segurança (CSP, XFO, Referrer-Policy, Permissions-Policy, COOP). |
| Backend | `dante-backend` | Python 3.12-slim, FastAPI, httpx | Autenticação local, sessões, CSRF, rate limit, linter LogQL, normalização de dados, catálogo de tecnologias, chamadas ao Engine de Alertas. |
| Engine de Alertas | `dante-alerting` | `alerting/alerting:12.4.0` (padrão) | Alerting unificado, pastas, regras, Alertmanager API v2, datasource Telemetria. |
| Bootstrap | `dante-alerting-bootstrap` | Shell + curl (`./alerting/bootstrap`) | Job idempotente: service account + token no volume `portal-secrets`, seed opcional de pasta/regras/silence. |
| Telemetria | `dante-telemetria` | `alerting/telemetria:3.4.2` (single-binary, sem auth) | Armazena os logs consultados pelas regras LogQL e recebe as linhas fictícias do laboratório. Volume `telemetria-data`, retenção de 7 dias, porta publicada apenas no loopback do host. |
| Datasource Telemetria | provisionado pelo Engine de Alertas | `telemetria` (`alerting/provisioning/datasources/telemetria.yml`) | Proxy do Engine de Alertas para `http://telemetria:3100`; é o caminho único de leitura (query) e escrita (push) usado pelo portal. |

Comunicação:

- `edge-net`: frontend ↔ backend.
- `core-net`: backend ↔ alerting; backend ↔ telemetria; alerting ↔ telemetria; bootstrap ↔ alerting.
- O backend é acessível apenas pelas redes internas; o frontend publica `8080`, o Engine de Alertas `3000` e o Telemetria publica `3100` apenas em `127.0.0.1` (push/inspeção manual).

---

## 3. Fluxos

### 3.1. Requisição autenticada

```
Browser ──(cookie dante_session + X-Requested-With)──▶ Nginx :8080
        ──/api/*──▶ FastAPI :8000 (--proxy-headers)
                ├─ get_current_user: cookie → SessionStore em memória
                ├─ require_csrf_header nas mutações
                └─ Engine de AlertasClient (Bearer token) ──▶ Engine de Alertas/Alertmanager
```

- Sessões são tokens opacos com expiração (`SESSION_TTL_MINUTES`) mantidos em memória (`SessionStore`), com purge de expirados.
- `client_ip` usa o IP resolvido pelo Uvicorn a partir do `X-Forwarded-For`, que o Nginx **sobrescreve** com `$remote_addr` — impede spoofing de IP no rate limit.
- Cabeçalhos de resposta adicionados pelo backend: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. Os cabeçalhos da SPA ficam no nível `server` do Nginx (nenhum `add_header` em `location`, para não cancelar a herança).

### 3.2. Criação de regra de detecção

```
POST /api/rules
  1. lint_logql(query, catálogo de tecnologias)     → 422 se inválido
  2. resolve tecnologia (payload.technology | rule_groups da query)
     - 0 candidatas → 422 (selecione a tecnologia)
     - >1 candidata → 422 (selecione explicitamente)
  3. rule_groups da query precisa pertencer à tecnologia → 422
  4. resolve pasta (global | cliente) e rule group
  5. monta labels padronizadas + anotações (descrição, query)
  6. Engine de Alertas: POST provisioning/alert-rules
```

Consequência: não existe caminho que grave regra sem passar pelo linter, nem regra cuja label `technology` divirja do `ss_groups` efetivamente consultado.

### 3.3. Replicação baseline → cliente

```
POST /api/rules/{uid}/duplicate
  1. regra de origem precisa estar em 'global'            → 403
  2. query efetiva = custom_logql | expr da regra global
  3. lint_logql(query efetiva)                            → 422 (antes de criar pasta/regra)
  4. cria pasta do cliente se não existir
  5. clona rule, novo uid ghp-<hex10>, isPaused=false,
     labels client/siem_tier, tecnologia re-resolvida pela query
  6. annotations.cloned_from + client_name (rastreabilidade)
```

### 3.4. Silences: classificação e ciclo de vida

O Alertmanager não possui metadados livres por silence. A natureza é reconstruída no backend (`mappers.classify_silence`) a partir de três sinais: tag no comentário, vigência e `createdBy`.

```
tag [excecao] | [permanente]        → permanent
vigência >= 365 dias | endsAt vazio → permanent
createdBy contém 'antiflood'        → antiflood
createdBy contém 'maintenance'      → maintenance
caso contrário                      → manual
```

Na criação (`POST /api/silences`) o backend normaliza o comentário (remove tag anterior, prefixa a canônica) e, para `kind=permanent`, **sobrescreve** `endsAt` com `now + 3652 dias` — o cliente não controla a permanência.

Na UI, a segregação é operacional: a visão *Exceções permanentes* só oferece **Revogar exceção** (destrutiva, confirmada); *Silences temporários* oferece **Prolongar** (+2h…+3d) e revogação. `+10y` num silence temporário o converte em exceção permanente.

### 3.5. Governança de baseline

`GET /api/rules/global-matrix` monta, para cada regra da pasta `global`, a cobertura por cliente comparando as regras existentes nas pastas de clientes:

- `active` — regra presente e não pausada;
- `paused` — presente com `isPaused`;
- `not_implemented` — ausente na pasta.

A UI deriva daí taxa de adesão, regras 100% implementadas e conformidade de baseline por cliente (usada na Visão Geral).

### 3.6. Página Tecnologias (catálogo, telemetria e baseline)

Módulos: `backend/app/routers/technologies.py` (rotas), `backend/app/technology_insights.py`
(distribuição/conformidade, puro e testável) e `backend/app/telemetria_presence.py` (consulta
implícita ao Telemetria).

**Validação implícita de telemetria.** Antes de cadastrar uma tecnologia o backend roda, sem
expor a query ao cliente:

```logql
sum(count_over_time({job="wazuh", rule_groups=~".*<tecnologia>.*"} | json [1m]))
```

- `count > 0` → cadastro liberado.
- Telemetria consultável e `count == 0` → `409`; a UI mostra o aviso e o aceite explícito
  (`confirm_without_logs`) vem de um pop-up de confirmação.
- Telemetria indisponível (sem datasource, timeout, erro) → cadastro **não** é bloqueado, porque a
  ausência de logs não pode ser comprovada; a resposta da API diferencia os casos via
  `available`/`found`.

O recorte e o `job` passam pelo mesmo validador usado na escrita (`validate_rule_groups_regex`
/ `validate_job`), então a interpolação na query não permite quebra de literal nem injeção de
estágios.

**Laboratório de logs sintéticos.** `backend/app/routers/telemetria.py` orquestra o push e a
verificação; `backend/app/telemetria_synthetic.py` concentra validação de labels, montagem do
payload de push (timestamps em nanossegundos, ordenados e sempre no passado), geração da
LogQL de conferência e do link do Explore. O push vai por
`POST /api/datasources/proxy/uid/telemetria/telemetria/api/v1/push` (JSON, sem protobuf), então o
backend não precisa de URL própria do Telemetria e o modo `external` continua funcionando. Toda
linha recebe `synthetic="true"`/`synthetic_source="portal"`; o Telemetria não tem autenticação,
portanto a validação de entrada do backend é a fronteira de confiança (200 linhas, 64 KiB
por linha, 256 KiB por requisição, `job` obrigatório).

**Grupo de avaliação por tenant.** Todo tenant tem o grupo padrão `5m` com intervalo
de `5m`. Como o Engine de Alertas não
persiste grupo vazio, o grupo é materializado por uma regra-âncora pausada marcada com
`portal_internal=rule_group_anchor`; ela nunca avalia, nunca dispara e é filtrada de todas as
contagens do portal. Replicações baseline→cliente passam a apontar sempre para o grupo do
tenant (`tenant_rule_group`), nunca para o grupo do baseline.

**Segregação de telemetria por data source.** Cada tenant possui um data source Telemetria com o
próprio nome (uid = uid da pasta), criado junto com a pasta e removido junto com ela; a URL
padrão vem de `TELEMETRY_TENANT_DATASOURCE_URL` e pode ser sobrescrita por tenant no cadastro.
No laboratório atual todos apontam para o mesmo Telemetria da stack; quando cada cliente tiver seu
Telemetria/endpoint, basta informar a URL específica — nenhuma regra de detecção muda, porque a
query continua referenciando o data source do tenant pela pasta.

**Distribuição por cliente.** O agrupamento analítico continua vindo do `alerting_folder`
(`global` = baseline), portanto "cliente consome a tecnologia" é medido pela presença de
regra daquela tecnologia na pasta do cliente. A tecnologia de uma regra é resolvida
pela label `technology` e, como fallback, pelo `rule_groups` da query (cobre regras antigas sem a
label).

**Mapa de conformidade.** Para cada tecnologia, o baseline é o conjunto de regras da pasta
`global` resolvidas para ela; a implementação em um cliente é localizada por
`annotations.cloned_from` e, na falta dele, por título-base normalizado. A célula vale
`implementadas / total_de_regras_baseline`, com status `complete | partial | none`; regras de
baseline sem tecnologia resolvível aparecem em `baseline_rules_unmapped`.

**Implementação automática de baseline.** `POST /technologies/{slug}/implement-baseline` copia
todas as regras do baseline para a pasta do cliente com `uid` novo, `isPaused=false`, labels
`client`/`siem_tier=client`/`technology` e annotations `cloned_from`/`client_name`/
`baseline_technology`. Regras já presentes são ignoradas (`skipped`), portanto a operação é
idempotente. A validação prévia de integração exige `confirm_client_without_technology=true`
quando o cliente ainda não tem regra da tecnologia — o aceite é coletado no pop-up de segurança
da UI e o servidor revalida.

### 3.7. Avaliação de LogQL

Dois caminhos independentes:

- **Lint** (`lint_logql`): análise estática da query — balanceamento, seletor de stream, operadores, estágios de pipeline, funções métricas, janelas, `job`/`rule_groups` e correspondência com o catálogo.
- **Teste sintético** (`evaluate_logql`): aplica a query a uma linha de log injetada, retornando campos extraídos e o status por estágio (`StageResult`), sem tocar no Engine de Alertas.
- **Execução real** (`POST /api/rules/execute-query`): consulta `/api/ds/query` no datasource Telemetria, com `asyncio.wait_for` de 8 s e parse dos dataframes em `LogLineResult` (`queryType: range` é obrigatório no plugin Telemetria do Engine de Alertas 12). O Telemetria aplica `maxLines` por consulta e devolve streams em ordem arbitrária: o backend pede uma margem, ordena por timestamp e só então corta o limite — sem isso as linhas mais novas podem sumir atrás de outro stream.

---

## 4. Persistência

| Volume | Conteúdo | Observações |
|---|---|---|
| `alerting-data` | Banco do Engine de Alertas (pastas, regras, silences, datasources) | Fonte de verdade do alerting. Backup obrigatório. |
| `portal-secrets` | `/secrets/alerting_token` (0400, dono UID 10001) | Gerado pelo bootstrap; lido pelo backend via `ENGINE_TOKEN_FILE`. |
| `portal-data` | `/data/technologies.json` | Catálogo de tecnologias do portal (escrita atômica). |

O catálogo de tecnologias é semeado a partir de `backend/app/data/technologies.seed.json` quando o arquivo não existe (`TechnologyStore` com `lru_cache`, um por processo). Escrita atômica evita JSON corrompido em queda abrupta.

Validações do catálogo (`backend/app/technologies.py`): slug `^[a-z0-9_]{2,32}$`, regex compilável e livre de `"`, backtick, `\` e newline (para não quebrar o literal LogQL), unicidade de slug e de recorte regex, e geração de `logql_selector` (`{job="...", rule_groups=~"..."}`) para a UI.

---

## 5. Decisões e trade-offs

| Decisão | Motivo | Custo |
|---|---|---|
| Backend como proxy único do Engine de Alertas | Protege o token, permite normalização e aplica regras de negócio | Um hop extra; backend vira ponto de falha do painel |
| Sessões em memória | Simplicidade e revogação imediata sem dependência externa | Reinício invalida sessões; não escala horizontalmente |
| Usuário único de portal | Modelo de operação inicial (MSSP pequeno, operador único) | Sem RBAC/auditoria por operador |
| Natureza do silence codificada no comentário | Alertmanager não tem campo de metadados | Depende do parse da tag; silences criados fora do portal caem em `manual` |
| Catálogo de tecnologias em JSON local | Independente do Engine de Alertas, fácil de versionar/editar | Sem histórico de alterações; um arquivo por instância |
| Lint no frontend **e** no backend | Feedback imediato na UI + invariante real no servidor | Duplicação inevitável de lógica (front chama o mesmo endpoint) |
| Engine de Alertas embutido como padrão | Experiência de demo/laboratório em um `up -d` | Superfície maior em produção — perfil `external` é o recomendado |

---

## 6. Superfície de segurança

- **Autenticação local** com comparação em tempo constante; rate limit por IP no login.
- **Sessão server-side** + cookie `HttpOnly`/`SameSite=Strict` (`Secure` conforme configuração) — sem JWT no cliente.
- **CSRF** por cabeçalho customizado exigido em todas as mutações.
- **CSP restritiva** (`default-src 'self'`, sem `unsafe-inline` em scripts), `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Nginx sem privilégios** e sem `server_tokens`; credenciais do Engine de Alertas nunca aparecem em linha de comando no bootstrap (arquivos de header temporários com `umask 077`).
- **Erros saneados**: `Engine de AlertasError` vira resposta JSON com mensagem controlada; logs nunca incluem senha.

Limites conhecidos: `/api/docs` desabilitado por padrão (habilite só em ambiente controlado); não há WAF/limite de requisições genérico além do login; o backend confia no `X-Forwarded-For` do Nginx, portanto não deve ser exposto diretamente fora das redes internas.
