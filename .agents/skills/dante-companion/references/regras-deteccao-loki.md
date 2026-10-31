# Regras de detecção de baseline com Loki real

Receita para criar regras de detecção que **detectam de verdade** (consulta ao Loki) no
baseline global, em vez das regras de demonstração do fluxo do portal.

---

## 1. Por que não usar `POST /api/rules` para entregar detecção

`POST /api/rules` (`routers/monitoring.py`) monta a query `A` com
`datasourceUid: testdata` + `scenarioId: csv_metric_values` e `stringInput` fixo. A LogQL vira
**anotação** (`annotations.logql_query`) e `model.expr`, mas a avaliação nunca toca o Loki —
a regra dispara por causa dos valores estáticos, não da telemetria.

Consequência prática: para regra que precisa disparar com o que está no Loki, provisione direto
na API de Provisioning do Grafana com `datasourceUid = "loki"` e `queryType: "range"`. Mantenha
o schema de labels/anotações do portal para a regra continuar aparecendo e sendo editável
(`technology`/`technology_name`, `scope`, `client`, `siem_tier`, `mitre_*`, `team`) e envie
`X-Disable-Provenance: true` **sem** `provenance` no corpo (senão nasce Provisioned/read-only).

Segundo bloqueio do mesmo endpoint: ele resolve a tecnologia pelo `rule_groups` da query e devolve
**422** quando o seletor não casa com nenhum `rule_groups_regex` do catálogo. Cenários de laboratório
com `rule_groups="linux"` ou `ss_groups="dns"` só passam por provisioning direto (ou depois de
cadastrar a tecnologia em Tecnologias).

---

## 2. Payload da regra (pipeline Loki → reduce → threshold)

```json
{
  "uid": "ghp-det-<slug-curto>",
  "title": "<Tecnologia> - <Nome da Regra>",
  "folderUID": "global",
  "ruleGroup": "global-detections",
  "condition": "C",
  "for": "0s",
  "noDataState": "OK",
  "execErrState": "Error",
  "isPaused": false,
  "labels": {"severity": "high", "category": "authentication", "mitre_tactic": "credential-access",
             "mitre_technique": "T1110", "scope": "baseline", "client": "global",
             "siem_tier": "global", "technology": "ad_windows", "technology_name": "AD/Windows",
             "team": "soc"},
  "annotations": {"summary": "...", "description": "...", "logql_query": "<query>", "runbook_url": "https://attack.mitre.org/..."},
  "notification_settings": {"receiver": "dev"},
  "data": [
    {"refId": "A", "queryType": "range", "relativeTimeRange": {"from": 300, "to": 0},
     "datasourceUid": "loki",
     "model": {"refId": "A", "editorMode": "code", "expr": "<query>", "queryType": "range",
               "legendFormat": "__auto", "datasource": {"type": "loki", "uid": "loki"},
               "intervalMs": 1000, "maxDataPoints": 43200}},
    {"refId": "B", "queryType": "", "relativeTimeRange": {"from": 0, "to": 0}, "datasourceUid": "__expr__",
     "model": {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last",
               "datasource": {"type": "__expr__", "uid": "__expr__"}}},
    {"refId": "C", "queryType": "", "relativeTimeRange": {"from": 0, "to": 0}, "datasourceUid": "__expr__",
     "model": {"refId": "C", "type": "threshold", "expression": "B",
               "conditions": [{"evaluator": {"type": "gt", "params": [5]}}],
               "datasource": {"type": "__expr__", "uid": "__expr__"}}}
  ]
}
```

- Título sempre no padrão `<Tecnologia> - <Nome da Regra>` (pedido permanente do usuário).
- `datasourceUid` na instância **e** em `model.datasource` com o uid provisionado `loki`.
- Regra de agregação (`count_over_time`) devolve valor único por stream: `sum(...)` sem `by`
  produz uma série; `sum by (data_srcip)` produz uma por IP (use para volume por origem).

---

## 3. Nomes de campo do `| json` no Loki (flatten com `_`)

Objetos aninhados viram `a_b_c`; **arrays não são indexáveis por nome** (`rule_groups_0`), então
filtre por um escalar do array (ex.: `rule_id`) ou por line filter.

Campos úteis da telemetria Wazuh/Victor (validados contra dados reais do laboratório):

- Linux/sshd: `rule_id`, `data_srcip`, `data_srcuser`, `data_dstuser`, `data_pam_status`, `full_log`
- Windows/AD: `rule_id`, `win_system_eventID`, `win_eventdata_targetUserName`, `win_eventdata_ipAddress`
- Fortigate: `rule_id`, `data_srcip`, `data_dstip`, `data_action` (`deny`/`blocked`), `data_dstport`
- DNS: `rule_id`, `data_query_name`, `data_qtype`, `data_srcip`, `data_response_length`
- Office365: `rule_id`, `data_office365_Operation`, `data_office365_UserId`,
  `data_office365_ClientIP`, `data_office365_ResultStatus` (`Failed`/`FailedOnly`)

Sintaxe do filtro é label filter LogQL: `| json | campo="valor"` ou `=~"a|b"`.
Valide a query antes de provisionar com `GET /loki/api/v1/query?query=<expr>` — erro de parser
volta como HTTP 400 com a mensagem exata, e campo inexistente devolve resultado vazio (silencioso).

---

## 4. Threshold: o quanto antes de alertar

- Evento de alta fidelidade (membro adicionado a grupo privilegiado, sudo para root com `nsenter`):
  `gt 0` — qualquer ocorrência justifica triagem.
- Força bruta / password spraying por volume: `gt 5` em janela de 5m.
- Varredura de portas: `sum by (data_srcip)` com `gt 20` em 5m (ruído normal de deny não chega lá).
- Exfiltração DNS: `gt 10` consultas TXT em 5m.
- `noDataState: "OK"` sempre — ausência de telemetria não é incidente; sem isso a regra vira
  ruído de `NoData` quando o agente cai.

---

## 5. Verificação (o que conta como "regra validada")

1. Semeie telemetria pelo caminho do produto: `POST /api/loki/logs` (página Logs Sintéticos).
   Login por curl com cookie jar — o `CookieJar` do `urllib` não repassa o `ghp_session` pelo
   proxy nginx e todas as chamadas seguintes voltam 401:
   ```bash
   U=$(grep '^PORTAL_ADMIN_USER=' .env | cut -d= -f2-); P=$(grep '^PORTAL_ADMIN_PASSWORD=' .env | cut -d= -f2-)
   curl -s -c jar.txt -X POST http://localhost:8080/api/auth/login \
     -H 'Content-Type: application/json' -H 'X-Requested-With: hunter-portal' \
     -d "{\"username\":\"$U\",\"password\":\"$P\"}"
   curl -s -b jar.txt -X POST http://localhost:8080/api/loki/logs \
     -H 'Content-Type: application/json' -H 'X-Requested-With: hunter-portal' --data-binary @preset.json
   ```
   Toda chamada de escrita exige `X-Requested-With: hunter-portal` (CSRF) além do cookie.
2. Confira a query isolada no Loki (`/loki/api/v1/query`) e anote o valor retornado.
3. Provisione as regras (script `scripts/upsert_baseline_rules.py` faz upsert por uid).
4. Espere um ciclo do ruler (interval do grupo é 60s) e leia
   `GET /api/prometheus/grafana/api/v1/rules` filtrando por `folderUid=global` +
   `name=global-detections`; exija `state=firing` **e** `health=ok` sem `lastError`.
5. Confira pelo portal: `GET /api/rules` deve devolver a regra com `contact_point=dev` e
   `deploy_status=homolog`.

**Pitfall do estado oscilante**: linha sintética com `spread_seconds` cai no passado e sai da
janela de 5m em poucos minutos — a regra passa de `firing` para `inactive` sem estar quebrada.
Para provar as N regras ao mesmo tempo, re-injete todos os presets e leia o ruler ~80s depois;
não conclua "regra com defeito" a partir de uma leitura isolada.

---

## 6. Versionar como seed sem sobrescrever edição do portal

`grafana/bootstrap/bootstrap.sh` → `seed_rules()` faz `GET /api/v1/provisioning/alert-rules/{uid}`
e **pula** a regra quando ela já existe ("já existe — mantida"); só cria em instalação nova ou
após exclusão. Portanto adicionar `grafana/bootstrap/seed/rules/NN-<slug>.json` é seguro: não
reaplica em cima do que o operador editou na UI. `folderUID` do arquivo é respeitado
(sem `folderUID`, o jq cai no default `"global"` — o bootstrap não cria mais pasta de
demonstração), então baseline usa `"folderUID": "global"` de forma explícita.

Valide o seed comparando campo a campo com a regra viva quando ela já existe
(`title`, `folderUID`, `ruleGroup`, `condition`, `for`, `noDataState`, `execErrState`, `labels`,
`annotations`, `notification_settings.receiver` e `data`) — divergência aí indica que o arquivo
não reproduz a regra em ambiente novo. `jq` não existe no host (só no container do bootstrap):
valide/parseie os JSONs com Python.

---

## 7. Custo de regra fora do catálogo

Regra cujo `technology` não está no catálogo (ex.: `linux`, `dns` em cenários de laboratório) cai
no fallback de `rule_groups` e continua sem tecnologia: aparece como `unmapped` em
`GET /api/technologies/overview` (`metrics.baseline_rules_unmapped`) e não entra na conformidade.
Cadastrar a tecnologia muda denominador de conformidade e footprint dos clientes — **não faça por
conta própria**: entregue a regra e leve a decisão ao usuário.
