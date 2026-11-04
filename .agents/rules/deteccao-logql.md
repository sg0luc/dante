---
trigger: model_decision
description: "Aplicar ao criar, revisar ou provisionar regras de detecção LogQL, mapear técnicas MITRE ATT&CK, lidar com rule_groups/tecnologias ou semear telemetria sintética no Loki."
---

# Regras de detecção e telemetria

- Título de regra: `<Tecnologia> - <Nome da Regra>`.
- Labels canônicas: `technology`, `technology_name`, `scope`, `client`, `siem_tier`,
  `mitre_tactic`, `mitre_technique`, `team`. Anotação `logql_query` sempre presente.
- `job` é sempre `wazuh`; `rule_groups` é a tecnologia (espelho de `rule.groups` do Wazuh).
- Só regras da pasta `global` podem ser replicadas para pastas de clientes.
- `POST /api/rules` recusa (422) `rule_groups` fora do catálogo de tecnologias e não lê o Loki
  (usa TestData). Detecção real exige provisioning direto com `datasourceUid: "loki"` e
  `queryType: "range"`.
- `| json` no Loki achata objeto aninhado com `_` (`win_system_eventID`) e **não** indexa
  array por nome (`rule_groups_0`): filtre por escalar (`rule_id`) ou por line filter.
- Prove a query em `GET /loki/api/v1/query` antes de provisionar. Parser errado = 400;
  campo errado = resultado vazio, silencioso.
- Threshold: `reduce(last)` → `threshold`. Receiver `dev` em regra nova/clonada.
- Seed sintético para validar: `POST /api/loki/logs` com `rule_groups` alvo, depois confirmar
  presença antes de checar o disparo.

Receita completa (payload, tabela de campos por tecnologia, ciclo de verificação):
skill `dante-companion`, arquivo `references/regras-deteccao-loki.md`.
