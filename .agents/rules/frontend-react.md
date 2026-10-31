---
trigger: glob
globs: "*.tsx, *.ts, *.css"
description: "Regras de frontend React/TypeScript do D.A.N.T.E.: tipagem estrita, LogQL Assist compartilhado, confirmação de ações destrutivas e UX de SOC."
---

# Frontend React + TypeScript — D.A.N.T.E.

## Tipagem e build
- TypeScript estrito. `npm run build` roda `tsc --noEmit && vite build`: o build Docker do
  frontend é o gate de tipagem real (não existe `node_modules` no host).
- Interfaces de API em `frontend/src/types.ts`; chamadas HTTP em `frontend/src/api.ts`
  (com `credentials: 'include'` e o header CSRF nos métodos mutantes).
- Após rebuild, subir com `docker compose up -d --force-recreate frontend` e conferir o
  digest — `up -d` normal serve o bundle velho.

## Paridade obrigatória de LogQL
Todo fluxo que persiste regra (criação em `RulesPage`, replicação baseline em
`GlobalMatrixPage`, implement-baseline em `TechnologiesPage`) usa o **mesmo**
`hooks/useLogQLAssist.ts` (`lint`, `run`, `assertValid`) e os componentes de
`components/LogQLAssist.tsx`. Nunca reimplemente painel de linting em uma tela só.

## Ações sensíveis
- Pausa/exclusão em lote, revogação de exceção permanente e qualquer ação massiva passam por
  `ConfirmModal`, explicitando volumetria e consequência operacional (cessação de alertas).
- Exceção permanente só oferece `Revogar exceção`; nunca `Prolongar`.
- Regra pausada continua visível e editável — não esconda nem desabilite o formulário.

## UX SOC
- Tema escuro, densidade alta, histogramas temporais, matriz de cobertura e badges de estado
  (`DeployStatusBadge`, `StatusBadge`).
- Toda tabela precisa de estado vazio explícito e de mensagem de erro real da API — não
  mascare "sem dados" quando a consulta falhou.
- Modais React controlados: preencha por eventos reais (`fill_input`), setar `.value` por JS
  não dispara os handlers do React.
