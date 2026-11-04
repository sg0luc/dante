---
name: dante-entrega-git
description: Gate de validação e entrega do D.A.N.T.E. — build Docker, import do backend, E2E com sessão/CSRF, screenshot autenticado, branch, commit convencional e PR. Use antes de commitar ou abrir PR neste repo.
---

# Validação e entrega (obrigatório antes de commitar)

Regra permanente: **toda entrega vira branch + commit convencional + git push + abertura automática de PR no GitHub**, sem esperar pedido explícito, e nunca se commita sem antes rodar a validação de verdade. Ao concluir qualquer alteração de código ou funcionalidade, realize o push da branch e abra o Pull Request automaticamente via API do GitHub (`/repos/sg0luc/dante/pulls`).

## 1. Build e subida

```bash
docker compose build backend frontend      # frontend roda tsc --noEmit && vite build
docker compose up -d                       # rodar em background, verificar em chamada separada
docker compose ps
docker compose logs backend --tail 20
```

Esperado: `dante-backend ... (healthy)` e `Application startup complete`.

Como `up -d` não recria o frontend após `build`, confirme o digest antes de testar UI:

```bash
docker compose images frontend
docker inspect dante-frontend --format '{{.Image}}'
```

Divergência → `docker compose up -d --force-recreate frontend`. Com assets estáticos que não
invalidam em cache, `docker compose build --no-cache frontend`.

## 2. Sanidade do backend (sem `compileall`)

`python -m compileall` falha com `Read-only file system` (a imagem copia `/app`). O teste
válido é importar e registrar as rotas:

```bash
docker exec dante-backend python -c "
import app.main, app.mappers, app.schemas, app.routers.monitoring
print([r.path for r in app.main.app.routes if 'silence' in r.path])"
```

`NameError` em anotação de rota só aparece no import — FastAPI resolve as anotações ao
registrar a rota e o erro derruba o app inteiro no rebuild.

## 3. E2E de API (sessão + CSRF)

- Header anti-CSRF obrigatório em POST/DELETE/PUT: `X-Requested-With: hunter-portal`.
- Login: `POST /api/auth/login` com `{"username","password"}` e o mesmo header.
- Cookie de sessão: `ghp_session` (HttpOnly, SameSite=Strict).
- Base externa: `http://localhost:8080` (nginx do frontend faz proxy de `/api`).
- Credenciais: `source .env` e exportar `PORTAL_ADMIN_USER`/`PORTAL_ADMIN_PASSWORD` para o
  script — nunca digitar senha em formulário de browser.
- Suítes prontas: `scripts/e2e_*.py`. Cada script purga artefatos de rodadas anteriores **no
  início e no fim** (senão a segunda execução acha a tecnologia já implementada e o baseline
  duplica).
- Ciclo mínimo de aceite de qualquer recurso novo: criar → listar conferindo o campo novo no
  JSON → remover.

Pitfalls: `DELETE /api/silences/{id}` devolve 204 mas o Alertmanager apenas expira — o silence
continua em `GET /api/silences` com `state: expired` (conte por estado, não por total).
Se `urllib` der 401 após login 200, refaça o ciclo com `curl` + cookie jar gravado em `.tmp/`
do repo (curl nativo do Windows não vê `/tmp` do MSYS).

## 4. Verificação visual (screenshot autenticado)

1. Obter o cookie por script (`http.cookiejar`) e gravar `nome=valor` em arquivo.
2. Injetar no browser por CDP:
   `cdp("Network.enable")` → `cdp("Network.setCookie", name=..., value=..., domain="localhost", path="/", httpOnly=True)`.
3. Navegar, interagir por JS/`fill_input` (modais React controlados ignoram `.value` setado
   direto) e capturar screenshot.
4. Recursos de demonstração criados para o teste devem ser removidos no fim; expirados
   permanecem no histórico — informe isso em vez de alegar limpeza total.

## 5. Branch, commit, push e PR

1. `git fetch origin --prune`; conferir `git branch -vv` e `git log main..HEAD`.
2. Branch `feat|fix|refactor|chore/<escopo-curto>` a partir do HEAD atual.
3. `git add` **só** dos arquivos da feature. Alterações alheias no working tree ficam de fora e
   são mencionadas no retorno.
4. Mensagem convencional em pt-BR sem acento no título (`feat(silences): ...`), corpo com
   backend/frontend e seção `Validacao executada` listando o que realmente rodou. Gravar a
   mensagem em arquivo e usar `git commit -F <arquivo>` — heredoc (`git commit -F - <<'EOF'`)
   é recusado por runtimes que tratam comando longo como processo persistente.
5. Push e PR pela REST API (não há `gh` no PATH).

```bash
git config --local credential.helper manager     # o git do bundle usa helper-selector, que falha o push
git credential-manager github login --no-ui      # opção 2 (device code) → autorizar em github.com/login/device
git push -u origin <branch>
```

PR via API:

```bash
curl -s -X POST https://api.github.com/repos/sg0luc/dante-portal/pulls \
  -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
  -d '{"title":"...","head":"<branch>","base":"main","body":"..."}'
```

- Base já mergeada/apagada → `422 Validation Failed (field: base)`. Com
  `git log origin/main..HEAD` mostrando só os commits da feature, use `base: main`.
- PR empilhada (documentação de branch ainda não mergeada): `base` = branch pendente; o GitHub
  retargeta para `main` quando ela mergear.
- Relatar branch, commit, validações executadas e link do PR.

Detalhes adicionais: `references/validacao-e-entrega.md` (esqueletos de script, login por
cookie no browser, device code do GCM).

## 6. Fluxo de releases oficiais e versionamento semântico

Toda atualização relevante no D.A.N.T.E. segue o fluxo oficial de releases:

1. **Versionamento semântico (`vMAJOR.MINOR.PATCH`)**:
   - `MAJOR`: quebra de compatibilidade ou redesign arquitetural.
   - `MINOR`: nova feature, página ou rota adicionada sem quebra.
   - `PATCH`: correções de bugs, ajustes de regras LogQL ou melhorias pontuais.
   - A versão canônica é mantida em `VERSION` e `backend/app/__init__.py` (`__version__`).

2. **Publicação 100% automatizada pós-merge**:
   - Toda entrega incrementa `VERSION` e `backend/app/__init__.py` conforme o tipo de alteração.
   - Ao fazer o merge do PR na branch `main`, o workflow `.github/workflows/release.yml` é acionado automaticamente.
   - Detecta a nova versão, cria e envia a tag `vX.Y.Z`, constrói as imagens no GHCR e publica o GitHub Release oficial com release notes e assets anexados.
   - Nenhuma intervenção manual (como criar tag local) é necessária pós-merge.

3. **Verificação no portal**:
   - O backend monitora atualizações via `GET /api/system/version` e `POST /api/system/version/check` consultando a API do GitHub.
