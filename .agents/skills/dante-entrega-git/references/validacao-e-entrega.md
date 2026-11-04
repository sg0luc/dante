# Validação e Entrega — D.A.N.T.E.

> Nota de portabilidade: este arquivo foi exportado do Hermes Dev Companion. Onde aparecer
> "runtime do Hermes" (execução em background de comandos longos, helpers de browser como
> `new_tab`/`cdp`/`capture_screenshot`, `process_manage`), leia como "o runtime em uso neste
> ambiente". As receitas de Docker, API, CSRF, cookie e git são as mesmas.

Receitas prontas para rodar antes de commitar e para entregar (push + PR).
Projeto local Windows: `%USERPROFILE%\Projetos\dante`
(remote `github.com/sg0luc/dante-portal`, containers `dante-backend`, `dante-frontend`, `dante-grafana`).

PRs empilhadas: para documentacao que descreve comportamento de uma branch ainda nao
mergeada, abra o PR com `base` igual a essa branch (o diff fica limpo e o GitHub
retargeta para `main` quando ela mergear). Checkout da branch nova pode partir do HEAD
da branch pendente sem conflito quando os arquivos doc nao divergem.

---

## 1. Build + subida (sempre nessa ordem)

```bash
cd "<repo>"
docker compose build backend frontend      # frontend roda tsc --noEmit && vite build
docker compose up -d                       # rodar com background=true no runtime do Hermes
```

Verificação em chamada separada:

```bash
docker compose ps
docker compose logs backend --tail 20
```

Esperado: `dante-backend ... (healthy)`, `Application startup complete`.

---

## 2. Sanidade do backend (sem `compileall`)

A imagem copia `/app` em camada somente leitura; `python -m compileall` falha com
`OSError: [Errno 30] Read-only file system`. O teste válido é importar e listar rotas:

```bash
docker exec dante-backend python -c "
import app.main, app.mappers, app.schemas, app.routers.monitoring
print([r.path for r in app.main.app.routes if 'silence' in r.path])"
```

Um `NameError` de tipo em anotação de rota (ex.: `typing.Any` não importado) só aparece
no import — FastAPI resolve as anotações no registro das rotas, e o erro derruba o app
inteiro no rebuild.

---

## 3. E2E de API (login + CSRF + ciclo criar/listar/remover)

A API exige cookie de sessão **e** o header anti-CSRF em todo POST/DELETE:

```python
req.add_header("X-Requested-With", "hunter-portal")   # CSRF_HEADER
```

- Login também exige o header: `POST /api/auth/login` com `{"username", "password"}`.
- Cookie de sessão: `ghp_session` (HttpOnly, SameSite=Strict).
- Base externa: `http://localhost:8080` (nginx do frontend faz proxy de `/api`).
- Credenciais: `source .env` no bash e exportar `PORTAL_ADMIN_USER` / `PORTAL_ADMIN_PASSWORD`
  para um script Python que faz o login — nunca digitar senha em formulário de browser.

Esqueleto (urllib + cookie jar, sem dependências externas):

```python
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def call(method, path, body=None, csrf=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if csrf:
        req.add_header("X-Requested-With", "hunter-portal")
    with opener.open(req, timeout=20) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)
```

**Pitfall**: `DELETE /api/silences/{id}` devolve 204 mas o Alertmanager apenas *expira* o
silence — ele continua aparecendo em `GET /api/silences` com `state: expired`. Não trate
"total não diminuiu" como falha; conte por `state` (`active` x `expired`).

Se o login via `urllib` responder 200 e a chamada seguinte devolver `401 Não autenticado`,
não insista no opener: faça o ciclo com `curl` e jar de cookies (funciona de primeira):

```bash
curl -s -c .tmp/jar.txt -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" -H "X-Requested-With: hunter-portal" \
  -d "{\"username\":\"$PORTAL_ADMIN_USER\",\"password\":\"$PORTAL_ADMIN_PASSWORD\"}"
curl -s -b .tmp/jar.txt -X POST http://localhost:8080/api/loki/logs \
  -H "Content-Type: application/json" -H "X-Requested-With: hunter-portal" \
  --data-binary @payload.json
```

Grave o jar em caminho relativo ao repo (`.tmp/...`), não em `/tmp`: o `curl` nativo do
Windows não enxerga o `/tmp` do MSYS e o arquivo some silenciosamente.

---

## 4. Verificação visual autenticada (screenshot)

Sem sessão no browser e sem senha digitável, autenticar por cookie:

1. Obter o cookie com um login via script Python (seção 3) e gravar `nome=valor` num arquivo.
2. No browser harness:

```python
name, value = cookie.split("=", 1)
new_tab("http://localhost:8080/")
cdp("Network.enable")
cdp("Network.setCookie", name=name, value=value, domain="localhost", path="/", httpOnly=True)
goto_url("http://localhost:8080/silences")
wait_for_load()
```

3. Interagir por `js("...")` (clicar em `.split-tab`, `.kind-option`, preencher com
   `fill_input('input[placeholder="Valor correspondente"]', ...)`) e capturar com
   `capture_screenshot()`.

Modais React controlados: `fill_input` funciona; setar `.value` direto por JS não dispara
os eventos que o React escuta.

Para exercitar um fluxo que grava no Grafana, criar os recursos de demonstração pela UI/API,
tirar os screenshots e **remover tudo no final** (os expirados permanecem no histórico —
informar isso ao usuário em vez de alegar limpeza total).

---

## 5. Git: autenticação e abertura de PR

Contexto do ambiente: sem `gh` no PATH, sem chave SSH, sem credencial armazenada
inicialmente; o helper é o Git Credential Manager (`helper-selector`).

**Device code (não depende de browser do host abrir sozinho):**

```bash
git credential-manager github login --no-ui
# escolher a opção 2 (Device code) via process_manage(action='submit', data='2')
# a saída traz: https://github.com/login/device e um código (ex.: ABCD-1234)
```

Repassar URL + código ao usuário e esperar a autorização dele (nunca pedir senha/token no
chat). O processo GCM fica em polling e sai com código 0 quando autorizado.

`git credential fill` não é confiável em bash não interativo: ele tenta UI/`/dev/tty` e
trava (timeout). Usar o login do GCM e, depois dele, `git push` normalmente.

**Criar o PR pela REST API** (o token fica no arquivo de credencial do GCM; use sem imprimir):

```bash
printf 'protocol=https\nhost=github.com\n\n' | git credential fill   # username=/password=<token>
curl -s -X POST https://api.github.com/repos/<owner>/<repo>/pulls \
  -H "Authorization: Bearer <token>" -H "Accept: application/vnd.github+json" \
  -d '{"title":"...","head":"<branch>","base":"main","body":"..."}'
```

**Cuidados de branch**: remotes marcados `gone` em `git branch -vv` indicam branch já
mergeada e apagada no remoto; `git log main..HEAD` dirá o que o PR realmente levará.
Se a árvore tiver alterações não relacionadas, deixe-as de fora do `git add`.

**Não use `git rm -r <diretório>`** para limpar um seed: ele apaga *todo* o diretório,
inclusive arquivos recém-adicionados que precisam ficar (o `git checkout HEAD -- <path>`
depois é o reparo). Liste os arquivos que saem e rode `git rm <arquivo> ...` por caminho
explícito, conferindo `git status --short` antes do commit.

---

## 6. Publicação 100% Automatizada de Releases Oficiais

O fluxo pós-merge é totalmente automatizado via GitHub Actions:

1. **Incremento de versão**: Toda feature ou fix branch atualiza `VERSION` e `backend/app/__init__.py`.
2. **Merge do PR**: Ao clicar em "Merge pull request" na branch `main`:
   - O workflow `.github/workflows/release.yml` detecta a nova versão em `VERSION`.
   - Cria e envia a tag Git `vX.Y.Z` correspondente automaticamente.
   - Executa checagem de sintaxe Python e build de produção do frontend.
   - Constrói as imagens multi-stage e publica no GitHub Container Registry (`ghcr.io/sg0luc/dante-*`).
   - Publica a Release oficial no GitHub com changelog gerado e assets operacionais anexados (`docker-compose.yml`, `.env.example`, `VERSION`).
   - Nenhuma intervenção manual (como criar tag no terminal) é necessária pós-merge.
3. **Verificação no portal**:
```bash
curl -s http://localhost:8080/api/system/version
```
