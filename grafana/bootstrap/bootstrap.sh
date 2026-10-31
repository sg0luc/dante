#!/bin/sh
# =============================================================================
# Grafana Hunter Portal - Bootstrap do Grafana
# -----------------------------------------------------------------------------
# Job executado uma vez a cada "docker compose up". É idempotente:
#
#   1. Aguarda o Grafana ficar saudável e valida as credenciais de admin.
#   2. Garante uma Service Account dedicada ao portal e um token válido.
#      O token é gravado em um volume compartilhado (0400, dono = usuário do
#      backend). O token NUNCA chega ao navegador.
#   3. Garante a pasta 'global' e aplica o seed de regras do baseline
#      (grafana/bootstrap/seed/rules/). Não cria pastas de cliente, regras
#      de demonstração nem silence.
#
# APIs utilizadas (documentação oficial):
#   Service accounts : https://grafana.com/docs/grafana/latest/developers/http_api/serviceaccount/
#   Folders          : https://grafana.com/docs/grafana/latest/developers/http_api/folder/
#   Alerting (prov.) : https://grafana.com/docs/grafana/latest/developers/http_api/alerting_provisioning/
#   Silences         : Alertmanager API v2 exposta em /api/alertmanager/grafana/api/v2
#
# Segurança:
#   - Credenciais vão em arquivos de cabeçalho temporários (curl -H @arquivo),
#     não na linha de comando (evita exposição via "ps").
#   - umask 077 em todos os arquivos temporários; removidos ao final.
#   - O corpo da resposta com o token nunca é impresso no log.
# =============================================================================
set -eu

GRAFANA_URL="${GRAFANA_URL:-http://grafana:3000}"
GRAFANA_ADMIN_USER="${GRAFANA_ADMIN_USER:?GRAFANA_ADMIN_USER não definido}"
GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:?GRAFANA_ADMIN_PASSWORD não definido}"
SA_NAME="${PORTAL_SA_NAME:-hunter-portal}"
# Admin é necessário para a API de provisionamento de alerting no Grafana OSS.
SA_ROLE="${PORTAL_SA_ROLE:-Admin}"
TOKEN_FILE="${TOKEN_FILE:-/secrets/grafana_token}"
TOKEN_OWNER="${TOKEN_OWNER:-10001:10001}"
SEED_DIR="${SEED_DIR:-/seed}"

umask 077
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM
RESP="$WORKDIR/response.json"
ADMIN_HDR="$WORKDIR/admin.hdr"
BEARER_HDR="$WORKDIR/bearer.hdr"

log()  { printf '[bootstrap] %s\n' "$*"; }
fail() { printf '[bootstrap] ERRO: %s\n' "$*" >&2; exit 1; }

# Cabeçalho Basic Auth do admin gravado em arquivo (fora da linha de comando).
printf 'Authorization: Basic %s\n' \
  "$(printf '%s:%s' "$GRAFANA_ADMIN_USER" "$GRAFANA_ADMIN_PASSWORD" | base64 | tr -d '\n')" \
  > "$ADMIN_HDR"

# -----------------------------------------------------------------------------
# api MÉTODO CAMINHO [ARQUIVO_JSON]
#   Chama a API do Grafana como admin. Imprime o HTTP status no stdout e grava
#   o corpo da resposta em $RESP.
#   "X-Disable-Provenance: true" mantém os recursos criados editáveis pela UI
#   do Grafana e pelo portal (caso contrário ficariam travados como "api").
# -----------------------------------------------------------------------------
api() {
  _method="$1"
  _path="$2"
  _body="${3:-}"
  if [ -n "$_body" ]; then
    curl -sS -o "$RESP" -w '%{http_code}' -X "$_method" \
      -H @"$ADMIN_HDR" \
      -H 'Content-Type: application/json' \
      -H 'X-Disable-Provenance: true' \
      --data-binary @"$_body" \
      "$GRAFANA_URL$_path"
  else
    curl -sS -o "$RESP" -w '%{http_code}' -X "$_method" \
      -H @"$ADMIN_HDR" \
      "$GRAFANA_URL$_path"
  fi
}

# -----------------------------------------------------------------------------
# 1. Espera o Grafana e valida credenciais
# -----------------------------------------------------------------------------
wait_for_grafana() {
  log "Aguardando Grafana em $GRAFANA_URL ..."
  _tries=0
  until curl -sf -o /dev/null "$GRAFANA_URL/api/health"; do
    _tries=$((_tries + 1))
    if [ "$_tries" -ge 60 ]; then
      fail "Grafana não respondeu após 120 segundos."
    fi
    sleep 2
  done

  _code=$(api GET /api/user)
  if [ "$_code" != "200" ]; then
    fail "Credenciais de admin rejeitadas (HTTP $_code). Lembre-se: GRAFANA_ADMIN_PASSWORD só é aplicada na primeira inicialização do volume grafana-data."
  fi
  log "Grafana disponível e credenciais de admin válidas."
}

# -----------------------------------------------------------------------------
# 2. Service account + token
# -----------------------------------------------------------------------------
token_is_valid() {
  [ -s "$TOKEN_FILE" ] || return 1
  printf 'Authorization: Bearer %s\n' "$(cat "$TOKEN_FILE")" > "$BEARER_HDR"
  _code=$(curl -sS -o /dev/null -w '%{http_code}' -H @"$BEARER_HDR" \
    "$GRAFANA_URL/api/search?type=dash-folder&limit=1")
  [ "$_code" = "200" ]
}

ensure_service_account() {
  _code=$(api GET "/api/serviceaccounts/search?perpage=100&page=1&query=$SA_NAME")
  [ "$_code" = "200" ] || fail "Falha ao buscar service accounts (HTTP $_code)."

  SA_ID=$(jq -r --arg n "$SA_NAME" \
    '[.serviceAccounts[]? | select(.name == $n) | .id][0] // empty' "$RESP")

  if [ -z "$SA_ID" ]; then
    jq -n --arg name "$SA_NAME" --arg role "$SA_ROLE" \
      '{name: $name, role: $role, isDisabled: false}' > "$WORKDIR/sa.json"
    _code=$(api POST /api/serviceaccounts "$WORKDIR/sa.json")
    case "$_code" in
      200|201) ;;
      *) fail "Falha ao criar service account (HTTP $_code): $(cat "$RESP")" ;;
    esac
    SA_ID=$(jq -r '.id' "$RESP")
    log "Service account '$SA_NAME' criada (id=$SA_ID, role=$SA_ROLE)."
  else
    log "Service account '$SA_NAME' já existe (id=$SA_ID)."
  fi
}

issue_token() {
  # Revoga tokens antigos desta service account (o atual é inválido/ausente).
  _code=$(api GET "/api/serviceaccounts/$SA_ID/tokens")
  if [ "$_code" = "200" ]; then
    for _tid in $(jq -r '.[].id' "$RESP"); do
      api DELETE "/api/serviceaccounts/$SA_ID/tokens/$_tid" > /dev/null
      log "Token antigo id=$_tid revogado."
    done
  fi

  jq -n --arg name "${SA_NAME}-$(date -u +%s)" '{name: $name}' > "$WORKDIR/token.json"
  _code=$(api POST "/api/serviceaccounts/$SA_ID/tokens" "$WORKDIR/token.json")
  case "$_code" in
    200|201) ;;
    *) fail "Falha ao emitir token da service account (HTTP $_code)." ;;
  esac

  _key=$(jq -r '.key // empty' "$RESP")
  rm -f "$RESP"
  [ -n "$_key" ] || fail "Resposta de criação de token sem o campo 'key'."

  # Escrita atômica: arquivo temporário -> permissões -> rename.
  _dir=$(dirname "$TOKEN_FILE")
  mkdir -p "$_dir"
  chmod 0755 "$_dir"
  _tmp="$_dir/.grafana_token.tmp"
  printf '%s' "$_key" > "$_tmp"
  chmod 0400 "$_tmp"
  chown "$TOKEN_OWNER" "$_tmp"
  mv -f "$_tmp" "$TOKEN_FILE"
  log "Novo token gravado em $TOKEN_FILE (0400, dono $TOKEN_OWNER)."
}

# -----------------------------------------------------------------------------
# 3. Pasta do baseline e seed de regras
# -----------------------------------------------------------------------------
# Garante a pasta canônica do baseline: as regras de detecção são criadas pelo
# portal (abrangência Baseline) e replicadas para os clientes a partir dela.
ensure_global_folder() {
  _code=$(api GET "/api/folders/global")
  if [ "$_code" = "200" ]; then
    log "Pasta 'global' já existe."
  else
    jq -n '{uid: "global", title: "global"}' > "$WORKDIR/global_folder.json"
    _code=$(api POST /api/folders "$WORKDIR/global_folder.json")
    case "$_code" in
      200|201) log "Pasta 'global' criada para regras modelo." ;;
      *) log "AVISO: falha ao criar pasta 'global' (HTTP $_code): $(cat "$RESP")" ;;
    esac
  fi
}

seed_rules() {
  for _file in "$SEED_DIR"/rules/*.json; do
    [ -f "$_file" ] || continue
    _uid=$(jq -r '.uid' "$_file")
    _code=$(api GET "/api/v1/provisioning/alert-rules/$_uid")
    if [ "$_code" = "200" ]; then
      log "Regra '$_uid' já existe — mantida."
      continue
    fi
    jq '.folderUID = (.folderUID // "global")' "$_file" > "$WORKDIR/rule.json"
    _code=$(api POST /api/v1/provisioning/alert-rules "$WORKDIR/rule.json")
    case "$_code" in
      200|201) log "Regra '$_uid' criada." ;;
      *) log "AVISO: falha ao criar regra '$_uid' (HTTP $_code): $(cat "$RESP")" ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# Execução
# -----------------------------------------------------------------------------
wait_for_grafana

if token_is_valid; then
  log "Token existente continua válido — nenhuma alteração necessária."
else
  ensure_service_account
  issue_token
fi

ensure_global_folder
seed_rules

log "Bootstrap concluído."

