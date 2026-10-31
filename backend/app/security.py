"""Autenticação e proteções de segurança do portal.

Modelo adotado nesta etapa:
  * Login local com um único usuário administrador definido por variáveis de
    ambiente (será substituível por OIDC/SSO em etapas futuras).
  * Sessões server-side em memória: o navegador recebe apenas um identificador
    aleatório em um cookie ``HttpOnly`` + ``SameSite=Strict`` (+ ``Secure``).
    No servidor guardamos somente o SHA-256 do identificador.
  * Proteção CSRF em camadas: ``SameSite=Strict`` + cabeçalho customizado
    obrigatório em requisições que alteram estado (força preflight CORS, e o
    backend não habilita CORS).
  * Limite de tentativas de login por IP (mitiga força bruta).

Limitação conhecida: sessões e contadores ficam em memória, então são perdidos
ao reiniciar o backend e não são compartilhados entre réplicas.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

SESSION_COOKIE = "ghp_session"
CSRF_HEADER = "X-Requested-With"
CSRF_HEADER_VALUE = "hunter-portal"
_MAX_TRACKED_IPS = 10_000


@dataclass(frozen=True)
class Session:
    """Sessão autenticada de um usuário do portal."""

    username: str
    created_at: float
    expires_at: float


class SessionStore:
    """Armazena sessões em memória, indexadas pelo hash do token."""

    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create(self, username: str) -> str:
        """Cria uma sessão e devolve o token opaco que vai no cookie."""
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._purge_expired(now)
            self._sessions[self._key(token)] = Session(
                username=username, created_at=now, expires_at=now + self._ttl
            )
        return token

    def get(self, token: str) -> Session | None:
        """Retorna a sessão válida associada ao token, ou ``None``."""
        key = self._key(token)
        now = time.time()
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                return None
            if session.expires_at <= now:
                del self._sessions[key]
                return None
            return session

    def revoke(self, token: str) -> None:
        """Invalida a sessão (logout)."""
        with self._lock:
            self._sessions.pop(self._key(token), None)

    def _purge_expired(self, now: float) -> None:
        expired = [k for k, s in self._sessions.items() if s.expires_at <= now]
        for key in expired:
            del self._sessions[key]


class LoginRateLimiter:
    """Janela deslizante de falhas de login por chave (normalmente o IP)."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max = max_attempts
        self._window = window_seconds
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> deque[float]:
        attempts = self._failures.setdefault(key, deque())
        while attempts and attempts[0] <= now - self._window:
            attempts.popleft()
        return attempts

    def is_blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.time())) >= self._max

    def register_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            if len(self._failures) > _MAX_TRACKED_IPS:
                # Evita crescimento ilimitado de memória: descarta chaves sem
                # falhas recentes.
                for stale in [k for k in self._failures if not self._recent(k, now)]:
                    del self._failures[stale]
            self._recent(key, now).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def verify_credentials(
    username: str, password: str, expected_username: str, expected_password: str
) -> bool:
    """Compara credenciais em tempo constante.

    Os valores são reduzidos a SHA-256 antes da comparação para que o tempo não
    dependa do tamanho das strings. As duas comparações sempre são executadas
    (sem curto-circuito) para não revelar qual campo estava errado.
    """
    user_ok = hmac.compare_digest(_digest(username), _digest(expected_username))
    pass_ok = hmac.compare_digest(_digest(password), _digest(expected_password))
    return user_ok and pass_ok


def client_ip(request: Request) -> str:
    """IP do cliente (já resolvido pelo uvicorn a partir do X-Forwarded-For do Nginx)."""
    return request.client.host if request.client else "unknown"


# ---------------------------------------------------------------------------
# Dependências FastAPI
# ---------------------------------------------------------------------------
def require_csrf_header(request: Request) -> None:
    """Exige o cabeçalho anti-CSRF em requisições que alteram estado."""
    if request.headers.get(CSRF_HEADER) != CSRF_HEADER_VALUE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cabeçalho anti-CSRF ausente ou inválido",
        )


def get_current_user(request: Request) -> Session:
    """Retorna a sessão do usuário autenticado ou responde 401."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Não autenticado")
    session = request.app.state.sessions.get(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessão expirada ou inválida"
        )
    return session

