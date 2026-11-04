# =============================================================================
# Backend do Grafana Hunter Portal (FastAPI)
# - Executa como usuário não-root (UID 10001, o mesmo dono do arquivo de token).
# - Sem ferramentas de build na imagem final.
# =============================================================================
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

ARG APP_VERSION=0.1.0
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app

RUN groupadd --system --gid 10001 portal \
    && useradd --system --uid 10001 --gid portal --no-create-home \
       --shell /usr/sbin/nologin portal

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory "*"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Diretório do catálogo de tecnologias (rule_groups -> datasource). Montado como
# volume nomeado em produção; criado aqui com o dono correto para o usuário non-root.
RUN mkdir -p /data && chown 10001:10001 /data

USER 10001:10001
EXPOSE 8000

# --proxy-headers: confia no X-Forwarded-For enviado pelo Nginx do frontend
#   (o backend só é alcançável pela rede interna edge-net/core-net).
# --no-server-header: não divulga a versão do servidor.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", \
     "--no-server-header"]

