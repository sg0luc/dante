# =============================================================================
# Frontend do Grafana Hunter Portal
#   Estágio 1: build da SPA com Node.
#   Estágio 2: Nginx sem privilégios (porta 8080) servindo os arquivos estáticos.
# =============================================================================
FROM node:22-alpine AS build
WORKDIR /app

# Usa "npm ci" quando houver package-lock.json (build reprodutível).
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; \
    else npm install --no-audit --no-fund; fi

COPY . .
ARG APP_VERSION=0.1.0
ENV VITE_APP_VERSION=${APP_VERSION}
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080

