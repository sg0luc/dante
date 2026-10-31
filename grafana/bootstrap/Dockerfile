# =============================================================================
# Imagem do job de bootstrap do Grafana.
# Contém apenas o necessário: shell (busybox), curl e jq.
# =============================================================================
FROM alpine:3.20

RUN apk add --no-cache curl jq

COPY bootstrap.sh /usr/local/bin/bootstrap.sh
COPY seed/ /seed/

# Remove CR (caso o arquivo tenha sido salvo com CRLF no Windows) e torna executável.
RUN sed -i 's/\r$//' /usr/local/bin/bootstrap.sh \
    && chmod 0755 /usr/local/bin/bootstrap.sh

ENTRYPOINT ["/usr/local/bin/bootstrap.sh"]

