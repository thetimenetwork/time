# Build only the separately allowlisted gateway context.
ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
ARG RUNTIME_IMAGE
RUN printf '%s\n' "$RUNTIME_IMAGE" | grep -E '^[-a-zA-Z0-9./:_]+@sha256:[a-f0-9]{64}$' && test "$(node --version)" = v26.13.0 && groupadd -g 10001 time && useradd -u 10001 -g 10001 -M time && mkdir -p /data/gateway && chown 10001:10001 /data/gateway
WORKDIR /opt/time
COPY client-v4 ./client-v4
COPY web-v4 ./web-v4
COPY deploy/gateway ./deploy/gateway
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["node","deploy/gateway/start.mjs"]
CMD ["/operator/gateway.json"]
