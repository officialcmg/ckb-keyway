# FNN 0.9.1, pinned by digest so the binary matches the backend's method table.
FROM nervos/fiber:0.9.1@sha256:b4d68916a42d1847b6c562b8710a20b409e3f5da57cfb347b6b7e0a38f57fe8a AS fiber

FROM node:24-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libstdc++6 tini \
  && rm -rf /var/lib/apt/lists/*
COPY --from=fiber /usr/local/bin/fnn /usr/local/bin/fnn
COPY --from=fiber /usr/local/share/fiber /usr/local/share/fiber
COPY index.mjs /app/index.mjs
ENV FIBER_CONFIG_TEMPLATE=/usr/local/share/fiber/config/testnet/config.yml \
    KEYWAY_MANAGED_DATA_DIR=/fiber/users \
    KEYWAY_MANAGED_BACKUP_DIR=/fiber/backups \
    NODE_ENV=production
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "/app/index.mjs"]
