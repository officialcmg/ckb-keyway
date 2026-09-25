FROM nervos/fiber:0.9.0 AS fiber

FROM node:24-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libstdc++6 tini \
  && rm -rf /var/lib/apt/lists/*
COPY --from=fiber /usr/local/bin/fnn /usr/local/bin/fnn
COPY --from=fiber /usr/local/share/fiber /usr/local/share/fiber
COPY index.mjs /app/index.mjs
ENV FIBER_CONFIG_TEMPLATE=/usr/local/share/fiber/config/testnet/config.yml \
    KEYWAY_MANAGED_DATA_DIR=/fiber/users \
    NODE_ENV=production
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "/app/index.mjs"]
