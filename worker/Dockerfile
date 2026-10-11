# Signing worker image. Build from the repo root:  docker build -f worker/Dockerfile -t ecid-worker .
FROM rust:1-bookworm AS signer
WORKDIR /src
COPY worker/signer ./
RUN cargo build --release

FROM node:20-bookworm-slim
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8787 ECID_WORKER_DATA=/data ECID_SIGNER_BIN=/app/worker/signer/target/release/ecid-signer
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 worker && mkdir /data && chown worker /data
WORKDIR /app
COPY lib ./lib
COPY api ./api
COPY public ./public
COPY worker/*.js worker/package.json ./worker/
COPY --from=signer /src/target/release/ecid-signer ./worker/signer/target/release/ecid-signer
USER worker
VOLUME /data
EXPOSE 8787
# JOB_HMAC_SECRET (required), PUBLIC_BASE_URL (https), ALLOWED_ORIGINS, TRUST_PROXY: pass with -e
CMD ["node", "worker/server.js"]
