# ──────────────────────────────────────────────────────────────────────────────
# SIGIMORA Server — Multi-stage Docker build
# ──────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM rust:1.85-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release -p sigimora-server && \
    cp target/release/sigimora-server /usr/local/bin/sigimora-server && \
    strip /usr/local/bin/sigimora-server

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*

RUN groupadd -r sigimora && useradd -r -g sigimora -d /var/lib/sigimora -s /sbin/nologin sigimora

COPY --from=builder /usr/local/bin/sigimora-server /usr/local/bin/sigimora-server

RUN mkdir -p /var/lib/sigimora/data && chown -R sigimora:sigimora /var/lib/sigimora

USER sigimora
WORKDIR /var/lib/sigimora

ENV SIGIMORA_LISTEN=0.0.0.0:8080
ENV SIGIMORA_DATA_DIR=/var/lib/sigimora/data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/api/v1/health || exit 1

CMD ["sigimora-server"]
