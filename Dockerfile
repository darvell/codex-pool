# syntax=docker/dockerfile:1.7
FROM node:24-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.25-bookworm AS build
WORKDIR /src
ENV CGO_ENABLED=1 GOOS=linux GOARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ libc6-dev && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN go build -trimpath -ldflags='-s -w' -o /out/codex-pool .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* \
 && groupadd --system codex && useradd --system --gid codex --home-dir /app codex
WORKDIR /app
COPY --from=build /out/codex-pool /app/codex-pool
RUN mkdir -p /app/data /app/pool /app/tmp && chown -R codex:codex /app
USER codex
ENV DUCKDB_PATH=/app/data/usage.duckdb
EXPOSE 8989
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://127.0.0.1:8989/healthz || exit 1
ENTRYPOINT ["/app/codex-pool"]
