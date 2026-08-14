# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build:spa

FROM golang:1.26.6-alpine AS build
ARG VERSION=dev
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
# Remove the small source fallback before inserting the real production UI.
RUN find internal/ui/dist -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
COPY --from=web /src/frontend/dist-spa/ ./internal/ui/dist/
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/i5cloud ./cmd/i5cloud

FROM alpine:3.22
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="I5CLOUD Remote Management Platform" \
      org.opencontainers.image.description="NPS-based customer network and remote device management platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/VAMPIRE0924/-" \
      org.opencontainers.image.licenses="NOASSERTION"
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 i5cloud && \
    adduser -S -D -H -u 10001 -G i5cloud i5cloud && \
    install -d -o i5cloud -g i5cloud -m 0750 /data
COPY --from=build /out/i5cloud /usr/local/bin/i5cloud
USER i5cloud:i5cloud
WORKDIR /data
ENV I5CLOUD_MODE=pro \
    I5CLOUD_CONFIG_FILE=/etc/i5cloud/i5cloud.conf \
    I5CLOUD_LISTEN_ADDR=0.0.0.0:8088 \
    I5CLOUD_DATA_DIR=/data \
    I5CLOUD_DB_PATH=/data/i5cloud.db \
    I5CLOUD_API_TOKEN_FILE=/run/secrets/i5cloud_api_token \
    I5CLOUD_SETUP_TOKEN_FILE=/run/secrets/i5cloud_setup_token
EXPOSE 8088
VOLUME ["/data"]
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/i5cloud", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/i5cloud"]
CMD ["serve"]
