# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build:spa

FROM --platform=$BUILDPLATFORM golang:1.26.6-alpine AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
# Remove the small source fallback before inserting the real production UI.
RUN find internal/ui/dist -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
COPY --from=web /src/frontend/dist-spa/ ./internal/ui/dist/
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/device-management-platform ./cmd/server

FROM public.ecr.aws/docker/library/alpine:3.24.1
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Device Management Platform" \
      org.opencontainers.image.description="NPS-based customer network and remote device management platform" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/VAMPIRE0924/device-management-platform" \
      org.opencontainers.image.licenses="NOASSERTION"
RUN apk add --no-cache ca-certificates su-exec tzdata && \
    addgroup -S -g 10001 platform && \
    adduser -S -D -H -u 10001 -G platform platform && \
    install -d -o platform -g platform -m 0750 /data
COPY --from=build /out/device-management-platform /usr/local/bin/device-management-platform
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
WORKDIR /data
ENV DMP_MODE=pro \
    DMP_CONFIG_FILE=/etc/device-management-platform/platform.conf \
    DMP_LISTEN_ADDR=0.0.0.0:8088 \
    DMP_DATA_DIR=/data \
    DMP_DB_PATH=/data/platform.db
EXPOSE 8088
VOLUME ["/data"]
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/device-management-platform", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
