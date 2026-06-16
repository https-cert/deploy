# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.26-alpine AS builder

# 版本号，CI 传入 git tag，本地默认 dev
ARG VERSION=dev
# 由 buildx 自动注入目标架构（amd64/arm64）
ARG TARGETARCH

WORKDIR /src

# 先拷贝依赖清单以利用构建缓存
COPY go.mod go.sum ./
RUN go mod download

# 拷贝源码并构建
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} \
    go build \
    -ldflags="-s -w -X github.com/https-cert/deploy/internal/config.Version=${VERSION}" \
    -trimpath \
    -o /out/anssl main.go

# ---- runtime stage ----
FROM alpine:latest

# HTTPS 根证书 + 时区数据
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/anssl /usr/local/bin/anssl

WORKDIR /app

# HTTP-01 challenge 服务端口（默认 19000）
EXPOSE 19000

# 前台运行，日志输出到 stdout（docker logs 可见），由 Docker 负责重启
ENTRYPOINT ["anssl"]
CMD ["start", "-c", "/app/config.yaml"]
