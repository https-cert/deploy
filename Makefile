.PHONY: build build-mac build-linux build-windows compress build-compress proto clean install docker-build docker-buildx docker-run

VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
BASE_LDFLAGS := -X github.com/https-cert/deploy/internal/config.Version=$(VERSION)
STRIP_LDFLAGS := -s -w $(BASE_LDFLAGS)

# Docker 镜像名（可通过 make docker-build DOCKER_IMAGE=xxx 覆盖）
DOCKER_IMAGE ?= ghcr.io/https-cert/deploy
DOCKER_TAG ?= dev
# 注入镜像的版本号：默认跟随 DOCKER_TAG；显式传 VERSION 时以 VERSION 为准
ifeq ($(origin VERSION),command line)
DOCKER_VERSION := $(VERSION)
else
DOCKER_VERSION := $(DOCKER_TAG)
endif

# 默认目标
all: proto build

# 构建二进制文件
build: build-mac build-linux build-windows
	@echo "所有平台构建完成"

# 构建 Mac 版本（打包为 tar.gz，内部二进制名为 anssl）
build-mac:
	@echo "构建 Mac 版本..."
	@mkdir -p bin bin/darwin-amd64 bin/darwin-arm64
	@GOOS=darwin GOARCH=amd64 go build -ldflags="$(STRIP_LDFLAGS)" -trimpath -o bin/darwin-amd64/anssl main.go
	@cp config.example.yaml bin/darwin-amd64/config.example.yaml
	@tar -C bin/darwin-amd64 -czf bin/anssl-darwin-amd64.tar.gz anssl config.example.yaml
	@GOOS=darwin GOARCH=arm64 go build -ldflags="$(STRIP_LDFLAGS)" -trimpath -o bin/darwin-arm64/anssl main.go
	@cp config.example.yaml bin/darwin-arm64/config.example.yaml
	@tar -C bin/darwin-arm64 -czf bin/anssl-darwin-arm64.tar.gz anssl config.example.yaml
	@rm -rf bin/darwin-amd64 bin/darwin-arm64
	@echo "Mac 版本构建完成"

# 构建 Linux 版本（打包为 tar.gz，内部二进制名为 anssl）
build-linux:
	@echo "构建 Linux 版本..."
	@mkdir -p bin bin/linux-amd64 bin/linux-arm64
	@GOOS=linux GOARCH=amd64 go build -ldflags="$(STRIP_LDFLAGS)" -trimpath -o bin/linux-amd64/anssl main.go
	@echo "尝试使用 UPX 压缩 linux-amd64 二进制..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best bin/linux-amd64/anssl || echo "UPX 压缩失败（linux-amd64），已忽略"; \
	else \
		echo "UPX 未安装，跳过 linux-amd64 压缩"; \
	fi
	@cp config.example.yaml bin/linux-amd64/config.example.yaml
	@tar -C bin/linux-amd64 -czf bin/anssl-linux-amd64.tar.gz anssl config.example.yaml
	@GOOS=linux GOARCH=arm64 go build -ldflags="$(STRIP_LDFLAGS)" -trimpath -o bin/linux-arm64/anssl main.go
	@echo "尝试使用 UPX 压缩 linux-arm64 二进制..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best bin/linux-arm64/anssl || echo "UPX 压缩失败（linux-arm64），已忽略"; \
	else \
		echo "UPX 未安装，跳过 linux-arm64 压缩"; \
	fi
	@cp config.example.yaml bin/linux-arm64/config.example.yaml
	@tar -C bin/linux-arm64 -czf bin/anssl-linux-arm64.tar.gz anssl config.example.yaml
	@rm -rf bin/linux-amd64 bin/linux-arm64
	@echo "Linux 版本构建完成"

# 构建 Windows 版本（打包为 zip，内部二进制名为 anssl.exe）
build-windows:
	@echo "构建 Windows 版本..."
	@mkdir -p bin bin/windows-amd64 bin/windows-arm64
	@GOOS=windows GOARCH=amd64 go build -ldflags="$(BASE_LDFLAGS)" -trimpath -o bin/windows-amd64/anssl.exe main.go
	@cp config.example.yaml bin/windows-amd64/config.example.yaml
	@cd bin/windows-amd64 && zip -q ../../bin/anssl-windows-amd64.zip anssl.exe config.example.yaml
	@GOOS=windows GOARCH=arm64 go build -ldflags="$(BASE_LDFLAGS)" -trimpath -o bin/windows-arm64/anssl.exe main.go
	@cp config.example.yaml bin/windows-arm64/config.example.yaml
	@cd bin/windows-arm64 && zip -q ../../bin/anssl-windows-arm64.zip anssl.exe config.example.yaml
	@rm -rf bin/windows-amd64 bin/windows-arm64
	@echo "Windows 版本构建完成"

# 兼容旧的 build-compress 目标（现在等价于 build）
build-compress: build
	@echo "构建完成（输出为压缩包，内部应用名为 anssl）"

# 构建本机架构 Docker 镜像（用于本地调试）
docker-build:
	@echo "构建 Docker 镜像 $(DOCKER_IMAGE):$(DOCKER_TAG) (VERSION=$(DOCKER_VERSION))..."
	@docker build --build-arg VERSION=$(DOCKER_VERSION) -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "Docker 镜像构建完成: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# 构建多架构 Docker 镜像（amd64 + arm64，仅校验构建，不加载到本地）
docker-buildx:
	@echo "构建多架构 Docker 镜像 $(DOCKER_IMAGE):$(DOCKER_TAG) (VERSION=$(DOCKER_VERSION))..."
	@docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=$(DOCKER_VERSION) -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "多架构镜像构建完成（如需推送请加 --push）"

# 运行本地镜像（前台，需当前目录存在 config.yaml）
docker-run: docker-build
	@echo "运行 $(DOCKER_IMAGE):$(DOCKER_TAG)（挂载 ./config.yaml，映射 19000 端口）..."
	@docker run --rm -it -v "$(PWD)/config.yaml:/app/config.yaml:ro" -p 19000:19000 $(DOCKER_IMAGE):$(DOCKER_TAG)
