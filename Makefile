.PHONY: build build-mac build-linux build-windows compress build-compress proto clean install

# 默认目标
all: proto build

# 构建二进制文件
build: build-mac build-linux build-windows
	@echo "所有平台构建完成"

# 构建 Mac 版本
build-mac:
	@echo "构建 Mac 版本..."
	@mkdir -p bin
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o bin/cert-deploy-mac main.go
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o bin/cert-deploy-mac-arm64 main.go
	@echo "Mac 版本构建完成"

# 构建 Linux 版本
build-linux:
	@echo "构建 Linux 版本..."
	@mkdir -p bin
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o bin/cert-deploy-linux main.go
	@GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o bin/cert-deploy-linux-arm64 main.go
	@echo "Linux 版本构建完成"

# 构建 Windows 版本
build-windows:
	@echo "构建 Windows 版本..."
	@mkdir -p bin
	@GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o bin/cert-deploy-windows.exe main.go
	@GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o bin/cert-deploy-windows-arm64.exe main.go
	@echo "Windows 版本构建完成"

# 压缩二进制文件（需要安装 UPX）
compress:
	@echo "压缩二进制文件..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best bin/cert-deploy-linux*; \
		echo "压缩完成"; \
	else \
		echo "UPX 未安装，跳过压缩步骤"; \
		echo "安装 UPX: brew install upx (macOS) 或 apt install upx (Ubuntu)"; \
	fi

# 构建并压缩所有版本
build-compress: build compress
	@echo "构建和压缩完成"
