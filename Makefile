.PHONY: build build-mac build-linux build-windows compress build-compress proto clean install

# 默认目标
all: proto build

# 构建二进制文件
build: build-mac build-linux build-windows
	@echo "所有平台构建完成"

# 构建 Mac 版本（打包为 tar.gz，内部二进制名为 anssl）
build-mac:
	@echo "构建 Mac 版本..."
	@mkdir -p bin bin/darwin-amd64 bin/darwin-arm64
	@GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o bin/darwin-amd64/anssl main.go
	@tar -C bin/darwin-amd64 -czf bin/anssl-darwin-amd64.tar.gz anssl
	@GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o bin/darwin-arm64/anssl main.go
	@tar -C bin/darwin-arm64 -czf bin/anssl-darwin-arm64.tar.gz anssl
	@rm -rf bin/darwin-amd64 bin/darwin-arm64
	@echo "Mac 版本构建完成"

# 构建 Linux 版本（打包为 tar.gz，内部二进制名为 anssl）
build-linux:
	@echo "构建 Linux 版本..."
	@mkdir -p bin bin/linux-amd64 bin/linux-arm64
	@GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o bin/linux-amd64/anssl main.go
	@echo "尝试使用 UPX 压缩 linux-amd64 二进制..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best bin/linux-amd64/anssl || echo "UPX 压缩失败（linux-amd64），已忽略"; \
	else \
		echo "UPX 未安装，跳过 linux-amd64 压缩"; \
	fi
	@tar -C bin/linux-amd64 -czf bin/anssl-linux-amd64.tar.gz anssl
	@GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o bin/linux-arm64/anssl main.go
	@echo "尝试使用 UPX 压缩 linux-arm64 二进制..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best bin/linux-arm64/anssl || echo "UPX 压缩失败（linux-arm64），已忽略"; \
	else \
		echo "UPX 未安装，跳过 linux-arm64 压缩"; \
	fi
	@tar -C bin/linux-arm64 -czf bin/anssl-linux-arm64.tar.gz anssl
	@rm -rf bin/linux-amd64 bin/linux-arm64
	@echo "Linux 版本构建完成"

# 构建 Windows 版本（打包为 zip，内部二进制名为 anssl.exe）
build-windows:
	@echo "构建 Windows 版本..."
	@mkdir -p bin bin/windows-amd64 bin/windows-arm64
	@GOOS=windows GOARCH=amd64 go build -trimpath -o bin/windows-amd64/anssl.exe main.go
	@cd bin/windows-amd64 && zip -q ../../bin/anssl-windows-amd64.zip anssl.exe
	@GOOS=windows GOARCH=arm64 go build -trimpath -o bin/windows-arm64/anssl.exe main.go
	@cd bin/windows-arm64 && zip -q ../../bin/anssl-windows-arm64.zip anssl.exe
	@rm -rf bin/windows-amd64 bin/windows-arm64
	@echo "Windows 版本构建完成"

# 兼容旧的 build-compress 目标（现在等价于 build）
build-compress: build
	@echo "构建完成（输出为压缩包，内部应用名为 anssl）"
