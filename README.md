# 证书自动部署 CLI 工具

<p align="center">
一个自动化的 SSL 证书部署工具，用于从 <a href="https://anssl.cn">anssl.cn</a> 下载并部署证书到服务器。
</p>

## ✨ 特性

- 🚀 **自动化部署**：自动下载证书、解压、部署到指定目录
- 🔄 **智能重载**：自动测试 Nginx 配置并重载服务
- 🌐 **实时通知**：通过长连接接收服务器推送的证书更新通知
- 🛡️ **稳定可靠**：心跳保活、自动重连机制
- 🔧 **守护进程**：支持后台运行，可通过命令管理进程状态
- 📦 **开箱即用**：单一可执行文件，无需依赖
- 🖥️ **多平台支持**：支持 macOS、Linux、Windows（amd64/arm64）

## 📥 安装

### 从 Release 下载（推荐）

从 [GitHub Releases](https://github.com/https-cert/deploy/releases) 下载适合你系统的二进制文件：

```bash
# Linux (amd64)
wget https://github.com/https-cert/deploy/releases/latest/download/cert-deploy-linux
chmod +x cert-deploy-linux
sudo mv cert-deploy-linux /usr/local/bin/cert-deploy

# Linux (arm64)
wget https://github.com/https-cert/deploy/releases/latest/download/cert-deploy-linux-arm64
chmod +x cert-deploy-linux-arm64
sudo mv cert-deploy-linux-arm64 /usr/local/bin/cert-deploy

# macOS (Intel)
wget https://github.com/https-cert/deploy/releases/latest/download/cert-deploy-mac
chmod +x cert-deploy-mac

# macOS (Apple Silicon)
wget https://github.com/https-cert/deploy/releases/latest/download/cert-deploy-mac-arm64
chmod +x cert-deploy-mac-arm64

# Windows (amd64)
wget https://github.com/https-cert/deploy/releases/latest/download/cert-deploy-windows-arm64.exe
chmod +x cert-deploy-windows-arm64.exe

# Windows (arm64)
wget https://github.com/https-cert/deploy/releases/download/latest/cert-deploy-windows-arm64.exe
chmod +x cert-deploy-windows-arm64.exe
```

### 从源码构建

需要 Go 1.25 或更高版本：

```bash
# 克隆仓库
git clone https://github.com/orange-juzipi/cert-deploy.git
cd cert-deploy

# 构建当前平台
go build -o cert-deploy main.go

# 或使用 Make 构建所有平台
make build

# 或使用 Make 构建所有平台并压缩（需要安装 upx）
make build-compress
```

## ⚙️ 配置

### 创建配置文件

在程序同级目录下创建 `config.yaml` 文件，或使用 `-c` 参数指定配置文件路径：

```yaml
# 服务器配置
server:
  # 从网站的 设置 -> 个人资料 中获取 AccessKey
  accessKey: "your_access_key_here"

# SSL 证书配置
ssl:
  # 证书存储根目录
  # 留空则默认存储在程序目录下的 certs 文件夹
  path: "/etc/nginx/ssl"

# 在线更新配置（可选）
update:
  # 镜像源类型，可选值：
  # - custom (自定义镜像地址)
  # - github (默认，直连 GitHub)
  # - ghproxy (使用 ghproxy 镜像加速，推荐国内用户使用)
  # - ghproxy2
  mirror: ""

  # 自定义镜像地址（仅当 mirror=custom 时使用）
  # 示例: "https://your-mirror.com"
  customUrl: ""

  # HTTP 代理地址（可选）
  # 支持 http、https、socks5 协议
  # 示例: "http://127.0.0.1:7890"
  # 示例: "socks5://127.0.0.1:1080"
  # 注意：也可以通过环境变量 HTTP_PROXY 和 HTTPS_PROXY 设置代理
  proxy: ""
```

### 配置说明

| 配置项             | 必填 | 说明                                                  |
| ------------------ | ---- | ----------------------------------------------------- |
| `server.accessKey` | ✅   | 从 [anssl.cn](https://anssl.cn) 获取的访问密钥        |
| `ssl.path`         | ❌   | 证书存储目录，留空则保存在程序目录下的 `certs` 文件夹 |

## 🚀 使用方法

### 基本命令

```bash
# 显示帮助信息
./cert-deploy --help

# 启动守护进程（后台运行，推荐）
./cert-deploy daemon -c config.yaml

# 前台运行（用于调试）
./cert-deploy start -c config.yaml

# 查看守护进程状态
./cert-deploy status

# 查看日志
./cert-deploy log

# 实时跟踪日志输出（类似 tail -f）
./cert-deploy log -f

# 重启守护进程
./cert-deploy restart -c config.yaml

# 停止守护进程
./cert-deploy stop

# 检查更新
./cert-deploy check-update

# 手动触发更新检查
./cert-deploy update
```

### 运行方式

根据你的环境，选择合适的运行方式：

#### 方式 1：使用 sudo（推荐）

如果部署目录是系统目录（如 `/etc/nginx/ssl`），需要 root 权限：

```bash
# 授予执行权限
chmod +x cert-deploy

# 使用 sudo 启动
sudo ./cert-deploy daemon -c config.yaml
```

#### 方式 2：配置为用户目录

修改 `config.yaml`，将证书目录设为用户目录：

```yaml
ssl:
  path: "$HOME/nginx/ssl" # 使用用户目录
```

然后正常运行：

```bash
./cert-deploy daemon -c config.yaml
```

#### 方式 3：配置目录权限

为当前用户配置 nginx 目录的访问权限：

```bash
# 将用户添加到 nginx 组
sudo usermod -aG nginx $USER

# 修改 SSL 目录权限
sudo chown -R root:nginx /etc/nginx/ssl
sudo chmod 775 /etc/nginx/ssl

# 重新登录以使组权限生效
# 然后运行
./cert-deploy daemon -c config.yaml
```

## 📋 系统要求

- **操作系统**：Linux、macOS、Windows
- **Nginx**（可选）：如果需要自动重载 Nginx，请确保系统已安装 Nginx 并且在 PATH 中
  - 未安装 Nginx 时，工具仅下载证书到指定目录，不会尝试重载服务
- **权限**：需要对证书存储目录有读写权限

## 📁 文件位置

- **PID 文件**：`~/.cert-deploy.pid`（用户主目录）
- **日志文件**：与 `config.yaml` 同目录下的 `cert-deploy.log`
- **证书文件**：
  - 下载的 zip 文件：`./certs/{domain}_certificates.zip`
  - 解压后的证书：`{ssl.path}/{domain}_certificates/`

## 🔍 示例输出

### 启动守护进程

```bash
$ ./cert-deploy daemon -c config.yaml
证书部署守护进程已启动
```

### 查看状态

```bash
$ ./cert-deploy status
PID文件路径: /Users/username/.cert-deploy.pid
证书部署守护进程正在运行 (PID: 12345)
```

### 查看日志

```bash
$ ./cert-deploy log -f
=== 实时日志跟踪 (按 Ctrl+C 退出) ===
2024/01/15 10:30:00 [INFO] 启动证书部署守护进程
2024/01/15 10:30:01 [INFO] 建立连接通知成功，开始监听通知
2024/01/15 10:35:22 [INFO] 证书下载完成: certs/example.com_certificates.zip
2024/01/15 10:35:23 [INFO] nginx配置测试通过
2024/01/15 10:35:23 [INFO] nginx重新加载成功
2024/01/15 10:35:23 [INFO] 自动部署流程完成: example.com
```

## 🛠️ 开发指南

### 构建项目

```bash
# 安装依赖
go mod download

# 运行测试
go test -v ./...

# 构建当前平台
go build -o cert-deploy main.go

# 构建所有平台（输出到 bin/ 目录）
make build

# 构建并使用 UPX 压缩（需要安装 upx）
make build-compress
```

### 项目结构

```
.
├── main.go                 # 主程序入口，Cobra CLI 命令定义
├── internal/
│   ├── client/            # RPC 客户端和证书部署逻辑
│   ├── config/            # 配置管理
│   ├── scheduler/         # 任务调度器
│   └── system/            # 系统信息收集
├── pkg/
│   ├── logger/            # 日志工具
│   └── utils/             # 工具函数
└── pb/                    # Protobuf 生成的代码
```

### 技术栈

- **CLI 框架**：[Cobra](https://github.com/spf13/cobra)
- **配置管理**：[Viper](https://github.com/spf13/viper)
- **RPC 通信**：[Connect RPC](https://connectrpc.com/)
- **协议**：Protocol Buffers

## 🐛 故障排除

### 连接服务器失败

**问题**：无法连接到 anssl.cn 服务器

**解决方案**：

1. 检查网络连接是否正常
2. 确认 `accessKey` 配置正确
3. 查看日志文件获取详细错误信息：`./cert-deploy log`

### 权限错误

**问题**：`Permission denied` 或无法写入证书目录

**解决方案**：

1. 使用 `sudo` 运行：`sudo ./cert-deploy daemon -c config.yaml`
2. 或参考"运行方式"章节配置目录权限
3. 或将 `ssl.path` 改为用户有权限的目录

### Nginx 重载失败

**问题**：证书下载成功，但 Nginx 重载失败

**解决方案**：

1. 确认 Nginx 已安装：`nginx -v`
2. 手动测试 Nginx 配置：`sudo nginx -t`
3. 检查 Nginx 配置中的证书路径是否与部署路径一致
4. 查看日志获取详细错误：`./cert-deploy log`

### 守护进程无法启动

**问题**：执行 `daemon` 命令后进程立即退出

**解决方案**：

1. 检查配置文件是否正确：`cat config.yaml`
2. 使用前台模式查看错误：`./cert-deploy start -c config.yaml`
3. 检查 PID 文件是否被占用：`cat ~/.cert-deploy.pid`
4. 如果进程异常退出，删除 PID 文件后重试：`rm ~/.cert-deploy.pid`

### Nginx 未安装

**问题**：系统未安装 Nginx

**影响**：证书会下载到指定目录，但不会自动重载 Nginx

**解决方案**：

- 工具会自动跳过 Nginx 相关操作，证书仍会正常下载
- 如需自动重载功能，请先安装 Nginx

## 📝 许可证

MIT License

---

## 🔗 相关链接

- **项目主页**：[https://github.com/https-cert/deploy](https://github.com/https-cert/deploy)
- **证书服务**：[https://anssl.cn](https://anssl.cn)
- **问题反馈**：[GitHub Issues](https://github.com/https-cert/deploy/issues)

## 🙋 常见问题

### 1. AccessKey 在哪里获取？

登录 [anssl.cn](https://anssl.cn)，进入 **设置 → 个人资料** 页面获取。

### 2. 支持哪些 Web 服务器？

目前仅支持 Nginx 的自动重载。其他 Web 服务器（如 Apache、Caddy）可以使用本工具下载证书，但需要手动配置服务器重载。

### 3. 证书更新频率是多少？

工具通过服务器推送实时接收证书更新通知，无需手动检查。客户端每 5 秒发送一次心跳保持连接。

### 4. 如何设置开机自启动？

可以使用系统服务管理器（如 systemd）来设置：

```bash
# 创建 systemd 服务文件
sudo tee /etc/systemd/system/cert-deploy.service > /dev/null <<EOF
[Unit]
Description=Certificate Deploy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/cert-deploy start -c /etc/cert-deploy/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 启用并启动服务
sudo systemctl daemon-reload
sudo systemctl enable cert-deploy
sudo systemctl start cert-deploy

# 查看服务状态
sudo systemctl status cert-deploy
```

### 5. 如何验证证书部署成功？

```bash
# 查看证书文件
ls -la /etc/nginx/ssl/yourdomain.com_certificates/

# 检查 Nginx 配置
sudo nginx -t

# 查看部署日志
./cert-deploy log
```
