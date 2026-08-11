# 证书自动部署 CLI 工具

[English README](README_EN.md)

一个自动化的 SSL 证书部署工具，用于从 [anssl.cn](https://anssl.cn) 下载并部署证书到服务器。

## 特性

- 🚀 自动化部署证书到 Nginx、Apache、RustFS、1Panel 并自动重载服务
- ✅ 内置 HTTP-01 验证服务，自动响应 ACME challenge
- ☁️ 支持自动上传证书到云服务（阿里云、七牛云、腾讯云）
- 🔧 守护进程模式，支持后台运行
- 🖥️ 多平台支持：macOS、Linux、Windows（amd64/arm64）

## 快速开始

### 1. 安装

Linux/macOS 推荐使用一键安装脚本，默认安装 [GitHub Releases](https://github.com/https-cert/deploy/releases) 最新版本：

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh
```

如需固定版本或修改安装目录：

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | VERSION=v0.6.0 APP_DIR=/opt/anssl sh
```

默认安装到 `/opt/anssl`，并创建 `/usr/local/bin/anssl` 软链接。如需卸载：

```bash
# 卸载程序，保留配置
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh -s -- --uninstall

# 卸载程序并删除配置
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh -s -- --uninstall --purge
```

### 2. 配置 Nginx

添加 HTTP-01 验证反向代理（用于证书申请）：

```nginx
# 在 server 块中添加
location ~ ^/.well-known/acme-challenge/(.+)$ {
    proxy_pass http://localhost:19000/acme-challenge/$1;
    proxy_set_header Host $host;
}
```

重载 Nginx：

```bash
sudo nginx -t && sudo nginx -s reload
```

### 3. 运行

```bash
# 启动守护进程
sudo anssl daemon -c /opt/anssl/config.yaml

# 查看状态
anssl status

# 查看日志
anssl log -f
```

## HTTP-01 验证工作流程

1. 在网站申请免费证书
2. 后端推送 ACME challenge token 到 CLI
3. CLI 自动缓存并响应 Let's Encrypt 验证请求
4. 验证成功，证书签发
5. 自动下载并部署证书到配置的服务（Nginx/Apache/RustFS/1Panel/飞牛OS）
6. 自动重载 Nginx 和 Apache 服务

**全程自动化，无需手动操作。**

## 常用命令

```bash
# 守护进程管理
anssl daemon -c /opt/anssl/config.yaml  # 启动守护进程
anssl status                            # 查看状态
anssl stop                              # 停止
anssl restart -c /opt/anssl/config.yaml # 重启

# 日志查看
anssl log                               # 查看日志
anssl log -f                            # 实时跟踪

# 更新
anssl check-update                      # 检查更新
anssl update                            # 执行更新
```

## 故障排除

### HTTP-01 验证失败

```bash
# 1. 检查 Nginx 配置
sudo nginx -t
cat /etc/nginx/sites-enabled/default | grep acme-challenge

# 2. 检查端口占用
lsof -i :19000

# 3. 测试验证服务
curl http://localhost:19000/acme-challenge/test-token

# 4. 查看日志
anssl log -f
```

### 权限错误

```bash
# 方式 1：使用 sudo
sudo anssl daemon -c /opt/anssl/config.yaml

# 方式 2：配置用户目录
# 修改 /opt/anssl/config.yaml: ssl.path: "$HOME/nginx/ssl"
anssl daemon -c /opt/anssl/config.yaml
```

### 开机自启动（systemd）

```bash
sudo tee /etc/systemd/system/anssl.service > /dev/null <<EOF
[Unit]
Description=Certificate Deploy Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/anssl start -c /opt/anssl/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable anssl
sudo systemctl start anssl
```

## 常见问题

**Q: server.accessKey 在哪里获取？**
A: 登录 [anssl.cn](https://anssl.cn) → 控制台 → 开发者 → API 凭证

**Q: 支持哪些 Web 服务器和管理面板？**
A: 支持 Nginx、Apache、RustFS、1Panel 和飞牛 OS 自动部署。飞牛部署目标默认使用客户端所在设备的内置本机逻辑；如果客户端未安装在飞牛 OS 上，可在 `config.yaml` 中填写 `ssl.feiNiu` 的主机、端口、用户名和密码，通过 SSH 远程部署。

**Q: 可以同时部署到多个服务吗？**
A: 可以。在 `config.yaml` 中配置所需目标（如 `nginxPath`、`apachePath`、`rustFSPath`、`onePanel` 和可选的远程 `feiNiu`），并在 anssl.cn 控制台为证书选择对应部署目标。

**Q: 1Panel 的 API 密钥在哪里获取？**
A: 登录 1Panel 面板 → 设置 → 安全 → API 接口 → 生成 API 密钥

**Q: 证书会同时部署到本地和云服务吗？**
A: 在 [anssl.cn](https://anssl.cn) 控制台配置部署目标时，可以选择部署到本地 CLI（Nginx/Apache/RustFS/1Panel/飞牛OS）或云服务（阿里云/七牛云/腾讯云）。每个证书可以配置多个部署目标，实现同时部署

**Q: HTTP-01 验证需要手动操作吗？**
A: 不需要。配置好 Nginx 反向代理后，验证全程自动完成

## 开发

```bash
# 安装依赖
go mod download

# 运行测试
go test -v ./...

# 构建
go build -o anssl main.go
```

## 相关链接

- 项目主页：[https://github.com/https-cert/deploy](https://github.com/https-cert/deploy)
- 证书服务：[https://anssl.cn](https://anssl.cn)
- 问题反馈：[GitHub Issues](https://github.com/https-cert/deploy/issues)

## 许可证

MIT License
