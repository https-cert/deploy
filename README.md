# 证书自动部署 CLI 工具

一个自动化的 SSL 证书部署工具，用于从 [anssl.cn](https://anssl.cn) 下载并部署证书到服务器。

## 特性

- 🚀 自动化部署证书并重载 Nginx
- ✅ 内置 HTTP-01 验证服务，自动响应 ACME challenge
- ☁️ 支持自动上传证书到云服务（阿里云、七牛云）
- 🔧 守护进程模式，支持后台运行
- 🖥️ 多平台支持：macOS、Linux、Windows（amd64/arm64）

## 快速开始

### 1. 安装

从 [GitHub Releases](https://github.com/https-cert/deploy/releases) 下载适合你系统的版本：

```bash
# Linux
wget https://github.com/https-cert/deploy/releases/latest/download/anssl-linux-amd64.tar.gz
tar -xzf anssl-linux-amd64.tar.gz
chmod +x anssl
sudo mv anssl /usr/local/bin/
```

### 2. 配置

创建 `config.yaml` 文件：

```yaml
server:
  # 从 anssl.cn 设置 -> 个人资料 中获取
  accessKey: "your_access_key_here"
  # HTTP-01 验证服务端口
  port: 19000

ssl:
  # 证书存储目录（留空则使用 ./certs）
  path: "/etc/nginx/ssl"

# 云服务配置（可选）
provider:
  - name: "aliyun"
    accessKeyId: "your_key"
    accessKeySecret: "your_secret"
```
> #### 已支持的CDN服务商
> 关于`provide.name`值请看下表
| 配置项参数 | 英文 | 说明 |
|--------|------|------|
| `name` | `aliyun` | 阿里云 |
| `name` | `qiniu` | 七牛云 |
| `name` | 更多 | 敬请期待 |


### 3. 配置 Nginx

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

### 4. 运行

```bash
# 启动守护进程
sudo ./anssl daemon -c config.yaml

# 查看状态
./anssl status

# 查看日志
./anssl log -f
```

## HTTP-01 验证工作流程

1. 在网站申请免费证书
2. 后端推送 ACME challenge token 到 CLI
3. CLI 自动缓存并响应 Let's Encrypt 验证请求
4. 验证成功，证书签发
5. 自动下载并部署证书
6. 自动重载 Nginx

**全程自动化，无需手动操作。**

## 常用命令

```bash
# 守护进程管理
./anssl daemon -c config.yaml  # 启动守护进程
./anssl status                 # 查看状态
./anssl stop                   # 停止
./anssl restart -c config.yaml # 重启

# 日志查看
./anssl log                    # 查看日志
./anssl log -f                 # 实时跟踪

# 更新
./anssl check-update           # 检查更新
./anssl update                 # 执行更新
```

## 配置说明

| 配置项 | 必填 | 说明 |
|--------|------|------|
| `server.accessKey` | ✅ | 从 anssl.cn 获取的访问密钥 |
| `server.port` | ❌ | HTTP-01 验证端口，默认 19000 |
| `ssl.path` | ❌ | 证书存储目录，默认 `./certs` |
| `provider` | ❌ | 云服务配置（阿里云/七牛云） |

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
./anssl log -f
```

### 权限错误

```bash
# 方式 1：使用 sudo
sudo ./anssl daemon -c config.yaml

# 方式 2：配置用户目录
# 修改 config.yaml: ssl.path: "$HOME/nginx/ssl"
./anssl daemon -c config.yaml
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
ExecStart=/usr/local/bin/anssl start -c /etc/anssl/config.yaml
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

**Q: AccessKey 在哪里获取？**
A: 登录 [anssl.cn](https://anssl.cn) → 设置 → 个人资料

**Q: 支持哪些 Web 服务器？**
A: 目前仅支持 Nginx 自动重载，其他服务器可使用本工具下载证书后手动配置

**Q: 证书会同时部署到本地和云服务吗？**
A: 不会。如果配置了云服务，会优先上传到云服务；否则部署到本地

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
