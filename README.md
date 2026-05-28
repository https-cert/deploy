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

从 [GitHub Releases](https://github.com/https-cert/deploy/releases) 下载适合你系统的版本：

```bash
# Linux
wget https://github.com/https-cert/deploy/releases/latest/download/anssl-linux-amd64.tar.gz
tar -xzf anssl-linux-amd64.tar.gz
chmod +x anssl
sudo mv anssl /usr/local/bin/
```

### 2. 配置

发布包中已包含 `config.yaml` 模板。启动前请修改其中的 `accessKey` 和需要启用的部署目标。

如果从源码运行，可以复制模板：

```bash
cp config.example.yaml config.yaml
```

`config.yaml` 示例：

```yaml
server:
  # 从 anssl.cn 设置 -> 个人资料 中获取
  accessKey: "your_access_key_here"
  # HTTP-01 验证服务端口
  port: 19000

ssl:
  # Nginx 证书目录（可选，留空则不部署到 Nginx）
  nginxPath: ""
  # Apache 证书目录（可选，留空则不部署到 Apache）
  apachePath: ""
  # RustFS TLS 证书目录（可选，留空则不部署到 RustFS）
  rustFSPath: ""
  # 飞牛部署（可选）
  feiNiuEnabled: false
  # 1Panel 配置（可选，留空则不部署到 1Panel）
  onePanel:
    url: ""
    apiKey: ""

update:
  # 镜像源类型：github、ghproxy、ghproxy2、custom
  mirror: "ghproxy"
  # 使用 custom 镜像源时填写
  customUrl: ""
  # HTTP 代理地址（可选）
  proxy: ""

# 云服务配置（可选）
provider:
  - name: "aliyun"
    remark: "阿里云"
    auth:
      accessKeyId: "your-aliyun-access-key-id"
      accessKeySecret: "your-aliyun-access-key-secret"
      # ESA 业务专用字段（仅在执行 ESA 业务时使用）
      esaSiteId: "your-esa-site-id"

  - name: "qiniu"
    remark: "七牛云"
    auth:
      accessKey: "your-qiniu-access-key"
      accessSecret: "your-qiniu-access-secret"

  - name: "cloudTencent"
    remark: "腾讯云"
    auth:
      secretId: "your-tencent-secret-id"
      secretKey: "your-tencent-secret-key"
```

> #### 已支持的云服务商
>
> | 服务商 |    name 值     |           认证字段           |
> | :----: | :------------: | :--------------------------: |
> | 阿里云 |    `aliyun`    | accessKeyId, accessKeySecret（ESA可选：esaSiteId） |
> | 七牛云 |    `qiniu`     |   accessKey, accessSecret    |
> | 腾讯云 | `cloudTencent` |     secretId, secretKey      |

> #### 阿里云 CAS/ESA 业务分离（无自动识别）
>
> - 选择“阿里云-CAS 上传证书”业务：调用 CAS `UploadUserCertificate`
> - 选择“阿里云-ESA 上传证书”业务：调用 ESA `SetCertificate`（需要 `esaSiteId`）
>
> #### 腾讯云上传证书
>
> - 选择“腾讯云-上传证书”业务：通过腾讯云官方 Go SDK 调用 SSL `UploadCertificate`（`ssl.tencentcloudapi.com`, `2019-12-05`）

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
5. 自动下载并部署证书到配置的服务（Nginx/Apache/RustFS/1Panel/飞牛OS）
6. 自动重载 Nginx 和 Apache 服务

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

| 配置项                 | 必填 | 说明                                         |
| ---------------------- | ---- | -------------------------------------------- |
| `server.accessKey`     | ✅   | 从 anssl.cn 获取的访问密钥                   |
| `server.port`          | ❌   | HTTP-01 验证端口，默认 19000                 |
| `ssl.nginxPath`        | ❌   | Nginx 证书目录，配置后自动部署并重载 Nginx   |
| `ssl.apachePath`       | ❌   | Apache 证书目录，配置后自动部署并重载 Apache |
| `ssl.rustFSPath`       | ❌   | RustFS TLS 证书目录，配置后自动部署证书      |
| `ssl.feiNiuEnabled`    | ❌   | 飞牛 OS 证书部署开关，默认 false             |
| `ssl.onePanel.url`     | ❌   | 1Panel 面板地址（如 http://localhost:10000） |
| `ssl.onePanel.apiKey`  | ❌   | 1Panel API 密钥，在面板设置中生成            |
| `provider`             | ❌   | 云服务配置（阿里云/七牛云/腾讯云）           |

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

**Q: 支持哪些 Web 服务器和管理面板？**
A: 支持 Nginx、Apache、RustFS、1Panel 和飞牛 OS 自动部署。只需在 `config.yaml` 中配置对应的证书目录或面板信息，即可实现自动部署和服务重载（Nginx 和 Apache）

**Q: 可以同时部署到多个服务吗？**
A: 可以。在 `config.yaml` 中同时配置多个部署目标（如 `nginxPath`、`apachePath`、`rustFSPath`、`onePanel`、`feiNiuEnabled`），证书更新时会自动部署到所有配置的服务

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
