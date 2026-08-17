# 证书自动部署 CLI 工具

[English README](README_EN.md)

一个自动化的 SSL 证书部署工具，用于从 [anssl.cn](https://anssl.cn) 下载并部署证书到服务器。

## 特性

- 🚀 自动化部署证书到 Nginx、Apache、RustFS、1Panel、雷池 WAF，并自动重载本地服务
- ✅ 内置 HTTP-01 验证服务，自动响应 ACME challenge
- ☁️ 支持阿里云、腾讯云、七牛云、华为云、火山引擎、京东云、百度云、多吉云和 LeCDN 自动部署
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
5. 自动下载并部署证书到配置的服务（Nginx/Apache/RustFS/1Panel/雷池 WAF/飞牛OS）
6. 自动重载 Nginx 和 Apache 服务

**全程自动化，无需手动操作。**

## 云服务能力

云资源类部署会先从 deploy 客户端实时发现资源，部署后再回读证书状态进行验收。只有具备资源发现、证书更新和回读验收闭环的产品才会出现在控制台。

| 云服务 | Provider 名称 | 已接入能力 |
| --- | --- | --- |
| 阿里云 | `aliyun` | 上传证书、CDN、DCDN、ESA、OSS 自定义域名、CLB、ALB、NLB |
| 腾讯云 | `cloudTencent` | 上传证书、CDN、EdgeOne、COS 自定义域名、CLB |
| 七牛云 | `qiniu` | 上传证书、CDN、DCDN |
| 华为云 | `huawei` | 上传证书、CDN、DCDN、OBS 自定义域名、ELB |
| 火山引擎 | `volcengine` | 上传证书、CDN、DCDN、TOS 自定义域名、CLB、ALB、NLB |
| 京东云 | `jdcloud` | 上传证书、CDN |
| 百度云 | `baidu` | 上传证书、CDN |
| 多吉云 | `dogecloud` | 上传证书、CDN |
| LeCDN | `lecdn` | CDN |

京东云、百度云和多吉云当前没有注册 DCDN；LeCDN 只注册 CDN。对应产品具备完整闭环后再开放能力。

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

### RustFS 与飞牛 SSH 部署

RustFS 使用 `ssl.rustFS.path` 指定证书目录：未填写 SSH 主机时部署到 deploy 客户端本机；填写 SSH 主机、端口、用户名和认证字段后，部署到远程 RustFS 主机。飞牛 OS 在未配置 `ssl.feiNiu` 时继续使用客户端所在设备的内置部署逻辑，配置后改为 SSH 远程部署。

SSH 支持密码或私钥认证，不需要单独配置 SCP。`privateKeyPath` 必须指向 deploy 客户端本机上的私钥绝对路径，私钥内容不会写入 `config.yaml` 或发送到后端。使用私钥认证时，`password` 可留空，也可作为非 root 用户的 sudo 密码。

```yaml
ssl:
  rustFS:
    path: "/opt/rustfs/tls"
    host: "192.168.1.30"
    port: 22
    username: "admin"
    privateKeyPath: "/home/anssl/.ssh/id_ed25519"
    privateKeyPassphrase: ""
    password: "" # 可选的 sudo 密码

  feiNiu:
    host: "192.168.1.20"
    port: 22
    username: "admin"
    password: "your-ssh-password"
```

### 雷池 WAF 证书部署

在雷池“通用设置”中生成 API Token，并将管理端地址与 Token 配置到 deploy 客户端。连接测试只调用只读证书列表接口；部署时按新证书的完整 SAN 域名集合查找已有证书，完全一致的记录会全部更新，没有完全一致的记录时新增证书，避免误改仅部分域名重叠的证书。

```yaml
ssl:
  safeLine:
    url: "https://waf.example.com:9443"
    apiToken: "your-safeline-api-token"
    insecureSkipVerify: false
```

`insecureSkipVerify` 默认必须保持 `false`。只有雷池管理端使用你明确信任的自签名 HTTPS 证书时才可开启；API Token 仅保存在 deploy 客户端本机，不会发送到 ANSSL 后端。

### 宝塔网站证书部署

在宝塔面板“面板设置 -> API 接口”中启用 API 并生成密钥，然后把面板地址和密钥配置到 deploy 客户端。网页端会实时读取网站及绑定域名，选择具体网站后建立自动部署目标；未启用 HTTPS 的运行中网站也可以选择，首次部署时会自动启用 HTTPS，之后部署会精确替换该网站证书。

```yaml
ssl:
  btPanel:
    url: "https://panel.example.com:8888"
    apiKey: "your-bt-panel-api-key"
    insecureSkipVerify: false
```

`insecureSkipVerify` 仅用于你明确信任的自签名 HTTPS 面板。面板地址、真实网站 ID、API 密钥、证书私钥和面板原始诊断不会作为部署目标数据保存到 ANSSL 后端。

### 宝塔证书库上传

在部署目标中选择“宝塔证书库”时，deploy 会通过宝塔的 `ssl/cert/save_cert` 接口保存证书，不绑定具体网站。连接测试只读取证书列表；上传后会在 deploy 客户端本地回读证书详情并校验叶证书 SHA-256 指纹。

## 常见问题

**Q: server.accessKey 在哪里获取？**
A: 登录 [anssl.cn](https://anssl.cn) → 控制台 → 开发者 → API 凭证

**Q: 支持哪些 Web 服务器和管理面板？**
A: 支持 Nginx、Apache、RustFS、1Panel、宝塔面板、雷池 WAF 和飞牛 OS 自动部署。RustFS 支持本机目录或 SSH 远程部署；飞牛部署目标默认使用客户端所在设备的内置逻辑，也可配置 `ssl.feiNiu` 通过 SSH 远程部署。两者都支持密码和私钥认证。

**Q: 可以同时部署到多个服务吗？**
A: 可以。在 `config.yaml` 中配置所需目标（如 `nginxPath`、`apachePath`、`rustFS`、`onePanel`、`btPanel`、`safeLine` 和可选的远程 `feiNiu`），并在 anssl.cn 控制台为证书选择对应部署目标。

**Q: 1Panel 的 API 密钥在哪里获取？**
A: 登录 1Panel 面板 → 设置 → 安全 → API 接口 → 生成 API 密钥

**Q: 宝塔面板的 API 密钥在哪里获取？**
A: 登录宝塔面板 → 面板设置 → API 接口 → 开启 API 并生成接口密钥。密钥只需填写在 deploy 客户端本机的 `ssl.btPanel.apiKey`。

**Q: 雷池的 API Token 在哪里获取？**
A: 登录雷池管理端 → 通用设置 → API Token。Token 只需填写在 deploy 客户端本机的 `ssl.safeLine.apiToken`。

**Q: 证书会同时部署到本地和云服务吗？**
A: 在 [anssl.cn](https://anssl.cn) 控制台配置部署目标时，可以选择部署到本地 CLI（Nginx/Apache/RustFS/1Panel/宝塔面板/雷池 WAF/飞牛OS）或已接入的云服务。每个证书可以配置多个部署目标，实现同时部署。

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
