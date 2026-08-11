# SSL Certificate Auto-Deploy CLI

[中文说明](README.md)

An automated SSL certificate deployment tool for downloading certificates from [anssl.cn](https://anssl.cn) and deploying them to your servers.

## Features

- 🚀 Automatically deploys certificates to Nginx, Apache, RustFS, 1Panel, and SafeLine WAF, then reloads local services
- ✅ Built-in HTTP-01 validation service to automatically respond to ACME challenges
- ☁️ Supports uploading certificates to cloud providers (Alibaba Cloud, Qiniu Cloud, Tencent Cloud)
- 🔧 Daemon mode for long-running background execution
- 🖥️ Multi-platform support: macOS, Linux, Windows (amd64/arm64)

## Quick Start

### 1. Install

For Linux/macOS, use the install script. It installs the latest version from [GitHub Releases](https://github.com/https-cert/deploy/releases) by default:

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh
```

To pin a version or customize paths:

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | VERSION=v0.6.0 APP_DIR=/opt/anssl sh
```

By default, anssl is installed into `/opt/anssl` and linked as `/usr/local/bin/anssl`. To uninstall:

```bash
# Remove the binary and keep config
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh -s -- --uninstall

# Remove the binary and config
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/https-cert/deploy/main/scripts/install.sh | sh -s -- --uninstall --purge
```

### 2. Configure Nginx

Add an HTTP-01 reverse proxy rule (for certificate issuance):

```nginx
# Add this inside the server block
location ~ ^/.well-known/acme-challenge/(.+)$ {
    proxy_pass http://localhost:19000/acme-challenge/$1;
    proxy_set_header Host $host;
}
```

Reload Nginx:

```bash
sudo nginx -t && sudo nginx -s reload
```

### 3. Run

```bash
# Start daemon
sudo anssl daemon -c /opt/anssl/config.yaml

# Check status
anssl status

# View logs
anssl log -f
```

## HTTP-01 Validation Flow

1. Request a free certificate on the website
2. Backend pushes ACME challenge tokens to the CLI
3. CLI caches and serves Let's Encrypt validation requests automatically
4. Validation succeeds and certificate is issued
5. Certificate is downloaded and deployed to configured services (Nginx/Apache/RustFS/1Panel/SafeLine WAF/FeiNiu OS)
6. Nginx and Apache are reloaded automatically

**Fully automated end-to-end, with no manual intervention.**

## Common Commands

```bash
# Daemon management
anssl daemon -c /opt/anssl/config.yaml  # Start daemon
anssl status                            # Check status
anssl stop                              # Stop
anssl restart -c /opt/anssl/config.yaml # Restart

# Logs
anssl log                               # View logs
anssl log -f                            # Follow logs

# Update
anssl check-update                      # Check updates
anssl update                            # Run update
```

## Troubleshooting

### HTTP-01 validation failed

```bash
# 1. Check Nginx config
sudo nginx -t
cat /etc/nginx/sites-enabled/default | grep acme-challenge

# 2. Check port usage
lsof -i :19000

# 3. Test validation service
curl http://localhost:19000/acme-challenge/test-token

# 4. Check logs
anssl log -f
```

### Permission errors

```bash
# Option 1: Use sudo
sudo anssl daemon -c /opt/anssl/config.yaml

# Option 2: Use user-owned directories
# Update /opt/anssl/config.yaml: ssl.path: "$HOME/nginx/ssl"
anssl daemon -c /opt/anssl/config.yaml
```

### Auto-start on boot (systemd)

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

### RustFS and FeiNiu SSH deployment

RustFS uses `ssl.rustFS.path` as its certificate directory. With no SSH host configured, deployment runs on the deploy client's local machine. After the SSH host, port, username, and authentication fields are set, deployment runs on the remote RustFS host. FeiNiu OS continues to use the built-in deployment method on the client's device when `ssl.feiNiu` is absent, and switches to remote SSH deployment when it is configured.

SSH supports password and private-key authentication; no separate SCP setting is required. `privateKeyPath` must be an absolute path to a key on the deploy client's local filesystem. The private key contents are never written to `config.yaml` or sent to the backend. In private-key mode, `password` may be left empty or used as the sudo password for a non-root user.

```yaml
ssl:
  rustFS:
    path: "/opt/rustfs/tls"
    host: "192.168.1.30"
    port: 22
    username: "admin"
    privateKeyPath: "/home/anssl/.ssh/id_ed25519"
    privateKeyPassphrase: ""
    password: "" # Optional sudo password

  feiNiu:
    host: "192.168.1.20"
    port: 22
    username: "admin"
    password: "your-ssh-password"
```

### SafeLine WAF certificate deployment

Generate an API Token in SafeLine's General Settings, then configure the management URL and token on the deploy client. Connection testing only calls the read-only certificate list endpoint. During deployment, existing certificates are matched by the complete SAN domain set: every exact match is updated, while a new certificate is created when no exact match exists. Partial domain overlap is never used for replacement.

```yaml
ssl:
  safeLine:
    url: "https://waf.example.com:9443"
    apiToken: "your-safeline-api-token"
    insecureSkipVerify: false
```

Keep `insecureSkipVerify` set to `false` by default. Enable it only when the SafeLine management endpoint uses a self-signed HTTPS certificate that you explicitly trust. The API Token remains on the deploy client and is never sent to the ANSSL backend.

## FAQ

**Q: Where can I get `server.accessKey`?**  
A: Log in to [anssl.cn](https://anssl.cn) → Console → Developer → API Credentials.

**Q: Which web servers and panels are supported?**  
A: Nginx, Apache, RustFS, 1Panel, SafeLine WAF, and FeiNiu OS. RustFS supports either a local directory or remote SSH deployment. FeiNiu uses the built-in method on the client's device by default and can also deploy remotely through `ssl.feiNiu`. Both SSH targets support password and private-key authentication.

**Q: Can I deploy to multiple targets at the same time?**  
A: Yes. Configure the required targets in `config.yaml` (`nginxPath`, `apachePath`, `rustFS`, `onePanel`, `safeLine`, and optional remote `feiNiu`) and select the corresponding targets in the anssl.cn console.

**Q: Where can I get the 1Panel API key?**  
A: 1Panel → Settings → Security → API Interface → Generate API Key.

**Q: Where can I get the SafeLine API Token?**
A: SafeLine management console → General Settings → API Token. Store it only in `ssl.safeLine.apiToken` on the deploy client.

**Q: Can certificates be deployed to both local services and cloud providers?**  
A: Yes. In the [anssl.cn](https://anssl.cn) console, you can configure deployment to local CLI targets (Nginx/Apache/RustFS/1Panel/SafeLine WAF/FeiNiu OS) and/or cloud providers (Alibaba Cloud/Qiniu Cloud/Tencent Cloud). Each certificate can have multiple deployment targets.

**Q: Is manual action required for HTTP-01 validation?**  
A: No. Once Nginx reverse proxy is configured, validation is fully automated.

## Development

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Build
go build -o anssl main.go
```

## Links

- Project: [https://github.com/https-cert/deploy](https://github.com/https-cert/deploy)
- Certificate service: [https://anssl.cn](https://anssl.cn)
- Issue tracker: [GitHub Issues](https://github.com/https-cert/deploy/issues)

## License

MIT License
