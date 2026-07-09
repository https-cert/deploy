# SSL Certificate Auto-Deploy CLI

[中文说明](README.md)

An automated SSL certificate deployment tool for downloading certificates from [anssl.cn](https://anssl.cn) and deploying them to your servers.

## Features

- 🚀 Automatically deploys certificates to Nginx, Apache, RustFS, and 1Panel, then reloads services
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
5. Certificate is downloaded and deployed to configured services (Nginx/Apache/RustFS/1Panel/FeiNiu OS)
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

## FAQ

**Q: Where can I get `server.accessKey`?**  
A: Log in to [anssl.cn](https://anssl.cn) → Console → Developer → API Credentials.

**Q: Which web servers and panels are supported?**  
A: Nginx, Apache, RustFS, 1Panel, and FeiNiu OS. Configure certificate directories or panel info in `config.yaml`, and deployment runs automatically (with reload for Nginx/Apache).

**Q: Can I deploy to multiple targets at the same time?**  
A: Yes. Configure multiple targets in `config.yaml` (`nginxPath`, `apachePath`, `rustFSPath`, `onePanel`, `feiNiuEnabled`) and updates deploy to all enabled targets.

**Q: Where can I get the 1Panel API key?**  
A: 1Panel → Settings → Security → API Interface → Generate API Key.

**Q: Can certificates be deployed to both local services and cloud providers?**  
A: Yes. In the [anssl.cn](https://anssl.cn) console, you can configure deployment to local CLI targets (Nginx/Apache/RustFS/1Panel/FeiNiu OS) and/or cloud providers (Alibaba Cloud/Qiniu Cloud/Tencent Cloud). Each certificate can have multiple deployment targets.

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
