# 证书自动部署 CLI 工具

## 配置

### 配置文件

创建配置文件 `config.yaml`:

```yaml
# 证书部署配置
server:
  accessKey: ""

# 证书存储配置
ssl:
  # 证书存储根目录
  path: "/etc/nginx/ssl"
```

## 使用方法

### 基本命令

```bash
# 显示帮助信息
cert-deploy --help

# 启动守护进程模式
cert-deploy daemon
```

## 许可证

MIT License
