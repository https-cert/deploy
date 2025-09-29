# 证书自动部署 CLI 工具

## 配置

### 配置文件

创建配置文件 `config.yaml`:

```yaml
server:
  # 在 设置-->个人资料 中找到
  accessKey: ""

ssl:
  # 证书存储根目录，不配置默认放在【与程序同级目录/certs】
  path: "/etc/nginx/ssl"
```

## 使用方法

### 基本命令

```bash
./cert-deploy --help      # 显示帮助信息

./cert-deploy daemon      # 启动守护进程（后台运行）
./cert-deploy log         # 查看守护进程日志，-f 实时跟踪日志输出
./cert-deploy restart     # 重启守护进程
./cert-deploy start       # 启动守护进程（前台运行）
./cert-deploy status      # 查看守护进程状态
./cert-deploy stop        # 停止守护进程
```

## 许可证

MIT License
