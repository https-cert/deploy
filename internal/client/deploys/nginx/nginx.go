package nginx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

// Deploy 部署证书到 Nginx 目录并生成配置文件。
func Deploy(sourceDir, nginxPath, folderName, safeDomain string) error {
	return DeployWithContext(context.Background(), sourceDir, nginxPath, folderName, safeDomain)
}

// DeployWithContext 部署证书并将调用方 context 传递给原子发布事务。
func DeployWithContext(ctx context.Context, sourceDir, nginxPath, folderName, safeDomain string) error {
	return deployWithContext(ctx, sourceDir, nginxPath, folderName, safeDomain, false)
}

// DeployAndReloadWithContext 将配置生成、校验和 reload 纳入同一发布事务。
func DeployAndReloadWithContext(ctx context.Context, sourceDir, nginxPath, folderName, safeDomain string) error {
	return deployWithContext(ctx, sourceDir, nginxPath, folderName, safeDomain, true)
}

// deployWithContext 执行 Nginx 目录发布，并可选执行发布后校验与 reload。
func deployWithContext(ctx context.Context, sourceDir, nginxPath, folderName, safeDomain string, reload bool) error {
	if err := shared.ValidateCertificateFiles(sourceDir, safeDomain); err != nil {
		return err
	}

	// 确保SSL目录存在
	if err := os.MkdirAll(nginxPath, 0755); err != nil {
		return fmt.Errorf("创建SSL目录失败: %w", err)
	}

	// 发布目录和生成配置必须作为一个事务处理，避免配置生成失败时覆盖旧证书目录。
	targetDir, err := shared.SafeJoinUnderBase(nginxPath, folderName)
	if err != nil {
		return err
	}
	return shared.PublishDirectoryWithValidationContext(ctx, sourceDir, targetDir, func() error {
		if err := GenerateNginxSSLConfig(nginxPath, folderName, safeDomain); err != nil {
			return fmt.Errorf("生成Nginx SSL配置失败: %w", err)
		}
		logger.Info("证书文件夹已更新", "path", targetDir)
		if reload && IsNginxAvailable() {
			if err := TestNginxConfigWithContext(ctx); err != nil {
				return fmt.Errorf("nginx配置测试失败: %w", err)
			}
			if err := ReloadNginxWithContext(ctx); err != nil {
				return fmt.Errorf("nginx重新加载失败: %w", err)
			}
		}
		return nil
	})
}

// GenerateNginxSSLConfig 生成 Nginx SSL 配置文件
func GenerateNginxSSLConfig(nginxPath, folderName, safeDomain string) error {
	if err := shared.ValidateSafeDomainName(safeDomain); err != nil {
		//lint:ignore ST1005 Nginx 是产品名称，错误文本需保持兼容。
		return fmt.Errorf("Nginx 域名无效: %w", err)
	}
	certDir, err := shared.SafeJoinUnderBase(nginxPath, folderName)
	if err != nil {
		return err
	}
	// 配置文件名包含域名，避免多域名冲突
	configFileName := fmt.Sprintf("%s.ssl.conf", safeDomain)
	configFile := filepath.Join(certDir, configFileName)

	// 证书文件路径
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "privateKey.key")

	// 生成配置内容
	configContent := fmt.Sprintf(`# SSL 证书配置 - %s
# 在 server 块中使用 include 引入此文件
# 示例: include %s;

ssl_certificate %s;
ssl_certificate_key %s;

# SSL 协议和加密套件（推荐配置）
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;

# SSL 会话缓存
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
`, safeDomain, configFile, certPath, keyPath)

	// 写入配置文件
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("写入SSL配置文件失败: %w", err)
	}

	logger.Info("Nginx SSL配置文件已生成", configFile)
	logger.Info("使用方法: 在 nginx server块中添加 include", configFile)
	return nil
}

// IsNginxAvailable 检查nginx是否可用
func IsNginxAvailable() bool {
	_, err := exec.LookPath("nginx")
	return err == nil
}

// TestNginxConfig 测试nginx配置
func TestNginxConfig() error {
	return TestNginxConfigWithContext(context.Background())
}

// TestNginxConfigWithContext 使用调用方上下文测试 Nginx 配置。
func TestNginxConfigWithContext(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}

	return nil
}

// ReloadNginx 重新加载nginx
func ReloadNginx() error {
	return ReloadNginxWithContext(context.Background())
}

// ReloadNginxWithContext 使用调用方上下文重新加载 Nginx。
func ReloadNginxWithContext(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}

	logger.Info("nginx重新加载成功")
	return nil
}
