package apache

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

// Deploy 部署证书到 Apache 目录。
func Deploy(sourceDir, apachePath, folderName, safeDomain string) error {
	return DeployWithContext(context.Background(), sourceDir, apachePath, folderName, safeDomain)
}

// DeployWithContext 部署证书并将调用方 context 传递给原子发布事务。
func DeployWithContext(ctx context.Context, sourceDir, apachePath, folderName, safeDomain string) error {
	return deployWithContext(ctx, sourceDir, apachePath, folderName, safeDomain, false)
}

// DeployAndReloadWithContext 将配置生成、校验和 reload 纳入同一发布事务。
func DeployAndReloadWithContext(ctx context.Context, sourceDir, apachePath, folderName, safeDomain string) error {
	return deployWithContext(ctx, sourceDir, apachePath, folderName, safeDomain, true)
}

// deployWithContext 执行 Apache 目录发布，并可选执行发布后校验与 reload。
func deployWithContext(ctx context.Context, sourceDir, apachePath, folderName, safeDomain string, reload bool) error {
	if err := shared.ValidateCertificateFiles(sourceDir, safeDomain); err != nil {
		return err
	}

	// 复制证书文件到 Apache 目录
	targetDir, err := shared.SafeJoinUnderBase(apachePath, folderName)
	if err != nil {
		return err
	}

	// 发布目录和生成配置必须作为一个事务处理，避免配置生成失败时覆盖旧证书目录。
	if err := shared.PublishDirectoryWithValidationContext(ctx, sourceDir, targetDir, func() error {
		if err := GenerateApacheSSLConfig(apachePath, folderName, safeDomain); err != nil {
			return fmt.Errorf("生成Apache SSL配置失败: %w", err)
		}
		logger.Info("证书已部署到Apache目录", "path", targetDir)
		if reload && IsApacheAvailable() {
			if err := TestApacheConfigWithContext(ctx); err != nil {
				return fmt.Errorf("apache配置测试失败: %w", err)
			}
			if err := ReloadApacheWithContext(ctx); err != nil {
				return fmt.Errorf("apache重新加载失败: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("发布证书到Apache目录失败: %w", err)
	}

	return nil
}

// GenerateApacheSSLConfig 生成 Apache SSL 配置文件
func GenerateApacheSSLConfig(apachePath, folderName, safeDomain string) error {
	if err := shared.ValidateSafeDomainName(safeDomain); err != nil {
		//lint:ignore ST1005 Apache 是产品名称，错误文本需保持兼容。
		return fmt.Errorf("Apache 域名无效: %w", err)
	}
	certDir, err := shared.SafeJoinUnderBase(apachePath, folderName)
	if err != nil {
		return err
	}
	// 配置文件名包含域名，避免多域名冲突
	configFileName := fmt.Sprintf("%s.ssl.conf", safeDomain)
	configFile := filepath.Join(certDir, configFileName)

	// 证书文件路径（使用用户配置的实际路径）
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "privateKey.key")

	// 生成配置内容
	configContent := fmt.Sprintf(`# Apache SSL 证书配置 - %s
# 在 VirtualHost 块中使用 Include 引入此文件
# 示例:
# <VirtualHost *:443>
#     ServerName example.com
#     Include %s
#     # ... 其他配置
# </VirtualHost>

SSLEngine on
SSLCertificateFile %s
SSLCertificateKeyFile %s

# SSL 协议配置（推荐配置）
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1

# SSL 加密套件（推荐配置）
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off

# SSL 会话配置
SSLSessionTickets off
`, safeDomain, configFile, certPath, keyPath)

	// 写入配置文件
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		return fmt.Errorf("写入Apache SSL配置文件失败: %w", err)
	}

	logger.Info("Apache SSL配置文件已生成", configFile)
	logger.Info("使用方法: 在Apache VirtualHost块中添加 include", configFile)
	return nil
}

// IsApacheAvailable 检查apache是否可用
func IsApacheAvailable() bool {
	// 检查常见的 Apache 命令名
	apacheCommands := []string{"apachectl", "apache2ctl", "httpd"}
	for _, cmd := range apacheCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return true
		}
	}
	return false
}

// GetApacheCommand 获取可用的 Apache 控制命令
func GetApacheCommand() string {
	apacheCommands := []string{"apachectl", "apache2ctl", "httpd"}
	for _, cmd := range apacheCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return cmd
		}
	}
	return ""
}

// TestApacheConfig 测试apache配置
func TestApacheConfig() error {
	return TestApacheConfigWithContext(context.Background())
}

// TestApacheConfigWithContext 使用调用方上下文测试 Apache 配置。
func TestApacheConfigWithContext(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	apacheCmd := GetApacheCommand()
	if apacheCmd == "" {
		return fmt.Errorf("未找到Apache控制命令")
	}

	cmd := exec.CommandContext(ctx, apacheCmd, "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}

	return nil
}

// ReloadApache 重新加载apache
func ReloadApache() error {
	return ReloadApacheWithContext(context.Background())
}

// ReloadApacheWithContext 使用调用方上下文重新加载 Apache。
func ReloadApacheWithContext(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	apacheCmd := GetApacheCommand()
	if apacheCmd == "" {
		return fmt.Errorf("未找到Apache控制命令")
	}

	cmd := exec.CommandContext(ctx, apacheCmd, "graceful")
	_, err := cmd.CombinedOutput()
	if err != nil {
		// 某些系统可能使用 reload 而不是 graceful
		cmd = exec.CommandContext(ctx, apacheCmd, "-k", "graceful")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w\n%s", err, string(output))
		}
	}

	logger.Info("apache重新加载成功")
	return nil
}
