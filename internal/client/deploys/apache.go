package deploys

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// DeployToApache 部署证书到 Apache 目录
func (cd *CertDeployer) DeployToApache(sourceDir, apachePath, folderName, safeDomain string) error {
	// 复制证书文件到 Apache 目录
	targetDir := filepath.Join(apachePath, folderName)

	// 如果目标目录已存在，先删除
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("删除现有Apache证书目录失败: %w", err)
		}
	}

	// 复制证书文件
	if err := CopyDirectory(sourceDir, targetDir); err != nil {
		return fmt.Errorf("复制证书到Apache目录失败: %w", err)
	}

	logger.Info("证书已部署到Apache目录", "path", targetDir)

	// 生成 Apache SSL 配置文件
	if err := GenerateApacheSSLConfig(apachePath, folderName, safeDomain); err != nil {
		return fmt.Errorf("生成Apache SSL配置失败: %w", err)
	}

	return nil
}

// DeployCertificateToApache 仅部署证书到 Apache
func (cd *CertDeployer) DeployCertificateToApache(domain, url string) error {
	sslConfig := config.GetConfig().SSL
	apachePath := sslConfig.ApachePath

	if apachePath == "" {
		return fmt.Errorf("未配置 Apache SSL 目录 (ssl.apachePath)")
	}

	// 创建certs目录
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	safeDomain := SanitizeDomain(domain)
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(CertsDir, fileName)

	// 下载zip文件
	if err := cd.downloadFunc(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			os.Remove(zipFile)
		}
	}()

	folderName := safeDomain + "_certificates"
	extractDir := filepath.Join(CertsDir, folderName)

	if err := ExtractZip(zipFile, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 部署到 Apache 目录
	if err := cd.DeployToApache(extractDir, apachePath, folderName, safeDomain); err != nil {
		return fmt.Errorf("部署到Apache失败: %w", err)
	}

	// 重新加载 apache
	if IsApacheAvailable() {
		// 测试apache配置
		if err := TestApacheConfig(); err != nil {
			logger.Warn("apache配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := ReloadApache(); err != nil {
				logger.Warn("apache重新加载失败，请手动重启apache", "error", err)
			}
		}
	} else {
		logger.Info("apache未安装或不在PATH中，跳过apache相关操作")
	}

	logger.Info("Apache证书部署完成", "domain", domain)
	return nil
}

// GenerateApacheSSLConfig 生成 Apache SSL 配置文件
func GenerateApacheSSLConfig(apachePath, folderName, safeDomain string) error {
	certDir := filepath.Join(apachePath, folderName)
	// 配置文件名包含域名，避免多域名冲突
	configFileName := fmt.Sprintf("%s.ssl.conf", safeDomain)
	configFile := filepath.Join(certDir, configFileName)

	// 证书文件路径（使用用户配置的实际路径）
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

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

	logger.Info("Apache SSL配置文件已生成", "file", configFile)
	logger.Info("使用方法: 在Apache VirtualHost块中添加 Include", "path", configFile)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apacheCmd := GetApacheCommand()
	if apacheCmd == "" {
		return fmt.Errorf("未找到Apache控制命令")
	}

	cmd := exec.CommandContext(ctx, apacheCmd, "graceful")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// 某些系统可能使用 reload 而不是 graceful
		cmd = exec.CommandContext(ctx, apacheCmd, "-k", "graceful")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w\n%s", err, string(output))
		}
	}

	logger.Info("apache重新加载成功")
	return nil
}
