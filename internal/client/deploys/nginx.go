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

// DeployToNginx 部署证书到 Nginx 目录并生成配置文件
func (cd *CertDeployer) DeployToNginx(sourceDir, nginxPath, folderName, safeDomain string) error {
	// 移动证书文件
	if err := moveCertificates(sourceDir, nginxPath, folderName); err != nil {
		return err
	}

	// 生成 Nginx SSL 配置文件
	if err := GenerateNginxSSLConfig(nginxPath, folderName, safeDomain); err != nil {
		return fmt.Errorf("生成Nginx SSL配置失败: %w", err)
	}

	return nil
}

// DeployCertificateToNginx 仅部署证书到 Nginx
func (cd *CertDeployer) DeployCertificateToNginx(domain, url string) error {
	sslConfig := config.GetConfig().SSL
	nginxPath := sslConfig.NginxPath

	if nginxPath == "" {
		return fmt.Errorf("未配置 Nginx SSL 目录 (ssl.nginxPath)")
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

	folderName := safeDomain
	extractDir := filepath.Join(CertsDir, folderName)

	if err := ExtractZip(zipFile, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 部署到 Nginx 目录
	if err := cd.DeployToNginx(extractDir, nginxPath, folderName, safeDomain); err != nil {
		return fmt.Errorf("部署到Nginx失败: %w", err)
	}

	// 重新加载 nginx
	if IsNginxAvailable() {
		if err := TestNginxConfig(); err != nil {
			logger.Warn("nginx配置测试失败", "error", err)
		} else {
			if err := ReloadNginx(); err != nil {
				logger.Warn("nginx重新加载失败，请手动重启nginx", "error", err)
			}
		}
	} else {
		logger.Info("nginx未安装或不在PATH中，跳过nginx相关操作")
	}

	logger.Info("Nginx证书部署完成", "domain", domain)
	return nil
}

// GenerateNginxSSLConfig 生成 Nginx SSL 配置文件
func GenerateNginxSSLConfig(nginxPath, folderName, safeDomain string) error {
	certDir := filepath.Join(nginxPath, folderName)
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

// moveCertificates 移动证书文件夹到SSL目录
func moveCertificates(sourceDir, sslPath, folderName string) error {
	// 确保SSL目录存在
	if err := os.MkdirAll(sslPath, 0755); err != nil {
		return fmt.Errorf("创建SSL目录失败: %w", err)
	}

	// 构建目标路径
	targetDir := filepath.Join(sslPath, folderName)

	// 如果目标目录已存在，直接删除
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("删除现有目录失败: %w", err)
		}
	}

	// 移动新证书到目标位置（跨磁盘时回退到复制）
	if err := os.Rename(sourceDir, targetDir); err != nil {
		if !IsCrossDeviceError(err) {
			return fmt.Errorf("移动证书文件夹失败: %w", err)
		}

		if err := CopyDirectory(sourceDir, targetDir); err != nil {
			return fmt.Errorf("复制证书文件夹失败: %w", err)
		}
		if err := os.RemoveAll(sourceDir); err != nil {
			return fmt.Errorf("清理解压目录失败: %w", err)
		}
	}

	logger.Info("证书文件夹已更新", "path", targetDir)
	return nil
}

// IsNginxAvailable 检查nginx是否可用
func IsNginxAvailable() bool {
	_, err := exec.LookPath("nginx")
	return err == nil
}

// TestNginxConfig 测试nginx配置
func TestNginxConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-s", "reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}

	logger.Info("nginx重新加载成功")
	return nil
}
