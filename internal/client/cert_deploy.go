package client

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	certsDir = "certs"
)

// sanitizeDomain 处理泛域名，将 * 转换为 _
func sanitizeDomain(domain string) string {
	return strings.ReplaceAll(domain, "*", "_")
}

// CertDeployer 证书部署器
type CertDeployer struct {
	client *Client
}

// NewCertDeployer 创建证书部署器
func NewCertDeployer(client *Client) *CertDeployer {
	return &CertDeployer{
		client: client,
	}
}

// DeployCertificate 部署证书（同时部署到 Nginx 和 Apache，根据配置）
func (cd *CertDeployer) DeployCertificate(domain, url string) error {
	// 创建certs目录
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 处理泛域名，将 * 转换为 _
	safeDomain := sanitizeDomain(domain)

	// 文件名格式为 {domain}_certificates.zip
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(certsDir, fileName)

	// 下载zip文件
	if err := cd.client.downloadFile(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	// 确保下载失败时清理
	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			// 部署成功后删除zip文件
			os.Remove(zipFile)
		}
	}()

	// 检查是否配置了SSL目录
	sslConfig := config.GetConfig().SSL
	nginxPath := sslConfig.NginxPath
	apachePath := sslConfig.ApachePath

	if nginxPath == "" && apachePath == "" {
		logger.Info("未配置SSL目录，证书已下载", "file", zipFile)
		return nil
	}

	// 证书文件夹名（使用处理后的安全域名）
	folderName := safeDomain + "_certificates"
	extractDir := filepath.Join(certsDir, folderName)

	// 1. 解压zip文件
	if err := cd.extractZip(zipFile, extractDir); err != nil {
		// 清理失败的解压文件
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}

	// 确保解压目录在部署完成后被清理
	defer os.RemoveAll(extractDir)

	// 2. 部署到 Nginx 目录
	if nginxPath != "" {
		if err := cd.deployToNginx(extractDir, nginxPath, folderName, safeDomain); err != nil {
			return fmt.Errorf("部署到Nginx失败: %w", err)
		}
	}

	// 3. 部署到 Apache 目录
	if apachePath != "" {
		if err := cd.deployToApache(extractDir, apachePath, folderName, safeDomain); err != nil {
			return fmt.Errorf("部署到Apache失败: %w", err)
		}
	}

	// 4. 检查nginx是否存在，如果存在则测试配置和重新加载
	if nginxPath != "" && cd.isNginxAvailable() {
		// 测试nginx配置
		if err := cd.testNginxConfig(); err != nil {
			logger.Warn("nginx配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := cd.reloadNginx(); err != nil {
				logger.Warn("nginx重新加载失败，请手动重启nginx", "error", err)
			}
		}
	} else if nginxPath != "" {
		logger.Info("nginx未安装或不在PATH中，跳过nginx相关操作")
	}

	// 5. 检查apache是否存在，如果存在则测试配置和重新加载
	if apachePath != "" && cd.isApacheAvailable() {
		// 测试apache配置
		if err := cd.testApacheConfig(); err != nil {
			logger.Warn("apache配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := cd.reloadApache(); err != nil {
				logger.Warn("apache重新加载失败，请手动重启apache", "error", err)
			}
		}
	} else if apachePath != "" {
		logger.Info("apache未安装或不在PATH中，跳过apache相关操作")
	}

	logger.Info("自动部署流程完成", "domain", domain)
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
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	safeDomain := sanitizeDomain(domain)
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(certsDir, fileName)

	// 下载zip文件
	if err := cd.client.downloadFile(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			os.Remove(zipFile)
		}
	}()

	folderName := safeDomain + "_certificates"
	extractDir := filepath.Join(certsDir, folderName)

	if err := cd.extractZip(zipFile, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 部署到 Nginx 目录
	if err := cd.deployToNginx(extractDir, nginxPath, folderName, safeDomain); err != nil {
		return fmt.Errorf("部署到Nginx失败: %w", err)
	}

	// 重新加载 nginx
	if cd.isNginxAvailable() {
		if err := cd.testNginxConfig(); err != nil {
			logger.Warn("nginx配置测试失败", "error", err)
		} else {
			if err := cd.reloadNginx(); err != nil {
				logger.Warn("nginx重新加载失败，请手动重启nginx", "error", err)
			}
		}
	} else {
		logger.Info("nginx未安装或不在PATH中，跳过nginx相关操作")
	}

	logger.Info("Nginx证书部署完成", "domain", domain)
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
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	safeDomain := sanitizeDomain(domain)
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(certsDir, fileName)

	// 下载zip文件
	if err := cd.client.downloadFile(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			os.Remove(zipFile)
		}
	}()

	folderName := safeDomain + "_certificates"
	extractDir := filepath.Join(certsDir, folderName)

	if err := cd.extractZip(zipFile, extractDir); err != nil {
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	// 部署到 Apache 目录
	if err := cd.deployToApache(extractDir, apachePath, folderName, safeDomain); err != nil {
		return fmt.Errorf("部署到Apache失败: %w", err)
	}

	// 重新加载 apache
	if cd.isApacheAvailable() {
		// 测试apache配置
		if err := cd.testApacheConfig(); err != nil {
			logger.Warn("apache配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := cd.reloadApache(); err != nil {
				logger.Warn("apache重新加载失败，请手动重启apache", "error", err)
			}
		}
	} else {
		logger.Info("apache未安装或不在PATH中，跳过apache相关操作")
	}

	logger.Info("Apache证书部署完成", "domain", domain)
	return nil
}

// deployToNginx 部署证书到 Nginx 目录并生成配置文件
func (cd *CertDeployer) deployToNginx(sourceDir, nginxPath, folderName, safeDomain string) error {
	// 移动证书文件
	if err := cd.moveCertificates(sourceDir, nginxPath, folderName); err != nil {
		return err
	}

	// 生成 Nginx SSL 配置文件
	if err := cd.generateNginxSSLConfig(nginxPath, folderName, safeDomain); err != nil {
		return fmt.Errorf("生成Nginx SSL配置失败: %w", err)
	}

	return nil
}

// deployToApache 部署证书到 Apache 目录
func (cd *CertDeployer) deployToApache(sourceDir, apachePath, folderName, safeDomain string) error {
	// 复制证书文件到 Apache 目录
	targetDir := filepath.Join(apachePath, folderName)

	// 如果目标目录已存在，先删除
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("删除现有Apache证书目录失败: %w", err)
		}
	}

	// 复制证书文件
	if err := copyDirectory(sourceDir, targetDir); err != nil {
		return fmt.Errorf("复制证书到Apache目录失败: %w", err)
	}

	logger.Info("证书已部署到Apache目录", "path", targetDir)

	// 生成 Apache SSL 配置文件
	if err := cd.generateApacheSSLConfig(apachePath, folderName, safeDomain); err != nil {
		return fmt.Errorf("生成Apache SSL配置失败: %w", err)
	}

	return nil
}

// generateNginxSSLConfig 生成 Nginx SSL 配置文件
func (cd *CertDeployer) generateNginxSSLConfig(nginxPath, folderName, safeDomain string) error {
	certDir := filepath.Join(nginxPath, folderName)
	// 配置文件名包含域名，避免多域名冲突
	configFileName := fmt.Sprintf("%s.ssl.conf", safeDomain)
	configFile := filepath.Join(certDir, configFileName)

	// 证书文件路径
	certPath := filepath.Join(certDir, "fullchain.pem")
	keyPath := filepath.Join(certDir, "privkey.pem")

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

	logger.Info("Nginx SSL配置文件已生成", "file", configFile)
	logger.Info("使用方法: 在nginx server块中添加 include", "path", configFile)
	return nil
}

// generateApacheSSLConfig 生成 Apache SSL 配置文件
func (cd *CertDeployer) generateApacheSSLConfig(apachePath, folderName, safeDomain string) error {
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

// extractZip 解压zip文件（修复：资源泄露）
func (cd *CertDeployer) extractZip(zipFile, extractDir string) error {
	// 创建解压目录
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("创建解压目录失败: %w", err)
	}

	// 打开zip文件
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("打开zip文件失败: %w", err)
	}
	defer reader.Close()

	// 解压所有文件
	for _, file := range reader.File {
		if err := cd.extractZipFile(file, extractDir); err != nil {
			return err
		}
	}

	return nil
}

// extractZipFile 解压单个zip文件条目
func (cd *CertDeployer) extractZipFile(file *zip.File, extractDir string) error {
	// 使用 filepath.Rel 安全地检查路径
	targetPath := filepath.Join(extractDir, file.Name)

	// 清理路径并检查符号链接
	cleanTarget := filepath.Clean(targetPath)
	rel, err := filepath.Rel(extractDir, cleanTarget)
	if err != nil || strings.HasPrefix(rel, "..") || strings.Contains(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("不安全的文件路径: %s", file.Name)
	}

	// 使用清理后的路径
	targetPath = cleanTarget

	// 创建目录
	if file.FileInfo().IsDir() {
		return os.MkdirAll(targetPath, file.FileInfo().Mode())
	}

	// 创建文件目录
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("创建文件目录失败: %w", err)
	}

	// 打开zip文件中的文件
	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("打开zip中的文件失败: %w", err)
	}
	defer rc.Close()

	// 创建目标文件
	outFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer outFile.Close()

	// 复制文件内容
	if _, err := io.Copy(outFile, rc); err != nil {
		return fmt.Errorf("复制文件内容失败: %w", err)
	}

	// 设置文件权限
	if err := os.Chmod(targetPath, file.FileInfo().Mode()); err != nil {
		return fmt.Errorf("设置文件权限失败: %w", err)
	}

	return nil
}

// moveCertificates 移动证书文件夹到SSL目录
func (cd *CertDeployer) moveCertificates(sourceDir, sslPath, folderName string) error {
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
		if !isCrossDeviceError(err) {
			return fmt.Errorf("移动证书文件夹失败: %w", err)
		}

		if err := copyDirectory(sourceDir, targetDir); err != nil {
			return fmt.Errorf("复制证书文件夹失败: %w", err)
		}
		if err := os.RemoveAll(sourceDir); err != nil {
			return fmt.Errorf("清理解压目录失败: %w", err)
		}
	}

	logger.Info("证书文件夹已更新", "path", targetDir)
	return nil
}

// isNginxAvailable 检查nginx是否可用
func (cd *CertDeployer) isNginxAvailable() bool {
	_, err := exec.LookPath("nginx")
	return err == nil
}

// testNginxConfig 测试nginx配置
func (cd *CertDeployer) testNginxConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(output))
	}

	return nil
}

// reloadNginx 重新加载nginx
func (cd *CertDeployer) reloadNginx() error {
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

// testApacheConfig 测试apache配置
func (cd *CertDeployer) testApacheConfig() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apacheCmd := cd.getApacheCommand()
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

// isApacheAvailable 检查apache是否可用
func (cd *CertDeployer) isApacheAvailable() bool {
	// 检查常见的 Apache 命令名
	apacheCommands := []string{"apachectl", "apache2ctl", "httpd"}
	for _, cmd := range apacheCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return true
		}
	}
	return false
}

// getApacheCommand 获取可用的 Apache 控制命令
func (cd *CertDeployer) getApacheCommand() string {
	apacheCommands := []string{"apachectl", "apache2ctl", "httpd"}
	for _, cmd := range apacheCommands {
		if _, err := exec.LookPath(cmd); err == nil {
			return cmd
		}
	}
	return ""
}

// reloadApache 重新加载apache
func (cd *CertDeployer) reloadApache() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	apacheCmd := cd.getApacheCommand()
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

// isCrossDeviceError 检测是否为跨设备移动
func isCrossDeviceError(err error) bool {
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return errors.Is(linkErr.Err, syscall.EXDEV)
	}
	return false
}

// copyDirectory 复制整个目录
func copyDirectory(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)

		info, err := d.Info()
		if err != nil {
			return err
		}

		if d.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}

		return copyFileWithMode(path, targetPath, info.Mode())
	})
}

// copyFileWithMode 复制文件并保持权限
func copyFileWithMode(src, dst string, mode fs.FileMode) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	dest, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return err
	}

	return dest.Sync()
}
