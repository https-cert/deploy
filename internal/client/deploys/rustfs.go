package deploys

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// DeployToRustFS 部署证书到 RustFS 目录
func (cd *CertDeployer) DeployToRustFS(sourceDir, rustFSPath, safeDomain string) error {
	// RustFS 目标目录（使用域名作为子目录）
	targetDir := filepath.Join(rustFSPath, safeDomain)

	// 如果目标目录已存在，先删除
	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("删除现有RustFS证书目录失败: %w", err)
		}
	}

	// 创建目标目录
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("创建RustFS证书目录失败: %w", err)
	}

	// 复制并重命名证书文件
	// cert.pem -> rustfs_cert.pem
	srcCert := filepath.Join(sourceDir, "cert.pem")
	dstCert := filepath.Join(targetDir, "rustfs_cert.pem")
	if err := CopyFileWithMode(srcCert, dstCert, 0644); err != nil {
		return fmt.Errorf("复制证书文件失败: %w", err)
	}

	// 复制并重命名私钥文件
	// privateKey.key -> rustfs_key.pem
	srcKey := filepath.Join(sourceDir, "privateKey.key")
	dstKey := filepath.Join(targetDir, "rustfs_key.pem")
	if err := CopyFileWithMode(srcKey, dstKey, 0600); err != nil {
		return fmt.Errorf("复制私钥文件失败: %w", err)
	}

	logger.Info("证书已部署到RustFS目录", "path", targetDir, "cert", "rustfs_cert.pem", "key", "rustfs_key.pem")
	return nil
}

// DeployCertificateToRustFS 仅部署证书到 RustFS
func (cd *CertDeployer) DeployCertificateToRustFS(domain, url string) error {
	sslConfig := config.GetConfig().SSL
	rustFSPath := sslConfig.RustFSPath

	if rustFSPath == "" {
		return fmt.Errorf("未配置 RustFS TLS 目录 (ssl.rustFSPath)")
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

	// 部署到 RustFS 目录
	if err := cd.DeployToRustFS(extractDir, rustFSPath, safeDomain); err != nil {
		return fmt.Errorf("部署到RustFS失败: %w", err)
	}

	logger.Info("RustFS证书部署完成", "domain", domain)
	return nil
}
