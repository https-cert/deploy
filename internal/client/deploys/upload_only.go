package deploys

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/https-cert/deploy/pkg/logger"
)

const uploadOnlyDirName = "upload_only"

// UploadOnlyBaseDir 返回“仅上传”业务的本地保存目录。
func UploadOnlyBaseDir() string {
	return filepath.Join(CertsDir, uploadOnlyDirName)
}

// UploadOnlyTargetDir 返回指定域名的“仅上传”保存目录。
func UploadOnlyTargetDir(domain string) string {
	return filepath.Join(UploadOnlyBaseDir(), SanitizeDomain(domain))
}

// DeployToUploadOnly 仅将证书保留到客户端本地目录，不执行额外部署动作。
func (cd *CertDeployer) DeployToUploadOnly(sourceDir, domain string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	targetDir := UploadOnlyTargetDir(domain)

	if _, err := os.Stat(targetDir); err == nil {
		if err := os.RemoveAll(targetDir); err != nil {
			return fmt.Errorf("清理旧的上传目录失败: %w", err)
		}
	}

	if err := CopyDirectory(sourceDir, targetDir); err != nil {
		return fmt.Errorf("保存证书到本地目录失败: %w", err)
	}

	logger.Info("证书已保存到本地上传目录", "domain", domain, "path", targetDir)
	return nil
}

// DeployCertificateToUploadOnly 下载证书并保留到本地目录。
func (cd *CertDeployer) DeployCertificateToUploadOnly(domain, url string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	if err := os.MkdirAll(CertsDir, 0o755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	safeDomain := SanitizeDomain(domain)
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(CertsDir, fileName)

	if err := cd.downloadFunc(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			_ = os.Remove(zipFile)
		}
	}()

	extractDir := filepath.Join(CertsDir, safeDomain)
	if err := ExtractZip(zipFile, extractDir); err != nil {
		_ = os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}
	defer os.RemoveAll(extractDir)

	if err := cd.DeployToUploadOnly(extractDir, domain); err != nil {
		return err
	}

	logger.Info("UploadOnly 证书保存完成", "domain", domain, "path", UploadOnlyTargetDir(domain))
	return nil
}
