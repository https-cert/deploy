package deploys

import (
	"fmt"
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
	_, safeDomain, err := NormalizeDeploymentDomain(domain)
	if err != nil {
		return ""
	}
	_, err = SafeJoinUnderBase(UploadOnlyBaseDir(), safeDomain)
	if err != nil {
		return ""
	}
	return filepath.Join(UploadOnlyBaseDir(), safeDomain)
}

// DeployToUploadOnly 仅将证书保留到客户端本地目录，不执行额外部署动作。
func (cd *CertDeployer) DeployToUploadOnly(sourceDir, domain string) error {
	canonicalDomain, _, err := NormalizeDeploymentDomain(domain)
	if err != nil {
		return err
	}
	if err := ValidateCertificateFiles(sourceDir, canonicalDomain); err != nil {
		return err
	}

	targetDir := UploadOnlyTargetDir(canonicalDomain)
	if targetDir == "" {
		return fmt.Errorf("生成 UploadOnly 目标目录失败")
	}

	if err := PublishDirectoryWithRollback(sourceDir, targetDir); err != nil {
		return fmt.Errorf("保存证书到本地目录失败: %w", err)
	}

	logger.Info("证书已保存到本地上传目录", "domain", canonicalDomain, "path", targetDir)
	return nil
}

// DeployCertificateToUploadOnly 下载证书并保留到本地目录。
func (cd *CertDeployer) DeployCertificateToUploadOnly(domain, url string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, url)
	if err != nil {
		return err
	}
	defer cleanup()
	domain = canonicalDomain

	if err := cd.DeployToUploadOnly(extractDir, domain); err != nil {
		return err
	}

	logger.Info("UploadOnly 证书保存完成", "domain", domain, "path", UploadOnlyTargetDir(domain))
	return nil
}
