package uploadonly

import (
	"fmt"
	"path/filepath"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/pkg/logger"
)

const uploadOnlyDirName = "upload_only"

// UploadOnlyBaseDir 返回“仅上传”业务的本地保存目录。
func UploadOnlyBaseDir() string {
	return filepath.Join(shared.CertsDir, uploadOnlyDirName)
}

// UploadOnlyTargetDir 返回指定域名的“仅上传”保存目录。
func UploadOnlyTargetDir(domain string) string {
	_, safeDomain, err := shared.NormalizeDeploymentDomain(domain)
	if err != nil {
		return ""
	}
	_, err = shared.SafeJoinUnderBase(UploadOnlyBaseDir(), safeDomain)
	if err != nil {
		return ""
	}
	return filepath.Join(UploadOnlyBaseDir(), safeDomain)
}

// Deploy 仅将证书保留到客户端本地目录，不执行额外部署动作。
func Deploy(sourceDir, domain string) error {
	canonicalDomain, _, err := shared.NormalizeDeploymentDomain(domain)
	if err != nil {
		return err
	}
	if err := shared.ValidateCertificateFiles(sourceDir, canonicalDomain); err != nil {
		return err
	}

	targetDir := UploadOnlyTargetDir(canonicalDomain)
	if targetDir == "" {
		return fmt.Errorf("生成 UploadOnly 目标目录失败")
	}

	if err := shared.PublishDirectoryWithRollback(sourceDir, targetDir); err != nil {
		return fmt.Errorf("保存证书到本地目录失败: %w", err)
	}

	logger.Info("证书已保存到本地上传目录", "domain", canonicalDomain, "path", targetDir)
	return nil
}
