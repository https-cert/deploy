package deploys

import (
	"context"
	"fmt"
	"os"

	"github.com/https-cert/deploy/internal/client/deploys/feiniu"
	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	CertsDir        = shared.CertsDir  // CertsDir 是证书临时存储目录。
	FeiNiuFixedPath = feiniu.FixedPath // FeiNiuFixedPath 是飞牛固定部署路径。
)

// Options 注入本地部署配置、下载器和 SSH known_hosts 依赖。
type Options struct {
	// SSL 是一次运行时加载的本地部署配置快照。
	SSL *config.DeployConfig
	// KnownHostsFile 是 SSH 主机密钥记录文件路径。
	KnownHostsFile string
	// DownloadFunc 下载证书归档并遵守调用方 context。
	DownloadFunc func(context.Context, string, string) error
}

// WithRuntime 将运行时配置附加到一次本地部署 operation context。
func WithRuntime(ctx context.Context, runtime *config.Runtime) context.Context {
	return shared.WithRuntime(ctx, runtime)
}

// CertDeployer 证书部署器
type CertDeployer struct {
	downloadFunc func(context.Context, string, string) error // 证书下载函数
	sslConfig    *config.DeployConfig                        // sslConfig 是本次部署使用的只读 SSL 配置。
	knownHosts   string                                      // knownHosts 是本次 SSH 部署使用的 known_hosts 路径。
}

// NewCertDeployer 创建证书部署器。
func NewCertDeployer(options Options) *CertDeployer {
	return &CertDeployer{
		sslConfig:    options.SSL,
		knownHosts:   options.KnownHostsFile,
		downloadFunc: options.DownloadFunc,
	}
}

// ssl 返回显式注入的 SSL 配置快照。
func (cd *CertDeployer) ssl() *config.DeployConfig {
	if cd != nil && cd.sslConfig != nil {
		return cd.sslConfig
	}
	return nil
}

// prepareCertificateArchive validates a domain, downloads its archive and returns a temporary extraction directory.
func (cd *CertDeployer) prepareCertificateArchive(ctx context.Context, domain, downloadURL string) (canonicalDomain, safeDomain, extractDir string, cleanup func(), err error) {
	if err := shared.OperationContextError(ctx); err != nil {
		return "", "", "", nil, err
	}
	canonicalDomain, safeDomain, err = shared.NormalizeDeploymentDomain(domain)
	if err != nil {
		return "", "", "", nil, err
	}
	if cd == nil || cd.downloadFunc == nil {
		return "", "", "", nil, fmt.Errorf("证书下载函数未初始化")
	}
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return "", "", "", nil, fmt.Errorf("创建证书目录失败: %w", err)
	}

	archivePath, err := newTemporaryArchivePath(safeDomain)
	if err != nil {
		return "", "", "", nil, err
	}
	extractDir, err = os.MkdirTemp(CertsDir, "."+safeDomain+"-extract-*")
	if err != nil {
		_ = os.Remove(archivePath)
		return "", "", "", nil, fmt.Errorf("创建临时解压目录失败: %w", err)
	}

	cleanup = func() {
		_ = os.Remove(archivePath)
		_ = os.RemoveAll(extractDir)
	}
	if err := cd.downloadFunc(ctx, downloadURL, archivePath); err != nil {
		cleanup()
		return "", "", "", nil, fmt.Errorf("下载证书失败: %w", err)
	}
	logger.Info("证书下载完成", "file", archivePath)
	if err := shared.ExtractTar(archivePath, extractDir); err != nil {
		cleanup()
		return "", "", "", nil, fmt.Errorf("解压证书失败: %w", err)
	}
	return canonicalDomain, safeDomain, extractDir, cleanup, nil
}

// newTemporaryArchivePath creates a unique archive path below the certificate directory.
func newTemporaryArchivePath(safeDomain string) (string, error) {
	tempFile, err := os.CreateTemp(CertsDir, "."+safeDomain+"-archive-*")
	if err != nil {
		return "", fmt.Errorf("创建临时归档文件失败: %w", err)
	}
	path := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("关闭临时归档文件失败: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("清理临时归档文件失败: %w", err)
	}
	return path, nil
}

// SanitizeDomain returns the filesystem-safe representation of a valid deployment domain.
func SanitizeDomain(domain string) string {
	return shared.SanitizeDomain(domain)
}
