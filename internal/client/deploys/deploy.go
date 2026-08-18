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

// Deployer 证书部署器接口（为未来扩展预留）
type Deployer interface {
	Deploy(sourceDir, domain string) error
}

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

// NewCertDeployer 创建证书部署器
func NewCertDeployer(download any, options ...Options) *CertDeployer {
	deployer := &CertDeployer{}
	if configured, ok := download.(Options); ok {
		deployer.sslConfig = configured.SSL
		deployer.knownHosts = configured.KnownHostsFile
		deployer.downloadFunc = configured.DownloadFunc
	}
	if len(options) > 0 {
		deployer.sslConfig = options[0].SSL
		deployer.knownHosts = options[0].KnownHostsFile
		deployer.downloadFunc = options[0].DownloadFunc
	}
	if deployer.downloadFunc == nil {
		if downloadFunc, ok := download.(func(context.Context, string, string) error); ok {
			deployer.downloadFunc = downloadFunc
		}
	}
	return deployer
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

// DeployCertificate 部署证书（同时部署到所有配置的目标）
func (cd *CertDeployer) DeployCertificate(ctx context.Context, domain, url string) error {
	if err := shared.OperationContextError(ctx); err != nil {
		return err
	}
	if cd == nil || cd.downloadFunc == nil {
		return fmt.Errorf("证书下载函数未初始化")
	}
	canonicalDomain, safeDomain, err := shared.NormalizeDeploymentDomain(domain)
	if err != nil {
		return err
	}
	domain = canonicalDomain

	// 创建certs目录
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 文件名格式为 {domain}_certificates.tar
	tarFile, err := newTemporaryArchivePath(safeDomain)
	if err != nil {
		return err
	}

	// 下载tar文件
	if err := cd.downloadFunc(ctx, url, tarFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", tarFile)

	// 确保下载失败时清理
	defer func() {
		if _, err := os.Stat(tarFile); err == nil {
			// 部署成功后删除tar文件
			os.Remove(tarFile)
		}
	}()

	// 检查是否配置了SSL目录
	sslConfig := cd.ssl()
	if sslConfig == nil {
		return fmt.Errorf("SSL 配置未初始化")
	}
	nginxPath := sslConfig.NginxPath
	apachePath := sslConfig.ApachePath
	rustFS := sslConfig.RustFS
	onePanelEnabled := sslConfig.OnePanel != nil && sslConfig.OnePanel.URL != ""
	safeLineEnabled := sslConfig.SafeLine != nil && sslConfig.SafeLine.URL != "" && sslConfig.SafeLine.APIToken != ""
	rustFSEnabled := rustFS != nil && rustFS.Path != ""

	if nginxPath == "" && apachePath == "" && !rustFSEnabled && !onePanelEnabled && !safeLineEnabled {
		logger.Info("未配置SSL目录，证书已下载", "file", tarFile)
		return nil
	}

	// 证书文件夹名（使用处理后的安全域名）
	folderName := safeDomain
	extractDir, err := os.MkdirTemp(CertsDir, "."+folderName+"-extract-*")
	if err != nil {
		return err
	}

	// 1. 解压tar文件
	if err := shared.ExtractTar(tarFile, extractDir); err != nil {
		// 清理失败的解压文件
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}

	// 确保解压目录在部署完成后被清理
	defer os.RemoveAll(extractDir)

	// 2. 部署到 Nginx 目录
	if nginxPath != "" {
		if err := cd.DeployToNginx(extractDir, nginxPath, folderName, safeDomain); err != nil {
			return fmt.Errorf("部署到Nginx失败: %w", err)
		}
	}

	// 3. 部署到 Apache 目录
	if apachePath != "" {
		if err := cd.DeployToApache(extractDir, apachePath, folderName, safeDomain); err != nil {
			return fmt.Errorf("部署到Apache失败: %w", err)
		}
	}

	// 4. 部署到 RustFS 目录
	if rustFSEnabled {
		var rustFSErr error
		if config.IsSSHConfigured(&rustFS.SSHConfig) {
			rustFSErr = cd.DeployToRemoteRustFS(ctx, extractDir, safeDomain, rustFS)
		} else {
			rustFSErr = cd.DeployToRustFS(extractDir, rustFS.Path, safeDomain)
		}
		if rustFSErr != nil {
			return fmt.Errorf("部署到RustFS失败: %w", rustFSErr)
		}
	}

	// 5. 部署到 1Panel 目录
	if onePanelEnabled {
		if err := cd.DeployTo1Panel(ctx, extractDir, domain); err != nil {
			return fmt.Errorf("部署到1Panel失败: %w", err)
		}
	}

	// 6. 部署到雷池 WAF
	if safeLineEnabled {
		if err := cd.DeployToSafeLine(ctx, extractDir, domain); err != nil {
			return fmt.Errorf("部署到雷池失败: %w", err)
		}
	}

	// 7. 检查nginx是否存在，如果存在则测试配置和重新加载
	if nginxPath != "" && IsNginxAvailable() {
		// 测试nginx配置
		if err := TestNginxConfigWithContext(ctx); err != nil {
			logger.Warn("nginx配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := ReloadNginxWithContext(ctx); err != nil {
				logger.Warn("nginx重新加载失败，请手动重启nginx", "error", err)
			}
		}
	} else if nginxPath != "" {
		logger.Info("nginx未安装或不在PATH中，跳过nginx相关操作")
	}

	// 8. 检查apache是否存在，如果存在则测试配置和重新加载
	if apachePath != "" && IsApacheAvailable() {
		// 测试apache配置
		if err := TestApacheConfigWithContext(ctx); err != nil {
			logger.Warn("apache配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := ReloadApacheWithContext(ctx); err != nil {
				logger.Warn("apache重新加载失败，请手动重启apache", "error", err)
			}
		}
	} else if apachePath != "" {
		logger.Info("apache未安装或不在PATH中，跳过apache相关操作")
	}

	logger.Info("自动部署流程完成", "domain", domain)
	return nil
}
