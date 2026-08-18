package deploys

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/https-cert/deploy/internal/client/deploys/apache"
	"github.com/https-cert/deploy/internal/client/deploys/btpanel"
	"github.com/https-cert/deploy/internal/client/deploys/feiniu"
	"github.com/https-cert/deploy/internal/client/deploys/nginx"
	"github.com/https-cert/deploy/internal/client/deploys/onepanel"
	"github.com/https-cert/deploy/internal/client/deploys/openvpnas"
	"github.com/https-cert/deploy/internal/client/deploys/rustfs"
	"github.com/https-cert/deploy/internal/client/deploys/safeline"
	"github.com/https-cert/deploy/internal/client/deploys/shared"
	"github.com/https-cert/deploy/internal/client/deploys/uploadonly"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

// OnePanelAPIResponse 是 1Panel API 通用响应的兼容别名。
type OnePanelAPIResponse = onepanel.OnePanelAPIResponse

// OnePanelWebsiteResource 是 1Panel 网站资源的兼容别名。
type OnePanelWebsiteResource = onepanel.OnePanelWebsiteResource

// BTPanelWebsiteResource 是宝塔网站资源的兼容别名。
type BTPanelWebsiteResource = btpanel.BTPanelWebsiteResource

// NormalizeDeploymentDomain 校验部署域名并返回规范域名和安全目录名。
func NormalizeDeploymentDomain(domain string) (string, string, error) {
	return shared.NormalizeDeploymentDomain(domain)
}

// ValidateSafeDomainName 校验已经规范化的安全目录名。
func ValidateSafeDomainName(safeName string) error {
	return shared.ValidateSafeDomainName(safeName)
}

// SafeJoinUnderBase 拼接路径并保证结果仍位于基础目录内。
func SafeJoinUnderBase(baseDir string, pathElements ...string) (string, error) {
	return shared.SafeJoinUnderBase(baseDir, pathElements...)
}

// ExtractTar 安全解压 tar、tar.gz 或 zip 证书归档。
func ExtractTar(archiveFile, extractDir string) error {
	return shared.ExtractTar(archiveFile, extractDir)
}

// ValidateCertificateFiles 校验证书、私钥、有效期和域名覆盖关系。
func ValidateCertificateFiles(sourceDir, domain string) error {
	return shared.ValidateCertificateFiles(sourceDir, domain)
}

// CopyDirectory 复制目录树并拒绝符号链接。
func CopyDirectory(sourceDir, targetDir string) error {
	return shared.CopyDirectory(sourceDir, targetDir)
}

// PublishDirectoryWithRollback 原子发布目录并在失败时恢复旧目录。
func PublishDirectoryWithRollback(sourceDir, targetDir string) error {
	return shared.PublishDirectoryWithRollback(sourceDir, targetDir)
}

// CopyFileWithMode 复制普通文件并设置目标权限。
func CopyFileWithMode(sourceFile, targetFile string, mode fs.FileMode) error {
	return shared.CopyFileWithMode(sourceFile, targetFile, mode)
}

// IsCrossDeviceError 判断错误是否表示跨文件系统重命名失败。
func IsCrossDeviceError(err error) bool {
	return shared.IsCrossDeviceError(err)
}

// DeployToNginx 部署证书到 Nginx 目录并生成配置文件。
func (cd *CertDeployer) DeployToNginx(sourceDir, nginxPath, folderName, safeDomain string) error {
	return nginx.Deploy(sourceDir, nginxPath, folderName, safeDomain)
}

// DeployCertificateToNginx 下载证书并仅部署到 Nginx。
func (cd *CertDeployer) DeployCertificateToNginx(ctx context.Context, domain, downloadURL string) error {
	sslConfig := cd.ssl()
	if sslConfig == nil {
		return fmt.Errorf("SSL 配置未初始化")
	}
	if sslConfig.NginxPath == "" {
		return fmt.Errorf("未配置 Nginx SSL 目录 (ssl.nginxPath)")
	}
	canonicalDomain, safeDomain, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := nginx.Deploy(extractDir, sslConfig.NginxPath, safeDomain, safeDomain); err != nil {
		return fmt.Errorf("部署到Nginx失败: %w", err)
	}
	if nginx.IsNginxAvailable() {
		if err := nginx.TestNginxConfigWithContext(ctx); err != nil {
			logger.Warn("nginx配置测试失败", "error", err)
		} else if err := nginx.ReloadNginxWithContext(ctx); err != nil {
			logger.Warn("nginx重新加载失败，请手动重启nginx", "error", err)
		}
	} else {
		logger.Info("nginx未安装或不在PATH中，跳过nginx相关操作")
	}
	logger.Info("Nginx证书部署完成", "domain", canonicalDomain)
	return nil
}

// GenerateNginxSSLConfig 生成 Nginx SSL 配置文件。
func GenerateNginxSSLConfig(nginxPath, folderName, safeDomain string) error {
	return nginx.GenerateNginxSSLConfig(nginxPath, folderName, safeDomain)
}

// IsNginxAvailable 返回本机是否可以找到 nginx 命令。
func IsNginxAvailable() bool { return nginx.IsNginxAvailable() }

// TestNginxConfig 使用兼容入口测试 Nginx 配置。
func TestNginxConfig() error { return nginx.TestNginxConfig() }

// TestNginxConfigWithContext 使用调用方 context 测试 Nginx 配置。
func TestNginxConfigWithContext(ctx context.Context) error {
	return nginx.TestNginxConfigWithContext(ctx)
}

// ReloadNginx 使用兼容入口重新加载 Nginx。
func ReloadNginx() error { return nginx.ReloadNginx() }

// ReloadNginxWithContext 使用调用方 context 重新加载 Nginx。
func ReloadNginxWithContext(ctx context.Context) error {
	return nginx.ReloadNginxWithContext(ctx)
}

// DeployToApache 部署证书到 Apache 目录并生成配置文件。
func (cd *CertDeployer) DeployToApache(sourceDir, apachePath, folderName, safeDomain string) error {
	return apache.Deploy(sourceDir, apachePath, folderName, safeDomain)
}

// DeployCertificateToApache 下载证书并仅部署到 Apache。
func (cd *CertDeployer) DeployCertificateToApache(ctx context.Context, domain, downloadURL string) error {
	sslConfig := cd.ssl()
	if sslConfig == nil {
		return fmt.Errorf("SSL 配置未初始化")
	}
	if sslConfig.ApachePath == "" {
		return fmt.Errorf("未配置 Apache SSL 目录 (ssl.apachePath)")
	}
	canonicalDomain, safeDomain, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := apache.Deploy(extractDir, sslConfig.ApachePath, safeDomain, safeDomain); err != nil {
		return fmt.Errorf("部署到Apache失败: %w", err)
	}
	if apache.IsApacheAvailable() {
		if err := apache.TestApacheConfigWithContext(ctx); err != nil {
			logger.Warn("apache配置测试失败", "error", err)
		} else if err := apache.ReloadApacheWithContext(ctx); err != nil {
			logger.Warn("apache重新加载失败，请手动重启apache", "error", err)
		}
	} else {
		logger.Info("apache未安装或不在PATH中，跳过apache相关操作")
	}
	logger.Info("Apache证书部署完成", "domain", canonicalDomain)
	return nil
}

// GenerateApacheSSLConfig 生成 Apache SSL 配置文件。
func GenerateApacheSSLConfig(apachePath, folderName, safeDomain string) error {
	return apache.GenerateApacheSSLConfig(apachePath, folderName, safeDomain)
}

// IsApacheAvailable 返回本机是否可以找到 Apache 控制命令。
func IsApacheAvailable() bool { return apache.IsApacheAvailable() }

// GetApacheCommand 返回本机可用的 Apache 控制命令。
func GetApacheCommand() string { return apache.GetApacheCommand() }

// TestApacheConfig 使用兼容入口测试 Apache 配置。
func TestApacheConfig() error { return apache.TestApacheConfig() }

// TestApacheConfigWithContext 使用调用方 context 测试 Apache 配置。
func TestApacheConfigWithContext(ctx context.Context) error {
	return apache.TestApacheConfigWithContext(ctx)
}

// ReloadApache 使用兼容入口重新加载 Apache。
func ReloadApache() error { return apache.ReloadApache() }

// ReloadApacheWithContext 使用调用方 context 重新加载 Apache。
func ReloadApacheWithContext(ctx context.Context) error {
	return apache.ReloadApacheWithContext(ctx)
}

// IsOnePanelConfigured 返回 operation context 是否包含可用 1Panel 配置。
func IsOnePanelConfigured() bool { return onepanel.IsOnePanelConfigured() }

// IsOnePanelConfiguredWithContext 返回 operation context 是否包含可用 1Panel 配置。
func IsOnePanelConfiguredWithContext(ctx context.Context) bool {
	return onepanel.IsOnePanelConfiguredWithContext(ctx)
}

// IsOnePanelErrorRetryable 判断 1Panel 错误是否适合稍后重试。
func IsOnePanelErrorRetryable(err error) bool { return onepanel.IsOnePanelErrorRetryable(err) }

// DiscoverOnePanelWebsiteResources 发现当前 1Panel 网站资源。
func DiscoverOnePanelWebsiteResources(ctx context.Context) ([]OnePanelWebsiteResource, error) {
	return onepanel.DiscoverOnePanelWebsiteResources(ctx)
}

// TestOnePanelWebsiteConnection 测试精确 1Panel 网站资源。
func TestOnePanelWebsiteConnection(ctx context.Context, targetRef string) error {
	return onepanel.TestOnePanelWebsiteConnection(ctx, targetRef)
}

// DeployCertificateTo1PanelWebsite 部署证书到精确 1Panel 网站资源。
func DeployCertificateTo1PanelWebsite(ctx context.Context, targetRef, certificatePEM, privateKeyPEM string) error {
	return onepanel.DeployCertificateTo1PanelWebsite(ctx, targetRef, certificatePEM, privateKeyPEM)
}

// TestOnePanelConnection 使用兼容入口测试 1Panel 证书库权限。
func TestOnePanelConnection() error { return onepanel.TestOnePanelConnection() }

// TestOnePanelConnectionWithContext 使用调用方 context 测试 1Panel 证书库权限。
func TestOnePanelConnectionWithContext(ctx context.Context) error {
	return onepanel.TestOnePanelConnectionWithContext(ctx)
}

// DeployTo1Panel 上传证书到 1Panel 证书库。
func (cd *CertDeployer) DeployTo1Panel(ctx context.Context, sourceDir, domain string) error {
	return onepanel.DeployToStore(ctx, sourceDir, domain)
}

// DeployCertificateTo1Panel 下载证书并上传到 1Panel 证书库。
func (cd *CertDeployer) DeployCertificateTo1Panel(ctx context.Context, domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := onepanel.DeployToStore(ctx, extractDir, canonicalDomain); err != nil {
		return err
	}
	logger.Info("1Panel 证书库上传完成", "domain", canonicalDomain)
	return nil
}

// IsBTPanelConfigured 返回 operation context 是否包含可用宝塔配置。
func IsBTPanelConfigured() bool { return btpanel.IsBTPanelConfigured() }

// IsBTPanelConfiguredWithContext 返回 operation context 是否包含可用宝塔配置。
func IsBTPanelConfiguredWithContext(ctx context.Context) bool {
	return btpanel.IsBTPanelConfiguredWithContext(ctx)
}

// IsBTPanelErrorRetryable 判断宝塔错误是否适合稍后重试。
func IsBTPanelErrorRetryable(err error) bool { return btpanel.IsBTPanelErrorRetryable(err) }

// DiscoverBTPanelWebsiteResources 发现当前宝塔网站资源。
func DiscoverBTPanelWebsiteResources(ctx context.Context) ([]BTPanelWebsiteResource, error) {
	return btpanel.DiscoverBTPanelWebsiteResources(ctx)
}

// TestBTPanelWebsiteConnection 测试精确宝塔网站资源。
func TestBTPanelWebsiteConnection(ctx context.Context, targetRef string) error {
	return btpanel.TestBTPanelWebsiteConnection(ctx, targetRef)
}

// DeployCertificateToBTPanelWebsite 部署证书到精确宝塔网站资源。
func DeployCertificateToBTPanelWebsite(ctx context.Context, targetRef, certificatePEM, privateKeyPEM string) error {
	return btpanel.DeployCertificateToBTPanelWebsite(ctx, targetRef, certificatePEM, privateKeyPEM)
}

// TestBTPanelCertificateConnection 使用兼容入口测试宝塔证书库权限。
func TestBTPanelCertificateConnection() error { return btpanel.TestBTPanelCertificateConnection() }

// TestBTPanelCertificateConnectionWithContext 使用调用方 context 测试宝塔证书库权限。
func TestBTPanelCertificateConnectionWithContext(ctx context.Context) error {
	return btpanel.TestBTPanelCertificateConnectionWithContext(ctx)
}

// DeployCertificateToBTPanelCertificateStore 上传证书到宝塔证书库。
func DeployCertificateToBTPanelCertificateStore(ctx context.Context, certificatePEM, privateKeyPEM string) error {
	return btpanel.DeployCertificateToBTPanelCertificateStore(ctx, certificatePEM, privateKeyPEM)
}

// DeployCertificateToBTPanelCertificateStoreFromURL 下载证书并上传到宝塔证书库。
func (cd *CertDeployer) DeployCertificateToBTPanelCertificateStoreFromURL(ctx context.Context, domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	certificatePEM, err := os.ReadFile(filepath.Join(extractDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("读取宝塔证书文件失败: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(extractDir, "privateKey.key"))
	if err != nil {
		return fmt.Errorf("读取宝塔私钥文件失败: %w", err)
	}
	if err := btpanel.DeployCertificateToBTPanelCertificateStore(ctx, string(certificatePEM), string(privateKeyPEM)); err != nil {
		return err
	}
	logger.Info("宝塔证书库上传完成", "domain", canonicalDomain)
	return nil
}

// TestFeiNiuConnection 使用兼容入口测试飞牛环境。
func TestFeiNiuConnection() error { return feiniu.TestFeiNiuConnection() }

// TestFeiNiuConnectionWithContext 使用调用方 context 测试飞牛环境。
func TestFeiNiuConnectionWithContext(ctx context.Context) error {
	return feiniu.TestFeiNiuConnectionWithContext(ctx)
}

// TestRemoteFeiNiuConnection 测试飞牛 SSH 环境。
func TestRemoteFeiNiuConnection(sshConfig *config.FeiNiuSSHConfig) error {
	return feiniu.TestRemoteFeiNiuConnection(sshConfig)
}

// DeployToFeiNiu 部署证书到本机飞牛目录。
func (cd *CertDeployer) DeployToFeiNiu(sourceDir, feiNiuPath, domain string) error {
	return feiniu.DeployLocal(sourceDir, feiNiuPath, domain)
}

// DeployToFeiNiuWithContext 使用调用方 context 部署证书到本机飞牛目录。
func (cd *CertDeployer) DeployToFeiNiuWithContext(ctx context.Context, sourceDir, feiNiuPath, domain string) error {
	return feiniu.DeployLocalWithContext(ctx, sourceDir, feiNiuPath, domain)
}

// DeployToRemoteFeiNiu 通过 SSH 部署证书到飞牛。
func (cd *CertDeployer) DeployToRemoteFeiNiu(sourceDir, domain string, sshConfig *config.FeiNiuSSHConfig) error {
	return feiniu.DeployRemote(sourceDir, domain, sshConfig, cd.knownHosts)
}

// DeployCertificateToFeiNiu 下载证书并仅部署到飞牛。
func (cd *CertDeployer) DeployCertificateToFeiNiu(ctx context.Context, domain, downloadURL string) error {
	sslConfig := cd.ssl()
	if sslConfig == nil {
		return fmt.Errorf("SSL 配置未初始化")
	}
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if sslConfig.FeiNiu != nil {
		if err := feiniu.DeployRemote(extractDir, canonicalDomain, sslConfig.FeiNiu, cd.knownHosts); err != nil {
			return fmt.Errorf("通过 SSH 部署到飞牛失败: %w", err)
		}
		logger.InfoLocal("飞牛远程证书部署完成", "domain", canonicalDomain, "host", sslConfig.FeiNiu.Host)
		return nil
	}
	if err := feiniu.DeployLocalWithContext(ctx, extractDir, feiniu.FixedPath, canonicalDomain); err != nil {
		return fmt.Errorf("部署到飞牛失败: %w", err)
	}
	logger.Info("飞牛证书部署完成", "domain", canonicalDomain)
	return nil
}

// TestRustFSConnection 使用兼容入口测试 RustFS。
func TestRustFSConnection() error { return rustfs.TestRustFSConnection() }

// TestRustFSConnectionWithContext 使用调用方 context 测试 RustFS。
func TestRustFSConnectionWithContext(ctx context.Context) error {
	return rustfs.TestRustFSConnectionWithContext(ctx)
}

// DeployToRustFS 部署证书到本机 RustFS 目录。
func (cd *CertDeployer) DeployToRustFS(sourceDir, rustFSBasePath, safeDomain string) error {
	return rustfs.DeployLocal(sourceDir, rustFSBasePath, safeDomain)
}

// DeployToRemoteRustFS 通过 SSH 部署证书到 RustFS。
func (cd *CertDeployer) DeployToRemoteRustFS(ctx context.Context, sourceDir, safeDomain string, rustFSConfig *config.RustFSConfig) error {
	return rustfs.DeployRemote(ctx, sourceDir, safeDomain, rustFSConfig, cd.knownHosts)
}

// DeployCertificateToRustFS 下载证书并仅部署到 RustFS。
func (cd *CertDeployer) DeployCertificateToRustFS(ctx context.Context, domain, downloadURL string) error {
	sslConfig := cd.ssl()
	if sslConfig == nil {
		return fmt.Errorf("SSL 配置未初始化")
	}
	rustFSConfig := sslConfig.RustFS
	if rustFSConfig == nil || rustFSConfig.Path == "" {
		return fmt.Errorf("未配置 RustFS TLS 目录 (ssl.rustFS.path)")
	}
	canonicalDomain, safeDomain, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if config.IsSSHConfigured(&rustFSConfig.SSHConfig) {
		err = rustfs.DeployRemote(ctx, extractDir, safeDomain, rustFSConfig, cd.knownHosts)
	} else {
		err = rustfs.DeployLocal(extractDir, rustFSConfig.Path, safeDomain)
	}
	if err != nil {
		return fmt.Errorf("部署到RustFS失败: %w", err)
	}
	logger.Info("RustFS证书部署完成", "domain", canonicalDomain)
	return nil
}

// TestSafeLineConnection 使用兼容入口测试雷池连接。
func TestSafeLineConnection() error { return safeline.TestSafeLineConnection() }

// TestSafeLineConnectionWithContext 使用调用方 context 测试雷池连接。
func TestSafeLineConnectionWithContext(ctx context.Context) error {
	return safeline.TestSafeLineConnectionWithContext(ctx)
}

// DeployToSafeLine 部署证书到雷池。
func (cd *CertDeployer) DeployToSafeLine(ctx context.Context, sourceDir, domain string) error {
	return safeline.Deploy(ctx, sourceDir, domain)
}

// DeployCertificateToSafeLine 下载证书并仅部署到雷池。
func (cd *CertDeployer) DeployCertificateToSafeLine(ctx context.Context, domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := safeline.Deploy(ctx, extractDir, canonicalDomain); err != nil {
		return err
	}
	logger.Info("雷池证书部署完成", "domain", canonicalDomain)
	return nil
}

// DeployToOpenVPNAS 将证书导入 OpenVPN-AS。
func (cd *CertDeployer) DeployToOpenVPNAS(ctx context.Context, sourceDir string) error {
	return openvpnas.Deploy(ctx, sourceDir)
}

// DeployCertificateToOpenVPNAS 下载证书并仅部署到 OpenVPN-AS。
func (cd *CertDeployer) DeployCertificateToOpenVPNAS(ctx context.Context, domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := openvpnas.Deploy(ctx, extractDir); err != nil {
		return err
	}
	logger.Info("OpenVPN-AS 证书上传完成", "domain", canonicalDomain)
	return nil
}

// UploadOnlyBaseDir 返回 UploadOnly 本地保存目录。
func UploadOnlyBaseDir() string { return uploadonly.UploadOnlyBaseDir() }

// UploadOnlyTargetDir 返回指定域名的 UploadOnly 保存目录。
func UploadOnlyTargetDir(domain string) string { return uploadonly.UploadOnlyTargetDir(domain) }

// DeployToUploadOnly 仅将证书保存到本地目录。
func (cd *CertDeployer) DeployToUploadOnly(sourceDir, domain string) error {
	return uploadonly.Deploy(sourceDir, domain)
}

// DeployCertificateToUploadOnly 下载证书并保存到本地目录。
func (cd *CertDeployer) DeployCertificateToUploadOnly(ctx context.Context, domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(ctx, domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := uploadonly.Deploy(extractDir, canonicalDomain); err != nil {
		return err
	}
	logger.Info("UploadOnly 证书保存完成", "domain", canonicalDomain, "path", uploadonly.UploadOnlyTargetDir(canonicalDomain))
	return nil
}
