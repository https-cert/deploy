package client

import (
	"context"
	"fmt"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// DeploymentExecutor 封装 v2 provider/type 对应的本地和云端部署逻辑。
type DeploymentExecutor struct {
	runtime                           *config.Runtime                             // runtime 是本次客户端使用的只读配置快照。
	downloadFile                      func(context.Context, string, string) error // downloadFile 下载本地部署所需的证书压缩包。
	deploymentResourceProviderFactory deploymentResourceProviderFactory           // deploymentResourceProviderFactory 允许测试替换云厂商适配器构造逻辑。
}

// NewDeploymentExecutor 使用显式运行时快照创建 v2 部署执行器。
func NewDeploymentExecutor(downloadFile func(context.Context, string, string) error, runtime *config.Runtime) *DeploymentExecutor {
	return &DeploymentExecutor{
		runtime:      runtime,
		downloadFile: downloadFile,
	}
}

// newCertDeployer 创建携带运行时 SSL 配置的本地部署器。
func (be *DeploymentExecutor) newCertDeployer() *deploys.CertDeployer {
	options := deploys.Options{DownloadFunc: be.downloadFile}
	if be.runtime != nil && be.runtime.Config != nil {
		options.SSL = be.runtime.Config.SSL
		options.KnownHostsFile = be.runtime.KnownHostsFile
	}
	return deploys.NewCertDeployer(options)
}

// executeNonResourceDeployment 执行不需要动态 targetRef 的 v2 部署类型。
func (be *DeploymentExecutor) executeNonResourceDeployment(ctx context.Context, provider deployPB.Provider, deploymentType deployPB.DeploymentType, domain, downloadURL, remark, cert, key string) error {
	switch provider {
	case deployPB.Provider_PROVIDER_ANSSL_CLI:
		switch deploymentType {
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT:
			// 部署证书到本地 nginx
			return be.handleNginxCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_APACHE_CERT:
			// 部署证书到本地 apache
			return be.handleApacheCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_OPENVPN_AS_CERT:
			// 部署证书到 OpenVPN-AS
			return be.handleOpenVPNASCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_UPLOAD_ONLY_CERT:
			// 仅将证书保存到本地目录
			return be.handleUploadOnlyCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT:
			// 部署证书到本地 RustFS
			return be.handleRustFSCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT:
			// 部署证书到本地 Feiniu
			return be.handleFeiniuCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT:
			// 部署证书到 1Panel
			return be.handle1PanelCertificateDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT:
			// 仅上传证书到宝塔证书库
			return be.handleBTPanelCertificateStoreDeploy(ctx, domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT:
			// 部署证书到雷池 WAF
			return be.handleSafeLineCertificateDeploy(ctx, domain, downloadURL)
		default:
			logger.Warn("不支持的部署类型", "deploymentType", deploymentType)
			return fmt.Errorf("不支持的部署类型: %s", deploymentType.String())
		}

	case deployPB.Provider_PROVIDER_ALIYUN,
		deployPB.Provider_PROVIDER_QINIU,
		deployPB.Provider_PROVIDER_TENCENT_CLOUD,
		deployPB.Provider_PROVIDER_DOGE_CLOUD,
		deployPB.Provider_PROVIDER_BAIDU_CLOUD,
		deployPB.Provider_PROVIDER_JD_CLOUD,
		deployPB.Provider_PROVIDER_VOLCENGINE,
		deployPB.Provider_PROVIDER_HUAWEI_CLOUD:
		if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_UPLOAD_CERT {
			return fmt.Errorf("provider %s 不支持部署类型 %s", provider.String(), deploymentType.String())
		}
		return be.handleCertificateProvider(ctx, provider, domain, remark, cert, key)

	default:
		logger.Warn("不支持的部署平台", "provider", provider.String())
		return fmt.Errorf("不支持的部署平台: %s", provider.String())
	}
}

// handleNginxCertificateDeploy 处理证书部署到本地 nginx
func (be *DeploymentExecutor) handleNginxCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToNginx(ctx, domain, downloadURL); err != nil {
		logger.Error("Nginx证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("Nginx 证书部署成功", "domain", domain)
	return nil
}

// handleApacheCertificateDeploy 处理证书部署到本地 apache
func (be *DeploymentExecutor) handleApacheCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToApache(ctx, domain, downloadURL); err != nil {
		logger.Error("Apache证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("Apache 证书部署成功", "domain", domain)
	return nil
}

// handleOpenVPNASCertificateDeploy 处理证书部署到 OpenVPN-AS
func (be *DeploymentExecutor) handleOpenVPNASCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToOpenVPNAS(ctx, domain, downloadURL); err != nil {
		logger.Error("OpenVPN-AS证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("OpenVPN-AS 证书部署成功", "domain", domain)
	return nil
}

// handleUploadOnlyCertificateDeploy 仅将证书保存到本地目录
func (be *DeploymentExecutor) handleUploadOnlyCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToUploadOnly(ctx, domain, downloadURL); err != nil {
		logger.Error("UploadOnly证书保存失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("UploadOnly 证书保存成功", "domain", domain, "path", deploys.UploadOnlyTargetDir(domain))
	return nil
}

// handleRustFSCertificateDeploy 处理证书部署到本地 RustFS
func (be *DeploymentExecutor) handleRustFSCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToRustFS(ctx, domain, downloadURL); err != nil {
		logger.ErrorLocal("RustFS证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("RustFS 证书部署成功", "domain", domain)
	return nil
}

// handleFeiniuCertificateDeploy 处理证书部署到本地飞牛
func (be *DeploymentExecutor) handleFeiniuCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToFeiNiu(ctx, domain, downloadURL); err != nil {
		logger.ErrorLocal("飞牛证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("飞牛证书部署成功", "domain", domain)
	return nil
}

// handle1PanelCertificateDeploy 处理证书部署到 1Panel
func (be *DeploymentExecutor) handle1PanelCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateTo1Panel(ctx, domain, downloadURL); err != nil {
		logger.ErrorLocal("1Panel证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("1Panel证书部署成功", "domain", domain)
	return nil
}

// handleBTPanelCertificateStoreDeploy 处理证书上传到宝塔证书库。
func (be *DeploymentExecutor) handleBTPanelCertificateStoreDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}
	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToBTPanelCertificateStoreFromURL(ctx, domain, downloadURL); err != nil {
		logger.ErrorLocal("宝塔证书库上传失败", "error", err, "domain", domain)
		return err
	}
	logger.Info("宝塔证书库上传成功", "domain", domain)
	return nil
}

// handleSafeLineCertificateDeploy 处理证书部署到雷池 WAF。
func (be *DeploymentExecutor) handleSafeLineCertificateDeploy(ctx context.Context, domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := be.newCertDeployer()
	if err := deployer.DeployCertificateToSafeLine(ctx, domain, downloadURL); err != nil {
		logger.ErrorLocal("雷池证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("雷池证书部署成功", "domain", domain)
	return nil
}

// handleCertificateProvider 处理证书提供商的上传操作。
func (be *DeploymentExecutor) handleCertificateProvider(ctx context.Context, provider deployPB.Provider, domain, remark, cert, key string) error {
	providerName, ok := config.DeploymentProviderName(provider)
	if !ok {
		return fmt.Errorf("不支持的部署平台: %s", provider.String())
	}
	providerHandler, err := be.getProviderHandler(provider)
	if err != nil {
		logger.ErrorLocal("创建提供商实例失败", "provider", providerName, "error", err)
		return err
	}

	// 上传证书
	if err := providerHandler.UploadCertificate(ctx, providers.CertificateMaterial{Name: remark, Domain: domain, CertificatePEM: cert, PrivateKeyPEM: key}); err != nil {
		logger.ErrorLocal("上传证书失败", "provider", providerName, "error", err)
		return err
	}

	logger.Info("证书上传成功", "provider", providerName, "remark", remark, "domain", domain)
	return nil
}

// getProviderHandler 根据 v2 provider 获取对应的证书上传 handler。
func (be *DeploymentExecutor) getProviderHandler(provider deployPB.Provider) (providers.ProviderHandler, error) {
	handler, err := newConfiguredProvider(be.runtime, provider)
	if err != nil {
		return nil, err
	}
	uploader, ok := handler.(providers.ProviderHandler)
	if !ok {
		return nil, fmt.Errorf("provider %s 不支持证书上传", provider.String())
	}
	return uploader, nil
}
