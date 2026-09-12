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
	if provider == deployPB.Provider_PROVIDER_ANSSL_CLI {
		if target, ok := findLocalTarget(deploymentType); ok && target.DeployURL != nil {
			return runLocalTargetDeployURL(ctx, be.newCertDeployer(), deploymentType, domain, downloadURL)
		}
		logger.Warn("不支持的部署类型", "deploymentType", deploymentType)
		return providers.NewDeploymentError(fmt.Sprintf("不支持的部署类型: %s", deploymentType.String()), false, "", nil)
	}

	switch provider {
	case deployPB.Provider_PROVIDER_ALIYUN,
		deployPB.Provider_PROVIDER_QINIU,
		deployPB.Provider_PROVIDER_TENCENT_CLOUD,
		deployPB.Provider_PROVIDER_DOGE_CLOUD,
		deployPB.Provider_PROVIDER_BAIDU_CLOUD,
		deployPB.Provider_PROVIDER_JD_CLOUD,
		deployPB.Provider_PROVIDER_VOLCENGINE,
		deployPB.Provider_PROVIDER_HUAWEI_CLOUD:
		if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_UPLOAD_CERT {
			return providers.NewDeploymentError(fmt.Sprintf("provider %s 不支持部署类型 %s", provider.String(), deploymentType.String()), false, "", nil)
		}
		return be.handleCertificateProvider(ctx, provider, domain, remark, cert, key)

	default:
		logger.Warn("不支持的部署平台", "provider", provider.String())
		return providers.NewDeploymentError(fmt.Sprintf("不支持的部署平台: %s", provider.String()), false, "", nil)
	}
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
	client, err := newProviderClient(be.runtime, provider)
	if err != nil {
		return nil, err
	}
	if client.Uploader == nil {
		return nil, fmt.Errorf("provider %s 不支持证书上传", provider.String())
	}
	return client.Uploader, nil
}
