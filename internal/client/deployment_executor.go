package client

import (
	"fmt"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	"github.com/https-cert/deploy/internal/client/providers/baidu"
	cloud_tencent "github.com/https-cert/deploy/internal/client/providers/cloud_tencent"
	"github.com/https-cert/deploy/internal/client/providers/dogecloud"
	"github.com/https-cert/deploy/internal/client/providers/huawei"
	"github.com/https-cert/deploy/internal/client/providers/jdcloud"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/client/providers/volcengine"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// DeploymentExecutor 封装 v2 provider/type 对应的本地和云端部署逻辑。
type DeploymentExecutor struct {
	downloadFile                      func(downloadURL, filePath string) error // downloadFile 下载本地部署所需的证书压缩包。
	deploymentResourceProviderFactory deploymentResourceProviderFactory        // deploymentResourceProviderFactory 允许测试替换云厂商适配器构造逻辑。
}

// NewDeploymentExecutor 创建 v2 部署执行器。
func NewDeploymentExecutor(downloadFile func(downloadURL, filePath string) error) *DeploymentExecutor {
	return &DeploymentExecutor{
		downloadFile: downloadFile,
	}
}

// executeNonResourceDeployment 执行不需要动态 targetRef 的 v2 部署类型。
func (be *DeploymentExecutor) executeNonResourceDeployment(provider deployPB.Provider, deploymentType deployPB.DeploymentType, domain, downloadURL, remark, cert, key string) error {
	switch provider {
	case deployPB.Provider_PROVIDER_ANSSL_CLI:
		switch deploymentType {
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT:
			// 部署证书到本地 nginx
			return be.handleNginxCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_APACHE_CERT:
			// 部署证书到本地 apache
			return be.handleApacheCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_OPENVPN_AS_CERT:
			// 部署证书到 OpenVPN-AS
			return be.handleOpenVPNASCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_UPLOAD_ONLY_CERT:
			// 仅将证书保存到本地目录
			return be.handleUploadOnlyCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT:
			// 部署证书到本地 RustFS
			return be.handleRustFSCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT:
			// 部署证书到本地 Feiniu
			return be.handleFeiniuCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT:
			// 部署证书到 1Panel
			return be.handle1PanelCertificateDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT:
			// 仅上传证书到宝塔证书库
			return be.handleBTPanelCertificateStoreDeploy(domain, downloadURL)
		case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT:
			// 部署证书到雷池 WAF
			return be.handleSafeLineCertificateDeploy(domain, downloadURL)
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
		return be.handleCertificateProvider(provider, domain, remark, cert, key)

	default:
		logger.Warn("不支持的部署平台", "provider", provider.String())
		return fmt.Errorf("不支持的部署平台: %s", provider.String())
	}
}

// handleNginxCertificateDeploy 处理证书部署到本地 nginx
func (be *DeploymentExecutor) handleNginxCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToNginx(domain, downloadURL); err != nil {
		logger.Error("Nginx证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("Nginx 证书部署成功", "domain", domain)
	return nil
}

// handleApacheCertificateDeploy 处理证书部署到本地 apache
func (be *DeploymentExecutor) handleApacheCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToApache(domain, downloadURL); err != nil {
		logger.Error("Apache证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("Apache 证书部署成功", "domain", domain)
	return nil
}

// handleOpenVPNASCertificateDeploy 处理证书部署到 OpenVPN-AS
func (be *DeploymentExecutor) handleOpenVPNASCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToOpenVPNAS(domain, downloadURL); err != nil {
		logger.Error("OpenVPN-AS证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("OpenVPN-AS 证书部署成功", "domain", domain)
	return nil
}

// handleUploadOnlyCertificateDeploy 仅将证书保存到本地目录
func (be *DeploymentExecutor) handleUploadOnlyCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToUploadOnly(domain, downloadURL); err != nil {
		logger.Error("UploadOnly证书保存失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("UploadOnly 证书保存成功", "domain", domain, "path", deploys.UploadOnlyTargetDir(domain))
	return nil
}

// handleRustFSCertificateDeploy 处理证书部署到本地 RustFS
func (be *DeploymentExecutor) handleRustFSCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToRustFS(domain, downloadURL); err != nil {
		logger.ErrorLocal("RustFS证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("RustFS 证书部署成功", "domain", domain)
	return nil
}

// handleFeiniuCertificateDeploy 处理证书部署到本地飞牛
func (be *DeploymentExecutor) handleFeiniuCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToFeiNiu(domain, downloadURL); err != nil {
		logger.ErrorLocal("飞牛证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("飞牛证书部署成功", "domain", domain)
	return nil
}

// handle1PanelCertificateDeploy 处理证书部署到 1Panel
func (be *DeploymentExecutor) handle1PanelCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateTo1Panel(domain, downloadURL); err != nil {
		logger.ErrorLocal("1Panel证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("1Panel证书部署成功", "domain", domain)
	return nil
}

// handleBTPanelCertificateStoreDeploy 处理证书上传到宝塔证书库。
func (be *DeploymentExecutor) handleBTPanelCertificateStoreDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}
	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToBTPanelCertificateStoreFromURL(domain, downloadURL); err != nil {
		logger.ErrorLocal("宝塔证书库上传失败", "error", err, "domain", domain)
		return err
	}
	logger.Info("宝塔证书库上传成功", "domain", domain)
	return nil
}

// handleSafeLineCertificateDeploy 处理证书部署到雷池 WAF。
func (be *DeploymentExecutor) handleSafeLineCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToSafeLine(domain, downloadURL); err != nil {
		logger.ErrorLocal("雷池证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("雷池证书部署成功", "domain", domain)
	return nil
}

// handleCertificateProvider 处理证书提供商的上传操作。
func (be *DeploymentExecutor) handleCertificateProvider(provider deployPB.Provider, domain, remark, cert, key string) error {
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
	if err := providerHandler.UploadCertificate(remark, domain, cert, key); err != nil {
		logger.ErrorLocal("上传证书失败", "provider", providerName, "error", err)
		return err
	}

	logger.Info("证书上传成功", "provider", providerName, "remark", remark, "domain", domain)
	return nil
}

// getCloudTencentProvider 获取腾讯云 provider
func (be *DeploymentExecutor) getCloudTencentProvider() (*cloud_tencent.Provider, error) {
	providerConfig := config.GetProvider("cloudTencent")
	if providerConfig == nil {
		return nil, fmt.Errorf("未配置【腾讯云】提供商配置")
	}

	secretID := providerConfig.GetSecretId()
	secretKey := providerConfig.GetSecretKey()
	if secretID == "" || secretKey == "" {
		return nil, fmt.Errorf("腾讯云配置不完整: secretId 或 secretKey 为空")
	}

	return cloud_tencent.New(secretID, secretKey), nil
}

// getProviderHandler 根据 v2 provider 获取对应的证书上传 handler。
func (be *DeploymentExecutor) getProviderHandler(provider deployPB.Provider) (providers.ProviderHandler, error) {
	providerName, ok := config.DeploymentProviderName(provider)
	if !ok {
		return nil, fmt.Errorf("不支持的部署平台: %s", provider.String())
	}
	providerConfig := config.GetProvider(providerName)
	if providerConfig == nil {
		return nil, fmt.Errorf("提供商配置不存在: %s", providerName)
	}

	switch provider {
	case deployPB.Provider_PROVIDER_ALIYUN:
		accessKeyID := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("阿里云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return aliyun.New(accessKeyID, accessKeySecret)
	case deployPB.Provider_PROVIDER_QINIU:
		accessKey := providerConfig.GetAccessKey()
		accessSecret := providerConfig.GetAccessSecret()
		if accessKey == "" || accessSecret == "" {
			return nil, fmt.Errorf("七牛云配置不完整: accessKey 或 accessSecret 为空")
		}
		return qiniu.New(accessKey, accessSecret), nil
	case deployPB.Provider_PROVIDER_TENCENT_CLOUD:
		return be.getCloudTencentProvider()
	case deployPB.Provider_PROVIDER_DOGE_CLOUD:
		accessKey := providerConfig.GetAccessKey()
		accessSecret := providerConfig.GetAccessSecret()
		if accessKey == "" || accessSecret == "" {
			return nil, fmt.Errorf("多吉云配置不完整: accessKey 或 accessSecret 为空")
		}
		return dogecloud.New(accessKey, accessSecret), nil
	case deployPB.Provider_PROVIDER_BAIDU_CLOUD:
		accessKeyID := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("百度云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return baidu.New(accessKeyID, accessKeySecret)
	case deployPB.Provider_PROVIDER_JD_CLOUD:
		accessKeyID := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("京东云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return jdcloud.New(accessKeyID, accessKeySecret), nil
	case deployPB.Provider_PROVIDER_VOLCENGINE:
		accessKeyID := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("火山引擎配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return volcengine.NewConfigured(accessKeyID, accessKeySecret, providerConfig.Region, providerConfig.CertificateRegion, providerConfig.Regions)
	case deployPB.Provider_PROVIDER_HUAWEI_CLOUD:
		accessKeyID := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyID == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("华为云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return huawei.New(accessKeyID, accessKeySecret, providerConfig.Region, providerConfig.CertificateRegion, providerConfig.Regions)

	default:
		return nil, fmt.Errorf("不支持的部署平台: %s", provider.String())
	}
}
