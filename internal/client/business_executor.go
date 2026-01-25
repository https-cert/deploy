package client

import (
	"fmt"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// BusinessExecutor 业务执行器，封装可复用的业务逻辑
type BusinessExecutor struct {
	downloadFile func(downloadURL, filePath string) error
}

// NewBusinessExecutor 创建业务执行器
func NewBusinessExecutor(downloadFile func(downloadURL, filePath string) error) *BusinessExecutor {
	return &BusinessExecutor{
		downloadFile: downloadFile,
	}
}

// ExecuteBusiness 执行业务（根据提供商和业务类型）
func (be *BusinessExecutor) ExecuteBusiness(providerName string, executeBusinesType deployPB.ExecuteBusinesType, domain, downloadURL, remark, cert, key string) error {
	switch providerName {
	case "ansslCli":
		// 根据业务类型选择部署方式
		switch executeBusinesType {
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_CERT:
			// 部署证书到本地 nginx
			return be.handleNginxCertificateDeploy(domain, downloadURL)
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_APACHE_CERT:
			// 部署证书到本地 apache
			return be.handleApacheCertificateDeploy(domain, downloadURL)
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_RUSTFS_CERT:
			// 部署证书到本地 RustFS
			return be.handleRustFSCertificateDeploy(domain, downloadURL)
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_FEINIU_CERT:
			// 部署证书到本地 Feiniu
			return be.handleFeiniuCertificateDeploy(domain, downloadURL)
		case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_1PANEL_CERT:
			// 部署证书到 1Panel
			return be.handle1PanelCertificateDeploy(domain, downloadURL)
		default:
			logger.Warn("不支持的业务类型", "executeBusinesType", executeBusinesType)
			return fmt.Errorf("不支持的业务类型: %d", executeBusinesType)
		}

	case "aliyun", "qiniu":
		// 上传证书到云服务商
		if executeBusinesType != deployPB.ExecuteBusinesType_EXECUTE_BUSINES_UPLOAD_CERT {
			return fmt.Errorf("不支持的业务类型: %d", executeBusinesType)
		}
		return be.handleCertificateProvider(providerName, remark, cert, key)

	default:
		logger.Warn("不支持的提供商", "provider", providerName)
		return fmt.Errorf("不支持的提供商: %s", providerName)
	}
}

// handleNginxCertificateDeploy 处理证书部署到本地 nginx
func (be *BusinessExecutor) handleNginxCertificateDeploy(domain, downloadURL string) error {
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
func (be *BusinessExecutor) handleApacheCertificateDeploy(domain, downloadURL string) error {
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

// handleRustFSCertificateDeploy 处理证书部署到本地 RustFS
func (be *BusinessExecutor) handleRustFSCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToRustFS(domain, downloadURL); err != nil {
		logger.Error("RustFS证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("RustFS 证书部署成功", "domain", domain)
	return nil
}

// handleFeiniuCertificateDeploy 处理证书部署到本地飞牛
func (be *BusinessExecutor) handleFeiniuCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateToFeiNiu(domain, downloadURL); err != nil {
		logger.Error("飞牛证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("飞牛证书部署成功", "domain", domain)
	return nil
}

// handle1PanelCertificateDeploy 处理证书部署到 1Panel
func (be *BusinessExecutor) handle1PanelCertificateDeploy(domain, downloadURL string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	deployer := deploys.NewCertDeployer(be.downloadFile)
	if err := deployer.DeployCertificateTo1Panel(domain, downloadURL); err != nil {
		logger.Error("1Panel证书部署失败", "error", err, "domain", domain)
		return err
	}

	logger.Info("1Panel证书部署成功", "domain", domain)
	return nil
}

// handleCertificateProvider 处理证书提供商的上传操作
func (be *BusinessExecutor) handleCertificateProvider(providerName, remark, cert, key string) error {
	// 获取 provider 实例
	providerHandler, err := be.getProviderHandler(providerName)
	if err != nil {
		logger.Error("创建提供商实例失败", "provider", providerName, "error", err)
		return err
	}

	// 上传证书
	if err := providerHandler.UploadCertificate(remark, cert, key); err != nil {
		logger.Error("上传证书失败", "provider", providerName, "error", err)
		return err
	}

	logger.Info("证书上传成功", "provider", providerName, "remark", remark)
	return nil
}

// getProviderHandler 根据提供商名称获取对应的 handler
func (be *BusinessExecutor) getProviderHandler(providerName string) (providers.ProviderHandler, error) {
	providerConfig := config.GetProvider(providerName)
	if providerConfig == nil {
		return nil, fmt.Errorf("提供商配置不存在: %s", providerName)
	}

	switch providerName {
	case "aliyun":
		accessKeyId := providerConfig.GetAccessKeyId()
		accessKeySecret := providerConfig.GetAccessKeySecret()
		if accessKeyId == "" || accessKeySecret == "" {
			return nil, fmt.Errorf("阿里云配置不完整: accessKeyId 或 accessKeySecret 为空")
		}
		return aliyun.New(accessKeyId, accessKeySecret)

	case "qiniu":
		accessKey := providerConfig.GetAccessKey()
		accessSecret := providerConfig.GetAccessSecret()
		if accessKey == "" || accessSecret == "" {
			return nil, fmt.Errorf("七牛云配置不完整: accessKey 或 accessSecret 为空")
		}
		return qiniu.New(accessKey, accessSecret), nil

	default:
		return nil, fmt.Errorf("不支持的提供商: %s", providerName)
	}
}
