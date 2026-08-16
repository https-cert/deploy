package client

import (
	"context"
	"fmt"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers/aliyun"
	cloud_tencent "github.com/https-cert/deploy/internal/client/providers/cloud_tencent"
	"github.com/https-cert/deploy/internal/client/providers/qiniu"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// testFeiNiuConnection 允许单元测试替换真实飞牛环境探测，生产环境始终使用 SSH 或本机检查。
var testFeiNiuConnection = deploys.TestFeiNiuConnection

// testRustFSConnection 允许连接测试使用替身而不触碰真实 RustFS 环境。
var testRustFSConnection = deploys.TestRustFSConnection

// testOnePanelConnection 允许连接测试使用替身而不请求真实 1Panel API。
var testOnePanelConnection = deploys.TestOnePanelConnection

// testOnePanelWebsiteConnection 允许连接测试使用替身而不请求真实 1Panel 网站接口。
var testOnePanelWebsiteConnection = deploys.TestOnePanelWebsiteConnection

// testBTPanelWebsiteConnection 允许连接测试使用替身而不请求真实宝塔网站接口。
var testBTPanelWebsiteConnection = deploys.TestBTPanelWebsiteConnection

// testBTPanelCertificateConnection 允许连接测试使用替身而不请求真实宝塔证书库。
var testBTPanelCertificateConnection = deploys.TestBTPanelCertificateConnection

// testSafeLineConnection 允许连接测试使用替身而不请求真实雷池 OpenAPI。
var testSafeLineConnection = deploys.TestSafeLineConnection

// TestProviderConnection 测试 config.yaml 中的云服务 provider，供 CLI doctor 复用。
func TestProviderConnection(providerName string) (bool, error) {
	provider, ok := config.DeploymentProviderFromName(providerName)
	if !ok {
		return false, fmt.Errorf("未知部署平台: %s", providerName)
	}
	return testDeploymentConnection(context.Background(), provider, deployPB.DeploymentType_DEPLOYMENT_TYPE_UNSPECIFIED, "")
}

// testDeploymentConnection 汇总 v2 provider 凭据测试与本地部署环境测试。
func testDeploymentConnection(ctx context.Context, provider deployPB.Provider, deploymentType deployPB.DeploymentType, targetRef string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	switch provider {
	case deployPB.Provider_PROVIDER_ANSSL_CLI:
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT {
			if err := testFeiNiuConnection(); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT {
			if err := testRustFSConnection(); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT {
			if err := testOnePanelConnection(); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT {
			if err := testOnePanelWebsiteConnection(ctx, targetRef); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT {
			if err := testBTPanelWebsiteConnection(ctx, targetRef); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT {
			if err := testBTPanelCertificateConnection(); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT {
			if err := testSafeLineConnection(); err != nil {
				return false, err
			}
		}
		return true, nil

	case deployPB.Provider_PROVIDER_ALIYUN:
		if config.IsDeploymentResourceType(deploymentType) {
			return testCloudDeploymentResource(ctx, provider, deploymentType, targetRef)
		}
		providerConfig := config.GetProvider(config.ProviderAliyun)
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【阿里云】提供商配置")
		}
		providerClient, err := aliyun.New(providerConfig.GetAccessKeyId(), providerConfig.GetAccessKeySecret())
		if err != nil {
			return false, fmt.Errorf("创建阿里云提供商实例失败: %w", err)
		}
		success, err := providerClient.TestConnection()
		if err != nil {
			return false, fmt.Errorf("阿里云连接测试失败: %w", err)
		}
		return success, nil

	case deployPB.Provider_PROVIDER_TENCENT_CLOUD:
		if config.IsDeploymentResourceType(deploymentType) {
			return testCloudDeploymentResource(ctx, provider, deploymentType, targetRef)
		}
		providerConfig := config.GetProvider(config.ProviderTencentCloud)
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【腾讯云】提供商配置")
		}
		if providerConfig.GetSecretId() == "" || providerConfig.GetSecretKey() == "" {
			return false, fmt.Errorf("腾讯云配置不完整: secretId 或 secretKey 为空")
		}
		providerClient := cloud_tencent.New(providerConfig.GetSecretId(), providerConfig.GetSecretKey())
		success, err := providerClient.TestConnection()
		if err != nil {
			return false, fmt.Errorf("腾讯云连接测试失败: %w", err)
		}
		return success, nil

	case deployPB.Provider_PROVIDER_QINIU:
		if config.IsDeploymentResourceType(deploymentType) {
			return testCloudDeploymentResource(ctx, provider, deploymentType, targetRef)
		}
		providerConfig := config.GetProvider(config.ProviderQiniu)
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【七牛云】提供商配置")
		}
		providerClient := qiniu.New(providerConfig.GetAccessKey(), providerConfig.GetAccessSecret())
		success, err := providerClient.TestConnection()
		if err != nil {
			return false, fmt.Errorf("七牛云连接测试失败: %w", err)
		}
		return success, nil

	default:
		logger.Warn("未知部署平台", "provider", provider.String())
		return false, fmt.Errorf("未知部署平台: %s", provider.String())
	}
}

// testCloudDeploymentResource 只读测试当前 v2 selector 指向的动态云资源。
func testCloudDeploymentResource(ctx context.Context, provider deployPB.Provider, deploymentType deployPB.DeploymentType, targetRef string) (bool, error) {
	if targetRef == "" {
		return false, fmt.Errorf("动态资源部署类型的 targetRef 不能为空")
	}
	adapter, err := newDeploymentResourceProvider(provider, deploymentType)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, deploymentResourceExecutionTimeout)
	defer cancel()
	if err := adapter.TestResource(ctx, deploymentType, targetRef); err != nil {
		return false, err
	}
	return true, nil
}
