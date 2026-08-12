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

// ProviderInfo 提供商信息
type ProviderInfo struct {
	Name   string // Name 是客户端配置中的 provider 名称。
	Remark string // Remark 是控制台展示的 provider 说明。
}

// testFeiNiuConnection 允许单元测试替换真实飞牛环境探测，生产环境始终使用 SSH 或本机检查。
var testFeiNiuConnection = deploys.TestFeiNiuConnection

// testRustFSConnection 允许连接测试使用替身而不触碰真实 RustFS 环境。
var testRustFSConnection = deploys.TestRustFSConnection

// testOnePanelConnection 允许连接测试使用替身而不请求真实 1Panel API。
var testOnePanelConnection = deploys.TestOnePanelConnection

// testOnePanelWebsiteConnection 允许连接测试使用替身而不请求真实 1Panel 网站接口。
var testOnePanelWebsiteConnection = deploys.TestOnePanelWebsiteConnection

// testSafeLineConnection 允许连接测试使用替身而不请求真实雷池 OpenAPI。
var testSafeLineConnection = deploys.TestSafeLineConnection

// GetProviderInfo 获取提供商信息列表
func GetProviderInfo() []ProviderInfo {
	cfg := config.GetConfig()
	var providers []ProviderInfo
	for _, p := range cfg.Provider {
		providers = append(providers, ProviderInfo{
			Name:   p.Name,
			Remark: p.Remark,
		})
	}
	return providers
}

// TestProviderConnection 测试云服务 provider 连接，供 CLI doctor 复用。
func TestProviderConnection(providerName string) (bool, error) {
	return testDeploymentConnection(providerName, deployPB.ExecuteBusinesType_EXECUTE_BUSINES_UNKNOWN, "")
}

// TestDeploymentConnection 根据具体部署业务执行对应的连接或环境检查。
func TestDeploymentConnection(providerName string, businessType deployPB.ExecuteBusinesType, targetRef string) (bool, error) {
	return testDeploymentConnection(providerName, businessType, targetRef)
}

// testDeploymentConnection 汇总 provider 凭据测试与本地部署环境测试的共同分发逻辑。
func testDeploymentConnection(providerName string, businessType deployPB.ExecuteBusinesType, targetRef string) (bool, error) {
	switch providerName {
	case "ansslCli":
		if businessType == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_FEINIU_CERT {
			if err := testFeiNiuConnection(); err != nil {
				return false, err
			}
		}
		if businessType == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_RUSTFS_CERT {
			if err := testRustFSConnection(); err != nil {
				return false, err
			}
		}
		if businessType == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_1PANEL_CERT {
			if err := testOnePanelConnection(); err != nil {
				return false, err
			}
		}
		if businessType == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_1PANEL_WEBSITE_CERT {
			if err := testOnePanelWebsiteConnection(context.Background(), targetRef); err != nil {
				return false, err
			}
		}
		if businessType == deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ANSSL_CLI_SAFELINE_CERT {
			if err := testSafeLineConnection(); err != nil {
				return false, err
			}
		}
		return true, nil

	case "aliyun":
		if config.IsDeploymentResourceBusiness(businessType) {
			return testCloudDeploymentResource(providerName, businessType, targetRef)
		}
		providerConfig := config.GetProvider("aliyun")
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【阿里云】提供商配置")
		}

		provider, err := aliyun.New(providerConfig.GetAccessKeyId(), providerConfig.GetAccessKeySecret())
		if err != nil {
			return false, fmt.Errorf("创建阿里云提供商实例失败: %w", err)
		}
		success, err := provider.TestConnection()
		if err != nil {
			return false, fmt.Errorf("阿里云连接测试失败: %w", err)
		}
		return success, nil

	case "cloudTencent":
		if config.IsDeploymentResourceBusiness(businessType) {
			return testCloudDeploymentResource(providerName, businessType, targetRef)
		}
		providerConfig := config.GetProvider("cloudTencent")
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【腾讯云】提供商配置")
		}
		if providerConfig.GetSecretId() == "" || providerConfig.GetSecretKey() == "" {
			return false, fmt.Errorf("腾讯云配置不完整: secretId 或 secretKey 为空")
		}

		provider := cloud_tencent.New(providerConfig.GetSecretId(), providerConfig.GetSecretKey())
		success, err := provider.TestConnection()
		if err != nil {
			return false, fmt.Errorf("腾讯云连接测试失败: %w", err)
		}
		return success, nil

	case "qiniu":
		if config.IsDeploymentResourceBusiness(businessType) {
			return testCloudDeploymentResource(providerName, businessType, targetRef)
		}
		providerConfig := config.GetProvider("qiniu")
		if providerConfig == nil {
			return false, fmt.Errorf("未配置【七牛云】提供商配置")
		}

		provider := qiniu.New(providerConfig.GetAccessKey(), providerConfig.GetAccessSecret())
		success, err := provider.TestConnection()
		if err != nil {
			return false, fmt.Errorf("七牛云连接测试失败: %w", err)
		}
		return success, nil

	default:
		logger.Warn("未知提供商", "provider", providerName)
		return false, fmt.Errorf("未知提供商: %s", providerName)
	}
}

// testCloudDeploymentResource 只读测试当前选择的动态云资源。
func testCloudDeploymentResource(providerName string, businessType deployPB.ExecuteBusinesType, targetRef string) (bool, error) {
	if targetRef == "" {
		return false, fmt.Errorf("资源型业务 targetRef 不能为空")
	}
	adapter, err := newDeploymentResourceProvider(providerName, businessType)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), deploymentResourceExecutionTimeout)
	defer cancel()
	if err := adapter.TestResource(ctx, businessType, targetRef); err != nil {
		return false, err
	}
	return true, nil
}
