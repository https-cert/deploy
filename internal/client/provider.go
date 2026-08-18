package client

import (
	"context"
	"fmt"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// testFeiNiuConnection 允许单元测试替换真实飞牛环境探测，生产环境始终使用 SSH 或本机检查。
var testFeiNiuConnection = deploys.TestFeiNiuConnectionWithContext

// testRustFSConnection 允许连接测试使用替身而不触碰真实 RustFS 环境。
var testRustFSConnection = deploys.TestRustFSConnectionWithContext

// testOnePanelConnection 允许连接测试使用替身而不请求真实 1Panel API。
var testOnePanelConnection = deploys.TestOnePanelConnectionWithContext

// testOnePanelWebsiteConnection 允许连接测试使用替身而不请求真实 1Panel 网站接口。
var testOnePanelWebsiteConnection = deploys.TestOnePanelWebsiteConnection

// testBTPanelWebsiteConnection 允许连接测试使用替身而不请求真实宝塔网站接口。
var testBTPanelWebsiteConnection = deploys.TestBTPanelWebsiteConnection

// testBTPanelCertificateConnection 允许连接测试使用替身而不请求真实宝塔证书库。
var testBTPanelCertificateConnection = deploys.TestBTPanelCertificateConnectionWithContext

// testSafeLineConnection 允许连接测试使用替身而不请求真实雷池 OpenAPI。
var testSafeLineConnection = deploys.TestSafeLineConnectionWithContext

// TestProviderConnection 测试 config.yaml 中的云服务 provider，供 CLI doctor 复用。
func TestProviderConnection(ctx context.Context, runtime *config.Runtime, providerName string) (bool, error) {
	provider, ok := config.DeploymentProviderFromName(providerName)
	if !ok {
		return false, fmt.Errorf("未知部署平台: %s", providerName)
	}
	return testDeploymentConnection(ctx, provider, deployPB.DeploymentType_DEPLOYMENT_TYPE_UNSPECIFIED, "", runtime)
}

// testDeploymentConnection 汇总 v2 provider 凭据测试与本地部署环境测试。
func testDeploymentConnection(ctx context.Context, provider deployPB.Provider, deploymentType deployPB.DeploymentType, targetRef string, runtime *config.Runtime) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if runtime != nil {
		ctx = deploys.WithRuntime(ctx, runtime)
	}
	switch provider {
	case deployPB.Provider_PROVIDER_ANSSL_CLI:
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT {
			if err := testFeiNiuConnection(ctx); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT {
			if err := testRustFSConnection(ctx); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT {
			if err := testOnePanelConnection(ctx); err != nil {
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
			if err := testBTPanelCertificateConnection(ctx); err != nil {
				return false, err
			}
		}
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT {
			if err := testSafeLineConnection(ctx); err != nil {
				return false, err
			}
		}
		return true, nil

	default:
		if providerSupportsResource(provider, deploymentType) {
			return testCloudDeploymentResource(ctx, provider, deploymentType, targetRef, runtime)
		}
		handler, err := newConfiguredProvider(runtime, provider)
		if err != nil {
			return false, err
		}
		tester, ok := handler.(providers.ConnectionTester)
		if !ok {
			return false, fmt.Errorf("provider %s 不支持连接测试", provider.String())
		}
		success, err := tester.TestConnection(ctx)
		return success, err
	}
}

// testCloudDeploymentResource 只读测试当前 v2 selector 指向的动态云资源。
func testCloudDeploymentResource(ctx context.Context, provider deployPB.Provider, deploymentType deployPB.DeploymentType, targetRef string, runtime *config.Runtime) (bool, error) {
	if targetRef == "" {
		return false, fmt.Errorf("动态资源部署类型的 targetRef 不能为空")
	}
	adapter, err := newDeploymentResourceProvider(provider, deploymentType, runtime)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, deploymentOperationTimeout)
	defer cancel()
	if err := adapter.TestResource(ctx, deploymentType, targetRef); err != nil {
		return false, err
	}
	return true, nil
}
