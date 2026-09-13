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

// localTarget 描述一个 v2 本地部署目标的完整能力，是 PROVIDER_ANSSL_CLI 的唯一能力表。
type localTarget struct {
	// DeploymentType 是 v2 本地部署类型。
	DeploymentType deployPB.DeploymentType
	// TargetMode 决定是否必须携带动态资源引用。
	TargetMode deployPB.DeploymentTargetMode
	// DomainPolicy 声明后端可使用的资源域名校验策略。
	DomainPolicy deployPB.DeploymentDomainPolicy
	// Test 测试目标连通性；targetRef 仅动态资源目标使用。
	Test func(ctx context.Context, runtime *config.Runtime, targetRef string) error
	// DeployURL 使用证书归档下载地址执行部署；无资源目标使用。
	DeployURL func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error
	// DeployMaterial 使用 PEM 材料执行动态资源部署；网站类目标使用。
	DeployMaterial func(ctx context.Context, runtime *config.Runtime, targetRef, certificatePEM, privateKeyPEM string) error
	// Discover 返回脱敏资源目录；ctx 需已附带 runtime；nil 表示不支持动态资源发现。
	// 未配置状态由 Discover 实现自行返回 NOT_CONFIGURED。
	Discover func(ctx context.Context) providers.ResourceCatalogResult
}

// localTargets 是全部本地部署目标的注册表；新增目标只需追加一条并保证 Test/Deploy 行为。
var localTargets = buildLocalTargets()

func buildLocalTargets() []localTarget {
	none := deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_NONE
	required := deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED
	noDomain := deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_NONE
	anyDomain := deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_ANY

	testAlwaysOK := func(context.Context, *config.Runtime, string) error { return nil }

	return []localTarget{
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test:           testAlwaysOK,
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToNginx(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_CADDY_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, _ string) error {
				if runtime == nil || runtime.Config == nil || runtime.Config.SSL == nil || runtime.Config.SSL.Caddy == nil {
					return fmt.Errorf("未配置 Caddy (ssl.caddy)")
				}
				return deploys.TestCaddyConnectionWithContext(ctx, runtime.Config.SSL.Caddy.Path, runtime.Config.SSL.Caddy.Config)
			},
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToCaddy(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_APACHE_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test:           testAlwaysOK,
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToApache(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, _ string) error {
				ctx = deploys.WithRuntime(ctx, runtime)
				return testRustFSConnection(ctx)
			},
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToRustFS(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, _ string) error {
				ctx = deploys.WithRuntime(ctx, runtime)
				return testFeiNiuConnection(ctx)
			},
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToFeiNiu(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, _ string) error {
				return testOnePanelConnection(deploys.WithRuntime(ctx, runtime))
			},
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateTo1Panel(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_OPENVPN_AS_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test:           testAlwaysOK,
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToOpenVPNAS(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_UPLOAD_ONLY_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test:           testAlwaysOK,
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToUploadOnly(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, _ string) error {
				return testSafeLineConnection(deploys.WithRuntime(ctx, runtime))
			},
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToSafeLine(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT,
			TargetMode:     none,
			DomainPolicy:   noDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, _ string) error {
				return testBTPanelCertificateConnection(deploys.WithRuntime(ctx, runtime))
			},
			DeployURL: func(ctx context.Context, deployer *deploys.CertDeployer, domain, downloadURL string) error {
				return deployer.DeployCertificateToBTPanelCertificateStoreFromURL(ctx, domain, downloadURL)
			},
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT,
			TargetMode:     required,
			DomainPolicy:   anyDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, targetRef string) error {
				return testOnePanelWebsiteConnection(deploys.WithRuntime(ctx, runtime), targetRef)
			},
			DeployMaterial: func(ctx context.Context, runtime *config.Runtime, targetRef, certificatePEM, privateKeyPEM string) error {
				if err := deploys.DeployCertificateTo1PanelWebsite(deploys.WithRuntime(ctx, runtime), targetRef, certificatePEM, privateKeyPEM); err != nil {
					return providers.NewDeploymentError(
						localDeploymentFailureMessage,
						deploys.IsOnePanelErrorRetryable(err),
						"",
						err,
					)
				}
				return nil
			},
			Discover: discoverOnePanelWebsiteResources,
		},
		{
			DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT,
			TargetMode:     required,
			DomainPolicy:   anyDomain,
			Test: func(ctx context.Context, runtime *config.Runtime, targetRef string) error {
				return testBTPanelWebsiteConnection(deploys.WithRuntime(ctx, runtime), targetRef)
			},
			DeployMaterial: func(ctx context.Context, runtime *config.Runtime, targetRef, certificatePEM, privateKeyPEM string) error {
				if err := deploys.DeployCertificateToBTPanelWebsite(deploys.WithRuntime(ctx, runtime), targetRef, certificatePEM, privateKeyPEM); err != nil {
					return providers.NewDeploymentError(
						localDeploymentFailureMessage,
						deploys.IsBTPanelErrorRetryable(err),
						"",
						err,
					)
				}
				return nil
			},
			Discover: discoverBTPanelWebsiteResources,
		},
	}
}

func findLocalTarget(deploymentType deployPB.DeploymentType) (localTarget, bool) {
	for _, target := range localTargets {
		if target.DeploymentType == deploymentType {
			return target, true
		}
	}
	return localTarget{}, false
}

// localTargetSpecs 将注册表投影为 handler 能力声明。
func localTargetSpecs() []deploymentHandlerSpec {
	specs := make([]deploymentHandlerSpec, 0, len(localTargets))
	for _, target := range localTargets {
		specs = append(specs, deploymentHandlerSpec{
			key: DeploymentHandlerKey{
				Provider:       deployPB.Provider_PROVIDER_ANSSL_CLI,
				DeploymentType: target.DeploymentType,
			},
			targetMode:    target.TargetMode,
			domainMode:    target.DomainPolicy,
			executionKind: localExecutionKindFor(target),
		})
	}
	return specs
}

func localExecutionKindFor(target localTarget) deploymentExecutionKind {
	if target.TargetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED {
		return deploymentExecutionLocalResource
	}
	return deploymentExecutionLocalNone
}

// discoverOnePanelWebsiteResources 发现 1Panel 网站资源目录；ctx 需已附带 runtime。
func discoverOnePanelWebsiteResources(ctx context.Context) providers.ResourceCatalogResult {
	if !deploys.IsOnePanelConfiguredWithContext(ctx) {
		return providers.NotConfiguredCatalog()
	}
	resources, err := deploys.DiscoverOnePanelWebsiteResources(ctx)
	if err != nil {
		return providers.UnavailableCatalog(err)
	}
	result := make([]providers.DeploymentResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, localWebsiteResource(resource.TargetRef, resource.Label, resource.Domain, resource.Domains, resource.Protocol, resource.Status))
	}
	return providers.CatalogFromResources(result)
}

// discoverBTPanelWebsiteResources 发现宝塔网站资源目录；ctx 需已附带 runtime。
func discoverBTPanelWebsiteResources(ctx context.Context) providers.ResourceCatalogResult {
	if !deploys.IsBTPanelConfiguredWithContext(ctx) {
		return providers.NotConfiguredCatalog()
	}
	resources, err := deploys.DiscoverBTPanelWebsiteResources(ctx)
	if err != nil {
		return providers.UnavailableCatalog(err)
	}
	result := make([]providers.DeploymentResource, 0, len(resources))
	for _, resource := range resources {
		result = append(result, localWebsiteResource(resource.TargetRef, resource.Label, resource.Domain, resource.Domains, resource.Protocol, resource.Status))
	}
	return providers.CatalogFromResources(result)
}

func localWebsiteResource(targetRef, label, domain string, domains []string, protocol, status string) providers.DeploymentResource {
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	if status != "Running" {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	}
	return providers.DeploymentResource{
		TargetRef:    targetRef,
		Label:        label,
		Domain:       domain,
		Domains:      append([]string(nil), domains...),
		Protocol:     protocol,
		Status:       status,
		Availability: availability,
	}
}

// runLocalTargetDeployURL 通过注册表执行一次 URL 型本地部署。
// 失败时保留原始 error：FailureKind 应归为 LOCAL_PUBLISH，而不是包成 DeploymentError 变成 PROVIDER。
func runLocalTargetDeployURL(ctx context.Context, deployer *deploys.CertDeployer, deploymentType deployPB.DeploymentType, domain, downloadURL string) error {
	target, ok := findLocalTarget(deploymentType)
	if !ok || target.DeployURL == nil {
		return fmt.Errorf("不支持的部署类型: %s", deploymentType.String())
	}
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}
	if err := target.DeployURL(ctx, deployer, domain, downloadURL); err != nil {
		logger.ErrorLocal("本地部署失败", "error", err, "deploymentType", deploymentType.String(), "domain", domain)
		return err
	}
	return nil
}

// runLocalTargetDeployMaterial 通过注册表执行一次 PEM 材料型本地资源部署。
func runLocalTargetDeployMaterial(ctx context.Context, runtime *config.Runtime, deploymentType deployPB.DeploymentType, targetRef, certificatePEM, privateKeyPEM string) (providers.DeploymentResult, error) {
	target, ok := findLocalTarget(deploymentType)
	if !ok || target.DeployMaterial == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError(fmt.Sprintf("不支持的本地资源部署类型: %s", deploymentType.String()), false, "", nil)
	}
	if err := target.DeployMaterial(ctx, runtime, targetRef, certificatePEM, privateKeyPEM); err != nil {
		return providers.DeploymentResult{}, err
	}
	return providers.DeploymentResult{Message: localTargetSuccessMessage(deploymentType)}, nil
}

func localTargetSuccessMessage(deploymentType deployPB.DeploymentType) string {
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT:
		return "1Panel 网站证书部署成功"
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT:
		return "宝塔网站证书部署成功"
	default:
		return "证书部署成功"
	}
}
