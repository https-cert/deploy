package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pkg/logger"
)

// DeploymentHandlerKey 唯一标识一个 v2 部署 handler。
type DeploymentHandlerKey struct {
	Provider       deployPB.Provider       // Provider 是 v2 部署平台。
	DeploymentType deployPB.DeploymentType // DeploymentType 是 v2 部署类型。
}

// DeploymentHandlerRequest 描述一次 v2 证书部署所需的完整输入。
type DeploymentHandlerRequest struct {
	RequestID      string // RequestID 是服务端生成的请求关联标识。
	TargetRef      string // TargetRef 是客户端生成的不透明资源引用。
	Domain         string // Domain 是证书的规范化主域名。
	DownloadURL    string // DownloadURL 是本地部署器下载证书压缩包的地址。
	CertificatePEM string // CertificatePEM 是云端部署使用的完整证书链。
	PrivateKeyPEM  string // PrivateKeyPEM 是云端部署使用的 PEM 私钥。
}

// DeploymentHandler 定义一个 provider/type 组合的 v2 部署能力。
type DeploymentHandler interface {
	// Key 返回 handler 的稳定 provider/type 键。
	Key() DeploymentHandlerKey
	// Capability 返回不包含实时资源的能力声明。
	Capability() *deployPB.DeploymentCapability
	// DiscoverResources 返回脱敏的实时资源目录。
	DiscoverResources(ctx context.Context) providers.ResourceCatalogResult
	// Test 测试当前选择器是否可用。
	Test(ctx context.Context, targetRef string) error
	// Deploy 执行一次证书部署。
	Deploy(ctx context.Context, request DeploymentHandlerRequest) (providers.DeploymentResult, error)
}

// DeploymentHandlerRegistry 集中维护所有 v2 provider/type handler。
type DeploymentHandlerRegistry struct {
	handlers map[DeploymentHandlerKey]DeploymentHandler // handlers 按稳定 provider/type 键索引执行器。
	keys     []DeploymentHandlerKey                     // keys 保持能力声明的确定性顺序。
}

// deploymentHandlerSpec 描述一个原生 v2 handler 的静态执行约束。
type deploymentHandlerSpec struct {
	key           DeploymentHandlerKey            // key 是 v2 provider/type 组合。
	targetMode    deployPB.DeploymentTargetMode   // targetMode 决定是否必须携带动态资源引用。
	domainMode    deployPB.DeploymentDomainPolicy // domainMode 声明后端可使用的资源域名校验策略。
	executionKind deploymentExecutionKind         // executionKind 明确执行器使用的业务分支。
}

// NewDeploymentHandlerRegistry 注册所有原生 v2 handler。
func NewDeploymentHandlerRegistry(client *WSClient) (*DeploymentHandlerRegistry, error) {
	if client == nil || client.deploymentExecutor == nil {
		return nil, errors.New("deployment handler registry 缺少 v2 部署执行器")
	}
	specs := deploymentHandlerSpecs()
	handlers := make([]DeploymentHandler, 0, len(specs))
	for _, spec := range specs {
		handlers = append(handlers, &nativeDeploymentHandler{client: client, spec: spec})
	}
	return newDeploymentHandlerRegistry(handlers)
}

// newDeploymentHandlerRegistry 校验并建立 handler 索引。
func newDeploymentHandlerRegistry(handlers []DeploymentHandler) (*DeploymentHandlerRegistry, error) {
	registry := &DeploymentHandlerRegistry{
		handlers: make(map[DeploymentHandlerKey]DeploymentHandler, len(handlers)),
		keys:     make([]DeploymentHandlerKey, 0, len(handlers)),
	}
	for _, handler := range handlers {
		if handler == nil {
			return nil, errors.New("deployment handler 不能为空")
		}
		key := handler.Key()
		if key.Provider == deployPB.Provider_PROVIDER_UNSPECIFIED || key.DeploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_UNSPECIFIED {
			return nil, fmt.Errorf("deployment handler key 无效: provider=%s deploymentType=%s", key.Provider.String(), key.DeploymentType.String())
		}
		if _, exists := registry.handlers[key]; exists {
			return nil, fmt.Errorf("deployment handler 重复注册: provider=%s deploymentType=%s", key.Provider.String(), key.DeploymentType.String())
		}
		capability := handler.Capability()
		if capability == nil || capability.GetProvider() != key.Provider || capability.GetDeploymentType() != key.DeploymentType {
			return nil, fmt.Errorf("deployment handler 能力声明与 key 不一致: provider=%s deploymentType=%s", key.Provider.String(), key.DeploymentType.String())
		}
		registry.handlers[key] = handler
		registry.keys = append(registry.keys, key)
	}
	return registry, nil
}

// Lookup 按 provider/type 返回唯一 handler。
func (r *DeploymentHandlerRegistry) Lookup(provider deployPB.Provider, deploymentType deployPB.DeploymentType) (DeploymentHandler, bool) {
	if r == nil {
		return nil, false
	}
	handler, ok := r.handlers[DeploymentHandlerKey{Provider: provider, DeploymentType: deploymentType}]
	return handler, ok
}

// Capabilities 返回所有已注册 handler 的能力声明副本。
func (r *DeploymentHandlerRegistry) Capabilities() []*deployPB.DeploymentCapability {
	if r == nil {
		return nil
	}
	capabilities := make([]*deployPB.DeploymentCapability, 0, len(r.keys))
	for _, key := range r.keys {
		capabilities = append(capabilities, r.handlers[key].Capability())
	}
	return capabilities
}

// nativeDeploymentHandler 直接使用 v2 provider/type 调用资源适配器和部署执行器。
type nativeDeploymentHandler struct {
	client *WSClient             // client 提供 v2 执行器、资源锁和生命周期上下文。
	spec   deploymentHandlerSpec // spec 保存该 handler 的稳定能力约束。
}

// Key 返回当前 handler 的 v2 键。
func (h *nativeDeploymentHandler) Key() DeploymentHandlerKey {
	return h.spec.key
}

// Capability 返回当前 handler 的静态能力声明。
func (h *nativeDeploymentHandler) Capability() *deployPB.DeploymentCapability {
	return &deployPB.DeploymentCapability{
		Provider:              h.spec.key.Provider,
		DeploymentType:        h.spec.key.DeploymentType,
		TargetMode:            h.spec.targetMode,
		SupportsTest:          true,
		SupportsManualExecute: true,
		DomainPolicy:          h.spec.domainMode,
		ResourceStatus:        deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNKNOWN,
	}
}

// DiscoverResources 直接读取当前 v2 handler 的实时资源目录。
func (h *nativeDeploymentHandler) DiscoverResources(ctx context.Context) providers.ResourceCatalogResult {
	ctx = deploys.WithRuntime(ctx, h.client.runtime)
	if h.spec.targetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_NONE {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY}
	}
	if h.spec.key.Provider == deployPB.Provider_PROVIDER_ANSSL_CLI {
		return discoverLocalDeploymentResources(ctx, h.spec.key.DeploymentType)
	}
	definition, ok := findProviderDefinition(h.spec.key.Provider)
	if !ok || configuredProvider(h.client.runtime, definition.ConfigName) == nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
	}
	adapter, err := newDeploymentResourceProvider(h.spec.key.Provider, h.spec.key.DeploymentType, h.client.runtime)
	if err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: err}
	}
	return adapter.DiscoverResources(ctx, h.spec.key.DeploymentType)
}

// Test 测试当前 v2 provider/type 和 targetRef 是否可访问。
func (h *nativeDeploymentHandler) Test(ctx context.Context, targetRef string) error {
	if err := h.validateTargetRef(targetRef); err != nil {
		return err
	}
	success, err := testDeploymentConnection(ctx, h.spec.key.Provider, h.spec.key.DeploymentType, targetRef, h.client.runtime)
	if err != nil {
		return err
	}
	if !success {
		return providers.NewDeploymentError("目标测试失败，请查看 deploy 客户端日志", true, "", nil)
	}
	return nil
}

// Deploy 将 v2 请求直接交给统一部署执行器。
func (h *nativeDeploymentHandler) Deploy(ctx context.Context, request DeploymentHandlerRequest) (providers.DeploymentResult, error) {
	if err := h.validateTargetRef(request.TargetRef); err != nil {
		return providers.DeploymentResult{}, err
	}
	canonicalDomain, _, err := deploys.NormalizeDeploymentDomain(request.Domain)
	if err != nil || canonicalDomain == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("部署域名无效", false, "", err)
	}
	lockKey := "deployment-v2\x00" + h.spec.key.Provider.String() + "\x00" + h.spec.key.DeploymentType.String() + "\x00"
	if h.spec.targetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED {
		lockKey += request.TargetRef
	} else {
		lockKey += canonicalDomain
	}
	release := h.client.lockOperation(lockKey)
	defer release()
	result, err := h.client.deploymentExecutor.Execute(ctx, DeploymentExecutionRequest{
		ExecutionKind:  h.spec.executionKind,
		Provider:       h.spec.key.Provider,
		DeploymentType: h.spec.key.DeploymentType,
		TargetRef:      request.TargetRef,
		Domain:         canonicalDomain,
		DownloadURL:    request.DownloadURL,
		Remark:         canonicalDomain + "_" + time.Now().Format(time.DateTime),
		CertificatePEM: request.CertificatePEM,
		PrivateKeyPEM:  request.PrivateKeyPEM,
	})
	if err != nil {
		logger.ErrorLocal("v2 部署执行失败", "error", err, "provider", h.spec.key.Provider.String(), "deploymentType", h.spec.key.DeploymentType.String(), "requestId", request.RequestID)
		return result, err
	}
	return result, nil
}

// validateTargetRef 保证目标引用符合 handler 声明的 target mode。
func (h *nativeDeploymentHandler) validateTargetRef(targetRef string) error {
	if strings.TrimSpace(targetRef) != targetRef {
		return providers.NewDeploymentError("targetRef 不能包含首尾空白", false, "", nil)
	}
	required := h.spec.targetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED
	if required != (targetRef != "") {
		return providers.NewDeploymentError("targetRef 与部署能力的目标模式不匹配", false, "", nil)
	}
	return nil
}

// discoverLocalDeploymentResources 读取本机面板服务的 v2 脱敏资源目录。
func discoverLocalDeploymentResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT:
		if !deploys.IsOnePanelConfiguredWithContext(ctx) {
			return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
		}
		resources, err := deploys.DiscoverOnePanelWebsiteResources(ctx)
		if err != nil {
			return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: err}
		}
		result := make([]providers.DeploymentResource, 0, len(resources))
		for _, resource := range resources {
			availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
			if resource.Status != "Running" {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
			}
			result = append(result, providers.DeploymentResource{TargetRef: resource.TargetRef, Label: resource.Label, Domain: resource.Domain, Domains: append([]string(nil), resource.Domains...), Protocol: resource.Protocol, Status: resource.Status, Availability: availability})
		}
		return completedResourceCatalog(result)

	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT:
		if !deploys.IsBTPanelConfiguredWithContext(ctx) {
			return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
		}
		resources, err := deploys.DiscoverBTPanelWebsiteResources(ctx)
		if err != nil {
			return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: err}
		}
		result := make([]providers.DeploymentResource, 0, len(resources))
		for _, resource := range resources {
			availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
			if resource.Status != "Running" {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
			}
			result = append(result, providers.DeploymentResource{TargetRef: resource.TargetRef, Label: resource.Label, Domain: resource.Domain, Domains: append([]string(nil), resource.Domains...), Protocol: resource.Protocol, Status: resource.Status, Availability: availability})
		}
		return completedResourceCatalog(result)

	default:
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: fmt.Errorf("本地部署类型不支持资源发现: %s", deploymentType.String())}
	}
}

// completedResourceCatalog 根据资源数量返回完整或空目录状态。
func completedResourceCatalog(resources []providers.DeploymentResource) providers.ResourceCatalogResult {
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// deploymentHandlerSpecs 返回 deploy 客户端支持的全部原生 v2 能力。
func deploymentHandlerSpecs() []deploymentHandlerSpec {
	none := deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_NONE
	required := deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED
	noDomain := deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_NONE
	allDomains := deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_ALL
	anyDomain := deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_ANY
	specs := []deploymentHandlerSpec{
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_APACHE_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_OPENVPN_AS_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_UPLOAD_ONLY_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT, none, noDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT, required, anyDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT, required, anyDomain),
		newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT, none, noDomain),
	}
	for _, definition := range providerDefinitions {
		if definition.UploadOnly {
			specs = append(specs, newDeploymentHandlerSpec(definition.Provider, deployPB.DeploymentType_DEPLOYMENT_TYPE_UPLOAD_CERT, none, noDomain))
		}
		for _, deploymentType := range definition.ResourceTypes {
			specs = append(specs, newDeploymentHandlerSpec(definition.Provider, deploymentType, required, allDomains))
		}
	}
	return specs
}

// newDeploymentHandlerSpec 创建一条原生 v2 handler 声明。
func newDeploymentHandlerSpec(provider deployPB.Provider, deploymentType deployPB.DeploymentType, targetMode deployPB.DeploymentTargetMode, domainMode deployPB.DeploymentDomainPolicy) deploymentHandlerSpec {
	kind := deploymentExecutionLocalNone
	if provider != deployPB.Provider_PROVIDER_ANSSL_CLI {
		kind = deploymentExecutionCloudUpload
	}
	if targetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED {
		kind = deploymentExecutionCloudResource
		if provider == deployPB.Provider_PROVIDER_ANSSL_CLI {
			kind = deploymentExecutionLocalResource
		}
	}
	return deploymentHandlerSpec{key: DeploymentHandlerKey{Provider: provider, DeploymentType: deploymentType}, targetMode: targetMode, domainMode: domainMode, executionKind: kind}
}
