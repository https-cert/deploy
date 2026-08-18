package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
	"google.golang.org/protobuf/proto"
)

// fakeDeploymentProvider 覆盖动态资源、连接测试和证书上传接口。
type fakeDeploymentProvider struct {
	catalog          providers.ResourceCatalogResult // catalog 是资源发现结果。
	resource         providers.DeploymentResource    // resource 是 targetRef 解析结果。
	resolveErr       error                           // resolveErr 是资源解析错误。
	testErr          error                           // testErr 是只读资源测试错误。
	deployResult     providers.DeploymentResult      // deployResult 是精确部署结果。
	deployErr        error                           // deployErr 是精确部署错误。
	connectionResult bool                            // connectionResult 是凭据测试结果。
	connectionErr    error                           // connectionErr 是凭据测试错误。
	uploadErr        error                           // uploadErr 是证书中心上传错误。
	uploaded         *providers.CertificateMaterial  // uploaded 保存最近一次上传材料。
}

// DiscoverResources 返回预设资源目录。
func (f *fakeDeploymentProvider) DiscoverResources(context.Context, deployPB.DeploymentType) providers.ResourceCatalogResult {
	return f.catalog
}

// ResolveResource 返回预设资源或错误。
func (f *fakeDeploymentProvider) ResolveResource(context.Context, deployPB.DeploymentType, string) (providers.DeploymentResource, error) {
	return f.resource, f.resolveErr
}

// TestResource 返回预设资源测试错误。
func (f *fakeDeploymentProvider) TestResource(context.Context, deployPB.DeploymentType, string) error {
	return f.testErr
}

// DeployCertificate 返回预设精确部署结果。
func (f *fakeDeploymentProvider) DeployCertificate(_ context.Context, certificate providers.CertificateMaterial, _ deployPB.DeploymentType, _ providers.DeploymentResource) (providers.DeploymentResult, error) {
	copy := certificate
	f.uploaded = &copy
	return f.deployResult, f.deployErr
}

// TestConnection 返回预设 provider 连接测试结果。
func (f *fakeDeploymentProvider) TestConnection(context.Context) (bool, error) {
	return f.connectionResult, f.connectionErr
}

// UploadCertificate 保存材料并返回预设错误。
func (f *fakeDeploymentProvider) UploadCertificate(_ context.Context, certificate providers.CertificateMaterial) error {
	copy := certificate
	f.uploaded = &copy
	return f.uploadErr
}

// fakeDeploymentHandler 为 handler registry 和消息路由提供可观察替身。
type fakeDeploymentHandler struct {
	key          DeploymentHandlerKey            // key 是 handler 注册键。
	capability   *deployPB.DeploymentCapability  // capability 是静态能力声明。
	catalog      providers.ResourceCatalogResult // catalog 是资源发现结果。
	testErr      error                           // testErr 是目标测试错误。
	deployResult providers.DeploymentResult      // deployResult 是部署结果。
	deployErr    error                           // deployErr 是部署错误。
	lastTarget   string                          // lastTarget 保存最近测试引用。
	lastRequest  DeploymentHandlerRequest        // lastRequest 保存最近部署请求。
}

// Key 返回 fake handler 键。
func (f *fakeDeploymentHandler) Key() DeploymentHandlerKey { return f.key }

// Capability 返回 fake handler 能力声明副本。
func (f *fakeDeploymentHandler) Capability() *deployPB.DeploymentCapability {
	if f.capability == nil {
		return nil
	}
	return proto.Clone(f.capability).(*deployPB.DeploymentCapability)
}

// DiscoverResources 返回 fake 资源目录。
func (f *fakeDeploymentHandler) DiscoverResources(context.Context) providers.ResourceCatalogResult {
	return f.catalog
}

// Test 记录 targetRef 并返回预设错误。
func (f *fakeDeploymentHandler) Test(_ context.Context, targetRef string) error {
	f.lastTarget = targetRef
	return f.testErr
}

// Deploy 记录部署请求并返回预设结果。
func (f *fakeDeploymentHandler) Deploy(_ context.Context, request DeploymentHandlerRequest) (providers.DeploymentResult, error) {
	f.lastRequest = request
	return f.deployResult, f.deployErr
}

// fakeChallengeServer 记录 HTTP-01 设置和删除调用。
type fakeChallengeServer struct {
	setToken     string // setToken 是最近设置的 token。
	setResponse  string // setResponse 是最近设置的 key authorization。
	setDomain    string // setDomain 是最近设置的规范域名。
	removedToken string // removedToken 是最近删除的 token。
	setErr       error  // setErr 是设置错误。
	removeErr    error  // removeErr 是删除错误。
}

// SetChallenge 记录 HTTP-01 challenge。
func (f *fakeChallengeServer) SetChallenge(token, response, domain string) error {
	f.setToken, f.setResponse, f.setDomain = token, response, domain
	return f.setErr
}

// RemoveChallenge 记录删除的 HTTP-01 token。
func (f *fakeChallengeServer) RemoveChallenge(token string) error {
	f.removedToken = token
	return f.removeErr
}

// TestProviderRegistryConstruction 验证注册表从单一配置快照构造所有云 provider。
func TestProviderRegistryConstruction(t *testing.T) {
	// Huawei 官方 SDK 构造 CDN 客户端时会自动查询 IAM domain ID，注册表测试通过
	// 已有注入边界验证路由，具体 SDK 编排由 provider 包的离线测试负责。
	installFakeProviderFactory(t, deployPB.Provider_PROVIDER_HUAWEI_CLOUD, func(*config.Provider) (any, error) {
		return &fakeDeploymentProvider{}, nil
	})
	auth := &config.ProviderAuth{
		AccessKeyId: "access-id", AccessKeySecret: "access-secret",
		SecretId: "secret-id", SecretKey: "secret-key",
		AccessKey: "access-key", AccessSecret: "access-secret",
		APIBaseURL: "https://api.example.com", APIToken: "token",
	}
	configured := make([]*config.Provider, 0, len(providerDefinitions))
	for _, definition := range providerDefinitions {
		configured = append(configured, &config.Provider{Name: definition.ConfigName, Auth: auth})
	}
	runtime := &config.Runtime{Config: &config.Configuration{Provider: configured}}
	for _, definition := range providerDefinitions {
		handler, err := newConfiguredProvider(runtime, definition.Provider)
		if err != nil || handler == nil {
			t.Fatalf("构造 provider 失败: provider=%s handler=%T err=%v", definition.Provider, handler, err)
		}
	}
	if configuredProvider(nil, config.ProviderAliyun) != nil || configuredProvider(&config.Runtime{}, config.ProviderAliyun) != nil {
		t.Fatal("未初始化 runtime 不应返回 provider")
	}
	if configuredProvider(runtime, config.ProviderAliyun) == nil {
		t.Fatal("已配置 provider 未找到")
	}
	if _, err := newConfiguredProvider(runtime, deployPB.Provider_PROVIDER_UNSPECIFIED); err == nil {
		t.Fatal("未知 provider 应返回错误")
	}
	if _, err := newConfiguredProvider(&config.Runtime{Config: &config.Configuration{}}, deployPB.Provider_PROVIDER_ALIYUN); err == nil {
		t.Fatal("缺少 provider 配置应返回错误")
	}
}

// TestProviderAuthHelpers 验证注册表认证字段读取和必填校验。
func TestProviderAuthHelpers(t *testing.T) {
	auth := &config.ProviderAuth{AccessKeyId: "id", AccessKeySecret: "secret", SecretId: "sid", SecretKey: "skey", AccessKey: "ak", AccessSecret: "as", APIBaseURL: "url", APIToken: "token"}
	provider := &config.Provider{Auth: auth}
	expected := map[string]string{"accessKeyId": "id", "accessKeySecret": "secret", "secretId": "sid", "secretKey": "skey", "accessKey": "ak", "accessSecret": "as", "apiBaseUrl": "url", "apiToken": "token", "unknown": ""}
	for field, want := range expected {
		if got := providerAuthValue(provider, field); got != want {
			t.Fatalf("认证字段不匹配: field=%q got=%q want=%q", field, got, want)
		}
	}
	if providerAuthValue(nil, "accessKey") != "" || providerAuthValue(&config.Provider{}, "accessKey") != "" {
		t.Fatal("空 provider auth 应返回空值")
	}
	if err := providerAuthRequired(provider, "accessKeyId", "accessKeySecret"); err != nil {
		t.Fatalf("完整认证被拒绝: %v", err)
	}
	if err := providerAuthRequired(nil, "accessKeyId", "accessKeySecret"); err == nil {
		t.Fatal("nil provider 应返回错误")
	}
	if err := providerAuthRequired(&config.Provider{Auth: &config.ProviderAuth{}}, "accessKeyId", "accessKeySecret"); err == nil {
		t.Fatal("空认证字段应返回错误")
	}
}

// TestDeploymentHandlerRegistryValidation 验证 handler 注册、查找、能力顺序和异常声明。
func TestDeploymentHandlerRegistryValidation(t *testing.T) {
	key := DeploymentHandlerKey{Provider: deployPB.Provider_PROVIDER_ALIYUN, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}
	valid := &fakeDeploymentHandler{key: key, capability: &deployPB.DeploymentCapability{Provider: key.Provider, DeploymentType: key.DeploymentType}}
	registry, err := newDeploymentHandlerRegistry([]DeploymentHandler{valid})
	if err != nil {
		t.Fatalf("注册有效 handler 失败: %v", err)
	}
	if handler, ok := registry.Lookup(key.Provider, key.DeploymentType); !ok || handler != valid {
		t.Fatal("handler 查找失败")
	}
	if len(registry.Capabilities()) != 1 || registry.Capabilities()[0].GetProvider() != key.Provider {
		t.Fatal("能力列表不匹配")
	}
	if handler, ok := (*DeploymentHandlerRegistry)(nil).Lookup(key.Provider, key.DeploymentType); ok || handler != nil || (*DeploymentHandlerRegistry)(nil).Capabilities() != nil {
		t.Fatal("nil registry 应安全返回")
	}

	invalidKey := &fakeDeploymentHandler{capability: &deployPB.DeploymentCapability{}}
	mismatch := &fakeDeploymentHandler{key: key, capability: &deployPB.DeploymentCapability{Provider: deployPB.Provider_PROVIDER_QINIU, DeploymentType: key.DeploymentType}}
	for name, handlers := range map[string][]DeploymentHandler{
		"nil handler":         {nil},
		"invalid key":         {invalidKey},
		"duplicate":           {valid, valid},
		"capability mismatch": {mismatch},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newDeploymentHandlerRegistry(handlers); err == nil {
				t.Fatal("无效 handler 注册应返回错误")
			}
		})
	}
	if _, err := NewDeploymentHandlerRegistry(nil); err == nil {
		t.Fatal("nil client 应返回错误")
	}
	if _, err := NewDeploymentHandlerRegistry(&WSClient{}); err == nil {
		t.Fatal("缺少 executor 应返回错误")
	}
	client := &WSClient{deploymentExecutor: &DeploymentExecutor{}, operationLocks: make(map[string]*resourceOperationLock)}
	if registry, err := NewDeploymentHandlerRegistry(client); err != nil || len(registry.keys) != len(deploymentHandlerSpecs()) {
		t.Fatalf("原生 handler 注册失败: keys=%d err=%v", len(registry.keys), err)
	}
}

// TestNativeDeploymentHandlerBehavior 验证能力声明、targetRef、资源发现和动态部署。
func TestNativeDeploymentHandlerBehavior(t *testing.T) {
	certificatePEM, privateKeyPEM := generateClientTestCertificate(t, "www.example.com")
	fakeProvider := &fakeDeploymentProvider{
		catalog:          providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY},
		resource:         providers.DeploymentResource{TargetRef: "target-1", Domain: "www.example.com", Domains: []string{"www.example.com"}, Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY},
		deployResult:     providers.DeploymentResult{RequestID: "request-provider", Message: "完成"},
		connectionResult: true,
	}
	runtime := fakeAliyunRuntime()
	installFakeProviderFactory(t, deployPB.Provider_PROVIDER_ALIYUN, func(*config.Provider) (any, error) { return fakeProvider, nil })
	executor := NewDeploymentExecutor(nil, runtime)
	executor.deploymentResourceProviderFactory = func(deployPB.Provider, deployPB.DeploymentType) (providers.DeploymentResourceProvider, error) {
		return fakeProvider, nil
	}
	client := &WSClient{runtime: runtime, deploymentExecutor: executor, operationLocks: make(map[string]*resourceOperationLock)}
	spec := newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ALIYUN, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED, deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_ALL)
	handler := &nativeDeploymentHandler{client: client, spec: spec}
	if handler.Key() != spec.key || handler.Capability().GetTargetMode() != deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED {
		t.Fatal("原生 handler 能力声明不匹配")
	}
	if catalog := handler.DiscoverResources(context.Background()); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY {
		t.Fatalf("资源发现状态不匹配: %+v", catalog)
	}
	if err := handler.Test(context.Background(), "target-1"); err != nil {
		t.Fatalf("动态资源测试失败: %v", err)
	}
	result, err := handler.Deploy(context.Background(), DeploymentHandlerRequest{RequestID: "request-1", TargetRef: "target-1", Domain: "WWW.Example.com", CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM})
	if err != nil || result.RequestID != "request-provider" || fakeProvider.uploaded == nil {
		t.Fatalf("动态资源部署失败: result=%+v uploaded=%+v err=%v", result, fakeProvider.uploaded, err)
	}
	for _, targetRef := range []string{"", " target-1"} {
		if err := handler.validateTargetRef(targetRef); err == nil {
			t.Fatalf("非法 targetRef 应被拒绝: %q", targetRef)
		}
	}
	if _, err := handler.Deploy(context.Background(), DeploymentHandlerRequest{TargetRef: "target-1", Domain: "bad/path"}); err == nil {
		t.Fatal("非法部署域名应被拒绝")
	}

	localSpec := newDeploymentHandlerSpec(deployPB.Provider_PROVIDER_ANSSL_CLI, deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT, deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_NONE, deployPB.DeploymentDomainPolicy_DEPLOYMENT_DOMAIN_POLICY_NONE)
	localHandler := &nativeDeploymentHandler{client: client, spec: localSpec}
	if catalog := localHandler.DiscoverResources(context.Background()); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY {
		t.Fatalf("无资源能力应直接 READY: %+v", catalog)
	}
	if err := localHandler.validateTargetRef(""); err != nil || localHandler.validateTargetRef("unexpected") == nil {
		t.Fatal("无资源 handler targetRef 校验不匹配")
	}

	unconfiguredClient := &WSClient{runtime: &config.Runtime{Config: &config.Configuration{}}, deploymentExecutor: &DeploymentExecutor{}}
	unconfiguredHandler := &nativeDeploymentHandler{client: unconfiguredClient, spec: spec}
	if catalog := unconfiguredHandler.DiscoverResources(context.Background()); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置云 provider 状态不匹配: %+v", catalog)
	}
}

// TestDeploymentExecutorRoutes 验证执行种类约束、动态资源错误和非资源路由。
func TestDeploymentExecutorRoutes(t *testing.T) {
	certificatePEM, privateKeyPEM := generateClientTestCertificate(t, "www.example.com")
	fakeProvider := &fakeDeploymentProvider{
		resource:         providers.DeploymentResource{TargetRef: "target-1", Domain: "www.example.com", Domains: []string{"www.example.com"}, Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY},
		deployResult:     providers.DeploymentResult{},
		connectionResult: true,
	}
	executor := NewDeploymentExecutor(nil, fakeAliyunRuntime())
	executor.deploymentResourceProviderFactory = func(deployPB.Provider, deployPB.DeploymentType) (providers.DeploymentResourceProvider, error) {
		return fakeProvider, nil
	}
	base := DeploymentExecutionRequest{ExecutionKind: deploymentExecutionCloudResource, Provider: deployPB.Provider_PROVIDER_ALIYUN, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, TargetRef: "target-1", Domain: "www.example.com", CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM}
	result, err := executor.Execute(context.Background(), base)
	if err != nil || result.Message != "证书部署成功" {
		t.Fatalf("动态资源成功结果不匹配: result=%+v err=%v", result, err)
	}

	invalidRequests := []DeploymentExecutionRequest{
		{Provider: deployPB.Provider_PROVIDER_ALIYUN},
		{ExecutionKind: deploymentExecutionLocalNone, Provider: deployPB.Provider_PROVIDER_ALIYUN},
		{ExecutionKind: deploymentExecutionCloudUpload, Provider: deployPB.Provider_PROVIDER_ANSSL_CLI},
		{ExecutionKind: deploymentExecutionCloudResource, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, TargetRef: "target"},
		{ExecutionKind: deploymentExecutionCloudResource, Provider: deployPB.Provider_PROVIDER_ALIYUN, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN},
		{ExecutionKind: deploymentExecutionLocalNone, Provider: deployPB.Provider_PROVIDER_ANSSL_CLI, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_UNSPECIFIED},
	}
	for index, request := range invalidRequests {
		if _, err := executor.Execute(context.Background(), request); err == nil {
			t.Fatalf("无效执行请求 #%d 应返回错误", index)
		}
	}

	fakeProvider.resolveErr = errors.New("stale")
	if _, err := executor.Execute(context.Background(), base); err == nil || !strings.Contains(err.Error(), "失效") {
		t.Fatalf("资源失效错误不匹配: %v", err)
	}
	fakeProvider.resolveErr = nil
	fakeProvider.resource.Availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_DISABLED
	if _, err := executor.Execute(context.Background(), base); err == nil || !strings.Contains(err.Error(), "不可用") {
		t.Fatalf("资源不可用错误不匹配: %v", err)
	}
	fakeProvider.resource.Availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	invalidCertificate := base
	invalidCertificate.CertificatePEM = "invalid"
	if _, err := executor.Execute(context.Background(), invalidCertificate); err == nil || !strings.Contains(err.Error(), "证书校验") {
		t.Fatalf("证书校验错误不匹配: %v", err)
	}
	fakeProvider.deployErr = providers.NewDeploymentError("deploy failed", true, "request-failed", nil)
	if _, err := executor.Execute(context.Background(), base); err == nil {
		t.Fatal("provider 部署错误应传播")
	}

	for _, deploymentType := range []deployPB.DeploymentType{
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_APACHE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_OPENVPN_AS_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_UPLOAD_ONLY_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT,
	} {
		if err := executor.executeNonResourceDeployment(context.Background(), deployPB.Provider_PROVIDER_ANSSL_CLI, deploymentType, "", "", "", "", ""); err == nil {
			t.Fatalf("空域名本地部署应被拒绝: %s", deploymentType)
		}
	}
	if err := executor.executeNonResourceDeployment(context.Background(), deployPB.Provider_PROVIDER_ALIYUN, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "domain", "", "", "", ""); err == nil {
		t.Fatal("云 provider 非上传类型应被拒绝")
	}
	if err := executor.executeNonResourceDeployment(context.Background(), deployPB.Provider_PROVIDER_UNSPECIFIED, deployPB.DeploymentType_DEPLOYMENT_TYPE_UPLOAD_CERT, "domain", "", "", "", ""); err == nil {
		t.Fatal("未知 provider 应被拒绝")
	}
}

// TestProviderConnectionRoutes 验证本地连接测试和 fake 云 provider 路由。
func TestProviderConnectionRoutes(t *testing.T) {
	originalFeiNiu := testFeiNiuConnection
	originalRustFS := testRustFSConnection
	originalOnePanel := testOnePanelConnection
	originalOnePanelWebsite := testOnePanelWebsiteConnection
	originalBTPanelWebsite := testBTPanelWebsiteConnection
	originalBTPanelCertificate := testBTPanelCertificateConnection
	originalSafeLine := testSafeLineConnection
	t.Cleanup(func() {
		testFeiNiuConnection = originalFeiNiu
		testRustFSConnection = originalRustFS
		testOnePanelConnection = originalOnePanel
		testOnePanelWebsiteConnection = originalOnePanelWebsite
		testBTPanelWebsiteConnection = originalBTPanelWebsite
		testBTPanelCertificateConnection = originalBTPanelCertificate
		testSafeLineConnection = originalSafeLine
	})
	called := 0
	success := func(context.Context) error { called++; return nil }
	testFeiNiuConnection = success
	testRustFSConnection = success
	testOnePanelConnection = success
	testBTPanelCertificateConnection = success
	testSafeLineConnection = success
	testOnePanelWebsiteConnection = func(context.Context, string) error { called++; return nil }
	testBTPanelWebsiteConnection = func(context.Context, string) error { called++; return nil }
	for _, deploymentType := range []deployPB.DeploymentType{
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT,
	} {
		ok, err := testDeploymentConnection(context.Background(), deployPB.Provider_PROVIDER_ANSSL_CLI, deploymentType, "target", nil)
		if !ok || err != nil {
			t.Fatalf("本地连接测试失败: type=%s ok=%v err=%v", deploymentType, ok, err)
		}
	}
	if called != 7 {
		t.Fatalf("本地连接测试调用次数不匹配: %d", called)
	}
	if _, err := TestProviderConnection(context.Background(), nil, "unknown"); err == nil {
		t.Fatal("未知 provider 名称应返回错误")
	}

	fakeProvider := &fakeDeploymentProvider{connectionResult: true, resource: providers.DeploymentResource{Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY}}
	installFakeProviderFactory(t, deployPB.Provider_PROVIDER_ALIYUN, func(*config.Provider) (any, error) { return fakeProvider, nil })
	runtime := fakeAliyunRuntime()
	if ok, err := TestProviderConnection(context.Background(), runtime, config.ProviderAliyun); !ok || err != nil {
		t.Fatalf("云 provider 连接测试失败: ok=%v err=%v", ok, err)
	}
	if ok, err := testCloudDeploymentResource(context.Background(), deployPB.Provider_PROVIDER_ALIYUN, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "target", runtime); !ok || err != nil {
		t.Fatalf("云资源连接测试失败: ok=%v err=%v", ok, err)
	}
	if _, err := testCloudDeploymentResource(context.Background(), deployPB.Provider_PROVIDER_ALIYUN, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "", runtime); err == nil {
		t.Fatal("空 targetRef 应返回错误")
	}
}

// TestDeploymentMessageHelpersAndChallenge 验证结果构造、资源映射和 HTTP-01 执行分支。
func TestDeploymentMessageHelpersAndChallenge(t *testing.T) {
	if hasDeploymentResponsePayload(nil) || hasDeploymentResponsePayload(&deployPB.DeploymentResponse{}) {
		t.Fatal("空 deployment 响应不应被识别为有效 payload")
	}
	response := &deployPB.DeploymentResponse{Data: &deployPB.DeploymentResponse_Register{Register: &deployPB.DeploymentRegisterV2{}}}
	if !hasDeploymentResponsePayload(response) {
		t.Fatal("带 payload 响应未被识别")
	}
	if deploymentRequestID("envelope", "payload") != "payload" || deploymentRequestID("envelope", "") != "envelope" {
		t.Fatal("请求 ID 兼容规则不匹配")
	}
	if successfulDeploymentResult("ok", "provider").GetStatus() != deployPB.DeploymentExecutionResult_STATUS_SUCCESS ||
		failedDeploymentResult("failed", true).GetStatus() != deployPB.DeploymentExecutionResult_STATUS_FAILED ||
		unsupportedDeploymentResult("unsupported").GetStatus() != deployPB.DeploymentExecutionResult_STATUS_NOT_SUPPORTED {
		t.Fatal("部署结果构造状态不匹配")
	}
	selector := &deployPB.DeploymentSelector{Provider: deployPB.Provider_PROVIDER_QINIU, DeploymentType: deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN}
	capability := unavailableDeploymentCapability(selector)
	if capability.GetProvider() != selector.GetProvider() || capability.GetResourceStatus() != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE || unavailableDeploymentCapability(nil).GetProvider() != deployPB.Provider_PROVIDER_UNSPECIFIED {
		t.Fatal("不可用能力构造不匹配")
	}
	converted := deploymentResourcesFromProvider([]providers.DeploymentResource{{TargetRef: "target", Label: "label", Domain: "example.com", Domains: []string{"example.com"}, ListenerPort: 443, Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY}})
	if len(converted) != 1 || converted[0].GetPort() != 443 || converted[0].GetDomains()[0] != "example.com" {
		t.Fatalf("资源协议映射不匹配: %+v", converted)
	}
	deploymentErr := providers.NewDeploymentError("failed", false, "request-provider", nil)
	if providerRequestID(deploymentErr) != "request-provider" || providerRequestID(errors.New("other")) != "" {
		t.Fatal("provider 请求 ID 提取不匹配")
	}
	//lint:ignore SA1012 此处刻意传入 nil 以覆盖兼容防御分支。
	if deploymentContext(nil) == nil {
		t.Fatal("nil context 应得到可用 context")
	}

	challenge := &fakeChallengeServer{}
	client := &WSClient{httpServer: challenge}
	request := &deployPB.DeploymentChallengeRequest{Action: deployPB.DeploymentChallengeRequest_ACTION_SET, OperationId: 1, CertId: 2, Domain: "WWW.Example.com", Token: "token", KeyAuth: "key-auth"}
	if result := client.executeDeploymentChallenge(request); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_SUCCESS || challenge.setDomain != "www.example.com" {
		t.Fatalf("challenge 设置失败: result=%+v server=%+v", result, challenge)
	}
	request.Action = deployPB.DeploymentChallengeRequest_ACTION_DELETE
	if result := client.executeDeploymentChallenge(request); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_SUCCESS || challenge.removedToken != "token" {
		t.Fatalf("challenge 删除失败: result=%+v server=%+v", result, challenge)
	}
	request.Action = deployPB.DeploymentChallengeRequest_ACTION_UNSPECIFIED
	if result := client.executeDeploymentChallenge(request); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_NOT_SUPPORTED {
		t.Fatal("未知 challenge 操作应返回不支持")
	}
	for _, invalid := range []*deployPB.DeploymentChallengeRequest{nil, {}, {OperationId: 1, CertId: 2, Token: "token", Domain: "bad/path"}} {
		if result := client.executeDeploymentChallenge(invalid); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_FAILED {
			t.Fatalf("非法 challenge 应失败: request=%+v result=%+v", invalid, result)
		}
	}
	client.httpServer = nil
	request.Action = deployPB.DeploymentChallengeRequest_ACTION_SET
	if result := client.executeDeploymentChallenge(request); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_FAILED {
		t.Fatal("缺少 HTTP server 应失败")
	}
	client.httpServer = &fakeChallengeServer{setErr: errors.New("set failed")}
	if result := client.executeDeploymentChallenge(request); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_FAILED {
		t.Fatal("设置错误应失败")
	}
	request.Action = deployPB.DeploymentChallengeRequest_ACTION_DELETE
	client.httpServer = &fakeChallengeServer{removeErr: errors.New("remove failed")}
	if result := client.executeDeploymentChallenge(request); result.GetStatus() != deployPB.DeploymentExecutionResult_STATUS_FAILED {
		t.Fatal("删除错误应失败")
	}
	if catalog := completedResourceCatalog(nil); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatal("空目录状态应为 EMPTY")
	}
	if catalog := completedResourceCatalog([]providers.DeploymentResource{{TargetRef: "x"}}); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY {
		t.Fatal("非空目录状态应为 READY")
	}
}

// installFakeProviderFactory 临时替换一个 provider 注册构造器并在测试后恢复。
func installFakeProviderFactory(t *testing.T, provider deployPB.Provider, factory func(*config.Provider) (any, error)) {
	t.Helper()
	original := append([]providerDefinition(nil), providerDefinitions...)
	t.Cleanup(func() { providerDefinitions = original })
	for index := range providerDefinitions {
		if providerDefinitions[index].Provider == provider {
			providerDefinitions[index].New = factory
			return
		}
	}
	t.Fatalf("未找到 provider 定义: %s", provider)
}

// fakeAliyunRuntime 创建包含完整阿里云认证的测试运行时。
func fakeAliyunRuntime() *config.Runtime {
	return &config.Runtime{Config: &config.Configuration{Server: &config.ServerConfig{AccessKey: "access-key"}, Provider: []*config.Provider{{Name: config.ProviderAliyun, Auth: &config.ProviderAuth{AccessKeyId: "access-id", AccessKeySecret: "access-secret"}}}}}
}

// generateClientTestCertificate 创建覆盖指定域名的离线 RSA 证书材料。
func generateClientTestCertificate(t *testing.T, domain string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	return string(certificatePEM), string(privateKeyPEM)
}
