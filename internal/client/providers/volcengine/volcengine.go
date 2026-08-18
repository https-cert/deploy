// Package volcengine implements verified Volcengine certificate deployment flows.
package volcengine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	dcdnapi "github.com/volcengine/volcengine-go-sdk/service/dcdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
)

const (
	defaultRegion     = "cn-beijing"
	certificateSource = "volc_cert_center"
	pageSize          = 100
	maxPages          = 100
	maxResources      = 10000
	sdkTimeout        = 30 * time.Second
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
)

// cdnClient 是火山 CDN 适配器需要的最小官方 SDK 接口。
type cdnClient interface {
	ListCdnDomainsWithContext(ctx volcengine.Context, input *cdnapi.ListCdnDomainsInput, options ...request.Option) (*cdnapi.ListCdnDomainsOutput, error)
	ListCertInfoWithContext(ctx volcengine.Context, input *cdnapi.ListCertInfoInput, options ...request.Option) (*cdnapi.ListCertInfoOutput, error)
	AddCertificateWithContext(ctx volcengine.Context, input *cdnapi.AddCertificateInput, options ...request.Option) (*cdnapi.AddCertificateOutput, error)
	DescribeCdnConfigWithContext(ctx volcengine.Context, input *cdnapi.DescribeCdnConfigInput, options ...request.Option) (*cdnapi.DescribeCdnConfigOutput, error)
	UpdateCdnConfigWithContext(ctx volcengine.Context, input *cdnapi.UpdateCdnConfigInput, options ...request.Option) (*cdnapi.UpdateCdnConfigOutput, error)
}

// dcdnClient 是火山 DCDN 适配器需要的最小官方 SDK 接口。
type dcdnClient interface {
	ListDomainConfigWithContext(ctx volcengine.Context, input *dcdnapi.ListDomainConfigInput, options ...request.Option) (*dcdnapi.ListDomainConfigOutput, error)
	DescribeDomainDetailWithContext(ctx volcengine.Context, input *dcdnapi.DescribeDomainDetailInput, options ...request.Option) (*dcdnapi.DescribeDomainDetailOutput, error)
	CreateCertBindWithContext(ctx volcengine.Context, input *dcdnapi.CreateCertBindInput, options ...request.Option) (*dcdnapi.CreateCertBindOutput, error)
	ListCertBindWithContext(ctx volcengine.Context, input *dcdnapi.ListCertBindInput, options ...request.Option) (*dcdnapi.ListCertBindOutput, error)
}

// Provider 保存火山引擎凭据、地域和各产品官方 SDK 客户端。
type Provider struct {
	accessKey         string               // accessKey 是火山引擎 Access Key ID。
	secretKey         string               // secretKey 是火山引擎 Secret Access Key。
	region            string               // region 是默认资源地域。
	certificateRegion string               // certificateRegion 是证书中心及 CDN/DCDN 签名地域。
	regions           []string             // regions 是参与 TOS 和负载均衡资源发现的地域集合。
	cdn               cdnClient            // cdn 是 CDN 和共享证书中心控制面客户端。
	dcdn              dcdnClient           // dcdn 是 DCDN 控制面客户端。
	tosClients        map[string]tosClient // tosClients 按地域保存 TOS 控制面客户端。
	clbClients        map[string]clbClient // clbClients 按地域保存 CLB 控制面客户端。
	albClients        map[string]albClient // albClients 按地域保存 ALB 控制面客户端。
	nlbClients        map[string]nlbClient // nlbClients 按地域保存 NLB 控制面客户端。
}

// New 使用默认地域集合创建向后兼容的火山引擎 provider。
func New(accessKey, secretKey, region string) (*Provider, error) {
	return NewConfigured(accessKey, secretKey, region, region, nil)
}

// NewConfigured 使用配置的证书地域和资源地域创建火山引擎 provider。
func NewConfigured(accessKey, secretKey, region, certificateRegion string, regions []string) (*Provider, error) {
	accessKey = strings.TrimSpace(accessKey)
	secretKey = strings.TrimSpace(secretKey)
	region = strings.ToLower(strings.TrimSpace(region))
	if region == "" {
		region = defaultRegion
	}
	certificateRegion = strings.ToLower(strings.TrimSpace(certificateRegion))
	if certificateRegion == "" {
		certificateRegion = region
	}
	resolvedRegions, err := normalizeVolcengineRegions(region, regions)
	if err != nil {
		return nil, err
	}
	config := volcengine.NewConfig().WithRegion(certificateRegion).WithCredentials(credentials.NewStaticCredentials(accessKey, secretKey, ""))
	sdkSession, err := session.NewSession(config)
	if err != nil {
		return nil, fmt.Errorf("创建火山引擎 SDK 会话失败: %w", err)
	}
	tosClients, err := newTOSClients(accessKey, secretKey, resolvedRegions)
	if err != nil {
		return nil, err
	}
	clbClients, albClients, nlbClients, err := newLoadBalancerClients(accessKey, secretKey, resolvedRegions)
	if err != nil {
		return nil, err
	}
	provider := newWithClients(accessKey, secretKey, certificateRegion, cdnapi.New(sdkSession), dcdnapi.New(sdkSession))
	provider.region = region
	provider.certificateRegion = certificateRegion
	provider.regions = resolvedRegions
	provider.tosClients = tosClients
	provider.clbClients = clbClients
	provider.albClients = albClients
	provider.nlbClients = nlbClients
	return provider, nil
}

// newWithClients 创建支持测试替身注入的火山引擎 provider。
func newWithClients(accessKey, secretKey, region string, cdn cdnClient, dcdn dcdnClient) *Provider {
	region = strings.ToLower(strings.TrimSpace(region))
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		region:            region,
		certificateRegion: region,
		regions:           []string{region},
		cdn:               cdn,
		dcdn:              dcdn,
	}
}

// TestConnection 验证火山 CDN 证书目录可读，从而覆盖证书中心权限。
func (p *Provider) TestConnection(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.cdn == nil {
		return false, providers.NewDeploymentError("火山引擎 CDN 客户端未初始化", false, "", nil)
	}
	output, err := p.cdn.ListCertInfoWithContext(ctx, &cdnapi.ListCertInfoInput{Source: volcengine.String(certificateSource), PageNum: volcengine.Int32(1), PageSize: volcengine.Int32(1)})
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	if output == nil {
		return false, providers.NewDeploymentError("火山引擎测试连接响应为空", true, "", nil)
	}
	return true, nil
}

// UploadCertificate 将证书导入火山证书中心，并通过指纹目录回读验收。
func (p *Provider) UploadCertificate(ctx context.Context, certificate providers.CertificateMaterial) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := providers.ValidateCertificateMaterial(certificate, certificate.Domain, time.Now()); err != nil {
		return providers.NewDeploymentError("火山引擎上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(ctx, certificate)
	return toDeploymentError("上传证书", err)
}

// DiscoverResources 实时发现火山 CDN、DCDN 或 TOS 自定义域名资源。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := p.validateCredentials(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	var resources []providers.DeploymentResource
	var partial bool
	var err error
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		resources, err = p.discoverCDN(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		resources, err = p.discoverDCDN(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_TOS_CUSTOM_DOMAIN:
		resources, partial, err = p.discoverTOSResources(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		resources, partial, err = p.discoverCLBResources(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB:
		resources, partial, err = p.discoverALBResources(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB:
		resources, partial, err = p.discoverNLBResources(ctx, deploymentType)
	default:
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if isPermissionDenied(err) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		if len(resources) > 0 {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
		}
		return providers.ResourceCatalogResult{Resources: resources, Status: status, Error: err}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if partial {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
	} else if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新读取火山资源目录并按 targetRef 唯一解析资源。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("火山引擎资源目录不可用", false, requestIDFromError(catalog.Error), catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认火山资源仍可部署。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("火山引擎资源当前不可部署", false, "", err)
	}
	return nil
}

// DeployCertificate 将证书部署到一个精确的火山资源并回读。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("火山引擎目标缺少 targetRef、域名或创建时间", false, "", nil)
	}
	targetDomains := resource.Domains
	if len(targetDomains) == 0 {
		targetDomains = []string{resource.Domain}
	}
	if err := providers.ValidateCertificateForDomains(certificate, targetDomains, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("火山引擎证书校验失败", false, "", err)
	}
	certificateID, requestID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		requestID, err = p.deployCDN(ctx, resource, certificateID, requestID)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		requestID, err = p.deployDCDN(ctx, resource, certificateID, requestID)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_TOS_CUSTOM_DOMAIN:
		requestID, err = p.deployTOS(ctx, resource, certificateID, requestID)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		requestID, err = p.deployCLB(ctx, resource, certificateID, requestID)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB:
		requestID, err = p.deployALB(ctx, resource, certificateID, requestID)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB:
		requestID, err = p.deployNLB(ctx, resource, certificateID, requestID)
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("火山引擎不支持该部署业务", false, requestID, nil)
	}
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("部署证书", err)
	}
	return providers.DeploymentResult{RequestID: requestID, Message: "火山引擎证书部署成功"}, nil
}
