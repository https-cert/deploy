// Package volcengine implements verified Volcengine certificate deployment flows.
package volcengine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	dcdnapi "github.com/volcengine/volcengine-go-sdk/service/dcdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/credentials"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
	"github.com/volcengine/volcengine-go-sdk/volcengine/response"
	"github.com/volcengine/volcengine-go-sdk/volcengine/session"
	"github.com/volcengine/volcengine-go-sdk/volcengine/volcengineerr"
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
func (p *Provider) TestConnection() (bool, error) {
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.cdn == nil {
		return false, providers.NewDeploymentError("火山引擎 CDN 客户端未初始化", false, "", nil)
	}
	output, err := p.cdn.ListCertInfoWithContext(context.Background(), &cdnapi.ListCertInfoInput{Source: volcengine.String(certificateSource), PageNum: volcengine.Int32(1), PageSize: volcengine.Int32(1)})
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	if output == nil {
		return false, providers.NewDeploymentError("火山引擎测试连接响应为空", true, "", nil)
	}
	return true, nil
}

// UploadCertificate 将证书导入火山证书中心，并通过指纹目录回读验收。
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	certificate := providers.CertificateMaterial{Name: name, Domain: domain, CertificatePEM: cert, PrivateKeyPEM: key}
	if err := providers.ValidateCertificateMaterial(certificate, domain, time.Now()); err != nil {
		return providers.NewDeploymentError("火山引擎上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(context.Background(), certificate)
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

// discoverCDN 分页读取 CDN 域名并生成稳定资源引用。
func (p *Provider) discoverCDN(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, error) {
	if p.cdn == nil {
		return nil, providers.NewDeploymentError("火山引擎 CDN 客户端未初始化", false, "", nil)
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := int64(1); page <= maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return resources, err
		}
		output, err := p.cdn.ListCdnDomainsWithContext(ctx, &cdnapi.ListCdnDomainsInput{PageNum: volcengine.Int64(page), PageSize: volcengine.Int64(pageSize)})
		if err != nil {
			return resources, err
		}
		if output == nil {
			return resources, providers.NewDeploymentError("火山 CDN 域名列表响应为空", true, "", nil)
		}
		for _, item := range output.Data {
			if item == nil || item.Domain == nil || item.CreateTime == nil {
				continue
			}
			domain, normalizeErr := providers.NormalizeDomain(*item.Domain)
			if normalizeErr != nil {
				continue
			}
			identity, ok := providers.StableDomainIdentity("", domain, fmt.Sprint(*item.CreateTime))
			if !ok {
				continue
			}
			status := strings.ToLower(stringValue(item.Status))
			availability := resourceAvailability(status)
			resources = append(resources, providers.DeploymentResource{TargetRef: providers.BuildTargetRef("volcengine", deploymentType, p.region, identity), Label: domain, Domain: domain, Domains: []string{domain}, Region: stringValue(item.ServiceRegion), Protocol: protocolFromBool(item.HTTPS), Status: status, Availability: availability, ResourceID: identity, CreatedAt: fmt.Sprint(*item.CreateTime)})
			if len(resources) > maxResources {
				return resources, providers.NewDeploymentError("火山 CDN 资源数量超过安全上限", false, metadataRequestID(output.Metadata), nil)
			}
		}
		if output.Total == nil || page*pageSize >= *output.Total || len(output.Data) < pageSize {
			break
		}
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
	return resources, nil
}

// discoverDCDN 分页读取 DCDN 域名并生成稳定资源引用。
func (p *Provider) discoverDCDN(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, error) {
	if p.dcdn == nil {
		return nil, providers.NewDeploymentError("火山引擎 DCDN 客户端未初始化", false, "", nil)
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := int32(1); page <= maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return resources, err
		}
		output, err := p.dcdn.ListDomainConfigWithContext(ctx, &dcdnapi.ListDomainConfigInput{PageNumber: volcengine.Int32(page), PageSize: volcengine.Int32(pageSize)})
		if err != nil {
			return resources, err
		}
		if output == nil {
			return resources, providers.NewDeploymentError("火山 DCDN 域名列表响应为空", true, "", nil)
		}
		for _, item := range output.DomainList {
			if item == nil || item.Domain == nil || strings.TrimSpace(stringValue(item.CreateTime)) == "" {
				continue
			}
			domain, normalizeErr := providers.NormalizeDomain(*item.Domain)
			if normalizeErr != nil {
				continue
			}
			createdAt := stringValue(item.CreateTime)
			identity, ok := providers.StableDomainIdentity("", domain, createdAt)
			if !ok {
				continue
			}
			status := strings.ToLower(stringValue(item.Status))
			protocol := "HTTP"
			if item.Https != nil && item.Https.CertBind != nil && strings.TrimSpace(stringValue(item.Https.CertBind.CertId)) != "" {
				protocol = "HTTPS"
			}
			resources = append(resources, providers.DeploymentResource{TargetRef: providers.BuildTargetRef("volcengine", deploymentType, p.region, identity), Label: domain, Domain: domain, Domains: []string{domain}, Region: p.region, Protocol: protocol, Status: status, Availability: resourceAvailability(status), ResourceID: identity, CreatedAt: createdAt})
			if len(resources) > maxResources {
				return resources, providers.NewDeploymentError("火山 DCDN 资源数量超过安全上限", false, metadataRequestID(output.Metadata), nil)
			}
		}
		if output.Total == nil || int64(page)*int64(pageSize) >= int64(*output.Total) || len(output.DomainList) < pageSize {
			break
		}
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
	return resources, nil
}

// ensureCertificate 按叶证书 SHA-256 指纹复用或导入火山证书中心证书。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	if p.cdn == nil {
		return "", "", providers.NewDeploymentError("火山引擎 CDN 客户端未初始化", false, "", nil)
	}
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	certificateID, requestID, err := p.findCertificate(ctx, fingerprint)
	if err != nil {
		return "", requestID, err
	}
	if certificateID != "" {
		return certificateID, requestID, nil
	}
	if err := ctx.Err(); err != nil {
		return "", requestID, err
	}
	input := &cdnapi.AddCertificateInput{Certificate: volcengine.String(certificate.CertificatePEM), PrivateKey: volcengine.String(certificate.PrivateKeyPEM), Repeatable: volcengine.Bool(false), Source: volcengine.String(certificateSource)}
	output, err := p.cdn.AddCertificateWithContext(ctx, input)
	if err != nil {
		if duplicateID := certificateIDFromError(err); duplicateID != "" {
			return duplicateID, requestIDFromError(err), nil
		}
		return "", requestIDFromError(err), err
	}
	if output == nil {
		return "", requestID, providers.NewDeploymentError("火山引擎上传证书响应为空", true, requestID, nil)
	}
	requestID = metadataRequestID(output.Metadata)
	if output.CertId == nil || strings.TrimSpace(*output.CertId) == "" {
		return "", requestID, providers.NewDeploymentError("火山引擎上传证书响应缺少 certId", false, requestID, nil)
	}
	readbackID, readbackRequestID, err := p.findCertificateByID(ctx, *output.CertId, fingerprint)
	requestID = firstNonEmpty(readbackRequestID, requestID)
	if err != nil {
		return "", requestID, err
	}
	if readbackID != *output.CertId {
		return "", requestID, providers.NewDeploymentError("火山引擎证书指纹回读不一致", true, requestID, nil)
	}
	return *output.CertId, requestID, nil
}

// findCertificate 分页查找拥有目标叶证书指纹的证书。
func (p *Provider) findCertificate(ctx context.Context, fingerprint string) (string, string, error) {
	for page := int32(1); page <= maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return "", "", err
		}
		output, err := p.cdn.ListCertInfoWithContext(ctx, &cdnapi.ListCertInfoInput{Source: volcengine.String(certificateSource), PageNum: volcengine.Int32(page), PageSize: volcengine.Int32(pageSize)})
		if err != nil {
			return "", requestIDFromError(err), err
		}
		if output == nil {
			return "", "", providers.NewDeploymentError("火山引擎证书列表响应为空", true, "", nil)
		}
		for _, item := range output.CertInfo {
			if item != nil && strings.TrimSpace(stringValue(item.CertId)) != "" && certFingerprintMatches(item.CertFingerprint, fingerprint) {
				return stringValue(item.CertId), metadataRequestID(output.Metadata), nil
			}
		}
		if output.Total == nil || int64(page)*int64(pageSize) >= *output.Total || len(output.CertInfo) < pageSize {
			return "", metadataRequestID(output.Metadata), nil
		}
	}
	return "", "", providers.NewDeploymentError("火山引擎证书分页超过安全上限", false, "", nil)
}

// findCertificateByID 回读指定证书并核对叶证书指纹。
func (p *Provider) findCertificateByID(ctx context.Context, certificateID, fingerprint string) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	output, err := p.cdn.ListCertInfoWithContext(ctx, &cdnapi.ListCertInfoInput{Source: volcengine.String(certificateSource), CertId: volcengine.String(certificateID), PageNum: volcengine.Int32(1), PageSize: volcengine.Int32(1)})
	if err != nil {
		return "", requestIDFromError(err), err
	}
	if output == nil {
		return "", "", providers.NewDeploymentError("火山引擎证书详情响应为空", true, "", nil)
	}
	for _, item := range output.CertInfo {
		if item != nil && stringValue(item.CertId) == certificateID && certFingerprintMatches(item.CertFingerprint, fingerprint) {
			return certificateID, metadataRequestID(output.Metadata), nil
		}
	}
	return "", metadataRequestID(output.Metadata), nil
}

// deployCDN 更新 CDN HTTPS 证书并通过 DescribeCdnConfig 回读。
func (p *Provider) deployCDN(ctx context.Context, resource providers.DeploymentResource, certificateID, requestID string) (string, error) {
	if p.cdn == nil {
		return requestID, providers.NewDeploymentError("火山引擎 CDN 客户端未初始化", false, requestID, nil)
	}
	preflight, err := p.cdn.DescribeCdnConfigWithContext(ctx, &cdnapi.DescribeCdnConfigInput{Domain: volcengine.String(resource.Domain)})
	if err != nil {
		return requestIDFromError(err), err
	}
	if preflight == nil {
		return requestID, providers.NewDeploymentError("火山 CDN 域名详情响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(metadataRequestID(preflight.Metadata), requestID)
	if preflight.DomainConfig == nil || !sameCDNIdentity(resource, preflight.DomainConfig.Domain, preflight.DomainConfig.CreateTime, preflight.DomainConfig.Status) {
		return requestID, providers.NewDeploymentError("火山 CDN 域名身份或状态已变化，请重新关联资源", false, requestID, nil)
	}
	output, err := p.cdn.UpdateCdnConfigWithContext(ctx, &cdnapi.UpdateCdnConfigInput{Domain: volcengine.String(resource.Domain), HTTPS: &cdnapi.HTTPSForUpdateCdnConfigInput{Switch: volcengine.Bool(true), CertInfo: &cdnapi.CertInfoForUpdateCdnConfigInput{CertId: volcengine.String(certificateID)}}})
	if err != nil {
		return requestIDFromError(err), err
	}
	if output == nil {
		return requestID, providers.NewDeploymentError("火山 CDN 配置更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(metadataRequestID(output.Metadata), requestID)
	readback, err := p.cdn.DescribeCdnConfigWithContext(ctx, &cdnapi.DescribeCdnConfigInput{Domain: volcengine.String(resource.Domain)})
	if err != nil {
		return requestIDFromError(err), err
	}
	if readback == nil {
		return requestID, providers.NewDeploymentError("火山 CDN 配置回读响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(metadataRequestID(readback.Metadata), requestID)
	if !cdnHTTPSMatches(readback.DomainConfig, certificateID) {
		return requestID, providers.NewDeploymentError("火山 CDN 证书回读尚未生效", true, requestID, nil)
	}
	return requestID, nil
}

// deployDCDN 创建 DCDN 证书绑定并通过绑定列表回读。
func (p *Provider) deployDCDN(ctx context.Context, resource providers.DeploymentResource, certificateID, requestID string) (string, error) {
	if p.dcdn == nil {
		return requestID, providers.NewDeploymentError("火山引擎 DCDN 客户端未初始化", false, requestID, nil)
	}
	preflight, err := p.dcdn.DescribeDomainDetailWithContext(ctx, &dcdnapi.DescribeDomainDetailInput{Domain: volcengine.String(resource.Domain)})
	if err != nil {
		return requestIDFromError(err), err
	}
	if preflight == nil {
		return requestID, providers.NewDeploymentError("火山 DCDN 域名详情响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(metadataRequestID(preflight.Metadata), requestID)
	if preflight.Domain == nil || !sameIdentity(resource.Domain, resource.CreatedAt, *preflight.Domain, stringValue(preflight.CreateTime)) || !isOnline(stringValue(preflight.Status)) {
		return requestID, providers.NewDeploymentError("火山 DCDN 域名身份或状态已变化，请重新关联资源", false, requestID, nil)
	}
	output, err := p.dcdn.CreateCertBindWithContext(ctx, &dcdnapi.CreateCertBindInput{CertId: volcengine.String(certificateID), CertSource: volcengine.String(certificateSource), DomainNames: volcengine.StringSlice([]string{resource.Domain})})
	if err != nil {
		return requestIDFromError(err), err
	}
	if output == nil {
		return requestID, providers.NewDeploymentError("火山 DCDN 证书绑定响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(metadataRequestID(output.Metadata), requestID)
	if output.Success != nil && !*output.Success {
		return requestID, providers.NewDeploymentError("火山 DCDN 证书绑定失败", true, requestID, nil)
	}
	readback, err := p.dcdn.ListCertBindWithContext(ctx, &dcdnapi.ListCertBindInput{SearchKey: volcengine.String(resource.Domain)})
	if err != nil {
		return requestIDFromError(err), err
	}
	if readback == nil {
		return requestID, providers.NewDeploymentError("火山 DCDN 证书绑定回读响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(metadataRequestID(readback.Metadata), requestID)
	for _, item := range readback.BindList {
		if item != nil && strings.EqualFold(stringValue(item.DomainName), resource.Domain) && stringValue(item.CertId) == certificateID && isBindSuccessful(stringValue(item.DeployStatus)) {
			return requestID, nil
		}
	}
	return requestID, providers.NewDeploymentError("火山 DCDN 证书绑定回读尚未生效", true, requestID, nil)
}

// sameCDNIdentity 校验 CDN 域名、创建时间和可部署状态。
func sameCDNIdentity(resource providers.DeploymentResource, domain *string, createTime *int64, status *string) bool {
	if domain == nil || createTime == nil || *createTime == 0 {
		return false
	}
	normalized, err := providers.NormalizeDomain(*domain)
	return err == nil && normalized == resource.Domain && fmt.Sprint(*createTime) == resource.CreatedAt && isOnline(stringValue(status))
}

// sameIdentity 校验 DCDN 域名和创建时间是否仍代表同一资源。
func sameIdentity(expectedDomain, expectedCreate, actualDomain, actualCreate string) bool {
	normalized, err := providers.NormalizeDomain(actualDomain)
	return err == nil && normalized == expectedDomain && strings.TrimSpace(actualCreate) == strings.TrimSpace(expectedCreate)
}

// cdnHTTPSMatches 判断 CDN 回读配置是否启用目标证书。
func cdnHTTPSMatches(config *cdnapi.DomainConfigForDescribeCdnConfigOutput, certificateID string) bool {
	if config == nil || config.HTTPS == nil || config.HTTPS.Switch == nil || !*config.HTTPS.Switch {
		return false
	}
	if config.HTTPS.CertInfo != nil && stringValue(config.HTTPS.CertInfo.CertId) == certificateID {
		return true
	}
	for _, item := range config.HTTPS.CertInfoList {
		if item != nil && stringValue(item.CertId) == certificateID {
			return true
		}
	}
	return false
}

// certFingerprintMatches 比较火山 CDN 证书目录返回的 SHA-256 指纹。
func certFingerprintMatches(fingerprint *cdnapi.CertFingerprintForListCertInfoOutput, expected string) bool {
	return fingerprint != nil && normalizeFingerprint(stringValue(fingerprint.Sha256)) == normalizeFingerprint(expected)
}

// resourceAvailability 将云端运行状态转换为统一资源状态。
func resourceAvailability(status string) deployPB.DeploymentResourceAvailability {
	if isOnline(status) {
		return deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	}
	return deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
}

// isOnline 判断火山产品的可部署在线状态。
func isOnline(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status == "online" || status == "running" || status == "enabled" || status == "normal"
}

// isBindSuccessful 判断 DCDN 绑定状态，未知状态不能误判成功。
func isBindSuccessful(status string) bool {
	status = strings.ToLower(strings.TrimSpace(status))
	return status == "success" || status == "succeeded" || status == "normal"
}

// protocolFromBool 将 CDN HTTPS 开关转换为展示协议。
func protocolFromBool(enabled *bool) string {
	if enabled != nil && *enabled {
		return "HTTPS"
	}
	return "HTTP"
}

// stringValue 安全读取可选字符串指针。
func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// normalizeFingerprint 统一十六进制指纹的大小写和分隔符。
func normalizeFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(strings.ReplaceAll(value, ":", ""), "-", "")
	return value
}

// metadataRequestID 提取火山 SDK 响应元数据中的请求 ID。
func metadataRequestID(metadata *response.ResponseMetadata) string {
	if metadata == nil {
		return ""
	}
	return strings.TrimSpace(metadata.RequestId)
}

// certificateIDFromError 从重复证书错误中提取官方 cert- ID。
func certificateIDFromError(err error) string {
	if err == nil {
		return ""
	}
	match := regexp.MustCompile(`cert-[a-f0-9]{32}`).FindString(err.Error())
	return match
}

// requestIDFromError 提取火山 SDK 错误中的请求 ID。
func requestIDFromError(err error) string {
	var requestFailure volcengineerr.RequestFailure
	if errors.As(err, &requestFailure) {
		return strings.TrimSpace(requestFailure.RequestID())
	}
	return tosRequestID(err)
}

// isPermissionDenied 判断火山错误是否属于认证或授权不足。
func isPermissionDenied(err error) bool {
	var requestFailure volcengineerr.RequestFailure
	if errors.As(err, &requestFailure) && (requestFailure.StatusCode() == 401 || requestFailure.StatusCode() == 403) {
		return true
	}
	var serviceError volcengineerr.Error
	if errors.As(err, &serviceError) {
		code := strings.ToLower(serviceError.Code())
		return strings.Contains(code, "accessdenied") || strings.Contains(code, "unauthorized") || strings.Contains(code, "forbidden")
	}
	statusCode := tosStatusCode(err)
	code := strings.ToLower(tosErrorCode(err))
	return statusCode == 401 || statusCode == 403 || strings.Contains(code, "accessdenied") || strings.Contains(code, "unauthorized") || strings.Contains(code, "forbidden")
}

// toDeploymentError 将火山 SDK 错误转换成统一重试分类。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	retryable := false
	var requestFailure volcengineerr.RequestFailure
	if errors.As(err, &requestFailure) {
		retryable = requestFailure.StatusCode() == 429 || requestFailure.StatusCode() >= 500
	}
	var serviceError volcengineerr.Error
	if errors.As(err, &serviceError) {
		code := strings.ToLower(serviceError.Code())
		retryable = retryable || strings.Contains(code, "throttl") || strings.Contains(code, "internal") || strings.Contains(code, "timeout")
	}
	tosCode := strings.ToLower(tosErrorCode(err))
	tosHTTPStatus := tosStatusCode(err)
	retryable = retryable || tosHTTPStatus == 429 || tosHTTPStatus >= 500 || strings.Contains(tosCode, "slowdown") || strings.Contains(tosCode, "timeout") || strings.Contains(tosCode, "internal")
	return providers.NewDeploymentError("火山引擎"+operation+"失败", retryable, requestIDFromError(err), err)
}

// validateCredentials 拒绝空密钥和控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("火山引擎 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("火山引擎访问密钥格式无效", false, "", nil)
	}
	return nil
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
