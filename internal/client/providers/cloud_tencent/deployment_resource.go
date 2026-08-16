package cloud_tencent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	tencentcdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencenterrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	tencentteo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
	"github.com/tencentyun/cos-go-sdk-v5"
)

const (
	tencentCDNHost       = "cdn.tencentcloudapi.com"
	tencentTEOHost       = "teo.tencentcloudapi.com"
	tencentEdgeOneMode   = "sslcert"
	cosCustomCertType    = "CustomCert"
	cosDomainStatusReady = "ENABLED"
)

var (
	_                providers.DeploymentResourceDeployer = (*Provider)(nil)
	cosRegionPattern                                      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	cosBucketPattern                                      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}-[0-9]+$`)
)

// cdnClient 定义腾讯云 CDN 资源部署所需的最小 SDK 调用集合。
type cdnClient interface {
	// DescribeDomainsConfigWithContext 精确查询 CDN 域名及其完整 HTTPS 配置。
	DescribeDomainsConfigWithContext(ctx context.Context, request *tencentcdn.DescribeDomainsConfigRequest) (*tencentcdn.DescribeDomainsConfigResponse, error)
	// UpdateDomainConfigWithContext 更新 CDN 域名的 HTTPS 配置。
	UpdateDomainConfigWithContext(ctx context.Context, request *tencentcdn.UpdateDomainConfigRequest) (*tencentcdn.UpdateDomainConfigResponse, error)
}

// teoClient 定义腾讯云 EdgeOne SDK 的最小调用集合，避免测试访问真实控制面。
type teoClient interface {
	// DescribeZonesWithContext 分页查询 EdgeOne 站点目录。
	DescribeZonesWithContext(ctx context.Context, request *tencentteo.DescribeZonesRequest) (*tencentteo.DescribeZonesResponse, error)
	// DescribeHostsSettingWithContext 精确查询 EdgeOne 加速域名及证书配置。
	DescribeHostsSettingWithContext(ctx context.Context, request *tencentteo.DescribeHostsSettingRequest) (*tencentteo.DescribeHostsSettingResponse, error)
	// ModifyHostsCertificateWithContext 为指定加速域名绑定 SSL 托管证书。
	ModifyHostsCertificateWithContext(ctx context.Context, request *tencentteo.ModifyHostsCertificateRequest) (*tencentteo.ModifyHostsCertificateResponse, error)
}

// cosClient 定义腾讯云 COS Bucket 自定义域名证书接口的最小调用集合。
type cosClient interface {
	// GetDomains 查询 Bucket 已配置的自定义域名。
	GetDomains(ctx context.Context) (*cos.BucketGetDomainResult, *cos.Response, error)
	// PutDomainCertificate 为一个精确自定义域名写入 PEM 证书和私钥。
	PutDomainCertificate(ctx context.Context, options *cos.BucketPutDomainCertificateOptions) (*cos.Response, error)
	// GetDomainCertificate 回读一个精确自定义域名的证书状态。
	GetDomainCertificate(ctx context.Context, domain string) (*cos.BucketGetDomainCertificateResult, *cos.Response, error)
}

// cdnClientFactory 创建腾讯云 CDN SDK 客户端。
type cdnClientFactory func(secretID, secretKey string) (cdnClient, error)

// teoClientFactory 创建腾讯云 EdgeOne SDK 客户端。
type teoClientFactory func(secretID, secretKey string) (teoClient, error)

// cosClientFactory 创建绑定到指定地域和 Bucket 的腾讯云 COS SDK 客户端。
type cosClientFactory func(secretID, secretKey, region, bucket string) (cosClient, error)

// cosServiceClient 定义 COS 账户级 Bucket 目录接口。
type cosServiceClient interface {
	// ListBuckets 分页查询当前账户的 Bucket。
	ListBuckets(ctx context.Context, options *cos.ServiceGetOptions) (*cos.ServiceGetResult, *cos.Response, error)
}

// cosServiceClientFactory 创建 COS 账户级服务客户端。
type cosServiceClientFactory func(secretID, secretKey string) cosServiceClient

// sdkCOSClient 将官方 COS BucketService 适配为便于测试替换的最小接口。
type sdkCOSClient struct {
	client *cos.Client // client 是绑定到单个 COS Bucket endpoint 的官方 SDK 客户端。
}

// sdkCOSServiceClient 将官方 COS ServiceService 适配为最小接口。
type sdkCOSServiceClient struct {
	client *cos.Client // client 是只绑定账户级 COS service endpoint 的客户端。
}

// defaultCDNClientFactory 基于官方 SDK 构建腾讯云 CDN 客户端。
func defaultCDNClientFactory(secretID, secretKey string) (cdnClient, error) {
	clientProfile := newTencentClientProfile(tencentCDNHost)
	return tencentcdn.NewClient(tencentcommon.NewCredential(secretID, secretKey), "", clientProfile)
}

// defaultTEOClientFactory 基于官方 SDK 构建腾讯云 EdgeOne 客户端。
func defaultTEOClientFactory(secretID, secretKey string) (teoClient, error) {
	clientProfile := newTencentClientProfile(tencentTEOHost)
	return tencentteo.NewClient(tencentcommon.NewCredential(secretID, secretKey), "", clientProfile)
}

// newTencentClientProfile 创建带固定 endpoint 和超时的腾讯云 SDK 配置。
func newTencentClientProfile(endpoint string) *profile.ClientProfile {
	clientProfile := profile.NewClientProfile()
	httpProfile := profile.NewHttpProfile()
	httpProfile.Endpoint = endpoint
	httpProfile.ReqTimeout = defaultTimeoutInS
	clientProfile.HttpProfile = httpProfile
	return clientProfile
}

// defaultCOSClientFactory 基于官方 SDK 构建只访问指定 COS Bucket 的客户端。
func defaultCOSClientFactory(secretID, secretKey, region, bucket string) (cosClient, error) {
	if !cosRegionPattern.MatchString(region) {
		return nil, fmt.Errorf("COS region 格式无效")
	}
	if !cosBucketPattern.MatchString(bucket) {
		return nil, fmt.Errorf("COS bucket 必须使用 bucket-appid 格式")
	}

	bucketURL := &url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s.cos.%s.myqcloud.com", bucket, region),
	}
	httpClient := &http.Client{
		Timeout: time.Duration(defaultTimeoutInS) * time.Second,
		Transport: &cos.AuthorizationTransport{
			SecretID:  secretID,
			SecretKey: secretKey,
		},
	}
	return &sdkCOSClient{
		client: cos.NewClient(&cos.BaseURL{BucketURL: bucketURL}, httpClient),
	}, nil
}

// defaultCOSServiceClientFactory 构建腾讯云 COS 账户级服务客户端。
func defaultCOSServiceClientFactory(secretID, secretKey string) cosServiceClient {
	serviceURL := &url.URL{Scheme: "https", Host: "service.cos.myqcloud.com"}
	httpClient := &http.Client{
		Timeout: time.Duration(defaultTimeoutInS) * time.Second,
		Transport: &cos.AuthorizationTransport{
			SecretID:  secretID,
			SecretKey: secretKey,
		},
	}
	return &sdkCOSServiceClient{client: cos.NewClient(&cos.BaseURL{ServiceURL: serviceURL}, httpClient)}
}

// ListBuckets 查询 COS Bucket 目录。
func (c *sdkCOSServiceClient) ListBuckets(ctx context.Context, options *cos.ServiceGetOptions) (*cos.ServiceGetResult, *cos.Response, error) {
	return c.client.Service.Get(ctx, options)
}

// GetDomains 查询当前 COS Bucket 的自定义域名目录。
func (c *sdkCOSClient) GetDomains(ctx context.Context) (*cos.BucketGetDomainResult, *cos.Response, error) {
	return c.client.Bucket.GetDomain(ctx)
}

// PutDomainCertificate 写入当前 COS Bucket 的自定义域名证书。
func (c *sdkCOSClient) PutDomainCertificate(ctx context.Context, options *cos.BucketPutDomainCertificateOptions) (*cos.Response, error) {
	return c.client.Bucket.PutDomainCertificate(ctx, options)
}

// GetDomainCertificate 回读当前 COS Bucket 的自定义域名证书。
func (c *sdkCOSClient) GetDomainCertificate(ctx context.Context, domain string) (*cos.BucketGetDomainCertificateResult, *cos.Response, error) {
	return c.client.Bucket.GetDomainCertificate(ctx, &cos.BucketGetDomainCertificateOptions{DomainName: domain})
}

// getCDNClient 获取或初始化腾讯云 CDN SDK 客户端。
func (p *Provider) getCDNClient() (cdnClient, error) {
	if p.cdnClient != nil {
		return p.cdnClient, nil
	}
	if p.newCDNClient == nil {
		p.newCDNClient = defaultCDNClientFactory
	}
	client, err := p.newCDNClient(p.SecretId, p.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("初始化腾讯云 CDN SDK 客户端失败: %w", err)
	}
	p.cdnClient = client
	return p.cdnClient, nil
}

// getTEOClient 获取或初始化腾讯云 EdgeOne SDK 客户端。
func (p *Provider) getTEOClient() (teoClient, error) {
	if p.teoClient != nil {
		return p.teoClient, nil
	}
	if p.newTEOClient == nil {
		p.newTEOClient = defaultTEOClientFactory
	}
	client, err := p.newTEOClient(p.SecretId, p.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("初始化腾讯云 EdgeOne SDK 客户端失败: %w", err)
	}
	p.teoClient = client
	return p.teoClient, nil
}

// getCOSClient 创建绑定到一个精确 COS Bucket 的 SDK 客户端。
func (p *Provider) getCOSClient(target providers.DeploymentResource) (cosClient, error) {
	if p.newCOSClient == nil {
		p.newCOSClient = defaultCOSClientFactory
	}
	client, err := p.newCOSClient(p.SecretId, p.SecretKey, strings.TrimSpace(target.Region), strings.TrimSpace(target.Bucket))
	if err != nil {
		return nil, fmt.Errorf("初始化腾讯云 COS SDK 客户端失败: %w", err)
	}
	return client, nil
}

// DeployCertificate 将证书部署到一个明确腾讯云业务下精确解析出的资源。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("资源部署", err)
	}
	if err := p.validateDeploymentInput(certificate, deploymentType, resource); err != nil {
		return providers.DeploymentResult{}, err
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云部署资源证书校验失败", false, "", err)
	}

	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		return p.deployCDNCertificate(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE:
		return p.deployEdgeOneCertificate(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_COS:
		return p.deployCOSCertificate(ctx, certificate, resource)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		return p.deployCLBCertificate(ctx, certificate, resource)
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云不支持该部署业务", false, "", nil)
	}
}

// validateDeploymentInput 拒绝空凭据和缺少产品定位字段的调用。
func (p *Provider) validateDeploymentInput(certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, target providers.DeploymentResource) error {
	if strings.TrimSpace(target.TargetRef) == "" {
		return providers.NewDeploymentError("腾讯云 targetRef 不能为空", false, "", nil)
	}
	if strings.TrimSpace(p.SecretId) == "" || strings.TrimSpace(p.SecretKey) == "" {
		return providers.NewDeploymentError("腾讯云 SecretId 或 SecretKey 未配置", false, "", nil)
	}
	if strings.TrimSpace(target.Domain) == "" {
		return providers.NewDeploymentError("腾讯云部署资源域名不能为空", false, "", nil)
	}
	if strings.TrimSpace(certificate.CertificatePEM) == "" || strings.TrimSpace(certificate.PrivateKeyPEM) == "" {
		return providers.NewDeploymentError("腾讯云部署证书或私钥不能为空", false, "", nil)
	}

	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE:
		if strings.TrimSpace(target.ZoneID) == "" {
			return providers.NewDeploymentError("腾讯云 EdgeOne zoneId 不能为空", false, "", nil)
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_COS:
		if strings.TrimSpace(target.Region) == "" || strings.TrimSpace(target.Bucket) == "" {
			return providers.NewDeploymentError("腾讯云 COS region 和 bucket-appid 不能为空", false, "", nil)
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		if strings.TrimSpace(target.Region) == "" || strings.TrimSpace(target.LoadBalancerID) == "" || strings.TrimSpace(target.ListenerID) == "" {
			return providers.NewDeploymentError("腾讯云 CLB region、loadBalancerId 和 listenerId 不能为空", false, "", nil)
		}
		return nil
	default:
		return providers.NewDeploymentError("腾讯云不支持该部署业务", false, "", nil)
	}
}

// deployCDNCertificate 精确读取 CDN HTTPS 配置，仅替换服务端证书 ID，并回读确认。
func (p *Provider) deployCDNCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getCDNClient()
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 CDN 客户端", err)
	}

	domainConfig, _, err := describeCDNDomain(ctx, client, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if domainConfig.Https == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 目标缺少可保留的 HTTPS 配置", false, "", nil)
	}
	if !strings.EqualFold(strings.TrimSpace(stringValue(domainConfig.Https.Switch)), "on") {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 目标尚未启用 HTTPS", false, "", nil)
	}

	uploaded, err := p.uploadCertificateForDeployment(ctx, certificate, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	// UpdateDomainConfig 对复杂对象执行整对象更新，因此复制当前 HTTPS 策略并只替换 CertInfo。
	httpsConfig := *domainConfig.Https
	httpsConfig.CertInfo = &tencentcdn.ServerCert{CertId: tencentcommon.StringPtr(uploaded.CertificateID)}
	request := tencentcdn.NewUpdateDomainConfigRequest()
	request.Domain = tencentcommon.StringPtr(strings.TrimSpace(target.Domain))
	request.Https = &httpsConfig
	response, err := client.UpdateDomainConfigWithContext(ctx, request)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("更新 CDN 域名证书", err)
	}
	if response == nil || response.Response == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 更新响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))

	readBack, _, err := describeCDNDomain(ctx, client, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if readBack.Https == nil || readBack.Https.CertInfo == nil ||
		strings.TrimSpace(stringValue(readBack.Https.CertInfo.CertId)) != uploaded.CertificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CDN 证书回读尚未生效", true, requestID, nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, uploaded.CertificateID, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(requestID, fingerprintRequestID),
		Message:   "腾讯云 CDN 域名证书部署成功",
	}, nil
}

// describeCDNDomain 使用精确域名过滤并再次校验响应，避免修改相似域名。
func describeCDNDomain(ctx context.Context, client cdnClient, domain string) (*tencentcdn.DetailDomain, string, error) {
	request := tencentcdn.NewDescribeDomainsConfigRequest()
	request.Offset = tencentcommon.Int64Ptr(0)
	request.Limit = tencentcommon.Int64Ptr(5)
	request.Filters = []*tencentcdn.DomainFilter{
		{
			Name:  tencentcommon.StringPtr("domain"),
			Value: []*string{tencentcommon.StringPtr(strings.TrimSpace(domain))},
			Fuzzy: tencentcommon.BoolPtr(false),
		},
	}
	response, err := client.DescribeDomainsConfigWithContext(ctx, request)
	if err != nil {
		return nil, "", newTencentDeploymentError("查询 CDN 域名配置", err)
	}
	if response == nil || response.Response == nil {
		return nil, "", providers.NewDeploymentError("腾讯云 CDN 查询响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	for _, candidate := range response.Response.Domains {
		if candidate != nil && strings.EqualFold(strings.TrimSpace(stringValue(candidate.Domain)), strings.TrimSpace(domain)) {
			return candidate, requestID, nil
		}
	}
	return nil, requestID, providers.NewDeploymentError("腾讯云 CDN 未找到配置的精确域名", false, requestID, nil)
}

// deployEdgeOneCertificate 校验精确 Zone/Host，绑定 SSL 托管证书，并回读确认。
func (p *Provider) deployEdgeOneCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getTEOClient()
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 EdgeOne 客户端", err)
	}
	if _, _, err := describeEdgeOneHost(ctx, client, target.ZoneID, target.Domain); err != nil {
		return providers.DeploymentResult{}, err
	}

	uploaded, err := p.uploadCertificateForDeployment(ctx, certificate, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	request := tencentteo.NewModifyHostsCertificateRequest()
	request.ZoneId = tencentcommon.StringPtr(strings.TrimSpace(target.ZoneID))
	request.Hosts = []*string{tencentcommon.StringPtr(strings.TrimSpace(target.Domain))}
	request.Mode = tencentcommon.StringPtr(tencentEdgeOneMode)
	request.ServerCertInfo = []*tencentteo.ServerCertInfo{
		{CertId: tencentcommon.StringPtr(uploaded.CertificateID)},
	}
	response, err := client.ModifyHostsCertificateWithContext(ctx, request)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("更新 EdgeOne 域名证书", err)
	}
	if response == nil || response.Response == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 EdgeOne 更新响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))

	readBack, _, err := describeEdgeOneHost(ctx, client, target.ZoneID, target.Domain)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if !edgeOneHostContainsCertificate(readBack, uploaded.CertificateID) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 EdgeOne 证书回读尚未生效", true, requestID, nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, uploaded.CertificateID, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(requestID, fingerprintRequestID),
		Message:   "腾讯云 EdgeOne 域名证书部署成功",
	}, nil
}

// describeEdgeOneHost 使用 Zone ID 和精确 Host 过滤并再次校验响应。
func describeEdgeOneHost(ctx context.Context, client teoClient, zoneID, host string) (*tencentteo.DetailHost, string, error) {
	request := tencentteo.NewDescribeHostsSettingRequest()
	request.ZoneId = tencentcommon.StringPtr(strings.TrimSpace(zoneID))
	request.Offset = tencentcommon.Int64Ptr(0)
	request.Limit = tencentcommon.Int64Ptr(20)
	request.Filters = []*tencentteo.Filter{
		{
			Name:   tencentcommon.StringPtr("host"),
			Values: []*string{tencentcommon.StringPtr(strings.TrimSpace(host))},
		},
	}
	response, err := client.DescribeHostsSettingWithContext(ctx, request)
	if err != nil {
		return nil, "", newTencentDeploymentError("查询 EdgeOne 域名配置", err)
	}
	if response == nil || response.Response == nil {
		return nil, "", providers.NewDeploymentError("腾讯云 EdgeOne 查询响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	for _, candidate := range response.Response.DetailHosts {
		if candidate == nil || !strings.EqualFold(strings.TrimSpace(stringValue(candidate.Host)), strings.TrimSpace(host)) {
			continue
		}
		candidateZoneID := strings.TrimSpace(stringValue(candidate.ZoneId))
		if candidateZoneID != "" && candidateZoneID != strings.TrimSpace(zoneID) {
			continue
		}
		return candidate, requestID, nil
	}
	return nil, requestID, providers.NewDeploymentError("腾讯云 EdgeOne 未找到配置的精确 Zone/Host", false, requestID, nil)
}

// edgeOneHostContainsCertificate 判断 EdgeOne 回读配置是否包含刚绑定的证书 ID。
func edgeOneHostContainsCertificate(host *tencentteo.DetailHost, certificateID string) bool {
	if host == nil || host.Https == nil {
		return false
	}
	for _, certificate := range host.Https.CertInfo {
		if certificate != nil && strings.TrimSpace(stringValue(certificate.CertId)) == certificateID {
			return true
		}
	}
	return false
}

// deployCOSCertificate 校验 Bucket 自定义域名，写入 PEM 证书和私钥，并回读确认。
func (p *Provider) deployCOSCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getCOSClient(target)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 COS 客户端", err)
	}

	domains, response, err := client.GetDomains(ctx)
	if err != nil {
		return providers.DeploymentResult{}, newCOSDeploymentError("查询 COS 自定义域名", err)
	}
	readRequestID := cosRequestID(response)
	if domains == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 自定义域名查询响应格式异常", true, readRequestID, nil)
	}
	if !containsEnabledCOSDomain(domains, target.Domain) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 未找到已启用的精确自定义域名", false, readRequestID, nil)
	}

	putResponse, err := client.PutDomainCertificate(ctx, &cos.BucketPutDomainCertificateOptions{
		CertificateInfo: &cos.BucketDomainCertificateInfo{
			CertType: cosCustomCertType,
			CustomCert: &cos.BucketDomainCustomCert{
				Cert:       certificate.CertificatePEM,
				PrivateKey: certificate.PrivateKeyPEM,
			},
		},
		DomainList: []string{strings.TrimSpace(target.Domain)},
	})
	if err != nil {
		return providers.DeploymentResult{}, newCOSDeploymentError("更新 COS 自定义域名证书", err)
	}
	requestID := cosRequestID(putResponse)

	readBack, readBackResponse, err := client.GetDomainCertificate(ctx, strings.TrimSpace(target.Domain))
	if err != nil {
		return providers.DeploymentResult{}, newCOSDeploymentError("回读 COS 自定义域名证书", err)
	}
	if requestID == "" {
		requestID = cosRequestID(readBackResponse)
	}
	if readBack == nil || !strings.EqualFold(strings.TrimSpace(readBack.Status), cosDomainStatusReady) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 证书回读尚未生效", true, requestID, nil)
	}
	if readBack.CertificateInfo == nil || strings.TrimSpace(readBack.CertificateInfo.CertId) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 COS 证书回读缺少证书 ID", true, requestID, nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, readBack.CertificateInfo.CertId, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(requestID, fingerprintRequestID),
		Message:   "腾讯云 COS 自定义域名证书部署成功",
	}, nil
}

// containsEnabledCOSDomain 检查 Bucket 域名目录中是否存在完全匹配且启用的自定义域名。
func containsEnabledCOSDomain(result *cos.BucketGetDomainResult, domain string) bool {
	if result == nil {
		return false
	}
	for _, rule := range result.Rules {
		if strings.EqualFold(strings.TrimSpace(rule.Name), strings.TrimSpace(domain)) &&
			strings.EqualFold(strings.TrimSpace(rule.Status), cosDomainStatusReady) {
			return true
		}
	}
	return false
}

// uploadCertificateForDeployment 上传腾讯云 SSL 证书并将错误转换为结构化部署错误。
func (p *Provider) uploadCertificateForDeployment(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (certificateUploadResult, error) {
	name := strings.TrimSpace(certificate.Name)
	if name == "" {
		name = strings.TrimSpace(target.Label)
	}
	if name == "" {
		name = strings.TrimSpace(target.Domain)
	}
	uploaded, err := p.uploadCertificateWithContext(
		ctx,
		name,
		target.Domain,
		certificate.CertificatePEM,
		certificate.PrivateKeyPEM,
	)
	if err != nil {
		return certificateUploadResult{}, newTencentDeploymentError("上传 SSL 证书", err)
	}
	return uploaded, nil
}

// newTencentDeploymentError 将 SDK、网络和 context 错误转换为统一的重试语义。
func newTencentDeploymentError(action string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}

	requestID := ""
	retryable := isRetryableTransportError(err)
	message := fmt.Sprintf("腾讯云%s失败", action)
	var sdkError *tencenterrors.TencentCloudSDKError
	if errors.As(err, &sdkError) {
		code := strings.TrimSpace(sdkError.GetCode())
		requestID = strings.TrimSpace(sdkError.GetRequestId())
		retryable = isRetryableTencentCode(code)
		if code != "" {
			message = fmt.Sprintf("腾讯云%s失败(code=%s)", action, code)
		}
	}
	return providers.NewDeploymentError(message, retryable, requestID, err)
}

// newCOSDeploymentError 将 COS SDK 错误转换为统一的重试语义和请求 ID。
func newCOSDeploymentError(action string, err error) error {
	if err == nil {
		return nil
	}
	requestID := ""
	retryable := isRetryableTransportError(err)
	message := fmt.Sprintf("腾讯云%s失败", action)
	var responseError *cos.ErrorResponse
	if errors.As(err, &responseError) {
		requestID = strings.TrimSpace(responseError.RequestID)
		statusCode := 0
		if responseError.Response != nil {
			statusCode = responseError.Response.StatusCode
			if requestID == "" {
				requestID = strings.TrimSpace(responseError.Response.Header.Get("X-Cos-Request-Id"))
			}
		}
		retryable = isRetryableHTTPStatus(statusCode)
		code := strings.TrimSpace(responseError.Code)
		if code != "" {
			message = fmt.Sprintf("腾讯云%s失败(code=%s)", action, code)
		}
	}
	return providers.NewDeploymentError(message, retryable, requestID, err)
}

// isRetryableTencentCode 判断腾讯云 API 错误码是否适合由任务队列重试。
func isRetryableTencentCode(code string) bool {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if strings.HasPrefix(normalized, "internalerror") ||
		strings.HasPrefix(normalized, "requestlimitexceeded") ||
		strings.HasPrefix(normalized, "limitexceeded") {
		return true
	}
	return strings.Contains(normalized, "inprogress") ||
		strings.Contains(normalized, "toooften") ||
		strings.Contains(normalized, "timeout") ||
		strings.Contains(normalized, "temporarilyunavailable")
}

// isRetryableTransportError 判断 context deadline 或临时网络错误是否适合重试。
func isRetryableTransportError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

// isRetryableHTTPStatus 判断 COS HTTP 状态码是否表示临时失败。
func isRetryableHTTPStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusConflict ||
		statusCode == http.StatusTooManyRequests ||
		statusCode >= http.StatusInternalServerError
}

// cosRequestID 从 COS 成功响应头提取请求 ID。
func cosRequestID(response *cos.Response) string {
	if response == nil || response.Response == nil {
		return ""
	}
	return strings.TrimSpace(response.Header.Get("X-Cos-Request-Id"))
}
