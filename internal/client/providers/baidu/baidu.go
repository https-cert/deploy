// Package baidu implements Baidu Cloud certificate-center upload and CDN deployment.
package baidu

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/baidubce/bce-sdk-go/bce"
	cdnservice "github.com/baidubce/bce-sdk-go/services/cdn"
	cdnapi "github.com/baidubce/bce-sdk-go/services/cdn/api"
	certservice "github.com/baidubce/bce-sdk-go/services/cert"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	cdnEndpoint         = "https://cdn.baidubce.com"
	certificateEndpoint = "https://certificate.baidubce.com"
	maxResourcePages    = 100
	maxResourceCount    = 10000
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
)

// cdnClient 是百度云 CDN 资源发现和 HTTPS 配置所需的最小官方 SDK 接口。
type cdnClient interface {
	ListDomains(marker string) ([]string, string, error)
	GetDomainConfig(domain string) (*cdnapi.DomainConfig, error)
	GetDomainHttps(domain string) (*cdnapi.HTTPSConfig, error)
	SetDomainHttps(domain string, httpsConfig *cdnapi.HTTPSConfig) error
}

// certificateClient 是百度云证书托管上传和回读所需的最小官方 SDK 接口。
type certificateClient interface {
	CreateCert(args *certservice.CreateCertArgs) (*certservice.CreateCertResult, error)
	ListCertDetail() (*certservice.ListCertDetailResult, error)
	GetCertDetail(id string) (*certservice.CertificateDetailMeta, error)
}

// Provider 保存百度云凭据及官方 SDK 客户端。
type Provider struct {
	accessKey         string            // accessKey 是百度云 Access Key ID。
	secretKey         string            // secretKey 是百度云 Secret Access Key。
	cdnClient         cdnClient         // cdnClient 负责 CDN 域名和 HTTPS 配置操作。
	certificateClient certificateClient // certificateClient 负责证书托管操作。
}

// New 使用 HTTPS 控制面创建百度云 provider。
func New(accessKey, secretKey string) (*Provider, error) {
	cdn, err := cdnservice.NewClient(strings.TrimSpace(accessKey), strings.TrimSpace(secretKey), cdnEndpoint)
	if err != nil {
		return nil, fmt.Errorf("初始化百度云 CDN 客户端失败: %w", err)
	}
	certificate, err := certservice.NewClient(strings.TrimSpace(accessKey), strings.TrimSpace(secretKey), certificateEndpoint)
	if err != nil {
		return nil, fmt.Errorf("初始化百度云证书客户端失败: %w", err)
	}
	return newWithClients(accessKey, secretKey, cdn, certificate), nil
}

// newWithClients 创建支持单元测试注入的百度云 provider。
func newWithClients(accessKey, secretKey string, cdn cdnClient, certificate certificateClient) *Provider {
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		cdnClient:         cdn,
		certificateClient: certificate,
	}
}

// TestConnection 验证凭据至少可以读取一页 CDN 域名目录。
func (p *Provider) TestConnection() (bool, error) {
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.cdnClient == nil {
		return false, providers.NewDeploymentError("百度云 CDN 客户端未初始化", false, "", nil)
	}
	_, _, err := p.cdnClient.ListDomains("")
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	return true, nil
}

// UploadCertificate 上传或复用百度云证书托管中的同一张叶证书，并回读验收。
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	certificate := providers.CertificateMaterial{
		Name:           name,
		Domain:         domain,
		CertificatePEM: cert,
		PrivateKeyPEM:  key,
	}
	if err := providers.ValidateCertificateMaterial(certificate, domain, time.Now()); err != nil {
		return providers.NewDeploymentError("百度云上传证书校验失败", false, "", err)
	}
	_, err := p.ensureCertificate(context.Background(), certificate)
	return toDeploymentError("上传证书", err)
}

// DiscoverResources 分页读取百度云 CDN 域名，并通过域名详情生成生命周期稳定的引用。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateCredentials(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	domains, err := p.listDomains(ctx)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if isPermissionDenied(err) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Status: status, Error: err}
	}

	resources := make([]providers.DeploymentResource, 0, len(domains))
	partial := false
	for _, listedDomain := range domains {
		if err := ctx.Err(); err != nil {
			return providers.ResourceCatalogResult{Resources: resources, Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL, Error: err}
		}
		config, detailErr := p.cdnClient.GetDomainConfig(listedDomain)
		if detailErr != nil || config == nil {
			partial = true
			continue
		}
		resource, ok := buildCDNResource(deploymentType, listedDomain, config)
		if !ok {
			partial = true
			continue
		}
		resources = append(resources, resource)
	}

	sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if partial {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
	} else if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新发现百度云 CDN 目录并按 targetRef 唯一解析资源。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("百度云 CDN 资源目录不可用", false, requestIDFromError(catalog.Error), catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认百度云 CDN 域名仍存在且运行状态允许部署。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("百度云 CDN 域名当前不可部署", false, "", err)
	}
	return nil
}

// DeployCertificate 上传或复用证书，更新精确 CDN 域名并回读证书 ID。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 目标缺少 targetRef、域名或创建时间", false, "", nil)
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 证书校验失败", false, "", err)
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 部署已取消", false, "", err)
	}
	current, err := p.cdnClient.GetDomainConfig(resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取 CDN 域名", err)
	}
	if err := validateCurrentResource(resource, current); err != nil {
		return providers.DeploymentResult{}, err
	}

	certificateID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}
	if err := ctx.Err(); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 部署已取消", false, "", err)
	}
	httpsConfig, err := p.cdnClient.GetDomainHttps(resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取 CDN HTTPS 配置", err)
	}
	if httpsConfig == nil {
		httpsConfig = &cdnapi.HTTPSConfig{}
	}
	updated := *httpsConfig
	updated.Enabled = true
	updated.CertId = certificateID
	if err := p.cdnClient.SetDomainHttps(resource.Domain, &updated); err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新 CDN HTTPS 配置", err)
	}
	readback, err := p.cdnClient.GetDomainHttps(resource.Domain)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读 CDN HTTPS 配置", err)
	}
	if readback == nil || !readback.Enabled || strings.TrimSpace(readback.CertId) != certificateID {
		return providers.DeploymentResult{}, providers.NewDeploymentError("百度云 CDN 证书回读尚未生效", true, "", nil)
	}
	return providers.DeploymentResult{Message: "百度云 CDN 证书部署成功"}, nil
}

// ensureCertificate 按叶证书指纹派生的稳定名称复用证书，或上传后回读验收。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, error) {
	if err := p.validateCredentials(); err != nil {
		return "", err
	}
	if p.certificateClient == nil {
		return "", providers.NewDeploymentError("百度云证书客户端未初始化", false, "", nil)
	}
	sha256Fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", err
	}
	sha1Fingerprint, err := leafCertificateSHA1(certificate.CertificatePEM)
	if err != nil {
		return "", err
	}
	certificateName := "anssl-" + sha256Fingerprint[:32]

	if err := ctx.Err(); err != nil {
		return "", err
	}
	list, err := p.certificateClient.ListCertDetail()
	if err != nil {
		return "", err
	}
	if list != nil {
		for index := range list.Certs {
			existing := &list.Certs[index]
			if strings.TrimSpace(existing.CertName) != certificateName || strings.TrimSpace(existing.CertId) == "" || existing.Expired {
				continue
			}
			if fingerprintMatches(existing.CertFingerprint, sha256Fingerprint, sha1Fingerprint) {
				return existing.CertId, nil
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return "", err
	}
	created, err := p.certificateClient.CreateCert(&certservice.CreateCertArgs{
		CertName:        certificateName,
		CertServerData:  certificate.CertificatePEM,
		CertPrivateData: certificate.PrivateKeyPEM,
	})
	if err != nil {
		return "", err
	}
	if created == nil || strings.TrimSpace(created.CertId) == "" {
		return "", providers.NewDeploymentError("百度云上传证书响应缺少 certId", false, "", nil)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	detail, err := p.certificateClient.GetCertDetail(created.CertId)
	if err != nil {
		return "", err
	}
	if detail == nil || strings.TrimSpace(detail.CertId) != strings.TrimSpace(created.CertId) || strings.TrimSpace(detail.CertName) != certificateName || detail.Expired {
		return "", providers.NewDeploymentError("百度云证书回读结果与上传请求不一致", true, "", nil)
	}
	if !fingerprintMatches(detail.CertFingerprint, sha256Fingerprint, sha1Fingerprint) {
		return "", providers.NewDeploymentError("百度云证书指纹回读不一致", false, "", nil)
	}
	return strings.TrimSpace(created.CertId), nil
}

// listDomains 分页读取百度云 CDN 域名，并拒绝循环游标和异常超量目录。
func (p *Provider) listDomains(ctx context.Context) ([]string, error) {
	if p.cdnClient == nil {
		return nil, providers.NewDeploymentError("百度云 CDN 客户端未初始化", false, "", nil)
	}
	marker := ""
	seenMarkers := make(map[string]struct{})
	domains := make([]string, 0)
	seenDomains := make(map[string]struct{})
	for page := 0; page < maxResourcePages; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pageDomains, nextMarker, err := p.cdnClient.ListDomains(marker)
		if err != nil {
			return nil, err
		}
		for _, rawDomain := range pageDomains {
			domain, normalizeErr := providers.NormalizeDomain(rawDomain)
			if normalizeErr != nil {
				continue
			}
			if _, exists := seenDomains[domain]; exists {
				continue
			}
			seenDomains[domain] = struct{}{}
			domains = append(domains, domain)
			if len(domains) > maxResourceCount {
				return nil, providers.NewDeploymentError("百度云 CDN 域名数量超过安全上限", false, "", nil)
			}
		}
		nextMarker = strings.TrimSpace(nextMarker)
		if nextMarker == "" {
			return domains, nil
		}
		if nextMarker == marker {
			return nil, providers.NewDeploymentError("百度云 CDN 分页游标未推进", true, "", nil)
		}
		if _, exists := seenMarkers[nextMarker]; exists {
			return nil, providers.NewDeploymentError("百度云 CDN 分页游标循环", true, "", nil)
		}
		seenMarkers[nextMarker] = struct{}{}
		marker = nextMarker
	}
	return nil, providers.NewDeploymentError("百度云 CDN 分页超过安全上限", false, "", nil)
}

// buildCDNResource 将百度云域名详情转换为可安全关联的部署资源。
func buildCDNResource(deploymentType deployPB.DeploymentType, listedDomain string, config *cdnapi.DomainConfig) (providers.DeploymentResource, bool) {
	rawDomain := strings.TrimSpace(config.Domain)
	if rawDomain == "" {
		rawDomain = listedDomain
	}
	domain, err := providers.NormalizeDomain(rawDomain)
	if err != nil {
		return providers.DeploymentResource{}, false
	}
	createdAt := strings.TrimSpace(config.CreateTime)
	identity, ok := providers.StableDomainIdentity("", domain, createdAt)
	if !ok {
		return providers.DeploymentResource{}, false
	}
	status := strings.ToUpper(strings.TrimSpace(config.Status))
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	if status != "RUNNING" {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	}
	protocol := "HTTP"
	if config.Https != nil && config.Https.Enabled {
		protocol = "HTTPS"
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("baidu", deploymentType, identity),
		Label:        domain,
		Domain:       domain,
		Domains:      []string{domain},
		Protocol:     protocol,
		Status:       status,
		Availability: availability,
		ResourceID:   identity,
		CreatedAt:    createdAt,
	}, true
}

// validateCurrentResource 防止同名域名删除重建后沿用旧 targetRef 部署。
func validateCurrentResource(resource providers.DeploymentResource, current *cdnapi.DomainConfig) error {
	if current == nil {
		return providers.NewDeploymentError("百度云 CDN 域名不存在", false, "", nil)
	}
	domain, err := providers.NormalizeDomain(current.Domain)
	if err != nil || domain != resource.Domain || strings.TrimSpace(current.CreateTime) != strings.TrimSpace(resource.CreatedAt) {
		return providers.NewDeploymentError("百度云 CDN 域名身份已变化，请重新关联资源", false, "", err)
	}
	if strings.ToUpper(strings.TrimSpace(current.Status)) != "RUNNING" {
		return providers.NewDeploymentError("百度云 CDN 域名当前不可部署", false, "", nil)
	}
	return nil
}

// leafCertificateSHA1 计算百度云可能返回的叶证书 SHA-1 指纹格式。
func leafCertificateSHA1(certificatePEM string) (string, error) {
	remaining := []byte(certificatePEM)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		fingerprint := sha1.Sum(certificate.Raw)
		return hex.EncodeToString(fingerprint[:]), nil
	}
	return "", fmt.Errorf("未找到 PEM 叶证书")
}

// fingerprintMatches 兼容百度云返回 SHA-1、SHA-256、冒号或短横线分隔格式。
func fingerprintMatches(actual string, expected ...string) bool {
	normalizedActual := normalizeFingerprint(actual)
	if normalizedActual == "" {
		return true
	}
	for _, value := range expected {
		if normalizedActual == normalizeFingerprint(value) {
			return true
		}
	}
	return false
}

// normalizeFingerprint 移除常见算法前缀和分隔符，只保留十六进制指纹。
func normalizeFingerprint(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, prefix := range []string{"sha-256:", "sha256:", "sha-1:", "sha1:"} {
		normalized = strings.TrimPrefix(normalized, prefix)
	}
	var builder strings.Builder
	for _, character := range normalized {
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

// validateCredentials 拒绝空凭据和可能污染签名输入的控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("百度云 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("百度云访问密钥格式无效", false, "", nil)
	}
	return nil
}

// isPermissionDenied 判断百度云凭据无效或权限不足错误。
func isPermissionDenied(err error) bool {
	var serviceError *bce.BceServiceError
	if !errors.As(err, &serviceError) {
		return false
	}
	return serviceError.StatusCode == http.StatusUnauthorized || serviceError.StatusCode == http.StatusForbidden ||
		serviceError.Code == bce.EACCESS_DENIED || serviceError.Code == bce.EINVALID_ACCESS_KEY_ID ||
		serviceError.Code == bce.ESIGNATURE_DOES_NOT_MATCH
}

// requestIDFromError 从百度云服务错误中提取请求 ID。
func requestIDFromError(err error) string {
	var serviceError *bce.BceServiceError
	if errors.As(err, &serviceError) {
		return strings.TrimSpace(serviceError.RequestId)
	}
	return ""
}

// toDeploymentError 将百度云 SDK 错误转换为统一的重试和请求 ID 分类。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	var serviceError *bce.BceServiceError
	if errors.As(err, &serviceError) {
		retryable := serviceError.StatusCode == http.StatusTooManyRequests || serviceError.StatusCode >= http.StatusInternalServerError || serviceError.Code == bce.EINTERNAL_ERROR
		return providers.NewDeploymentError("百度云"+operation+"失败", retryable, strings.TrimSpace(serviceError.RequestId), err)
	}
	return providers.NewDeploymentError("百度云"+operation+"失败", false, "", err)
}
