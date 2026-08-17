// Package huawei implements Huawei Cloud SCM, CDN, DCDN, OBS and ELB certificate deployment flows.
package huawei

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/global"
	sdkconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	cdnapi "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2"
	cdnmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2/model"
	cdnregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2/region"
	scmapi "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3"
	scmmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3/model"
	scmregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3/region"
)

const (
	defaultRegion            = "cn-north-4"
	defaultCertificateRegion = "cn-north-4"
	cdnPageSize              = 1000
	scmPageSize              = 50
	maxPages                 = 100
	maxResources             = 10000
	sdkTimeout               = 30 * time.Second
)

var (
	_             providers.ProviderHandler            = (*Provider)(nil)
	_             providers.DeploymentResourceProvider = (*Provider)(nil)
	regionPattern                                      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)
)

// scmClient 是华为云证书管理闭环所需的最小官方 SDK 接口。
type scmClient interface {
	ListCertificates(request *scmmodel.ListCertificatesRequest) (*scmmodel.ListCertificatesResponse, error)
	ImportCertificate(request *scmmodel.ImportCertificateRequest) (*scmmodel.ImportCertificateResponse, error)
	ShowCertificate(request *scmmodel.ShowCertificateRequest) (*scmmodel.ShowCertificateResponse, error)
}

// cdnClient 是华为云 CDN 和全站加速闭环所需的最小官方 SDK 接口。
type cdnClient interface {
	ListDomains(request *cdnmodel.ListDomainsRequest) (*cdnmodel.ListDomainsResponse, error)
	ShowDomainDetailByName(request *cdnmodel.ShowDomainDetailByNameRequest) (*cdnmodel.ShowDomainDetailByNameResponse, error)
	ShowDomainFullConfig(request *cdnmodel.ShowDomainFullConfigRequest) (*cdnmodel.ShowDomainFullConfigResponse, error)
	UpdateDomainMultiCertificates(request *cdnmodel.UpdateDomainMultiCertificatesRequest) (*cdnmodel.UpdateDomainMultiCertificatesResponse, error)
}

// Provider 保存华为云凭据、地域和各产品官方 SDK 客户端。
type Provider struct {
	accessKey         string               // accessKey 是华为云 Access Key ID。
	secretKey         string               // secretKey 是华为云 Secret Access Key。
	region            string               // region 是默认 OBS 和 ELB 地域。
	certificateRegion string               // certificateRegion 是 SCM 证书中心地域。
	regions           []string             // regions 是参与 OBS 和 ELB 资源发现的地域集合。
	scm               scmClient            // scm 负责证书导入、复用和指纹回读。
	cdn               cdnClient            // cdn 负责 CDN 和全站加速域名控制面。
	elbClients        map[string]elbClient // elbClients 按地域保存 ELB 控制面客户端。
	obsClients        map[string]obsClient // obsClients 按地域保存 OBS 控制面客户端。
}

// New 使用华为云官方 SDK 创建 provider。
func New(accessKey, secretKey, region, certificateRegion string, regions []string) (*Provider, error) {
	accessKey = strings.TrimSpace(accessKey)
	secretKey = strings.TrimSpace(secretKey)
	region = strings.TrimSpace(region)
	if region == "" {
		region = defaultRegion
	}
	certificateRegion = strings.TrimSpace(certificateRegion)
	if certificateRegion == "" {
		certificateRegion = defaultCertificateRegion
	}
	resolvedRegions, err := normalizeRegions(region, regions)
	if err != nil {
		return nil, err
	}

	globalCredential, err := global.NewCredentialsBuilder().WithAk(accessKey).WithSk(secretKey).SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云全局凭据失败: %w", err)
	}
	cdnHTTPClient, err := cdnapi.CdnClientBuilder().
		WithRegion(cdnregion.CN_NORTH_1).
		WithCredential(globalCredential).
		WithHttpConfig(sdkconfig.DefaultHttpConfig().WithTimeout(sdkTimeout)).
		SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云 CDN 客户端失败: %w", err)
	}

	certificateServiceRegion, err := scmregion.SafeValueOf(certificateRegion)
	if err != nil {
		return nil, fmt.Errorf("华为云 SCM 地域无效: %w", err)
	}
	certificateCredential, err := basic.NewCredentialsBuilder().WithAk(accessKey).WithSk(secretKey).SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云 SCM 凭据失败: %w", err)
	}
	scmHTTPClient, err := scmapi.ScmClientBuilder().
		WithRegion(certificateServiceRegion).
		WithCredential(certificateCredential).
		WithHttpConfig(sdkconfig.DefaultHttpConfig().WithTimeout(sdkTimeout)).
		SafeBuild()
	if err != nil {
		return nil, fmt.Errorf("创建华为云 SCM 客户端失败: %w", err)
	}

	elbClients, err := newELBClients(accessKey, secretKey, resolvedRegions)
	if err != nil {
		return nil, err
	}
	obsClients, err := newOBSClients(accessKey, secretKey, resolvedRegions)
	if err != nil {
		return nil, err
	}
	return newWithClients(
		accessKey,
		secretKey,
		region,
		certificateRegion,
		resolvedRegions,
		scmapi.NewScmClient(scmHTTPClient),
		cdnapi.NewCdnClient(cdnHTTPClient),
		elbClients,
		obsClients,
	), nil
}

// newWithClients 创建支持单元测试替身注入的华为云 provider。
func newWithClients(accessKey, secretKey, region, certificateRegion string, regions []string, scm scmClient, cdn cdnClient, elbClients map[string]elbClient, obsClients map[string]obsClient) *Provider {
	return &Provider{
		accessKey:         strings.TrimSpace(accessKey),
		secretKey:         strings.TrimSpace(secretKey),
		region:            strings.TrimSpace(region),
		certificateRegion: strings.TrimSpace(certificateRegion),
		regions:           append([]string(nil), regions...),
		scm:               scm,
		cdn:               cdn,
		elbClients:        elbClients,
		obsClients:        obsClients,
	}
}

// TestConnection 验证凭据可以读取 SCM 证书目录。
func (p *Provider) TestConnection() (bool, error) {
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	if p.scm == nil {
		return false, providers.NewDeploymentError("华为云 SCM 客户端未初始化", false, "", nil)
	}
	limit := int32(1)
	response, err := p.scm.ListCertificates(&scmmodel.ListCertificatesRequest{Limit: &limit})
	if err != nil {
		return false, toDeploymentError("测试连接", err)
	}
	if response == nil {
		return false, providers.NewDeploymentError("华为云测试连接响应为空", true, "", nil)
	}
	return true, nil
}

// UploadCertificate 导入或复用相同叶证书，并通过 SCM 详情指纹回读验收。
func (p *Provider) UploadCertificate(name, domain, certificatePEM, privateKeyPEM string) error {
	certificate := providers.CertificateMaterial{
		Name:           name,
		Domain:         domain,
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
	}
	if err := providers.ValidateCertificateMaterial(certificate, domain, time.Now()); err != nil {
		return providers.NewDeploymentError("华为云上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(context.Background(), certificate)
	return toDeploymentError("上传证书", err)
}

// DiscoverResources 实时发现华为云 CDN、DCDN、OBS 或 ELB 资源。
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
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		resources, partial, err = p.discoverCDNResources(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OBS_CUSTOM_DOMAIN:
		resources, partial, err = p.discoverOBSResources(ctx, deploymentType)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ELB:
		resources, partial, err = p.discoverELBResources(ctx, deploymentType)
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

// ResolveResource 重新发现资源并按不透明 targetRef 唯一解析。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("华为云资源目录不可用", false, requestIDFromError(catalog.Error), catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认华为云资源仍存在并处于可部署状态。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("华为云资源当前不可部署", false, "", err)
	}
	return nil
}

// DeployCertificate 将证书部署到精确的华为云资源并执行控制面回读验收。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("华为云目标缺少 targetRef 或域名", false, "", nil)
	}
	targetDomains := resource.Domains
	if len(targetDomains) == 0 {
		targetDomains = []string{resource.Domain}
	}
	if err := providers.ValidateCertificateForDomains(certificate, targetDomains, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("华为云证书校验失败", false, "", err)
	}
	scmCertificateID, requestID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}

	var message string
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		requestID, err = p.deployCDN(ctx, certificate, deploymentType, resource, scmCertificateID, requestID)
		message = "华为云 CDN 证书部署成功"
		if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN {
			message = "华为云 DCDN 证书部署成功"
		}
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OBS_CUSTOM_DOMAIN:
		requestID, err = p.deployOBS(ctx, certificate, resource, scmCertificateID, requestID)
		message = "华为云 OBS 自定义域名证书部署成功"
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ELB:
		requestID, err = p.deployELB(ctx, certificate, resource, scmCertificateID, requestID)
		message = "华为云 ELB 证书部署成功"
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("华为云不支持该部署业务", false, requestID, nil)
	}
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("部署证书", err)
	}
	return providers.DeploymentResult{RequestID: requestID, Message: message}, nil
}

// ensureCertificate 按稳定名称和叶证书 SHA-1 指纹复用或导入 SCM 证书。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	if p.scm == nil {
		return "", "", providers.NewDeploymentError("华为云 SCM 客户端未初始化", false, "", nil)
	}
	sha256Fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	sha1Fingerprint, err := leafCertificateSHA1(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	certificateName := "anssl-" + sha256Fingerprint[:32]
	certificateID, err := p.findCertificate(ctx, certificateName, sha1Fingerprint)
	if err != nil {
		return "", requestIDFromError(err), err
	}
	if certificateID != "" {
		return certificateID, "", nil
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	duplicateCheck := false
	response, err := p.scm.ImportCertificate(&scmmodel.ImportCertificateRequest{Body: &scmmodel.ImportCertificateRequestBody{
		Name:           certificateName,
		Certificate:    certificate.CertificatePEM,
		PrivateKey:     certificate.PrivateKeyPEM,
		DuplicateCheck: &duplicateCheck,
	}})
	if err != nil {
		return "", requestIDFromError(err), err
	}
	if response == nil || response.CertificateId == nil || strings.TrimSpace(*response.CertificateId) == "" {
		return "", "", providers.NewDeploymentError("华为云 SCM 导入响应缺少证书 ID", true, "", nil)
	}
	certificateID = strings.TrimSpace(*response.CertificateId)
	if err := p.verifySCMCertificate(ctx, certificateID, sha1Fingerprint); err != nil {
		return "", requestIDFromError(err), err
	}
	return certificateID, "", nil
}

// findCertificate 分页查找名称和 SHA-1 指纹均匹配的 SCM 证书。
func (p *Provider) findCertificate(ctx context.Context, certificateName, fingerprint string) (string, error) {
	limit := int32(scmPageSize)
	ownedBySelf := true
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		offset := int32(page * scmPageSize)
		response, err := p.scm.ListCertificates(&scmmodel.ListCertificatesRequest{
			Limit:       &limit,
			Offset:      &offset,
			Content:     &certificateName,
			OwnedBySelf: &ownedBySelf,
		})
		if err != nil {
			return "", err
		}
		if response == nil {
			return "", providers.NewDeploymentError("华为云 SCM 证书列表响应为空", true, "", nil)
		}
		items := []scmmodel.CertificateDetail{}
		if response.Certificates != nil {
			items = *response.Certificates
		}
		for _, item := range items {
			if item.Name != certificateName || strings.TrimSpace(item.Id) == "" {
				continue
			}
			matched, err := p.scmCertificateMatches(ctx, item.Id, fingerprint)
			if err != nil {
				return "", err
			}
			if matched {
				return strings.TrimSpace(item.Id), nil
			}
		}
		if len(items) < scmPageSize || response.TotalCount == nil || offset+int32(len(items)) >= *response.TotalCount {
			return "", nil
		}
	}
	return "", providers.NewDeploymentError("华为云 SCM 证书分页超过安全上限", false, "", nil)
}

// scmCertificateMatches 回读 SCM 证书详情并比较状态和 SHA-1 指纹。
func (p *Provider) scmCertificateMatches(ctx context.Context, certificateID, fingerprint string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	response, err := p.scm.ShowCertificate(&scmmodel.ShowCertificateRequest{CertificateId: certificateID})
	if err != nil {
		return false, err
	}
	if response == nil || response.Id == nil || strings.TrimSpace(*response.Id) != strings.TrimSpace(certificateID) {
		return false, nil
	}
	status := strings.ToUpper(stringPointerValue(response.Status))
	if status != "UPLOAD" && status != "ISSUED" {
		return false, nil
	}
	return normalizeFingerprint(stringPointerValue(response.Fingerprint)) == normalizeFingerprint(fingerprint), nil
}

// verifySCMCertificate 确认导入后的 SCM 证书 ID、状态和指纹均正确。
func (p *Provider) verifySCMCertificate(ctx context.Context, certificateID, fingerprint string) error {
	matched, err := p.scmCertificateMatches(ctx, certificateID, fingerprint)
	if err != nil {
		return err
	}
	if !matched {
		return providers.NewDeploymentError("华为云 SCM 证书指纹回读不一致", true, "", nil)
	}
	return nil
}

// discoverCDNResources 分页发现普通 CDN 或全站加速域名。
func (p *Provider) discoverCDNResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	if p.cdn == nil {
		return nil, false, providers.NewDeploymentError("华为云 CDN 客户端未初始化", false, "", nil)
	}
	resources := make([]providers.DeploymentResource, 0)
	partial := false
	pageSize := int32(cdnPageSize)
	for page := int32(1); page <= maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return resources, true, err
		}
		response, err := p.cdn.ListDomains(&cdnmodel.ListDomainsRequest{PageSize: &pageSize, PageNumber: &page})
		if err != nil {
			return resources, len(resources) > 0, err
		}
		if response == nil {
			return resources, len(resources) > 0, providers.NewDeploymentError("华为云 CDN 域名列表响应为空", true, "", nil)
		}
		items := []cdnmodel.Domains{}
		if response.Domains != nil {
			items = *response.Domains
		}
		for _, item := range items {
			businessType := strings.ToLower(stringPointerValue(item.BusinessType))
			if !matchesCDNDeploymentType(deploymentType, businessType) {
				continue
			}
			resource, ok := buildCDNResource(deploymentType, item)
			if !ok {
				partial = true
				continue
			}
			resources = append(resources, resource)
			if len(resources) > maxResources {
				return resources, true, providers.NewDeploymentError("华为云 CDN 资源数量超过安全上限", false, stringPointerValue(response.XRequestId), nil)
			}
		}
		if len(items) < cdnPageSize || response.Total == nil || page*pageSize >= *response.Total {
			break
		}
		if page == maxPages {
			partial = true
		}
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
	return resources, partial, nil
}

// buildCDNResource 将华为云域名记录转换为生命周期稳定的资源引用。
func buildCDNResource(deploymentType deployPB.DeploymentType, item cdnmodel.Domains) (providers.DeploymentResource, bool) {
	domain, err := providers.NormalizeDomain(stringPointerValue(item.DomainName))
	if err != nil || item.Id == nil || strings.TrimSpace(*item.Id) == "" || item.CreateTime == nil || *item.CreateTime <= 0 {
		return providers.DeploymentResource{}, false
	}
	identity := strings.TrimSpace(*item.Id)
	status := strings.ToLower(stringPointerValue(item.DomainStatus))
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	if status == "online" && int32PointerValue(item.Disabled) == 0 && int32PointerValue(item.Locked) == 0 {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	}
	protocol := "HTTP"
	if int32PointerValue(item.HttpsStatus) > 0 {
		protocol = "HTTPS"
	}
	region := "global"
	if item.ServiceArea != nil && strings.TrimSpace(item.ServiceArea.Value()) != "" {
		region = strings.TrimSpace(item.ServiceArea.Value())
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("huawei", deploymentType, identity, fmt.Sprint(*item.CreateTime)),
		Label:        domain,
		Domain:       domain,
		Domains:      []string{domain},
		Group:        strings.TrimSpace(stringPointerValue(item.BusinessType)),
		Region:       region,
		Protocol:     protocol,
		Status:       status,
		Availability: availability,
		ResourceID:   identity,
		CreatedAt:    fmt.Sprint(*item.CreateTime),
	}, true
}

// deployCDN 更新 CDN 或 DCDN 证书，同时保留回源、跳转和 HTTP/2 设置。
func (p *Provider) deployCDN(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource, scmCertificateID, requestID string) (string, error) {
	if p.cdn == nil {
		return requestID, providers.NewDeploymentError("华为云 CDN 客户端未初始化", false, requestID, nil)
	}
	if strings.TrimSpace(resource.ResourceID) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return requestID, providers.NewDeploymentError("华为云 CDN 目标缺少资源 ID 或创建时间", false, requestID, nil)
	}
	if err := ctx.Err(); err != nil {
		return requestID, err
	}
	preflight, err := p.cdn.ShowDomainDetailByName(&cdnmodel.ShowDomainDetailByNameRequest{DomainName: resource.Domain})
	if err != nil {
		return requestIDFromError(err), err
	}
	if preflight == nil {
		return requestID, providers.NewDeploymentError("华为云 CDN 域名详情响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(stringPointerValue(preflight.XRequestId), requestID)
	if !sameCDNIdentity(preflight.Domain, deploymentType, resource) {
		return requestID, providers.NewDeploymentError("华为云 CDN 域名身份或状态已变化，请重新关联资源", false, requestID, nil)
	}

	currentConfig, currentRequestID, err := p.readCDNConfig(ctx, resource.Domain)
	requestID = firstNonEmpty(currentRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	certificateName := stableCertificateName(certificate.CertificatePEM)
	httpsConfig := &cdnmodel.UpdateDomainMultiCertificatesRequestBodyContent{
		DomainName:       resource.Domain,
		HttpsSwitch:      1,
		CertName:         &certificateName,
		CertificateType:  int32Pointer(2),
		ScmCertificateId: &scmCertificateID,
		AccessOriginWay:  int32Pointer(originProtocolCode(currentConfig)),
	}
	preserveCDNHTTPSSettings(currentConfig, httpsConfig)
	response, err := p.cdn.UpdateDomainMultiCertificates(&cdnmodel.UpdateDomainMultiCertificatesRequest{
		Body: &cdnmodel.UpdateDomainMultiCertificatesRequestBody{Https: httpsConfig},
	})
	if err != nil {
		return requestIDFromError(err), err
	}
	if response == nil {
		return requestID, providers.NewDeploymentError("华为云 CDN 证书更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(stringPointerValue(response.XRequestId), requestID)
	if !cdnUpdateSucceeded(response, resource.Domain) {
		return requestID, providers.NewDeploymentError("华为云 CDN 证书更新未成功", false, requestID, nil)
	}

	readback, readbackRequestID, err := p.readCDNConfig(ctx, resource.Domain)
	requestID = firstNonEmpty(readbackRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	if err := verifyCDNReadback(readback, scmCertificateID, certificate.CertificatePEM); err != nil {
		return requestID, providers.NewDeploymentError("华为云 CDN 证书回读尚未生效", true, requestID, err)
	}
	return requestID, nil
}

// readCDNConfig 读取完整域名配置并返回请求 ID。
func (p *Provider) readCDNConfig(ctx context.Context, domain string) (*cdnmodel.ConfigsGetBody, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	response, err := p.cdn.ShowDomainFullConfig(&cdnmodel.ShowDomainFullConfigRequest{DomainName: domain})
	if err != nil {
		return nil, requestIDFromError(err), err
	}
	if response == nil || response.Configs == nil {
		return nil, stringPointerValue(responseRequestID(response)), providers.NewDeploymentError("华为云 CDN 完整配置响应为空", true, stringPointerValue(responseRequestID(response)), nil)
	}
	return response.Configs, stringPointerValue(response.XRequestId), nil
}

// responseRequestID 安全读取可能为空的 CDN 完整配置响应请求 ID。
func responseRequestID(response *cdnmodel.ShowDomainFullConfigResponse) *string {
	if response == nil {
		return nil
	}
	return response.XRequestId
}

// preserveCDNHTTPSSettings 将回读到的跳转和 HTTP/2 设置复制到证书更新请求。
func preserveCDNHTTPSSettings(config *cdnmodel.ConfigsGetBody, update *cdnmodel.UpdateDomainMultiCertificatesRequestBodyContent) {
	if config == nil || update == nil {
		return
	}
	if config.Https != nil && strings.EqualFold(stringPointerValue(config.Https.Http2Status), "on") {
		update.Http2 = int32Pointer(1)
	} else {
		update.Http2 = int32Pointer(0)
	}
	if config.ForceRedirect == nil {
		return
	}
	switchValue := int32(0)
	if strings.EqualFold(strings.TrimSpace(config.ForceRedirect.Status), "on") {
		switchValue = 1
	}
	redirectType := stringPointerValue(config.ForceRedirect.Type)
	if redirectType == "" {
		redirectType = "https"
	}
	update.ForceRedirectConfig = &cdnmodel.ForceRedirect{Switch: switchValue, RedirectType: redirectType}
}

// originProtocolCode 将完整配置中的回源协议转换为批量证书接口枚举。
func originProtocolCode(config *cdnmodel.ConfigsGetBody) int32 {
	if config == nil {
		return 2
	}
	switch strings.ToLower(stringPointerValue(config.OriginProtocol)) {
	case "follow":
		return 1
	case "https":
		return 3
	default:
		return 2
	}
}

// cdnUpdateSucceeded 校验批量更新的总状态和目标域名明细状态。
func cdnUpdateSucceeded(response *cdnmodel.UpdateDomainMultiCertificatesResponse, domain string) bool {
	if response == nil || !strings.EqualFold(stringPointerValue(response.Status), "success") {
		return false
	}
	if response.Result == nil || len(*response.Result) == 0 {
		return true
	}
	for _, result := range *response.Result {
		if strings.EqualFold(stringPointerValue(result.DomainName), domain) {
			return strings.EqualFold(stringPointerValue(result.Status), "success")
		}
	}
	return false
}

// verifyCDNReadback 核对 HTTPS 开关、SCM 证书 ID，并在响应包含 PEM 时核对指纹。
func verifyCDNReadback(config *cdnmodel.ConfigsGetBody, scmCertificateID, certificatePEM string) error {
	if config == nil || config.Https == nil || !strings.EqualFold(stringPointerValue(config.Https.HttpsStatus), "on") {
		return errors.New("HTTPS 尚未启用")
	}
	if int32PointerValue(config.Https.CertificateSource) != 2 || stringPointerValue(config.Https.ScmCertificateId) != scmCertificateID {
		return errors.New("SCM 证书 ID 回读不一致")
	}
	readbackPEM := stringPointerValue(config.Https.CertificateValue)
	if readbackPEM != "" {
		if err := providers.VerifyLeafCertificateSHA256(certificatePEM, readbackPEM); err != nil {
			return err
		}
	}
	return nil
}

// sameCDNIdentity 校验域名详情仍代表同一生命周期和部署类型。
func sameCDNIdentity(detail *cdnmodel.DomainsDetail, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) bool {
	if detail == nil || detail.Id == nil || detail.DomainName == nil || detail.CreateTime == nil {
		return false
	}
	domain, err := providers.NormalizeDomain(*detail.DomainName)
	if err != nil || domain != resource.Domain || strings.TrimSpace(*detail.Id) != resource.ResourceID || fmt.Sprint(*detail.CreateTime) != resource.CreatedAt {
		return false
	}
	return matchesCDNDeploymentType(deploymentType, strings.ToLower(stringPointerValue(detail.BusinessType))) && strings.EqualFold(stringPointerValue(detail.DomainStatus), "online") && int32PointerValue(detail.Disabled) == 0 && int32PointerValue(detail.Locked) == 0
}

// matchesCDNDeploymentType 区分普通 CDN 和 business_type=wholeSite 的 DCDN 域名。
func matchesCDNDeploymentType(deploymentType deployPB.DeploymentType, businessType string) bool {
	businessType = strings.ToLower(strings.TrimSpace(businessType))
	isDCDN := businessType == "wholesite" || businessType == "whole_site"
	if deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN {
		return isDCDN
	}
	return deploymentType == deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN && !isDCDN
}

// stableCertificateName 根据叶证书 SHA-256 生成满足云端长度约束的稳定名称。
func stableCertificateName(certificatePEM string) string {
	fingerprint, err := providers.LeafCertificateSHA256(certificatePEM)
	if err != nil || len(fingerprint) < 32 {
		return "anssl-certificate"
	}
	return "anssl-" + fingerprint[:32]
}

// leafCertificateSHA1 计算 SCM 详情返回格式对应的叶证书 SHA-1 指纹。
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
	return "", errors.New("未找到 PEM 证书块")
}

// splitCertificateChain 将完整 PEM 拆分为叶证书和剩余证书链。
func splitCertificateChain(certificatePEM string) (string, string, error) {
	remaining := []byte(certificatePEM)
	certificates := make([][]byte, 0)
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificates = append(certificates, pem.EncodeToMemory(block))
	}
	if len(certificates) == 0 {
		return "", "", errors.New("未找到 PEM 证书块")
	}
	leaf := string(certificates[0])
	chainBuilder := strings.Builder{}
	for _, certificate := range certificates[1:] {
		chainBuilder.Write(certificate)
	}
	return leaf, chainBuilder.String(), nil
}

// normalizeRegions 归一化并校验需要初始化的地域集合。
func normalizeRegions(primary string, regions []string) ([]string, error) {
	values := append([]string{strings.TrimSpace(primary)}, regions...)
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		region := strings.ToLower(strings.TrimSpace(value))
		if region == "" {
			continue
		}
		if !regionPattern.MatchString(region) {
			return nil, fmt.Errorf("华为云地域格式无效: %s", region)
		}
		if _, exists := seen[region]; exists {
			continue
		}
		seen[region] = struct{}{}
		result = append(result, region)
	}
	if len(result) == 0 {
		return nil, errors.New("华为云地域列表不能为空")
	}
	sort.Strings(result)
	return result, nil
}

// validateCredentials 拒绝空凭据和控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.secretKey) == "" {
		return providers.NewDeploymentError("华为云 accessKeyId 或 accessKeySecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.secretKey, "\r\n\x00") {
		return providers.NewDeploymentError("华为云访问密钥格式无效", false, "", nil)
	}
	return nil
}

// toDeploymentError 将华为云 SDK 错误转换为统一重试分类。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	retryable := false
	var serviceError *sdkerr.ServiceResponseError
	if errors.As(err, &serviceError) {
		code := strings.ToLower(strings.TrimSpace(serviceError.ErrorCode))
		retryable = serviceError.StatusCode == http.StatusTooManyRequests || serviceError.StatusCode >= http.StatusInternalServerError || strings.Contains(code, "throttl") || strings.Contains(code, "timeout") || strings.Contains(code, "internal")
	}
	if obsError, ok := asOBSError(err); ok {
		code := strings.ToLower(strings.TrimSpace(obsError.Code))
		retryable = obsError.StatusCode == http.StatusTooManyRequests || obsError.StatusCode >= http.StatusInternalServerError || strings.Contains(code, "slowdown") || strings.Contains(code, "timeout") || strings.Contains(code, "internal")
	}
	return providers.NewDeploymentError("华为云"+operation+"失败", retryable, requestIDFromError(err), err)
}

// isPermissionDenied 判断华为云错误是否属于认证或授权不足。
func isPermissionDenied(err error) bool {
	var serviceError *sdkerr.ServiceResponseError
	if errors.As(err, &serviceError) {
		code := strings.ToLower(strings.TrimSpace(serviceError.ErrorCode))
		return serviceError.StatusCode == http.StatusUnauthorized || serviceError.StatusCode == http.StatusForbidden || strings.Contains(code, "denied") || strings.Contains(code, "unauthorized") || strings.Contains(code, "forbidden")
	}
	if obsError, ok := asOBSError(err); ok {
		code := strings.ToLower(strings.TrimSpace(obsError.Code))
		return obsError.StatusCode == http.StatusUnauthorized || obsError.StatusCode == http.StatusForbidden || strings.Contains(code, "accessdenied")
	}
	return false
}

// requestIDFromError 提取华为云 SDK 错误中的请求 ID。
func requestIDFromError(err error) string {
	var serviceError *sdkerr.ServiceResponseError
	if errors.As(err, &serviceError) {
		return strings.TrimSpace(serviceError.RequestId)
	}
	if obsError, ok := asOBSError(err); ok {
		return strings.TrimSpace(obsError.RequestId)
	}
	return ""
}

// normalizeFingerprint 统一十六进制指纹的大小写和分隔符。
func normalizeFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.ReplaceAll(strings.ReplaceAll(value, ":", ""), "-", "")
}

// stringPointerValue 安全读取可选字符串。
func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

// int32PointerValue 安全读取可选 int32。
func int32PointerValue(value *int32) int32 {
	if value == nil {
		return 0
	}
	return *value
}

// int32Pointer 返回 int32 指针。
func int32Pointer(value int32) *int32 {
	return &value
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
