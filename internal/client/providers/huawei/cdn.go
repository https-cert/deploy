package huawei

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2/model"
)

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
