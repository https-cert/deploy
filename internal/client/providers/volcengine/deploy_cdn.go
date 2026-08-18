package volcengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	dcdnapi "github.com/volcengine/volcengine-go-sdk/service/dcdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
)

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
