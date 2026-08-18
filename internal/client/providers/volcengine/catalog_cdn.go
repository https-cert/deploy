package volcengine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnapi "github.com/volcengine/volcengine-go-sdk/service/cdn"
	dcdnapi "github.com/volcengine/volcengine-go-sdk/service/dcdn"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
)

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
