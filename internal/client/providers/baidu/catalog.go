package baidu

import (
	"context"
	"sort"
	"strings"

	cdnapi "github.com/baidubce/bce-sdk-go/services/cdn/api"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

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
