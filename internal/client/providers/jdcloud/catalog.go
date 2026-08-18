package jdcloud

import (
	"context"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	cdnapi "github.com/jdcloud-api/jdcloud-sdk-go/services/cdn/apis"
)

// DiscoverResources 分页读取京东云 CDN 域名并构建生命周期稳定的目标引用。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateCredentials(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	resources, err := p.listCDNResources(ctx, deploymentType)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if len(resources) > 0 {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
		} else if isPermissionDenied(err) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Resources: resources, Status: status, Error: err}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新读取 CDN 目录并按 targetRef 唯一解析京东云域名。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("京东云 CDN 资源目录不可用", false, requestIDFromError(catalog.Error), catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认京东云 CDN 域名仍存在且处于 online 状态。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("京东云 CDN 域名当前不可部署", false, "", err)
	}
	return nil
}

// listCDNResources 分页读取京东云域名，限制最大页数和资源数量。
func (p *Provider) listCDNResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, error) {
	if p.cdnClient == nil {
		return nil, providers.NewDeploymentError("京东云 CDN 客户端未初始化", false, "", nil)
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := 1; page <= resourceMaxPages; page++ {
		if err := ctx.Err(); err != nil {
			return resources, err
		}
		request := cdnapi.NewGetDomainListRequest()
		request.SetPageNumber(page)
		request.SetPageSize(resourcePageSize)
		response, err := p.cdnClient.GetDomainList(request)
		if err != nil {
			return resources, err
		}
		if err := checkResponse("读取 CDN 域名", responseRequestID(response), responseError(response)); err != nil {
			return resources, err
		}
		for _, item := range response.Result.Domains {
			domain, normalizeErr := providers.NormalizeDomain(item.Domain)
			if normalizeErr != nil {
				continue
			}
			identity, ok := providers.StableDomainIdentity("", domain, item.Created)
			if !ok {
				continue
			}
			status := strings.ToLower(strings.TrimSpace(item.Status))
			availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
			if status != "online" {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
			}
			resources = append(resources, providers.DeploymentResource{
				TargetRef:    providers.BuildTargetRef("jdcloud", deploymentType, identity),
				Label:        domain,
				Domain:       domain,
				Domains:      []string{domain},
				Protocol:     "HTTPS",
				Status:       status,
				Availability: availability,
				ResourceID:   identity,
				CreatedAt:    strings.TrimSpace(item.Created),
			})
			if len(resources) > resourceMaxCount {
				return resources, providers.NewDeploymentError("京东云 CDN 域名数量超过安全上限", false, response.RequestID, nil)
			}
		}
		if len(resources) >= response.Result.TotalCount || len(response.Result.Domains) < resourcePageSize {
			sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
			return resources, nil
		}
	}
	return resources, providers.NewDeploymentError("京东云 CDN 分页超过安全上限", false, "", nil)
}
