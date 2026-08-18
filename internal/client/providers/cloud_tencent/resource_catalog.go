package cloud_tencent

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	tencentCatalogPageSize    = 100
	tencentCatalogMaxPages    = 100
	tencentCatalogMaxCount    = 10000
	tencentCatalogConcurrency = 4
)

// DiscoverResources 实时读取腾讯云指定产品的资源目录。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if strings.TrimSpace(p.SecretId) == "" || strings.TrimSpace(p.SecretKey) == "" {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
	}
	var resources []providers.DeploymentResource
	var partial bool
	var err error
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		resources, partial, err = p.discoverCDNResources(ctx)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE:
		resources, partial, err = p.discoverEdgeOneResources(ctx)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_COS:
		resources, partial, err = p.discoverCOSResources(ctx)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		resources, partial, err = p.discoverCLBResources(ctx)
	default:
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: fmt.Errorf("腾讯云不支持该资源业务")}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if err != nil && len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if providers.IsPermissionDenied(err) || isCOSPermissionDenied(err) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
	} else if partial || err != nil {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
	} else if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].Label < resources[right].Label })
	return providers.ResourceCatalogResult{Resources: resources, Status: status, Error: err}
}

// ResolveResource 实时扫描腾讯云产品并按引用唯一解析私有资源。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, fmt.Errorf("腾讯云资源目录不可用: %w", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 只读确认腾讯云资源仍存在且可精确部署。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return err
	}
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		client, err := p.getCDNClient()
		if err != nil {
			return err
		}
		_, _, err = describeCDNDomain(ctx, client, resource.Domain)
		return err
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE:
		client, err := p.getTEOClient()
		if err != nil {
			return err
		}
		_, _, err = describeEdgeOneHost(ctx, client, resource.ZoneID, resource.Domain)
		return err
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_COS:
		client, err := p.getCOSClient(resource)
		if err != nil {
			return err
		}
		domains, _, err := client.GetDomains(ctx)
		if err != nil {
			return err
		}
		if !containsEnabledCOSDomain(domains, resource.Domain) {
			return fmt.Errorf("COS 自定义域名已失效")
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		client, err := p.getCLBClient(resource)
		if err != nil {
			return err
		}
		listener, _, err := describeCLBListener(ctx, client, resource)
		if err != nil {
			return err
		}
		_, err = selectCLBCertificateSlot(resource.Domain, listener)
		return err
	default:
		return fmt.Errorf("腾讯云不支持该资源业务")
	}
}

// int64Value 安全读取 SDK int64 指针。
func int64Value(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

// uint64Value 安全读取 SDK uint64 指针。
func uint64Value(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}
