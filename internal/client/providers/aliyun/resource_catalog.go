package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	aliyunCatalogPageSize    = 100
	aliyunCatalogMaxPages    = 100
	aliyunCatalogMaxCount    = 10000
	aliyunCatalogConcurrency = 4
)

// DiscoverResources 实时读取阿里云指定产品的资源目录。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if strings.TrimSpace(p.AccessKeyId) == "" || strings.TrimSpace(p.AccessKeySecret) == "" {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
	}
	var resources []providers.DeploymentResource
	var partial bool
	var err error
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		resources, partial, err = p.discoverAcceleratedResources(ctx, deploymentType, acceleratedProduct{
			Endpoint: aliyunCDNEndpoint, Version: aliyunCDNVersion, DisplayName: "CDN",
		}, "DescribeUserDomains", "Domains", "PageNumber", "PageSize")
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		resources, partial, err = p.discoverAcceleratedResources(ctx, deploymentType, acceleratedProduct{
			Endpoint: aliyunDCDNEndpoint, Version: aliyunDCDNVersion, DisplayName: "DCDN",
		}, "DescribeDcdnUserDomains", "Domains", "PageNumber", "PageSize")
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA:
		resources, partial, err = p.discoverESAResources(ctx)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN:
		resources, partial, err = p.discoverOSSResources(ctx)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		resources, partial, err = p.discoverCLBResources(ctx)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB:
		resources, partial, err = p.discoverModernLoadBalancerResources(ctx, deploymentType, "alb", aliyunALBVersion)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB:
		resources, partial, err = p.discoverModernLoadBalancerResources(ctx, deploymentType, "nlb", aliyunNLBVersion)
	default:
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE, Error: fmt.Errorf("阿里云不支持该资源业务")}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if err != nil && len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if providers.IsPermissionDenied(err) || isAliyunPermissionDenied(err) {
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

// isAliyunPermissionDenied 读取 Darabonba SDK 元数据并按明确错误码识别权限不足。
func isAliyunPermissionDenied(err error) bool {
	_, code, _ := aliyunErrorMetadata(err)
	return providers.IsPermissionDeniedCode(code)
}

// ResolveResource 实时扫描阿里云产品并按引用唯一解析私有资源。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, fmt.Errorf("阿里云资源目录不可用: %w", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 只读确认阿里云资源仍存在且具备精确证书槽位。
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
		product := aliyunCDNProduct()
		response, err := p.readAcceleratedDomain(ctx, resource.Domain, product)
		if err != nil {
			return err
		}
		return validateAcceleratedDomain(response.Body, resource.Domain, product)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		product := aliyunDCDNProduct()
		response, err := p.readAcceleratedDomain(ctx, resource.Domain, product)
		if err != nil {
			return err
		}
		return validateAcceleratedDomain(response.Body, resource.Domain, product)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA:
		response, err := p.listESACertificatesByRecord(ctx, resource.SiteID, resource.Domain)
		if err != nil {
			return err
		}
		if _, found := findESARecord(response.Body, resource.Domain); !found {
			return fmt.Errorf("ESA Record 已失效")
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN:
		result, err := p.ossAPI.ListCname(ctx, resource)
		if err != nil {
			return err
		}
		_, found := findExactOSSCname(result.Records, resource.Domain)
		if !found {
			return fmt.Errorf("OSS 自定义域名已失效")
		}
		return nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB:
		response, err := p.describeCLBDomainExtensions(ctx, resource, "")
		if err != nil {
			return err
		}
		extensions, err := parseCLBDomainExtensions(response.Body)
		if err != nil {
			return err
		}
		_, err = selectCLBCertificateSlot(resource.Domain, "", extensions)
		return err
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_ALB:
		return p.testModernLoadBalancerResource(ctx, resource, true)
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_NLB:
		return p.testModernLoadBalancerResource(ctx, resource, false)
	default:
		return fmt.Errorf("阿里云不支持该资源业务")
	}
}
