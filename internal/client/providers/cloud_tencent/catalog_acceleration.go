package cloud_tencent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	tencentcdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencentteo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
)

// discoverCDNResources 分页读取腾讯云 CDN 域名及 HTTPS 状态。
func (p *Provider) discoverCDNResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	client, err := p.getCDNClient()
	if err != nil {
		return nil, false, err
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := 0; page < tencentCatalogMaxPages && len(resources) < tencentCatalogMaxCount; page++ {
		request := tencentcdn.NewDescribeDomainsConfigRequest()
		request.Offset = tencentcommon.Int64Ptr(int64(page * tencentCatalogPageSize))
		request.Limit = tencentcommon.Int64Ptr(tencentCatalogPageSize)
		response, err := client.DescribeDomainsConfigWithContext(ctx, request)
		if err != nil {
			return resources, len(resources) > 0, err
		}
		if response == nil || response.Response == nil {
			return resources, len(resources) > 0, fmt.Errorf("CDN 域名目录响应格式异常")
		}
		for _, detail := range response.Response.Domains {
			if detail == nil {
				continue
			}
			if resource, ok := tencentCDNResource(detail); ok {
				resources = append(resources, resource)
			}
		}
		total := int64Value(response.Response.TotalNumber)
		if len(response.Response.Domains) < tencentCatalogPageSize || int64(len(resources)) >= total {
			return resources, false, nil
		}
	}
	return resources, true, fmt.Errorf("CDN 域名目录超过安全分页上限")
}

// tencentCDNResource 将 CDN SDK 记录映射为动态资源。
func tencentCDNResource(detail *tencentcdn.DetailDomain) (providers.DeploymentResource, bool) {
	domain, err := providers.NormalizeDomain(stringValue(detail.Domain))
	if err != nil {
		return providers.DeploymentResource{}, false
	}
	identity, ok := providers.StableDomainIdentity(stringValue(detail.ResourceId), domain, stringValue(detail.CreateTime))
	if !ok {
		return providers.DeploymentResource{}, false
	}
	status := strings.TrimSpace(stringValue(detail.Status))
	disable := strings.TrimSpace(stringValue(detail.Disable))
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	if strings.EqualFold(disable, "readonly") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_LOCKED
	} else if disable != "" && !strings.EqualFold(disable, "normal") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_DISABLED
	} else if !strings.EqualFold(status, "online") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	} else if detail.Https == nil || !strings.EqualFold(stringValue(detail.Https.Switch), "on") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_UNSUPPORTED
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, identity),
		Label:        domain,
		Domain:       domain,
		Domains:      []string{domain},
		Protocol:     "HTTPS",
		Status:       status,
		Availability: availability,
		ResourceID:   identity,
		CreatedAt:    strings.TrimSpace(stringValue(detail.CreateTime)),
	}, true
}

// discoverEdgeOneResources 分页读取站点并有限并发扫描 Host。
func (p *Provider) discoverEdgeOneResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	client, err := p.getTEOClient()
	if err != nil {
		return nil, false, err
	}
	zones, partial, err := listTencentZones(ctx, client)
	if err != nil {
		return nil, partial, err
	}
	type zoneResult struct {
		resources []providers.DeploymentResource
		err       error
	}
	results := make(chan zoneResult, len(zones))
	sem := make(chan struct{}, tencentCatalogConcurrency)
	var workers sync.WaitGroup
	for _, zone := range zones {
		zone := zone
		workers.Add(1)
		go func() {
			defer workers.Done()
			select {
			case <-ctx.Done():
				results <- zoneResult{err: ctx.Err()}
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()
			resources, _, scanErr := listTencentZoneHosts(ctx, client, zone)
			// Zone 没有可部署 Host 或 Host 扫描失败时保留只读行，避免控制台可见站点从目录中消失。
			if len(resources) == 0 {
				if zoneResource, ok := tencentEdgeOneZoneResource(zone); ok {
					resources = append(resources, zoneResource)
				}
			}
			results <- zoneResult{resources: resources, err: scanErr}
		}()
	}
	workers.Wait()
	close(results)
	resources := make([]providers.DeploymentResource, 0)
	var scanErr error
	for result := range results {
		resources = append(resources, result.resources...)
		if result.err != nil {
			partial = true
			scanErr = result.err
		}
	}
	return resources, partial, scanErr
}

// listTencentZones 分页读取 EdgeOne 站点。
func listTencentZones(ctx context.Context, client teoClient) ([]*tencentteo.Zone, bool, error) {
	zones := make([]*tencentteo.Zone, 0)
	for page := 0; page < tencentCatalogMaxPages; page++ {
		request := tencentteo.NewDescribeZonesRequest()
		request.Offset = tencentcommon.Int64Ptr(int64(page * tencentCatalogPageSize))
		request.Limit = tencentcommon.Int64Ptr(tencentCatalogPageSize)
		response, err := client.DescribeZonesWithContext(ctx, request)
		if err != nil {
			return zones, len(zones) > 0, err
		}
		if response == nil || response.Response == nil {
			return zones, len(zones) > 0, fmt.Errorf("EdgeOne 站点目录响应格式异常")
		}
		zones = append(zones, response.Response.Zones...)
		if len(response.Response.Zones) < tencentCatalogPageSize || int64(len(zones)) >= int64Value(response.Response.TotalCount) {
			return zones, false, nil
		}
	}
	return zones, true, fmt.Errorf("EdgeOne 站点目录超过安全分页上限")
}

// listTencentZoneHosts 分页读取单个 EdgeOne 站点的 Host。
func listTencentZoneHosts(ctx context.Context, client teoClient, zone *tencentteo.Zone) ([]providers.DeploymentResource, bool, error) {
	if zone == nil || strings.TrimSpace(stringValue(zone.ZoneId)) == "" {
		return nil, false, nil
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := 0; page < tencentCatalogMaxPages; page++ {
		request := tencentteo.NewDescribeHostsSettingRequest()
		request.ZoneId = zone.ZoneId
		request.Offset = tencentcommon.Int64Ptr(int64(page * 1000))
		request.Limit = tencentcommon.Int64Ptr(1000)
		response, err := client.DescribeHostsSettingWithContext(ctx, request)
		if err != nil {
			return resources, len(resources) > 0, err
		}
		if response == nil || response.Response == nil {
			return resources, len(resources) > 0, fmt.Errorf("EdgeOne Host 目录响应格式异常")
		}
		for _, host := range response.Response.DetailHosts {
			if resource, ok := tencentEdgeOneResource(zone, host); ok {
				resources = append(resources, resource)
			}
		}
		if len(response.Response.DetailHosts) < 1000 || int64(len(resources)) >= int64Value(response.Response.TotalNumber) {
			return resources, false, nil
		}
	}
	return resources, true, fmt.Errorf("EdgeOne Host 目录超过安全分页上限")
}

// tencentEdgeOneResource 将 EdgeOne Host 映射为动态资源。
func tencentEdgeOneResource(zone *tencentteo.Zone, host *tencentteo.DetailHost) (providers.DeploymentResource, bool) {
	if zone == nil || host == nil {
		return providers.DeploymentResource{}, false
	}
	domain, err := providers.NormalizeDomain(stringValue(host.Host))
	if err != nil || strings.TrimSpace(stringValue(host.Id)) == "" {
		return providers.DeploymentResource{}, false
	}
	status := strings.TrimSpace(stringValue(host.Status))
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	if host.Lock != nil && *host.Lock != 0 || !strings.EqualFold(stringValue(zone.LockStatus), "enable") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_LOCKED
	} else if !strings.EqualFold(status, "online") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE, stringValue(zone.ZoneId), stringValue(host.Id)),
		Label:        domain,
		Domain:       domain,
		Domains:      []string{domain},
		Group:        strings.TrimSpace(stringValue(zone.ZoneName)),
		Region:       strings.TrimSpace(stringValue(zone.Area)),
		Protocol:     "HTTPS",
		Status:       status,
		Availability: availability,
		ResourceID:   strings.TrimSpace(stringValue(host.Id)),
		ZoneID:       strings.TrimSpace(stringValue(zone.ZoneId)),
	}, true
}

// tencentEdgeOneZoneResource 将没有可配置 Host 的站点映射为只读目录占位项。
func tencentEdgeOneZoneResource(zone *tencentteo.Zone) (providers.DeploymentResource, bool) {
	if zone == nil {
		return providers.DeploymentResource{}, false
	}
	zoneID := strings.TrimSpace(stringValue(zone.ZoneId))
	zoneName, err := providers.NormalizeDomain(stringValue(zone.ZoneName))
	if zoneID == "" || err != nil || zoneName == "" {
		return providers.DeploymentResource{}, false
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.DeploymentType_DEPLOYMENT_TYPE_EDGEONE, zoneID, "zone"),
		Label:        zoneName,
		Domain:       zoneName,
		Domains:      []string{zoneName},
		Group:        "EdgeOne 站点",
		Region:       strings.TrimSpace(stringValue(zone.Area)),
		Protocol:     "SITE",
		Status:       strings.TrimSpace(stringValue(zone.Status)),
		Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_UNSUPPORTED,
		ZoneID:       zoneID,
	}, true
}
