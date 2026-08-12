package cloud_tencent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	tencentcdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	tencentclb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
	tencentteo "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/teo/v20220901"
	"github.com/tencentyun/cos-go-sdk-v5"
)

const (
	tencentCatalogPageSize    = 100
	tencentCatalogMaxPages    = 100
	tencentCatalogMaxCount    = 10000
	tencentCatalogConcurrency = 4
)

// DiscoverResources 实时读取腾讯云指定产品的资源目录。
func (p *Provider) DiscoverResources(ctx context.Context, business deployPB.ExecuteBusinesType) providers.ResourceCatalogResult {
	if strings.TrimSpace(p.SecretId) == "" || strings.TrimSpace(p.SecretKey) == "" {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
	}
	var resources []providers.DeploymentResource
	var partial bool
	var err error
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		resources, partial, err = p.discoverCDNResources(ctx)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE:
		resources, partial, err = p.discoverEdgeOneResources(ctx)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS:
		resources, partial, err = p.discoverCOSResources(ctx)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
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
func (p *Provider) ResolveResource(ctx context.Context, business deployPB.ExecuteBusinesType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, business)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, fmt.Errorf("腾讯云资源目录不可用: %w", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 只读确认腾讯云资源仍存在且可精确部署。
func (p *Provider) TestResource(ctx context.Context, business deployPB.ExecuteBusinesType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, business, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return err
	}
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		client, err := p.getCDNClient()
		if err != nil {
			return err
		}
		_, _, err = describeCDNDomain(ctx, client, resource.Domain)
		return err
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE:
		client, err := p.getTEOClient()
		if err != nil {
			return err
		}
		_, _, err = describeEdgeOneHost(ctx, client, resource.ZoneID, resource.Domain)
		return err
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS:
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
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
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
		TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN, identity),
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
		TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE, stringValue(zone.ZoneId), stringValue(host.Id)),
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
		TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_EDGEONE, zoneID, "zone"),
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

// discoverCOSResources 读取 Bucket 并有限并发扫描自定义域名。
func (p *Provider) discoverCOSResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	if p.cosService == nil {
		if p.newCOSService == nil {
			p.newCOSService = defaultCOSServiceClientFactory
		}
		p.cosService = p.newCOSService(p.SecretId, p.SecretKey)
	}
	buckets := make([]cos.Bucket, 0)
	marker := ""
	for page := 0; page < tencentCatalogMaxPages; page++ {
		response, _, err := p.cosService.ListBuckets(ctx, &cos.ServiceGetOptions{MaxKeys: 1000, Marker: marker})
		if err != nil {
			return nil, false, err
		}
		if response == nil {
			return nil, false, fmt.Errorf("COS Bucket 目录响应格式异常")
		}
		buckets = append(buckets, response.Buckets...)
		if !response.IsTruncated || response.NextMarker == "" {
			break
		}
		marker = response.NextMarker
		if page == tencentCatalogMaxPages-1 {
			return nil, true, fmt.Errorf("COS Bucket 目录超过安全分页上限")
		}
	}
	type bucketResult struct {
		resources []providers.DeploymentResource
		err       error
	}
	results := make(chan bucketResult, len(buckets))
	sem := make(chan struct{}, tencentCatalogConcurrency)
	var workers sync.WaitGroup
	for _, bucket := range buckets {
		bucket := bucket
		workers.Add(1)
		go func() {
			defer workers.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resources, err := p.readCOSBucketResources(ctx, bucket)
			results <- bucketResult{resources: resources, err: err}
		}()
	}
	workers.Wait()
	close(results)
	resources := make([]providers.DeploymentResource, 0)
	partial := false
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

// readCOSBucketResources 读取一个 Bucket 的全部自定义域名。
func (p *Provider) readCOSBucketResources(ctx context.Context, bucket cos.Bucket) ([]providers.DeploymentResource, error) {
	target := providers.DeploymentResource{Region: bucket.Region, Bucket: bucket.Name}
	client, err := p.getCOSClient(target)
	if err != nil {
		return nil, err
	}
	domains, _, err := client.GetDomains(ctx)
	if err != nil {
		if isCOSDomainConfigNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if domains == nil {
		return nil, fmt.Errorf("COS 自定义域名响应格式异常")
	}
	resources := make([]providers.DeploymentResource, 0, len(domains.Rules))
	for _, rule := range domains.Rules {
		domain, err := providers.NormalizeDomain(rule.Name)
		if err != nil {
			continue
		}
		availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
		if !strings.EqualFold(rule.Status, cosDomainStatusReady) {
			availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_DISABLED
		}
		resources = append(resources, providers.DeploymentResource{
			TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_COS, bucket.Name, bucket.CreationDate, domain),
			Label:        domain,
			Domain:       domain,
			Domains:      []string{domain},
			Group:        "COS Bucket",
			Region:       bucket.Region,
			Protocol:     "HTTPS",
			Status:       rule.Status,
			Availability: availability,
			Bucket:       bucket.Name,
			CreatedAt:    bucket.CreationDate,
		})
	}
	return resources, nil
}

// isCOSDomainConfigNotFound 判断 Bucket 尚未创建自定义域名配置的正常空状态。
func isCOSDomainConfigNotFound(err error) bool {
	var responseError *cos.ErrorResponse
	return errors.As(err, &responseError) && strings.EqualFold(strings.TrimSpace(responseError.Code), "DomainConfigNotFoundError")
}

// isCOSPermissionDenied 判断 COS 返回的错误码是否明确表示密钥无权访问资源。
func isCOSPermissionDenied(err error) bool {
	var responseError *cos.ErrorResponse
	return errors.As(err, &responseError) && providers.IsPermissionDeniedCode(responseError.Code)
}

// discoverCLBResources 使用 CVM 地域目录并发扫描现有 SNI 域名规则。
func (p *Provider) discoverCLBResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	regions, err := p.listTencentRegions(ctx)
	if err != nil {
		return nil, false, err
	}
	type regionResult struct {
		resources []providers.DeploymentResource
		err       error
	}
	results := make(chan regionResult, len(regions))
	sem := make(chan struct{}, tencentCatalogConcurrency)
	var workers sync.WaitGroup
	for _, region := range regions {
		region := region
		workers.Add(1)
		go func() {
			defer workers.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resources, err := p.listTencentRegionCLBResources(ctx, region)
			results <- regionResult{resources: resources, err: err}
		}()
	}
	workers.Wait()
	close(results)
	resources := make([]providers.DeploymentResource, 0)
	partial := false
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

// listTencentRegions 查询可用腾讯云地域。
func (p *Provider) listTencentRegions(ctx context.Context) ([]string, error) {
	if p.regionClient == nil {
		if p.newRegionClient == nil {
			p.newRegionClient = defaultRegionClientFactory
		}
		client, err := p.newRegionClient(p.SecretId, p.SecretKey)
		if err != nil {
			return nil, err
		}
		p.regionClient = client
	}
	response, err := p.regionClient.DescribeRegionsWithContext(ctx, cvm.NewDescribeRegionsRequest())
	if err != nil {
		return nil, err
	}
	if response == nil || response.Response == nil {
		return nil, fmt.Errorf("腾讯云地域目录响应格式异常")
	}
	regions := make([]string, 0, len(response.Response.RegionSet))
	for _, region := range response.Response.RegionSet {
		if region != nil && strings.EqualFold(stringValue(region.RegionState), "AVAILABLE") && stringValue(region.Region) != "" {
			regions = append(regions, stringValue(region.Region))
		}
	}
	return regions, nil
}

// listTencentRegionCLBResources 分页读取一个地域的实例及其 SNI 监听器。
func (p *Provider) listTencentRegionCLBResources(ctx context.Context, region string) ([]providers.DeploymentResource, error) {
	if p.newCLBClient == nil {
		p.newCLBClient = defaultCLBClientFactory
	}
	client, err := p.newCLBClient(p.SecretId, p.SecretKey, region)
	if err != nil {
		return nil, err
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := 0; page < tencentCatalogMaxPages; page++ {
		request := tencentclb.NewDescribeLoadBalancersRequest()
		request.Offset = tencentcommon.Int64Ptr(int64(page * tencentCatalogPageSize))
		request.Limit = tencentcommon.Int64Ptr(tencentCatalogPageSize)
		response, err := client.DescribeLoadBalancersWithContext(ctx, request)
		if err != nil {
			return resources, err
		}
		if response == nil || response.Response == nil {
			return resources, fmt.Errorf("CLB 实例目录响应格式异常")
		}
		for _, loadBalancer := range response.Response.LoadBalancerSet {
			found, err := listTencentCLBListeners(ctx, client, region, loadBalancer)
			if err != nil {
				return resources, err
			}
			resources = append(resources, found...)
		}
		if len(response.Response.LoadBalancerSet) < tencentCatalogPageSize || uint64((page+1)*tencentCatalogPageSize) >= uint64Value(response.Response.TotalCount) {
			return resources, nil
		}
	}
	return resources, fmt.Errorf("CLB 实例目录超过安全分页上限")
}

// listTencentCLBListeners 只映射 HTTPS 且开启 SNI 的域名规则。
func listTencentCLBListeners(ctx context.Context, client clbClient, region string, loadBalancer *tencentclb.LoadBalancer) ([]providers.DeploymentResource, error) {
	if loadBalancer == nil || stringValue(loadBalancer.LoadBalancerId) == "" {
		return nil, nil
	}
	request := tencentclb.NewDescribeListenersRequest()
	request.LoadBalancerId = loadBalancer.LoadBalancerId
	response, err := client.DescribeListenersWithContext(ctx, request)
	if err != nil {
		return nil, err
	}
	if response == nil || response.Response == nil {
		return nil, fmt.Errorf("CLB 监听器目录响应格式异常")
	}
	resources := make([]providers.DeploymentResource, 0)
	for _, listener := range response.Response.Listeners {
		if listener == nil || !strings.EqualFold(stringValue(listener.Protocol), tencentCLBHTTPS) || listener.SniSwitch == nil || *listener.SniSwitch != tencentCLBSNIEnabled {
			continue
		}
		for _, rule := range listener.Rules {
			for _, domain := range tencentCLBRuleDomains(rule) {
				normalized, err := providers.NormalizeDomain(domain)
				if err != nil || rule == nil || rule.Certificate == nil || len(rule.Certificate.ExtCertIds) > 0 {
					continue
				}
				availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
				if rule.DefaultServer != nil && *rule.DefaultServer {
					availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_UNSUPPORTED
				}
				resources = append(resources, providers.DeploymentResource{
					TargetRef:      providers.BuildTargetRef("cloudTencent", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB, region, stringValue(loadBalancer.LoadBalancerId), stringValue(listener.ListenerId), normalized),
					Label:          normalized,
					Domain:         normalized,
					Domains:        []string{normalized},
					Group:          strings.TrimSpace(stringValue(loadBalancer.LoadBalancerName)),
					Region:         region,
					Protocol:       tencentCLBHTTPS,
					Status:         "Running",
					Availability:   availability,
					LoadBalancerID: stringValue(loadBalancer.LoadBalancerId),
					ListenerID:     stringValue(listener.ListenerId),
					ListenerPort:   int(int64Value(listener.Port)),
				})
			}
		}
	}
	return resources, nil
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
