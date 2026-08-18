package cloud_tencent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	tencentclb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	cvm "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cvm/v20170312"
)

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
					TargetRef:      providers.BuildTargetRef("cloudTencent", deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB, region, stringValue(loadBalancer.LoadBalancerId), stringValue(listener.ListenerId), normalized),
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
