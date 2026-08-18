package aliyun

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// discoverCLBResources 跨地域读取阿里云 CLB HTTPS SNI 扩展。
func (p *Provider) discoverCLBResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	regions, err := p.listAliyunRegions(ctx)
	if err != nil {
		return nil, false, err
	}
	return p.scanAliyunRegions(ctx, regions, func(ctx context.Context, region string) ([]providers.DeploymentResource, error) {
		return p.listRegionCLBResources(ctx, region)
	})
}

// listRegionCLBResources 分页读取地域实例、HTTPS 监听器和 SNI 扩展。
func (p *Provider) listRegionCLBResources(ctx context.Context, region string) ([]providers.DeploymentResource, error) {
	resources := make([]providers.DeploymentResource, 0)
	for page := 1; page <= aliyunCatalogMaxPages; page++ {
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunSLBEndpoint, Action: "DescribeLoadBalancers", Version: aliyunSLBVersion, Method: "POST", Query: map[string]string{
			"RegionId": region, "PageNumber": strconv.Itoa(page), "PageSize": strconv.Itoa(aliyunCatalogPageSize),
		}})
		if err != nil {
			return resources, err
		}
		loadBalancers := nestedMapSlice(response.Body, "LoadBalancers", "LoadBalancer")
		for _, loadBalancer := range loadBalancers {
			loadBalancerID := firstMapString(loadBalancer, "LoadBalancerId")
			if loadBalancerID == "" {
				continue
			}
			listeners, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunSLBEndpoint, Action: "DescribeLoadBalancerListeners", Version: aliyunSLBVersion, Method: "POST", Query: map[string]string{
				"RegionId": region, "LoadBalancerId": loadBalancerID,
			}})
			if err != nil {
				return resources, err
			}
			for _, listener := range nestedMapSlice(listeners.Body, "Listeners", "Listener") {
				if !strings.EqualFold(firstMapString(listener, "ListenerProtocol"), "https") {
					continue
				}
				port, ok := firstMapInt64(listener, "ListenerPort")
				if !ok || port < 1 || port > 65535 {
					continue
				}
				target := providers.DeploymentResource{Region: region, LoadBalancerID: loadBalancerID, ListenerPort: int(port)}
				extensionResponse, err := p.describeCLBDomainExtensions(ctx, target, "")
				if err != nil {
					return resources, err
				}
				extensions, err := parseCLBDomainExtensions(extensionResponse.Body)
				if err != nil {
					return resources, err
				}
				for _, extension := range extensions {
					domain, err := providers.NormalizeDomain(extension.Domain)
					if err != nil {
						continue
					}
					resources = append(resources, providers.DeploymentResource{
						TargetRef: providers.BuildTargetRef("aliyun", deployPB.DeploymentType_DEPLOYMENT_TYPE_CLB, region, loadBalancerID, strconv.Itoa(int(port)), extension.ExtensionID),
						Label:     domain, Domain: domain, Domains: []string{domain}, Group: firstMapString(loadBalancer, "LoadBalancerName"), Region: region,
						Protocol: "HTTPS", Status: firstMapString(loadBalancer, "LoadBalancerStatus"), Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY,
						LoadBalancerID: loadBalancerID, ListenerPort: int(port), ResourceID: extension.ExtensionID,
					})
				}
			}
		}
		if len(loadBalancers) < aliyunCatalogPageSize {
			return resources, nil
		}
	}
	return resources, fmt.Errorf("CLB 实例目录超过安全分页上限")
}

// discoverModernLoadBalancerResources 跨地域读取 ALB 或 NLB 的现有 SNI 证书域名集合。
func (p *Provider) discoverModernLoadBalancerResources(ctx context.Context, deploymentType deployPB.DeploymentType, product, version string) ([]providers.DeploymentResource, bool, error) {
	regions, err := p.listAliyunRegions(ctx)
	if err != nil {
		return nil, false, err
	}
	casCertificates, _, err := p.listCASCertificates(ctx)
	if err != nil {
		return nil, false, err
	}
	return p.scanAliyunRegions(ctx, regions, func(ctx context.Context, region string) ([]providers.DeploymentResource, error) {
		return p.listModernLoadBalancerRegion(ctx, deploymentType, product, version, region, casCertificates)
	})
}

// listModernLoadBalancerRegion 读取一个地域的 ALB/NLB 监听器和非默认证书。
func (p *Provider) listModernLoadBalancerRegion(ctx context.Context, deploymentType deployPB.DeploymentType, product, version, region string, casCertificates []casCertificateMetadata) ([]providers.DeploymentResource, error) {
	endpoint, err := aliyunRegionalEndpoint(product, region)
	if err != nil {
		return nil, err
	}
	resources := make([]providers.DeploymentResource, 0)
	nextToken := ""
	for page := 0; page < aliyunCatalogMaxPages; page++ {
		query := map[string]string{"RegionId": region, "MaxResults": strconv.Itoa(aliyunCatalogPageSize)}
		if nextToken != "" {
			query["NextToken"] = nextToken
		}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: endpoint, Action: "ListLoadBalancers", Version: version, Method: "POST", Query: query})
		if err != nil {
			return resources, err
		}
		for _, loadBalancer := range nestedMapSlice(response.Body, "LoadBalancers") {
			loadBalancerID := firstMapString(loadBalancer, "LoadBalancerId")
			if loadBalancerID == "" {
				continue
			}
			listeners, err := p.listModernListeners(ctx, endpoint, version, region, loadBalancerID)
			if err != nil {
				return resources, err
			}
			for _, listener := range listeners {
				listenerID := firstMapString(listener, "ListenerId")
				protocol := strings.ToUpper(firstMapString(listener, "ListenerProtocol"))
				if listenerID == "" || product == "alb" && protocol != "HTTPS" && protocol != "QUIC" || product == "nlb" && protocol != "TCPSSL" {
					continue
				}
				target := providers.DeploymentResource{Region: region, LoadBalancerID: loadBalancerID, ListenerID: listenerID}
				var certificates []listenerCertificateMetadata
				if product == "alb" {
					listed, err := p.listALBListenerCertificates(ctx, region, listenerID)
					if err != nil {
						return resources, err
					}
					certificates = listed.Certificates
				} else {
					listed, err := p.listNLBListenerCertificates(ctx, target)
					if err != nil {
						return resources, err
					}
					certificates = listed.Certificates
				}
				for _, listenerCertificate := range certificates {
					if listenerCertificate.IsDefault {
						continue
					}
					certificate, count := findCASCertificateByListenerID(casCertificates, region, listenerCertificate.CertificateID)
					if count != 1 {
						continue
					}
					domains := append([]string(nil), certificate.SubjectAltNames...)
					if len(domains) == 0 {
						domains = []string{certificate.CommonName}
					}
					domains = providers.NormalizeDomains(domains...)
					if len(domains) == 0 {
						continue
					}
					port, _ := firstMapInt64(listener, "ListenerPort")
					status := firstMapString(listener, "ListenerStatus")
					availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
					if usable, _ := classifyLoadBalancerListenerStatus(status); !usable {
						availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
					}
					resources = append(resources, providers.DeploymentResource{
						TargetRef: providers.BuildTargetRef("aliyun", deploymentType, region, loadBalancerID, listenerID, strings.Join(domains, ",")),
						Label:     domains[0], Domain: domains[0], Domains: domains, Group: firstMapString(loadBalancer, "LoadBalancerName"), Region: region,
						Protocol: protocol, Status: status, Availability: availability, LoadBalancerID: loadBalancerID, ListenerID: listenerID, ListenerPort: int(port),
					})
				}
			}
		}
		nextToken = firstMapString(response.Body, "NextToken")
		if nextToken == "" {
			return resources, nil
		}
	}
	return resources, fmt.Errorf("%s 实例目录超过安全分页上限", strings.ToUpper(product))
}

// listModernListeners 分页读取 ALB/NLB 实例监听器。
func (p *Provider) listModernListeners(ctx context.Context, endpoint, version, region, loadBalancerID string) ([]map[string]any, error) {
	listeners := make([]map[string]any, 0)
	nextToken := ""
	for page := 0; page < aliyunCatalogMaxPages; page++ {
		query := map[string]string{"RegionId": region, "LoadBalancerIds.1": loadBalancerID, "MaxResults": strconv.Itoa(aliyunCatalogPageSize)}
		if nextToken != "" {
			query["NextToken"] = nextToken
		}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: endpoint, Action: "ListListeners", Version: version, Method: "POST", Query: query})
		if err != nil {
			return listeners, err
		}
		listeners = append(listeners, nestedMapSlice(response.Body, "Listeners")...)
		nextToken = firstMapString(response.Body, "NextToken")
		if nextToken == "" {
			return listeners, nil
		}
	}
	return listeners, fmt.Errorf("监听器目录超过安全分页上限")
}

// testModernLoadBalancerResource 重新读取监听器证书并确认严格域名集合仍存在。
func (p *Provider) testModernLoadBalancerResource(ctx context.Context, resource providers.DeploymentResource, alb bool) error {
	casCertificates, _, err := p.listCASCertificates(ctx)
	if err != nil {
		return err
	}
	var certificates []listenerCertificateMetadata
	if alb {
		listed, err := p.listALBListenerCertificates(ctx, resource.Region, resource.ListenerID)
		if err != nil {
			return err
		}
		certificates = listed.Certificates
	} else {
		listed, err := p.listNLBListenerCertificates(ctx, resource)
		if err != nil {
			return err
		}
		certificates = listed.Certificates
	}
	targetDomains := strings.Join(providers.NormalizeDomains(resource.Domains...), ",")
	for _, listenerCertificate := range certificates {
		if listenerCertificate.IsDefault {
			continue
		}
		certificate, count := findCASCertificateByListenerID(casCertificates, resource.Region, listenerCertificate.CertificateID)
		if count != 1 {
			continue
		}
		domains := certificate.SubjectAltNames
		if len(domains) == 0 {
			domains = []string{certificate.CommonName}
		}
		if strings.Join(providers.NormalizeDomains(domains...), ",") == targetDomains {
			return nil
		}
	}
	return fmt.Errorf("SNI 域名集合已发生变化")
}

// listAliyunRegions 通过 ECS 公共接口读取可用地域。
func (p *Provider) listAliyunRegions(ctx context.Context) ([]string, error) {
	response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunECSEndpoint, Action: "DescribeRegions", Version: aliyunECSVersion, Method: "POST"})
	if err != nil {
		return nil, err
	}
	regions := make([]string, 0)
	for _, record := range nestedMapSlice(response.Body, "Regions", "Region") {
		if region := firstMapString(record, "RegionId"); isSafeAliyunRegionID(region) {
			regions = append(regions, region)
		}
	}
	return regions, nil
}

// scanAliyunRegions 使用有限并发扫描地域目录。
func (p *Provider) scanAliyunRegions(ctx context.Context, regions []string, scan func(context.Context, string) ([]providers.DeploymentResource, error)) ([]providers.DeploymentResource, bool, error) {
	type regionResult struct {
		resources []providers.DeploymentResource
		err       error
	}
	results := make(chan regionResult, len(regions))
	sem := make(chan struct{}, aliyunCatalogConcurrency)
	var workers sync.WaitGroup
	for _, region := range regions {
		region := region
		workers.Add(1)
		go func() {
			defer workers.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resources, err := scan(ctx, region)
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
