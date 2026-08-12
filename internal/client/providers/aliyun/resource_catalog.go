package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

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
func (p *Provider) DiscoverResources(ctx context.Context, business deployPB.ExecuteBusinesType) providers.ResourceCatalogResult {
	if strings.TrimSpace(p.AccessKeyId) == "" || strings.TrimSpace(p.AccessKeySecret) == "" {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
	}
	var resources []providers.DeploymentResource
	var partial bool
	var err error
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		resources, partial, err = p.discoverAcceleratedResources(ctx, business, acceleratedProduct{
			Endpoint: aliyunCDNEndpoint, Version: aliyunCDNVersion, DisplayName: "CDN",
		}, "DescribeUserDomains", "Domains", "PageNumber", "PageSize")
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		resources, partial, err = p.discoverAcceleratedResources(ctx, business, acceleratedProduct{
			Endpoint: aliyunDCDNEndpoint, Version: aliyunDCDNVersion, DisplayName: "DCDN",
		}, "DescribeDcdnUserDomains", "Domains", "PageNumber", "PageSize")
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		resources, partial, err = p.discoverESAResources(ctx)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN:
		resources, partial, err = p.discoverOSSResources(ctx)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
		resources, partial, err = p.discoverCLBResources(ctx)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ALB:
		resources, partial, err = p.discoverModernLoadBalancerResources(ctx, business, "alb", aliyunALBVersion)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_NLB:
		resources, partial, err = p.discoverModernLoadBalancerResources(ctx, business, "nlb", aliyunNLBVersion)
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
func (p *Provider) ResolveResource(ctx context.Context, business deployPB.ExecuteBusinesType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, business)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, fmt.Errorf("阿里云资源目录不可用: %w", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 只读确认阿里云资源仍存在且具备精确证书槽位。
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
		product := aliyunCDNProduct()
		response, err := p.readAcceleratedDomain(ctx, resource.Domain, product)
		if err != nil {
			return err
		}
		return validateAcceleratedDomain(response.Body, resource.Domain, product)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		product := aliyunDCDNProduct()
		response, err := p.readAcceleratedDomain(ctx, resource.Domain, product)
		if err != nil {
			return err
		}
		return validateAcceleratedDomain(response.Body, resource.Domain, product)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA:
		response, err := p.listESACertificatesByRecord(ctx, resource.SiteID, resource.Domain)
		if err != nil {
			return err
		}
		if _, found := findESARecord(response.Body, resource.Domain); !found {
			return fmt.Errorf("ESA Record 已失效")
		}
		return nil
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN:
		result, err := p.ossAPI.ListCname(ctx, resource)
		if err != nil {
			return err
		}
		_, found := findExactOSSCname(result.Records, resource.Domain)
		if !found {
			return fmt.Errorf("OSS 自定义域名已失效")
		}
		return nil
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB:
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
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ALB:
		return p.testModernLoadBalancerResource(ctx, resource, true)
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_NLB:
		return p.testModernLoadBalancerResource(ctx, resource, false)
	default:
		return fmt.Errorf("阿里云不支持该资源业务")
	}
}

// readAcceleratedDomain 精确读取一个 CDN 或 DCDN 域名详情。
func (p *Provider) readAcceleratedDomain(ctx context.Context, domain string, product acceleratedProduct) (cloudAPIResponse, error) {
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: product.Endpoint, Action: product.PreflightAction, Version: product.Version, Method: "POST",
		Query: map[string]string{"DomainName": domain},
	})
}

// aliyunCDNProduct 返回 CDN 精确读取和部署契约。
func aliyunCDNProduct() acceleratedProduct {
	return acceleratedProduct{DisplayName: "CDN", Endpoint: aliyunCDNEndpoint, Version: aliyunCDNVersion, PreflightAction: "DescribeCdnDomainDetail", WriteAction: "SetCdnDomainSSLCertificate", ReadbackAction: "DescribeDomainCertificateInfo", DetailKey: "GetDomainDetailModel", HTTPSKey: "ServerCertificateStatus"}
}

// aliyunDCDNProduct 返回 DCDN 精确读取和部署契约。
func aliyunDCDNProduct() acceleratedProduct {
	return acceleratedProduct{DisplayName: "DCDN", Endpoint: aliyunDCDNEndpoint, Version: aliyunDCDNVersion, PreflightAction: "DescribeDcdnDomainDetail", WriteAction: "SetDcdnDomainSSLCertificate", ReadbackAction: "DescribeDcdnDomainCertificateInfo", DetailKey: "DomainDetail", HTTPSKey: "SSLProtocol"}
}

// discoverAcceleratedResources 分页读取 CDN 或 DCDN 加速域名。
func (p *Provider) discoverAcceleratedResources(ctx context.Context, business deployPB.ExecuteBusinesType, product acceleratedProduct, action, containerKey, pageKey, sizeKey string) ([]providers.DeploymentResource, bool, error) {
	resources := make([]providers.DeploymentResource, 0)
	for page := 1; page <= aliyunCatalogMaxPages && len(resources) < aliyunCatalogMaxCount; page++ {
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
			Endpoint: product.Endpoint, Action: action, Version: product.Version, Method: "POST",
			Query: map[string]string{pageKey: strconv.Itoa(page), sizeKey: strconv.Itoa(aliyunCatalogPageSize)},
		})
		if err != nil {
			return resources, len(resources) > 0, err
		}
		records := nestedMapSlice(response.Body, containerKey, "PageData", "Domain")
		for _, record := range records {
			domain, err := providers.NormalizeDomain(firstMapString(record, "DomainName", "Domain"))
			if err != nil {
				continue
			}
			status := firstMapString(record, "DomainStatus", "Status")
			https := firstMapString(record, "HttpsSwitch", "SSLProtocol", "HttpsStatus")
			availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
			if !isAliyunRunningStatus(status) {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
			} else if https != "" && !strings.EqualFold(https, "on") && !strings.EqualFold(https, "enabled") {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_UNSUPPORTED
			}
			createdAt := firstMapString(record, "GmtCreated", "CreateTime")
			identity, ok := providers.StableDomainIdentity(firstMapString(record, "ResourceId", "DomainId"), domain, createdAt)
			if !ok {
				continue
			}
			resources = append(resources, providers.DeploymentResource{
				TargetRef: providers.BuildTargetRef("aliyun", business, identity), Label: domain, Domain: domain,
				Domains: []string{domain}, Protocol: "HTTPS", Status: status, Availability: availability,
				ResourceID: identity, CreatedAt: createdAt,
			})
		}
		total, hasTotal := firstMapInt64(response.Body, "TotalCount", "TotalNumber")
		if len(records) < aliyunCatalogPageSize || hasTotal && int64(len(resources)) >= total {
			return resources, false, nil
		}
	}
	return resources, true, fmt.Errorf("%s 域名目录超过安全分页上限", product.DisplayName)
}

// discoverESAResources 分页读取站点并读取站点下的 Record。
func (p *Provider) discoverESAResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	sites, partial, err := p.listESASites(ctx)
	if err != nil {
		return nil, partial, err
	}
	type siteResult struct {
		resources []providers.DeploymentResource
		err       error
	}
	results := make(chan siteResult, len(sites))
	sem := make(chan struct{}, aliyunCatalogConcurrency)
	var workers sync.WaitGroup
	for _, site := range sites {
		site := site
		workers.Add(1)
		go func() {
			defer workers.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			resources, scanErr := p.listESARecords(ctx, site)
			results <- siteResult{resources: resources, err: scanErr}
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

// listESASites 分页读取 ESA Site 摘要。
func (p *Provider) listESASites(ctx context.Context) ([]map[string]any, bool, error) {
	sites := make([]map[string]any, 0)
	nextToken := ""
	for page := 0; page < aliyunCatalogMaxPages; page++ {
		query := map[string]string{"MaxResults": strconv.Itoa(aliyunCatalogPageSize)}
		if nextToken != "" {
			query["NextToken"] = nextToken
		}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunESAEndpoint, Action: "ListSites", Version: aliyunESAVersion, Method: "GET", Query: query})
		if err != nil {
			return sites, len(sites) > 0, err
		}
		records := nestedMapSlice(response.Body, "Sites", "Result")
		sites = append(sites, records...)
		nextToken = firstMapString(response.Body, "NextToken")
		if nextToken == "" {
			return sites, false, nil
		}
	}
	return sites, true, fmt.Errorf("ESA 站点目录超过安全分页上限")
}

// listESARecords 分页读取单个站点的加速 Record。
func (p *Provider) listESARecords(ctx context.Context, site map[string]any) ([]providers.DeploymentResource, error) {
	siteID := firstMapString(site, "SiteId")
	if siteID == "" {
		return nil, nil
	}
	resources := make([]providers.DeploymentResource, 0)
	nextToken := ""
	for page := 0; page < aliyunCatalogMaxPages; page++ {
		query := map[string]string{"SiteId": siteID, "MaxResults": strconv.Itoa(aliyunCatalogPageSize)}
		if nextToken != "" {
			query["NextToken"] = nextToken
		}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunESAEndpoint, Action: "ListRecords", Version: aliyunESAVersion, Method: "GET", Query: query})
		if err != nil {
			return resources, err
		}
		for _, record := range nestedMapSlice(response.Body, "Records", "Result") {
			domain, err := providers.NormalizeDomain(firstMapString(record, "RecordName", "Record"))
			if err != nil {
				continue
			}
			recordID := firstMapString(record, "RecordId", "Id")
			if recordID == "" {
				continue
			}
			status := firstMapString(record, "RecordStatus", "Status")
			availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
			if !isAliyunRunningStatus(status) {
				availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
			}
			resources = append(resources, providers.DeploymentResource{
				TargetRef: providers.BuildTargetRef("aliyun", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_ESA, siteID, recordID),
				Label:     domain, Domain: domain, Domains: []string{domain}, Group: firstMapString(site, "SiteName", "SiteNameCN"),
				Protocol: "HTTPS", Status: status, Availability: availability, SiteID: siteID, ResourceID: recordID,
			})
		}
		nextToken = firstMapString(response.Body, "NextToken")
		if nextToken == "" {
			return resources, nil
		}
	}
	return resources, fmt.Errorf("ESA Record 目录超过安全分页上限")
}

// discoverOSSResources 读取 Bucket 并有限并发扫描自定义 CNAME。
func (p *Provider) discoverOSSResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	buckets, err := p.ossAPI.ListBuckets(ctx)
	if err != nil {
		return nil, false, err
	}
	type bucketResult struct {
		resources []providers.DeploymentResource
		err       error
	}
	results := make(chan bucketResult, len(buckets))
	sem := make(chan struct{}, aliyunCatalogConcurrency)
	var workers sync.WaitGroup
	for _, bucket := range buckets {
		bucket := bucket
		workers.Add(1)
		go func() {
			defer workers.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			target := providers.DeploymentResource{Region: bucket.Region, Bucket: bucket.Name}
			result, err := p.ossAPI.ListCname(ctx, target)
			if err != nil {
				results <- bucketResult{err: err}
				return
			}
			resources := make([]providers.DeploymentResource, 0, len(result.Records))
			for _, record := range result.Records {
				domain, err := providers.NormalizeDomain(record.Domain)
				if err != nil {
					continue
				}
				availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
				if !isAliyunRunningStatus(record.Status) {
					availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
				}
				resources = append(resources, providers.DeploymentResource{
					TargetRef: providers.BuildTargetRef("aliyun", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_OSS_CUSTOM_DOMAIN, bucket.Name, bucket.CreatedAt, domain),
					Label:     domain, Domain: domain, Domains: []string{domain}, Group: "OSS Bucket", Region: bucket.Region,
					Protocol: "HTTPS", Status: record.Status, Availability: availability, Bucket: bucket.Name, CreatedAt: bucket.CreatedAt,
				})
			}
			results <- bucketResult{resources: resources}
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
						TargetRef: providers.BuildTargetRef("aliyun", deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CLB, region, loadBalancerID, strconv.Itoa(int(port)), extension.ExtensionID),
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
func (p *Provider) discoverModernLoadBalancerResources(ctx context.Context, business deployPB.ExecuteBusinesType, product, version string) ([]providers.DeploymentResource, bool, error) {
	regions, err := p.listAliyunRegions(ctx)
	if err != nil {
		return nil, false, err
	}
	casCertificates, _, err := p.listCASCertificates(ctx)
	if err != nil {
		return nil, false, err
	}
	return p.scanAliyunRegions(ctx, regions, func(ctx context.Context, region string) ([]providers.DeploymentResource, error) {
		return p.listModernLoadBalancerRegion(ctx, business, product, version, region, casCertificates)
	})
}

// listModernLoadBalancerRegion 读取一个地域的 ALB/NLB 监听器和非默认证书。
func (p *Provider) listModernLoadBalancerRegion(ctx context.Context, business deployPB.ExecuteBusinesType, product, version, region string, casCertificates []casCertificateMetadata) ([]providers.DeploymentResource, error) {
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
						TargetRef: providers.BuildTargetRef("aliyun", business, region, loadBalancerID, listenerID, strings.Join(domains, ",")),
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

// nestedMapSlice 从若干常见容器路径中读取记录数组。
func nestedMapSlice(body map[string]any, keys ...string) []map[string]any {
	for _, key := range keys {
		if records := mapSlice(body, key); len(records) > 0 {
			return records
		}
		value, found := getMapValue(body, key)
		if !found {
			continue
		}
		container, ok := normalizeToMap(value)
		if !ok {
			continue
		}
		for _, nestedKey := range keys {
			if records := mapSlice(container, nestedKey); len(records) > 0 {
				return records
			}
		}
	}
	return nil
}

// firstMapString 返回首个非空候选字段。
func firstMapString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(mapString(data, key)); value != "" {
			return value
		}
	}
	return ""
}

// firstMapInt64 返回首个可解析的整数候选字段。
func firstMapInt64(data map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		if value, ok := mapInt64(data, key); ok {
			return value, true
		}
	}
	return 0, false
}

// isAliyunRunningStatus 将常见云产品状态归一为可部署判断。
func isAliyunRunningStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "online", "running", "active", "success", "enabled", "configured", "normal", "available", "stopped":
		return true
	default:
		return false
	}
}
