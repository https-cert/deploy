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
func (p *Provider) discoverAcceleratedResources(ctx context.Context, deploymentType deployPB.DeploymentType, product acceleratedProduct, action, containerKey, pageKey, sizeKey string) ([]providers.DeploymentResource, bool, error) {
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
				TargetRef: providers.BuildTargetRef("aliyun", deploymentType, identity), Label: domain, Domain: domain,
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
				TargetRef: providers.BuildTargetRef("aliyun", deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, siteID, recordID),
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
