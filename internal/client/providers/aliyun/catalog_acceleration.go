package aliyun

import (
	"context"
	"fmt"
	"strconv"
	"strings"

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

// discoverESAResources 按 SetCertificate 的 SiteId 粒度发现站点，不依赖 DNS Record 已存在。
func (p *Provider) discoverESAResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	sites, partial, err := p.listESASites(ctx)
	resources := make([]providers.DeploymentResource, 0, len(sites))
	for _, site := range sites {
		resource, ok := esaSiteResource(site)
		if ok {
			resources = append(resources, resource)
		}
	}
	return resources, partial, err
}

// esaSiteResource 保留站点身份和根域名，以新引用区分历史 Record 目标。
func esaSiteResource(site map[string]any) (providers.DeploymentResource, bool) {
	siteID, err := parseESASiteID(mapString(site, "SiteId"))
	if err != nil {
		return providers.DeploymentResource{}, false
	}
	domain, err := providers.NormalizeDomain(mapString(site, "SiteName"))
	if err != nil || strings.HasPrefix(domain, "*.") {
		return providers.DeploymentResource{}, false
	}
	status := mapString(site, "Status")
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	// pending 站点允许预先配置证书；offline 和 moved 不应成为可执行目标。
	if strings.EqualFold(status, "active") || strings.EqualFold(status, "pending") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	}
	return providers.DeploymentResource{
		TargetRef: providers.BuildTargetRef("aliyun", deployPB.DeploymentType_DEPLOYMENT_TYPE_ESA, "site", siteID),
		Label:     domain, Domain: domain, SiteDomain: domain, Domains: []string{domain},
		Protocol: "HTTPS", Status: status, Availability: availability, SiteID: siteID,
		Region: mapString(site, "Coverage"),
	}, true
}

// listESASites 使用官方 PageNumber/PageSize 分页，避免 MaxResults/NextToken 导致只读取第一页。
// https://api.aliyun.com/api/ESA/2024-09-10/ListSites
func (p *Provider) listESASites(ctx context.Context) ([]map[string]any, bool, error) {
	sites := make([]map[string]any, 0)
	for page := 1; page <= aliyunCatalogMaxPages; page++ {
		query := map[string]string{"PageNumber": strconv.Itoa(page), "PageSize": strconv.Itoa(aliyunCatalogPageSize)}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunESAEndpoint, Action: "ListSites", Version: aliyunESAVersion, Method: "GET", Query: query})
		if err != nil {
			return sites, len(sites) > 0, err
		}
		records := nestedMapSlice(response.Body, "Sites", "Result")
		sites = append(sites, records...)
		total, hasTotal := mapInt64(response.Body, "TotalCount")
		if hasTotal && int64(len(sites)) >= total || !hasTotal && len(records) < aliyunCatalogPageSize {
			return sites, false, nil
		}
		if len(records) == 0 {
			return sites, true, fmt.Errorf("ESA 站点分页未返回完整目录")
		}
	}
	return sites, true, fmt.Errorf("ESA 站点目录超过安全分页上限")
}

// listESARecords 仅为已保存的旧目标分页解析 Record，新建目标不再依赖此接口。
func (p *Provider) listESARecords(ctx context.Context, site map[string]any) ([]providers.DeploymentResource, error) {
	siteID := firstMapString(site, "SiteId")
	if siteID == "" {
		return nil, nil
	}
	resources := make([]providers.DeploymentResource, 0)
	for page := 1; page <= aliyunCatalogMaxPages; page++ {
		query := map[string]string{"SiteId": siteID, "PageNumber": strconv.Itoa(page), "PageSize": strconv.Itoa(aliyunCatalogPageSize)}
		response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{Endpoint: aliyunESAEndpoint, Action: "ListRecords", Version: aliyunESAVersion, Method: "GET", Query: query})
		if err != nil {
			return resources, err
		}
		records := nestedMapSlice(response.Body, "Records", "Result")
		for _, record := range records {
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
		total, hasTotal := mapInt64(response.Body, "TotalCount")
		if hasTotal && int64(page*aliyunCatalogPageSize) >= total || !hasTotal && len(records) < aliyunCatalogPageSize {
			return resources, nil
		}
		if len(records) == 0 {
			return resources, fmt.Errorf("ESA Record 分页未返回完整目录")
		}
	}
	return resources, fmt.Errorf("ESA Record 目录超过安全分页上限")
}
