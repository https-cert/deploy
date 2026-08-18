package lecdn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DiscoverResources 按 certificate_id 聚合全部已启用的站点域名引用。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateConfiguration(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	resources, partial, err := p.discoverCertificateResources(ctx)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		var requestError *apiError
		if errors.As(err, &requestError) && (requestError.Status == http.StatusUnauthorized || requestError.Status == http.StatusForbidden) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Status: status, Error: err}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if partial {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
	} else if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新发现资源并按不透明 targetRef 唯一解析。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("LeCDN 资源目录不可用", false, "", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认证书引用仍存在且证书详情可读取。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("LeCDN 资源当前不可部署", false, "", err)
	}
	_, _, err = p.getCertificate(ctx, resource.ResourceID)
	return toDeploymentError("读取证书详情", err)
}

// discoverCertificateResources 分页读取站点并聚合全部证书引用。
func (p *Provider) discoverCertificateResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	aggregated := make(map[string]*certificateResource)
	partial := false
	seenSites := 0
	for page := 1; page <= maxPages && seenSites < maxResources; page++ {
		sites, total, requestID, err := p.listSites(ctx, page)
		if err != nil {
			if len(aggregated) > 0 {
				partial = true
				break
			}
			return nil, false, withRequestID(err, requestID)
		}
		for _, site := range sites {
			siteID := strings.TrimSpace(string(site.ID))
			if siteID == "" {
				partial = true
				continue
			}
			domains, _, err := p.listSiteDomains(ctx, siteID)
			if err != nil {
				partial = true
				continue
			}
			for _, domain := range domains {
				if !domain.CertificateEnable {
					continue
				}
				certificateID := strings.TrimSpace(string(domain.CertificateID))
				normalizedDomain, normalizeErr := providers.NormalizeDomain(domain.DomainName)
				if certificateID == "" || certificateID == "0" || normalizeErr != nil {
					continue
				}
				entry := aggregated[certificateID]
				if entry == nil {
					entry = &certificateResource{CertificateID: certificateID, Domains: make(map[string]struct{}), SiteIDs: make(map[string]struct{})}
					aggregated[certificateID] = entry
				}
				entry.Domains[normalizedDomain] = struct{}{}
				entry.SiteIDs[siteID] = struct{}{}
			}
		}
		seenSites += len(sites)
		if len(sites) < pageSize || seenSites >= total {
			break
		}
		if page == maxPages || seenSites >= maxResources {
			partial = true
		}
	}

	resources := make([]providers.DeploymentResource, 0, len(aggregated))
	for _, entry := range aggregated {
		domains := sortedKeys(entry.Domains)
		siteIDs := sortedKeys(entry.SiteIDs)
		if len(domains) == 0 || len(siteIDs) == 0 {
			continue
		}
		resources = append(resources, providers.DeploymentResource{
			TargetRef:    providers.BuildTargetRef("lecdn", deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, entry.CertificateID),
			Label:        fmt.Sprintf("LeCDN 证书 #%s (%s)", entry.CertificateID, strings.Join(domains, ", ")),
			Domain:       domains[0],
			Domains:      domains,
			Group:        fmt.Sprintf("%d 个站点", len(siteIDs)),
			Protocol:     "HTTPS",
			Status:       "bound",
			Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY,
			ResourceID:   entry.CertificateID,
			SiteIDs:      siteIDs,
		})
	}
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].TargetRef < resources[right].TargetRef
	})
	return resources, partial, nil
}

// listSites 读取一页 LeCDN 站点目录。
func (p *Provider) listSites(ctx context.Context, page int) ([]siteItem, int, string, error) {
	query := url.Values{"current_page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}}
	data, requestID, err := p.request(ctx, "读取站点列表", http.MethodGet, "/site?"+query.Encode(), nil)
	if err != nil {
		return nil, 0, requestID, err
	}
	var result pageResult[siteItem]
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, 0, requestID, &apiError{Operation: "解析站点列表", RequestID: requestID, Retryable: true, Cause: err}
	}
	return result.Items, result.Total, requestID, nil
}

// listSiteDomains 读取一个站点的全部域名及证书引用。
func (p *Provider) listSiteDomains(ctx context.Context, siteID string) ([]siteDomainItem, string, error) {
	data, requestID, err := p.request(ctx, "读取站点域名", http.MethodGet, "/site/"+url.PathEscape(siteID)+"/domain_name", nil)
	if err != nil {
		return nil, requestID, err
	}
	var domains []siteDomainItem
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, requestID, &apiError{Operation: "解析站点域名", RequestID: requestID, Retryable: true, Cause: err}
	}
	return domains, requestID, nil
}
