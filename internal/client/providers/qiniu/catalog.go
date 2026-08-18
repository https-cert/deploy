package qiniu

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
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// DiscoverResources 实时发现七牛 CDN 或 DCDN 域名资源。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	product, err := productForDeploymentType(deploymentType)
	if err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateCredentials("发现域名目录"); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED}
	}

	summaries, partial, err := p.listDomainSummaries(ctx)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		if isQiniuPermissionDenied(err) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Status: status, Error: err}
	}
	resources, detailPartial := p.readDomainResources(ctx, summaries, product, deploymentType)
	partial = partial || detailPartial
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].Domain < resources[right].Domain
	})
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if partial {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
	} else if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 实时发现目录并按引用唯一解析七牛域名。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, fmt.Errorf("七牛云资源目录不可用")
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// isQiniuPermissionDenied 将七牛 401/403 控制面响应识别为凭据或授权不足。
func isQiniuPermissionDenied(err error) bool {
	var apiError *APIError
	return errors.As(err, &apiError) &&
		(apiError.StatusCode == http.StatusUnauthorized || apiError.StatusCode == http.StatusForbidden)
}

// TestResource 只读确认七牛域名仍存在、产品一致且已启用 HTTPS。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return err
	}
	product, err := productForDeploymentType(deploymentType)
	if err != nil {
		return err
	}
	_, err = p.readAndValidateDomain(ctx, product, resource.Domain)
	return err
}

// productForDeploymentType 将公共业务枚举映射为七牛产品类型。
func productForDeploymentType(deploymentType deployPB.DeploymentType) (Product, error) {
	switch deploymentType {
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN:
		return ProductCDN, nil
	case deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN:
		return ProductDCDN, nil
	default:
		return "", fmt.Errorf("七牛云不支持该资源业务")
	}
}

// listDomainSummaries 分页读取账户域名目录。
func (p *Provider) listDomainSummaries(ctx context.Context) ([]domainSummary, bool, error) {
	marker := ""
	result := make([]domainSummary, 0)
	for page := 0; page < resourceMaxPages && len(result) < resourceMaxCount; page++ {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(resourcePageSize))
		if marker != "" {
			query.Set("marker", marker)
		}
		response, err := p.execute(ctx, "获取域名列表", http.MethodGet, p.apiBaseURL, "/domain?"+query.Encode(), authorizationQiniuV2, nil)
		if err != nil {
			if len(result) > 0 {
				return result, true, nil
			}
			return nil, false, err
		}
		var pageResult domainListResponse
		if err := json.Unmarshal(response.Body, &pageResult); err != nil {
			if len(result) > 0 {
				return result, true, nil
			}
			return nil, false, newLocalError("解析域名列表响应", err)
		}
		result = append(result, pageResult.Domains...)
		if pageResult.Marker == "" || len(pageResult.Domains) == 0 {
			return result, false, nil
		}
		marker = pageResult.Marker
	}
	return result, true, nil
}

// readDomainResources 有限并发读取域名详情并构建脱敏资源。
func (p *Provider) readDomainResources(ctx context.Context, summaries []domainSummary, product Product, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool) {
	type detailResult struct {
		resource *providers.DeploymentResource
		err      error
	}
	jobs := make(chan domainSummary)
	results := make(chan detailResult, len(summaries))
	workerCount := min(resourceConcurrency, len(summaries))
	var workers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for summary := range jobs {
				detail, err := p.getDomain(ctx, summary.Name)
				if err != nil {
					results <- detailResult{err: err}
					continue
				}
				if !strings.EqualFold(strings.TrimSpace(detail.Product), string(product)) {
					results <- detailResult{}
					continue
				}
				resource, ok := buildDomainResource(detail, deploymentType)
				if !ok {
					results <- detailResult{}
					continue
				}
				results <- detailResult{resource: &resource}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, summary := range summaries {
			select {
			case <-ctx.Done():
				return
			case jobs <- summary:
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	resources := make([]providers.DeploymentResource, 0)
	partial := false
	for result := range results {
		if result.err != nil {
			partial = true
			continue
		}
		if result.resource != nil {
			resources = append(resources, *result.resource)
		}
	}
	if ctx.Err() != nil {
		partial = true
	}
	return resources, partial
}

// buildDomainResource 将具备稳定生命周期身份的七牛详情映射为本地私有资源和公开展示字段。
func buildDomainResource(detail *domainInfo, deploymentType deployPB.DeploymentType) (providers.DeploymentResource, bool) {
	if detail == nil {
		return providers.DeploymentResource{}, false
	}
	domain, err := providers.NormalizeDomain(detail.Name)
	if err != nil {
		return providers.DeploymentResource{}, false
	}
	identity, ok := providers.StableDomainIdentity("", domain, detail.CreateAt)
	if !ok {
		return providers.DeploymentResource{}, false
	}
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	if !strings.EqualFold(strings.TrimSpace(detail.Protocol), "https") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_UNSUPPORTED
	} else if !strings.EqualFold(strings.TrimSpace(detail.OperatingState), "success") {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("qiniu", deploymentType, identity),
		Label:        domain,
		Domain:       domain,
		Domains:      []string{domain},
		Protocol:     strings.ToUpper(strings.TrimSpace(detail.Protocol)),
		Status:       strings.TrimSpace(detail.OperatingState),
		Availability: availability,
		ResourceID:   domain,
		CreatedAt:    strings.TrimSpace(detail.CreateAt),
	}, true
}
