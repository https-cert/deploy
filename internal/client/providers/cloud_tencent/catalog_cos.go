package cloud_tencent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/tencentyun/cos-go-sdk-v5"
)

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
			TargetRef:    providers.BuildTargetRef("cloudTencent", deployPB.DeploymentType_DEPLOYMENT_TYPE_COS, bucket.Name, bucket.CreationDate, domain),
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
