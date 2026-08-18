package aliyun

import (
	"context"
	"sync"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

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
					TargetRef: providers.BuildTargetRef("aliyun", deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN, bucket.Name, bucket.CreatedAt, domain),
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
