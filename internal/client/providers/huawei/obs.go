package huawei

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	obsapi "github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
)

const obsPageSize = 1000

// obsClient 是 OBS Bucket 和自定义域名证书闭环所需的最小官方 SDK 接口。
type obsClient interface {
	ListBuckets(input *obsapi.ListBucketsInput) (*obsapi.ListBucketsOutput, error)
	GetBucketCustomDomain(bucketName string) (*obsapi.GetBucketCustomDomainOutput, error)
	SetBucketCustomDomain(input *obsapi.SetBucketCustomDomainInput) (*obsapi.BaseModel, error)
}

// sdkOBSClient 将带内部可变参数的官方客户端适配为可测试的最小接口。
type sdkOBSClient struct {
	client *obsapi.ObsClient // client 是绑定到一个地域 endpoint 的官方 OBS 客户端。
}

// ListBuckets 调用官方 SDK 读取账户下的 Bucket 目录。
func (c *sdkOBSClient) ListBuckets(input *obsapi.ListBucketsInput) (*obsapi.ListBucketsOutput, error) {
	return c.client.ListBuckets(input)
}

// GetBucketCustomDomain 调用官方 SDK 读取 Bucket 自定义域名配置。
func (c *sdkOBSClient) GetBucketCustomDomain(bucketName string) (*obsapi.GetBucketCustomDomainOutput, error) {
	return c.client.GetBucketCustomDomain(bucketName)
}

// SetBucketCustomDomain 调用官方 SDK 更新精确自定义域名的证书。
func (c *sdkOBSClient) SetBucketCustomDomain(input *obsapi.SetBucketCustomDomainInput) (*obsapi.BaseModel, error) {
	return c.client.SetBucketCustomDomain(input)
}

// newOBSClients 为每个配置地域创建一个官方 OBS 客户端。
func newOBSClients(accessKey, secretKey string, regions []string) (map[string]obsClient, error) {
	clients := make(map[string]obsClient, len(regions))
	for _, region := range regions {
		client, err := obsapi.New(
			accessKey,
			secretKey,
			obsEndpointForRegion(region),
			obsapi.WithConnectTimeout(int(sdkTimeout/time.Second)),
			obsapi.WithSocketTimeout(int(sdkTimeout/time.Second)),
			obsapi.WithMaxRetryCount(1),
		)
		if err != nil {
			return nil, fmt.Errorf("创建华为云 OBS 客户端失败[%s]: %w", region, err)
		}
		clients[region] = &sdkOBSClient{client: client}
	}
	return clients, nil
}

// obsEndpointForRegion 根据地域生成官方 HTTPS endpoint。
func obsEndpointForRegion(region string) string {
	suffix := "myhuaweicloud.com"
	if strings.EqualFold(strings.TrimSpace(region), "eu-west-101") {
		suffix = "myhuaweicloud.eu"
	}
	return "https://obs." + strings.ToLower(strings.TrimSpace(region)) + "." + suffix
}

// discoverOBSResources 读取 Bucket 目录及其自定义域名，并生成稳定资源引用。
func (p *Provider) discoverOBSResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	listClient, ok := p.obsClients[p.region]
	if !ok || listClient == nil {
		for _, region := range p.regions {
			if candidate := p.obsClients[region]; candidate != nil {
				listClient = candidate
				break
			}
		}
	}
	if listClient == nil {
		return nil, false, providers.NewDeploymentError("华为云 OBS 客户端未初始化", false, "", nil)
	}

	resources := make([]providers.DeploymentResource, 0)
	partial := false
	marker := ""
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return resources, true, err
		}
		output, err := listClient.ListBuckets(&obsapi.ListBucketsInput{QueryLocation: true, MaxKeys: obsPageSize, Marker: marker})
		if err != nil {
			return resources, len(resources) > 0, err
		}
		if output == nil {
			return resources, len(resources) > 0, providers.NewDeploymentError("华为云 OBS Bucket 列表响应为空", true, "", nil)
		}
		for _, bucket := range output.Buckets {
			if len(resources) > maxResources {
				return resources, true, providers.NewDeploymentError("华为云 OBS 资源数量超过安全上限", false, output.RequestId, nil)
			}
			region := strings.ToLower(strings.TrimSpace(bucket.Location))
			if region == "" {
				region = p.region
			}
			bucketClient := p.obsClients[region]
			if bucketClient == nil || strings.TrimSpace(bucket.Name) == "" || bucket.CreationDate.IsZero() {
				continue
			}
			if err := ctx.Err(); err != nil {
				return resources, true, err
			}
			domainOutput, err := bucketClient.GetBucketCustomDomain(bucket.Name)
			if err != nil {
				partial = true
				continue
			}
			if domainOutput == nil {
				partial = true
				continue
			}
			for _, domain := range domainOutput.Domains {
				resource, ok := buildOBSResource(deploymentType, region, bucket, domain)
				if !ok {
					partial = true
					continue
				}
				resources = append(resources, resource)
			}
		}
		if !output.IsTruncated {
			break
		}
		nextMarker := strings.TrimSpace(output.NextMarker)
		if nextMarker == "" || nextMarker == marker {
			return resources, true, providers.NewDeploymentError("华为云 OBS Bucket 分页游标无效", false, output.RequestId, nil)
		}
		marker = nextMarker
		if page == maxPages-1 {
			partial = true
		}
	}
	sort.Slice(resources, func(left, right int) bool {
		if resources[left].Bucket == resources[right].Bucket {
			return resources[left].Domain < resources[right].Domain
		}
		return resources[left].Bucket < resources[right].Bucket
	})
	return resources, partial, nil
}

// buildOBSResource 将 Bucket 自定义域名转换为生命周期稳定的资源引用。
func buildOBSResource(deploymentType deployPB.DeploymentType, region string, bucket obsapi.Bucket, domain obsapi.Domain) (providers.DeploymentResource, bool) {
	normalizedDomain, err := providers.NormalizeDomain(domain.DomainName)
	if err != nil || strings.TrimSpace(domain.CreateTime) == "" {
		return providers.DeploymentResource{}, false
	}
	bucketCreatedAt := bucket.CreationDate.UTC().Format(time.RFC3339Nano)
	lifecycle := obsLifecycle(bucketCreatedAt, domain.CreateTime)
	protocol := "HTTP"
	if strings.TrimSpace(domain.CertificateId) != "" {
		protocol = "HTTPS"
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("huawei", deploymentType, region, bucket.Name, bucketCreatedAt, normalizedDomain, domain.CreateTime),
		Label:        normalizedDomain,
		Domain:       normalizedDomain,
		Domains:      []string{normalizedDomain},
		Group:        bucket.Name,
		Region:       region,
		Protocol:     protocol,
		Status:       "bound",
		Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY,
		Bucket:       bucket.Name,
		ResourceID:   normalizedDomain,
		CreatedAt:    lifecycle,
	}, true
}

// deployOBS 更新一个精确 Bucket 自定义域名并通过证书 ID 回读验收。
func (p *Provider) deployOBS(ctx context.Context, certificate providers.CertificateMaterial, resource providers.DeploymentResource, scmCertificateID, requestID string) (string, error) {
	region := strings.ToLower(strings.TrimSpace(resource.Region))
	client := p.obsClients[region]
	if client == nil {
		return requestID, providers.NewDeploymentError("华为云 OBS 目标地域客户端未初始化", false, requestID, nil)
	}
	if strings.TrimSpace(resource.Bucket) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return requestID, providers.NewDeploymentError("华为云 OBS 目标缺少 Bucket 或创建时间", false, requestID, nil)
	}
	if err := ctx.Err(); err != nil {
		return requestID, err
	}
	preflight, err := client.GetBucketCustomDomain(resource.Bucket)
	if err != nil {
		return requestIDFromError(err), err
	}
	if preflight == nil {
		return requestID, providers.NewDeploymentError("华为云 OBS 自定义域名详情响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(preflight.RequestId, requestID)
	currentDomain, ok := findOBSDomain(preflight.Domains, resource.Domain)
	if !ok || !obsDomainLifecycleMatches(resource.CreatedAt, currentDomain.CreateTime) {
		return requestID, providers.NewDeploymentError("华为云 OBS 自定义域名身份已变化，请重新关联资源", false, requestID, nil)
	}
	leafCertificate, certificateChain, err := splitCertificateChain(certificate.CertificatePEM)
	if err != nil {
		return requestID, err
	}
	name := stableCertificateName(certificate.CertificatePEM)
	writeOutput, err := client.SetBucketCustomDomain(&obsapi.SetBucketCustomDomainInput{
		Bucket:       resource.Bucket,
		CustomDomain: resource.Domain,
		CustomDomainConfiguration: &obsapi.CustomDomainConfiguration{
			Name:             name,
			CertificateId:    scmCertificateID,
			Certificate:      leafCertificate,
			CertificateChain: certificateChain,
			PrivateKey:       certificate.PrivateKeyPEM,
		},
	})
	if err != nil {
		return requestIDFromError(err), err
	}
	if writeOutput == nil {
		return requestID, providers.NewDeploymentError("华为云 OBS 证书更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(writeOutput.RequestId, requestID)
	if err := ctx.Err(); err != nil {
		return requestID, err
	}
	readback, err := client.GetBucketCustomDomain(resource.Bucket)
	if err != nil {
		return requestIDFromError(err), err
	}
	if readback == nil {
		return requestID, providers.NewDeploymentError("华为云 OBS 证书回读响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(readback.RequestId, requestID)
	readbackDomain, ok := findOBSDomain(readback.Domains, resource.Domain)
	if !ok || !obsDomainLifecycleMatches(resource.CreatedAt, readbackDomain.CreateTime) || strings.TrimSpace(readbackDomain.CertificateId) != scmCertificateID {
		return requestID, providers.NewDeploymentError("华为云 OBS 证书 ID 回读尚未生效", true, requestID, nil)
	}
	return requestID, nil
}

// findOBSDomain 在自定义域名列表中执行规范化后的精确匹配。
func findOBSDomain(domains []obsapi.Domain, expected string) (obsapi.Domain, bool) {
	for _, domain := range domains {
		normalized, err := providers.NormalizeDomain(domain.DomainName)
		if err == nil && normalized == expected {
			return domain, true
		}
	}
	return obsapi.Domain{}, false
}

// obsLifecycle 组合 Bucket 和自定义域名创建时间。
func obsLifecycle(bucketCreatedAt, domainCreatedAt string) string {
	return strings.TrimSpace(bucketCreatedAt) + "\x00" + strings.TrimSpace(domainCreatedAt)
}

// obsDomainLifecycleMatches 比较资源中保存的自定义域名创建时间。
func obsDomainLifecycleMatches(lifecycle, domainCreatedAt string) bool {
	parts := strings.SplitN(lifecycle, "\x00", 2)
	return len(parts) == 2 && strings.TrimSpace(parts[1]) == strings.TrimSpace(domainCreatedAt)
}

// asOBSError 兼容官方 SDK 以值或指针返回的 OBS 错误。
func asOBSError(err error) (obsapi.ObsError, bool) {
	var value obsapi.ObsError
	if errors.As(err, &value) {
		return value, true
	}
	var pointer *obsapi.ObsError
	if errors.As(err, &pointer) && pointer != nil {
		return *pointer, true
	}
	return obsapi.ObsError{}, false
}
