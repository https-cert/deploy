package volcengine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	tosapi "github.com/volcengine/ve-tos-golang-sdk/v2/tos"
	"github.com/volcengine/ve-tos-golang-sdk/v2/tos/enum"
)

var volcengineRegionPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)

// tosClient 是 TOS Bucket 和自定义域名证书闭环所需的最小官方 SDK 接口。
type tosClient interface {
	ListBuckets(ctx context.Context, input *tosapi.ListBucketsInput) (*tosapi.ListBucketsOutput, error)
	ListBucketCustomDomain(ctx context.Context, input *tosapi.ListBucketCustomDomainInput) (*tosapi.ListBucketCustomDomainOutput, error)
	PutBucketCustomDomain(ctx context.Context, input *tosapi.PutBucketCustomDomainInput) (*tosapi.PutBucketCustomDomainOutput, error)
}

// newTOSClients 为每个配置地域创建一个使用 HTTPS endpoint 的 TOS 客户端。
func newTOSClients(accessKey, secretKey string, regions []string) (map[string]tosClient, error) {
	clients := make(map[string]tosClient, len(regions))
	for _, region := range regions {
		client, err := tosapi.NewClientV2(
			tosEndpointForRegion(region),
			tosapi.WithCredentials(tosapi.NewStaticCredentials(accessKey, secretKey)),
			tosapi.WithRegion(region),
			tosapi.WithConnectionTimeout(sdkTimeout),
			tosapi.WithRequestTimeout(sdkTimeout),
			tosapi.WithSocketTimeout(sdkTimeout, sdkTimeout),
			tosapi.WithMaxRetryCount(1),
		)
		if err != nil {
			return nil, fmt.Errorf("创建火山引擎 TOS 客户端失败[%s]: %w", region, err)
		}
		clients[region] = client
	}
	return clients, nil
}

// tosEndpointForRegion 返回经过地域格式白名单约束的 TOS endpoint。
func tosEndpointForRegion(region string) string {
	return "tos-" + strings.ToLower(strings.TrimSpace(region)) + ".volces.com"
}

// normalizeVolcengineRegions 归一化默认地域和多地域发现列表。
func normalizeVolcengineRegions(primary string, regions []string) ([]string, error) {
	values := append([]string{strings.TrimSpace(primary)}, regions...)
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		region := strings.ToLower(strings.TrimSpace(value))
		if region == "" {
			continue
		}
		if !volcengineRegionPattern.MatchString(region) {
			return nil, fmt.Errorf("火山引擎地域格式无效: %s", region)
		}
		if _, exists := seen[region]; exists {
			continue
		}
		seen[region] = struct{}{}
		result = append(result, region)
	}
	if len(result) == 0 {
		return nil, errors.New("火山引擎地域列表不能为空")
	}
	sort.Strings(result)
	return result, nil
}

// discoverTOSResources 发现配置地域内 Bucket 的现有自定义域名。
func (p *Provider) discoverTOSResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	listClient := p.tosClients[p.region]
	if listClient == nil {
		for _, region := range p.regions {
			if candidate := p.tosClients[region]; candidate != nil {
				listClient = candidate
				break
			}
		}
	}
	if listClient == nil {
		return nil, false, providers.NewDeploymentError("火山引擎 TOS 客户端未初始化", false, "", nil)
	}

	output, err := listClient.ListBuckets(ctx, &tosapi.ListBucketsInput{})
	if err != nil {
		return nil, false, err
	}
	if output == nil {
		return nil, false, providers.NewDeploymentError("火山引擎 TOS Bucket 列表响应为空", true, "", nil)
	}

	resources := make([]providers.DeploymentResource, 0)
	partial := false
	var firstError error
	for _, bucket := range output.Buckets {
		if err := ctx.Err(); err != nil {
			return resources, true, err
		}
		region := strings.ToLower(strings.TrimSpace(bucket.Location))
		client := p.tosClients[region]
		if client == nil {
			continue
		}
		if strings.TrimSpace(bucket.Name) == "" || strings.TrimSpace(bucket.CreationDate) == "" {
			partial = true
			continue
		}
		domainOutput, domainErr := client.ListBucketCustomDomain(ctx, &tosapi.ListBucketCustomDomainInput{Bucket: bucket.Name})
		if domainErr != nil {
			partial = true
			if firstError == nil {
				firstError = domainErr
			}
			continue
		}
		if domainOutput == nil {
			partial = true
			if firstError == nil {
				firstError = providers.NewDeploymentError("火山引擎 TOS 自定义域名列表响应为空", true, output.RequestID, nil)
			}
			continue
		}
		for _, rule := range domainOutput.Rules {
			resource, ok := buildTOSResource(deploymentType, region, bucket, rule)
			if !ok {
				partial = true
				continue
			}
			resources = append(resources, resource)
			if len(resources) > maxResources {
				return resources, true, providers.NewDeploymentError("火山引擎 TOS 资源数量超过安全上限", false, domainOutput.RequestID, nil)
			}
		}
	}
	sort.Slice(resources, func(left, right int) bool {
		if resources[left].Region != resources[right].Region {
			return resources[left].Region < resources[right].Region
		}
		if resources[left].Bucket != resources[right].Bucket {
			return resources[left].Bucket < resources[right].Bucket
		}
		return resources[left].Domain < resources[right].Domain
	})
	if firstError != nil && len(resources) == 0 {
		return resources, partial, firstError
	}
	return resources, partial, nil
}

// buildTOSResource 将 Bucket 和自定义域名规则转换为稳定资源引用。
func buildTOSResource(deploymentType deployPB.DeploymentType, region string, bucket tosapi.ListedBucket, rule tosapi.CustomDomainRule) (providers.DeploymentResource, bool) {
	domain, err := providers.NormalizeDomain(rule.Domain)
	if err != nil || strings.TrimSpace(region) == "" || strings.TrimSpace(bucket.Name) == "" || strings.TrimSpace(bucket.CreationDate) == "" {
		return providers.DeploymentResource{}, false
	}
	status := strings.TrimSpace(string(rule.CertStatus))
	if status == "" {
		status = "unbound"
	}
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
	if rule.Forbidden {
		status = "forbidden"
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	}
	protocol := "HTTP"
	if strings.TrimSpace(rule.CertID) != "" {
		protocol = "HTTPS"
	}
	return providers.DeploymentResource{
		TargetRef:    providers.BuildTargetRef("volcengine", deploymentType, region, bucket.Name, bucket.CreationDate, domain),
		Label:        domain,
		Domain:       domain,
		Domains:      []string{domain},
		Group:        bucket.Name,
		Region:       region,
		Protocol:     protocol,
		Status:       status,
		Availability: availability,
		Bucket:       bucket.Name,
		ResourceID:   domain,
		CreatedAt:    strings.TrimSpace(bucket.CreationDate),
	}, true
}

// deployTOS 更新精确 Bucket 自定义域名的证书 ID，并要求回读状态为 CertBound。
func (p *Provider) deployTOS(ctx context.Context, resource providers.DeploymentResource, certificateID, requestID string) (string, error) {
	region := strings.ToLower(strings.TrimSpace(resource.Region))
	client := p.tosClients[region]
	if client == nil {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 目标地域客户端未初始化", false, requestID, nil)
	}
	if strings.TrimSpace(resource.Bucket) == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 目标缺少 Bucket 或创建时间", false, requestID, nil)
	}
	bucket, bucketRequestID, err := findTOSBucket(ctx, client, resource.Bucket)
	requestID = firstNonEmpty(bucketRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	if !tosBucketMatchesResource(bucket, resource) {
		return requestID, providers.NewDeploymentError("火山引擎 TOS Bucket 身份已变化，请重新关联资源", false, requestID, nil)
	}

	preflight, err := client.ListBucketCustomDomain(ctx, &tosapi.ListBucketCustomDomainInput{Bucket: resource.Bucket})
	if err != nil {
		return firstNonEmpty(tosRequestID(err), requestID), err
	}
	if preflight == nil {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 自定义域名详情响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(preflight.RequestID, requestID)
	currentRule, found, err := findTOSRule(preflight.Rules, resource.Domain)
	if err != nil {
		return requestID, err
	}
	if !found {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 自定义域名已失效，请重新关联资源", false, requestID, nil)
	}
	if currentRule.Forbidden {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 自定义域名已被禁用", false, requestID, nil)
	}
	if strings.TrimSpace(currentRule.CertID) == strings.TrimSpace(certificateID) && currentRule.CertStatus == enum.CertStatusBound {
		return requestID, nil
	}

	writeOutput, err := client.PutBucketCustomDomain(ctx, &tosapi.PutBucketCustomDomainInput{
		Bucket: resource.Bucket,
		Rule: tosapi.CustomDomainRule{
			CertID:   strings.TrimSpace(certificateID),
			Domain:   resource.Domain,
			Protocol: currentRule.Protocol,
		},
	})
	if err != nil {
		return firstNonEmpty(tosRequestID(err), requestID), err
	}
	if writeOutput == nil {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 证书更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(writeOutput.RequestID, requestID)

	readback, err := client.ListBucketCustomDomain(ctx, &tosapi.ListBucketCustomDomainInput{Bucket: resource.Bucket})
	if err != nil {
		return firstNonEmpty(tosRequestID(err), requestID), err
	}
	if readback == nil {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 证书回读响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(readback.RequestID, requestID)
	confirmedRule, found, err := findTOSRule(readback.Rules, resource.Domain)
	if err != nil {
		return requestID, err
	}
	if !found || strings.TrimSpace(confirmedRule.CertID) != strings.TrimSpace(certificateID) || confirmedRule.CertStatus != enum.CertStatusBound {
		return requestID, providers.NewDeploymentError("火山引擎 TOS 自定义域名证书尚未生效", true, requestID, nil)
	}
	return requestID, nil
}

// findTOSBucket 查找精确 Bucket，并返回目录请求 ID。
func findTOSBucket(ctx context.Context, client tosClient, bucketName string) (tosapi.ListedBucket, string, error) {
	output, err := client.ListBuckets(ctx, &tosapi.ListBucketsInput{})
	if err != nil {
		return tosapi.ListedBucket{}, tosRequestID(err), err
	}
	if output == nil {
		return tosapi.ListedBucket{}, "", providers.NewDeploymentError("火山引擎 TOS Bucket 回读响应为空", true, "", nil)
	}
	for _, bucket := range output.Buckets {
		if bucket.Name == bucketName {
			return bucket, output.RequestID, nil
		}
	}
	return tosapi.ListedBucket{}, output.RequestID, providers.NewDeploymentError("火山引擎 TOS Bucket 已失效，请重新关联资源", false, output.RequestID, nil)
}

// tosBucketMatchesResource 校验 Bucket 地域和创建时间仍与已关联资源一致。
func tosBucketMatchesResource(bucket tosapi.ListedBucket, resource providers.DeploymentResource) bool {
	return bucket.Name == resource.Bucket &&
		strings.EqualFold(strings.TrimSpace(bucket.Location), strings.TrimSpace(resource.Region)) &&
		strings.TrimSpace(bucket.CreationDate) == strings.TrimSpace(resource.CreatedAt)
}

// findTOSRule 按规范化域名唯一查找自定义域名规则。
func findTOSRule(rules []tosapi.CustomDomainRule, targetDomain string) (tosapi.CustomDomainRule, bool, error) {
	target, err := providers.NormalizeDomain(targetDomain)
	if err != nil {
		return tosapi.CustomDomainRule{}, false, err
	}
	var matched *tosapi.CustomDomainRule
	for index := range rules {
		domain, normalizeErr := providers.NormalizeDomain(rules[index].Domain)
		if normalizeErr != nil || domain != target {
			continue
		}
		if matched != nil {
			return tosapi.CustomDomainRule{}, false, providers.NewDeploymentError("火山引擎 TOS 自定义域名回读结果不唯一", false, "", nil)
		}
		copyRule := rules[index]
		matched = &copyRule
	}
	if matched == nil {
		return tosapi.CustomDomainRule{}, false, nil
	}
	return *matched, true, nil
}

// tosRequestID 从 TOS 错误链中提取请求 ID。
func tosRequestID(err error) string {
	for current := err; current != nil; current = errors.Unwrap(current) {
		if requestID := strings.TrimSpace(tosapi.RequestID(current)); requestID != "" {
			return requestID
		}
	}
	return ""
}

// tosStatusCode 从 TOS 错误链中提取 HTTP 状态码。
func tosStatusCode(err error) int {
	for current := err; current != nil; current = errors.Unwrap(current) {
		if statusCode := tosapi.StatusCode(current); statusCode != 0 {
			return statusCode
		}
	}
	return 0
}

// tosErrorCode 从 TOS 错误链中提取服务错误码。
func tosErrorCode(err error) string {
	for current := err; current != nil; current = errors.Unwrap(current) {
		if code := strings.TrimSpace(tosapi.Code(current)); code != "" {
			return code
		}
	}
	return ""
}
