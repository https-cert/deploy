package volcengine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	albapi "github.com/volcengine/volcengine-go-sdk/service/alb"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
)

// albClient 是 ALB HTTPS 监听器发现、更新和回读所需的最小官方 SDK 接口。
type albClient interface {
	DescribeLoadBalancersWithContext(ctx volcengine.Context, input *albapi.DescribeLoadBalancersInput, options ...request.Option) (*albapi.DescribeLoadBalancersOutput, error)
	DescribeListenersWithContext(ctx volcengine.Context, input *albapi.DescribeListenersInput, options ...request.Option) (*albapi.DescribeListenersOutput, error)
	DescribeListenerAttributesWithContext(ctx volcengine.Context, input *albapi.DescribeListenerAttributesInput, options ...request.Option) (*albapi.DescribeListenerAttributesOutput, error)
	DescribeCertificatesWithContext(ctx volcengine.Context, input *albapi.DescribeCertificatesInput, options ...request.Option) (*albapi.DescribeCertificatesOutput, error)
	ModifyListenerAttributesWithContext(ctx volcengine.Context, input *albapi.ModifyListenerAttributesInput, options ...request.Option) (*albapi.ModifyListenerAttributesOutput, error)
}

// discoverALBResources 跨配置地域发现 ALB HTTPS 监听器默认证书槽位。
func (p *Provider) discoverALBResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	resources := make([]providers.DeploymentResource, 0)
	partial := false
	var firstError error
	for _, region := range p.regions {
		if err := ctx.Err(); err != nil {
			return resources, true, err
		}
		client := p.albClients[region]
		if client == nil {
			partial = true
			continue
		}
		regionResources, regionPartial, err := p.discoverALBRegion(ctx, client, region, deploymentType)
		resources = append(resources, regionResources...)
		partial = partial || regionPartial
		if err != nil {
			partial = true
			if firstError == nil {
				firstError = err
			}
		}
		if len(resources) > maxResources {
			return resources, true, providers.NewDeploymentError("火山引擎 ALB 资源数量超过安全上限", false, requestIDFromError(firstError), firstError)
		}
	}
	sort.Slice(resources, func(left, right int) bool {
		if resources[left].Region != resources[right].Region {
			return resources[left].Region < resources[right].Region
		}
		if resources[left].Group != resources[right].Group {
			return resources[left].Group < resources[right].Group
		}
		return resources[left].Label < resources[right].Label
	})
	if firstError != nil && len(resources) == 0 {
		return resources, partial, firstError
	}
	return resources, partial, nil
}

// discoverALBRegion 发现单个地域内 ALB 实例的 HTTPS 监听器默认证书。
func (p *Provider) discoverALBRegion(ctx context.Context, client albClient, region string, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	loadBalancers, _, err := listALBLoadBalancers(ctx, client, nil)
	if err != nil {
		return nil, false, err
	}
	resources := make([]providers.DeploymentResource, 0)
	certificateCache := make(map[string]certificateDomainResult)
	partial := false
	var firstError error
	for _, loadBalancer := range loadBalancers {
		if loadBalancer == nil || stringValue(loadBalancer.LoadBalancerId) == "" || stringValue(loadBalancer.CreateTime) == "" {
			partial = true
			continue
		}
		listeners, _, listErr := listALBListeners(ctx, client, stringValue(loadBalancer.LoadBalancerId))
		if listErr != nil {
			partial = true
			if firstError == nil {
				firstError = listErr
			}
			continue
		}
		for _, listener := range listeners {
			if listener == nil || !strings.EqualFold(stringValue(listener.Protocol), "HTTPS") {
				continue
			}
			cacheKey := albCertificateCacheKey(listener)
			cached, exists := certificateCache[cacheKey]
			if !exists {
				domains, resolveErr := p.resolveALBCertificateDomains(ctx, client, listener)
				cached = certificateDomainResult{domains: domains, err: resolveErr}
				certificateCache[cacheKey] = cached
			}
			if cached.err != nil || len(cached.domains) == 0 {
				partial = true
				if firstError == nil {
					firstError = cached.err
				}
				continue
			}
			resource, ok := buildALBResource(deploymentType, region, loadBalancer, listener, cached.domains)
			if !ok {
				partial = true
				continue
			}
			resources = append(resources, resource)
		}
	}
	if firstError != nil && len(resources) == 0 {
		return resources, partial, firstError
	}
	return resources, partial, nil
}

// listALBLoadBalancers 分页读取 ALB 实例，可按实例 ID 精确过滤。
func listALBLoadBalancers(ctx context.Context, client albClient, loadBalancerIDs []*string) ([]*albapi.LoadBalancerForDescribeLoadBalancersOutput, string, error) {
	items := make([]*albapi.LoadBalancerForDescribeLoadBalancersOutput, 0)
	requestID := ""
	for page := int64(1); page <= maxPages; page++ {
		output, err := client.DescribeLoadBalancersWithContext(ctx, &albapi.DescribeLoadBalancersInput{
			LoadBalancerIds: loadBalancerIDs,
			PageNumber:      volcengine.Int64(page),
			PageSize:        volcengine.Int64(pageSize),
		})
		if err != nil {
			return items, firstNonEmpty(requestIDFromError(err), requestID), err
		}
		if output == nil {
			return items, requestID, providers.NewDeploymentError("火山引擎 ALB 实例列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(outputRequestID(output.RequestId, output.Metadata), requestID)
		items = append(items, output.LoadBalancers...)
		if output.TotalCount != nil {
			if int64(len(items)) >= *output.TotalCount {
				return items, requestID, nil
			}
			if len(output.LoadBalancers) == 0 {
				return items, requestID, providers.NewDeploymentError("火山引擎 ALB 实例分页结果不完整", true, requestID, nil)
			}
			continue
		}
		if len(output.LoadBalancers) < pageSize {
			return items, requestID, nil
		}
	}
	return items, requestID, providers.NewDeploymentError("火山引擎 ALB 实例目录超过安全分页上限", false, requestID, nil)
}

// listALBListeners 分页读取一个 ALB 实例的 HTTPS 监听器。
func listALBListeners(ctx context.Context, client albClient, loadBalancerID string) ([]*albapi.ListenerForDescribeListenersOutput, string, error) {
	items := make([]*albapi.ListenerForDescribeListenersOutput, 0)
	requestID := ""
	for page := int64(1); page <= maxPages; page++ {
		output, err := client.DescribeListenersWithContext(ctx, &albapi.DescribeListenersInput{
			LoadBalancerId: volcengine.String(loadBalancerID),
			Protocol:       volcengine.String("HTTPS"),
			PageNumber:     volcengine.Int64(page),
			PageSize:       volcengine.Int64(pageSize),
		})
		if err != nil {
			return items, firstNonEmpty(requestIDFromError(err), requestID), err
		}
		if output == nil {
			return items, requestID, providers.NewDeploymentError("火山引擎 ALB 监听器列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(outputRequestID(output.RequestId, output.Metadata), requestID)
		items = append(items, output.Listeners...)
		if output.TotalCount != nil {
			if int64(len(items)) >= *output.TotalCount {
				return items, requestID, nil
			}
			if len(output.Listeners) == 0 {
				return items, requestID, providers.NewDeploymentError("火山引擎 ALB 监听器分页结果不完整", true, requestID, nil)
			}
			continue
		}
		if len(output.Listeners) < pageSize {
			return items, requestID, nil
		}
	}
	return items, requestID, providers.NewDeploymentError("火山引擎 ALB 监听器目录超过安全分页上限", false, requestID, nil)
}

// albCertificateCacheKey 返回监听器当前默认证书引用的缓存键。
func albCertificateCacheKey(listener *albapi.ListenerForDescribeListenersOutput) string {
	if listener == nil {
		return ""
	}
	return strings.ToLower(stringValue(listener.CertificateSource)) + "\x00" + stringValue(listener.CertCenterCertificateId) + "\x00" + stringValue(listener.CertificateId)
}

// resolveALBCertificateDomains 按监听器证书来源读取共享证书中心或 ALB 本地证书域名。
func (p *Provider) resolveALBCertificateDomains(ctx context.Context, client albClient, listener *albapi.ListenerForDescribeListenersOutput) ([]string, error) {
	if listener == nil {
		return nil, providers.NewDeploymentError("火山引擎 ALB 监听器为空", false, "", nil)
	}
	source := strings.ToLower(stringValue(listener.CertificateSource))
	centerID := stringValue(listener.CertCenterCertificateId)
	localID := stringValue(listener.CertificateId)
	if source == loadBalancerCertificateSource || (source == "" && centerID != "") {
		return p.certificateCenterDomains(ctx, centerID)
	}
	if source == "alb" || (source == "" && localID != "") {
		return listALBCertificateDomains(ctx, client, localID)
	}
	return nil, providers.NewDeploymentError("火山引擎 ALB 监听器证书来源不受支持", false, "", nil)
}

// listALBCertificateDomains 读取 ALB 本地证书记录中的主域名和 SAN。
func listALBCertificateDomains(ctx context.Context, client albClient, certificateID string) ([]string, error) {
	output, err := client.DescribeCertificatesWithContext(ctx, &albapi.DescribeCertificatesInput{
		CertificateIds: []*string{volcengine.String(certificateID)},
		PageNumber:     volcengine.Int64(1),
		PageSize:       volcengine.Int64(2),
	})
	if err != nil {
		return nil, err
	}
	if output == nil {
		return nil, providers.NewDeploymentError("火山引擎 ALB 证书详情响应为空", true, "", nil)
	}
	for _, certificate := range output.Certificates {
		if certificate == nil || stringValue(certificate.CertificateId) != certificateID {
			continue
		}
		domains := parseVolcengineCertificateDomains(stringValue(certificate.DomainName), stringValue(certificate.San))
		if len(domains) == 0 {
			break
		}
		return domains, nil
	}
	return nil, providers.NewDeploymentError("火山引擎 ALB 证书记录缺少可识别域名", false, outputRequestID(output.RequestId, output.Metadata), nil)
}

// buildALBResource 将 ALB HTTPS 监听器默认证书槽位转换为稳定资源引用。
func buildALBResource(deploymentType deployPB.DeploymentType, region string, loadBalancer *albapi.LoadBalancerForDescribeLoadBalancersOutput, listener *albapi.ListenerForDescribeListenersOutput, domains []string) (providers.DeploymentResource, bool) {
	if loadBalancer == nil || listener == nil || len(domains) == 0 {
		return providers.DeploymentResource{}, false
	}
	loadBalancerID := stringValue(loadBalancer.LoadBalancerId)
	listenerID := stringValue(listener.ListenerId)
	loadBalancerCreatedAt := stringValue(loadBalancer.CreateTime)
	listenerCreatedAt := stringValue(listener.CreateTime)
	port := int64Value(listener.Port)
	if loadBalancerID == "" || listenerID == "" || loadBalancerCreatedAt == "" || listenerCreatedAt == "" || port < 1 || port > 65535 {
		return providers.DeploymentResource{}, false
	}
	ready := loadBalancerReady(stringValue(loadBalancer.Status), stringValue(loadBalancer.BusinessStatus), stringValue(listener.Status), stringValue(listener.Enabled))
	loadBalancerName := firstNonEmpty(stringValue(loadBalancer.LoadBalancerName), loadBalancerID)
	listenerName := firstNonEmpty(stringValue(listener.ListenerName), listenerID)
	return providers.DeploymentResource{
		TargetRef:      providers.BuildTargetRef("volcengine", deploymentType, region, loadBalancerID, loadBalancerCreatedAt, listenerID, listenerCreatedAt, loadBalancerDefaultSlot),
		Label:          fmt.Sprintf("%s:%d 默认 (%s)", listenerName, port, strings.Join(domains, ", ")),
		Domain:         domains[0],
		Domains:        append([]string(nil), domains...),
		Group:          loadBalancerName,
		Region:         region,
		Protocol:       "HTTPS",
		Status:         strings.ToLower(stringValue(listener.Status)),
		Availability:   loadBalancerAvailability(ready),
		LoadBalancerID: loadBalancerID,
		ListenerPort:   int(port),
		ListenerID:     listenerID,
		ResourceID:     loadBalancerDefaultSlot,
		CreatedAt:      loadBalancerLifecycle(loadBalancerCreatedAt, listenerCreatedAt),
	}, true
}

// deployALB 切换精确 ALB HTTPS 监听器的默认证书，并回读证书中心引用。
func (p *Provider) deployALB(ctx context.Context, resource providers.DeploymentResource, certificateID, requestID string) (string, error) {
	client := p.albClients[strings.ToLower(strings.TrimSpace(resource.Region))]
	if client == nil {
		return requestID, providers.NewDeploymentError("火山引擎 ALB 目标地域客户端未初始化", false, requestID, nil)
	}
	loadBalancer, loadBalancerRequestID, err := describeALBLoadBalancer(ctx, client, resource.LoadBalancerID)
	requestID = firstNonEmpty(loadBalancerRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	listener, listenerRequestID, err := describeALBListener(ctx, client, resource.ListenerID)
	requestID = firstNonEmpty(listenerRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	if !sameALBIdentity(resource, loadBalancer, listener) {
		return requestID, providers.NewDeploymentError("火山引擎 ALB 监听器身份已变化，请重新关联资源", false, requestID, nil)
	}
	if !loadBalancerReady(stringValue(loadBalancer.Status), stringValue(loadBalancer.BusinessStatus), stringValue(listener.Status), stringValue(listener.Enabled)) {
		return requestID, providers.NewDeploymentError("火山引擎 ALB 监听器当前不可部署", loadBalancerTransitioning(stringValue(loadBalancer.Status), stringValue(listener.Status)), requestID, nil)
	}
	if strings.EqualFold(stringValue(listener.CertificateSource), loadBalancerCertificateSource) && stringValue(listener.CertCenterCertificateId) == certificateID {
		return requestID, nil
	}

	writeOutput, err := client.ModifyListenerAttributesWithContext(ctx, &albapi.ModifyListenerAttributesInput{
		ListenerId:              volcengine.String(resource.ListenerID),
		CertificateSource:       volcengine.String(loadBalancerCertificateSource),
		CertCenterCertificateId: volcengine.String(certificateID),
	})
	if err != nil {
		return firstNonEmpty(requestIDFromError(err), requestID), err
	}
	if writeOutput == nil {
		return requestID, providers.NewDeploymentError("火山引擎 ALB 监听器更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(outputRequestID(writeOutput.RequestId, writeOutput.Metadata), requestID)

	readback, readbackRequestID, err := describeALBListener(ctx, client, resource.ListenerID)
	requestID = firstNonEmpty(readbackRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	if !sameALBIdentity(resource, loadBalancer, readback) {
		return requestID, providers.NewDeploymentError("火山引擎 ALB 监听器回读身份不一致", false, requestID, nil)
	}
	if !strings.EqualFold(stringValue(readback.CertificateSource), loadBalancerCertificateSource) || stringValue(readback.CertCenterCertificateId) != certificateID || !loadBalancerReady(stringValue(loadBalancer.Status), stringValue(loadBalancer.BusinessStatus), stringValue(readback.Status), stringValue(readback.Enabled)) {
		return requestID, providers.NewDeploymentError("火山引擎 ALB 监听器证书尚未生效", true, requestID, nil)
	}
	return requestID, nil
}

// describeALBLoadBalancer 精确读取一个 ALB 实例。
func describeALBLoadBalancer(ctx context.Context, client albClient, loadBalancerID string) (*albapi.LoadBalancerForDescribeLoadBalancersOutput, string, error) {
	items, requestID, err := listALBLoadBalancers(ctx, client, []*string{volcengine.String(loadBalancerID)})
	if err != nil {
		return nil, requestID, err
	}
	var matched *albapi.LoadBalancerForDescribeLoadBalancersOutput
	for _, item := range items {
		if item == nil || stringValue(item.LoadBalancerId) != loadBalancerID {
			continue
		}
		if matched != nil {
			return nil, requestID, providers.NewDeploymentError("火山引擎 ALB 实例回读结果不唯一", false, requestID, nil)
		}
		matched = item
	}
	if matched == nil {
		return nil, requestID, providers.NewDeploymentError("火山引擎 ALB 实例已失效，请重新关联资源", false, requestID, nil)
	}
	return matched, requestID, nil
}

// describeALBListener 精确读取一个 ALB 监听器详情。
func describeALBListener(ctx context.Context, client albClient, listenerID string) (*albapi.DescribeListenerAttributesOutput, string, error) {
	output, err := client.DescribeListenerAttributesWithContext(ctx, &albapi.DescribeListenerAttributesInput{ListenerId: volcengine.String(listenerID)})
	if err != nil {
		return nil, requestIDFromError(err), err
	}
	if output == nil {
		return nil, "", providers.NewDeploymentError("火山引擎 ALB 监听器详情响应为空", true, "", nil)
	}
	requestID := outputRequestID(output.RequestId, output.Metadata)
	return output, requestID, nil
}

// sameALBIdentity 校验 ALB 实例、监听器、端口和创建时间未发生变化。
func sameALBIdentity(resource providers.DeploymentResource, loadBalancer *albapi.LoadBalancerForDescribeLoadBalancersOutput, listener *albapi.DescribeListenerAttributesOutput) bool {
	if loadBalancer == nil || listener == nil || resource.ResourceID != loadBalancerDefaultSlot {
		return false
	}
	return stringValue(loadBalancer.LoadBalancerId) == resource.LoadBalancerID &&
		stringValue(listener.LoadBalancerId) == resource.LoadBalancerID &&
		stringValue(listener.ListenerId) == resource.ListenerID &&
		int64Value(listener.Port) == int64(resource.ListenerPort) &&
		strings.EqualFold(stringValue(listener.Protocol), "HTTPS") &&
		loadBalancerLifecycle(stringValue(loadBalancer.CreateTime), stringValue(listener.CreateTime)) == resource.CreatedAt
}
