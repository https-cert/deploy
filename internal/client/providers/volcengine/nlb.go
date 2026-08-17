package volcengine

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	clbapi "github.com/volcengine/volcengine-go-sdk/service/clb"
	"github.com/volcengine/volcengine-go-sdk/volcengine"
	"github.com/volcengine/volcengine-go-sdk/volcengine/request"
)

const nlbTLSProtocol = "TLS"

// nlbClient 是 NLB TLS 监听器发现、更新和回读所需的最小官方 SDK 接口。
type nlbClient interface {
	DescribeNetworkLoadBalancersWithContext(ctx volcengine.Context, input *clbapi.DescribeNetworkLoadBalancersInput, options ...request.Option) (*clbapi.DescribeNetworkLoadBalancersOutput, error)
	DescribeNLBListenersWithContext(ctx volcengine.Context, input *clbapi.DescribeNLBListenersInput, options ...request.Option) (*clbapi.DescribeNLBListenersOutput, error)
	DescribeNLBListenerAttributesWithContext(ctx volcengine.Context, input *clbapi.DescribeNLBListenerAttributesInput, options ...request.Option) (*clbapi.DescribeNLBListenerAttributesOutput, error)
	DescribeNLBListenerCertificatesWithContext(ctx volcengine.Context, input *clbapi.DescribeNLBListenerCertificatesInput, options ...request.Option) (*clbapi.DescribeNLBListenerCertificatesOutput, error)
	ModifyNLBListenerAttributesWithContext(ctx volcengine.Context, input *clbapi.ModifyNLBListenerAttributesInput, options ...request.Option) (*clbapi.ModifyNLBListenerAttributesOutput, error)
}

// nlbCertificateResult 缓存监听器默认证书的域名、终态和解析错误。
type nlbCertificateResult struct {
	domains []string // domains 是默认证书覆盖的规范化域名集合。
	active  bool     // active 表示默认证书关联已进入 Active 终态。
	err     error    // err 是证书关联目录或证书中心读取错误。
}

// discoverNLBResources 跨配置地域发现 NLB TLS 监听器默认证书槽位。
func (p *Provider) discoverNLBResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	resources := make([]providers.DeploymentResource, 0)
	partial := false
	var firstError error
	for _, region := range p.regions {
		if err := ctx.Err(); err != nil {
			return resources, true, err
		}
		client := p.nlbClients[region]
		if client == nil {
			partial = true
			continue
		}
		regionResources, regionPartial, err := p.discoverNLBRegion(ctx, client, region, deploymentType)
		resources = append(resources, regionResources...)
		partial = partial || regionPartial
		if err != nil {
			partial = true
			if firstError == nil {
				firstError = err
			}
		}
		if len(resources) > maxResources {
			return resources, true, providers.NewDeploymentError("火山引擎 NLB 资源数量超过安全上限", false, requestIDFromError(firstError), firstError)
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

// discoverNLBRegion 发现单个地域内 NLB 实例的 TLS 监听器默认证书。
func (p *Provider) discoverNLBRegion(ctx context.Context, client nlbClient, region string, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	loadBalancers, _, err := listNLBLoadBalancers(ctx, client, nil)
	if err != nil {
		return nil, false, err
	}
	resources := make([]providers.DeploymentResource, 0)
	certificateCache := make(map[string]nlbCertificateResult)
	partial := false
	var firstError error
	for _, loadBalancer := range loadBalancers {
		if loadBalancer == nil || stringValue(loadBalancer.LoadBalancerId) == "" || stringValue(loadBalancer.CreateTime) == "" {
			partial = true
			continue
		}
		listeners, _, listErr := listNLBListeners(ctx, client, stringValue(loadBalancer.LoadBalancerId))
		if listErr != nil {
			partial = true
			if firstError == nil {
				firstError = listErr
			}
			continue
		}
		for _, listener := range listeners {
			if listener == nil || !strings.EqualFold(stringValue(listener.Protocol), nlbTLSProtocol) {
				continue
			}
			cacheKey := nlbCertificateCacheKey(listener)
			cached, exists := certificateCache[cacheKey]
			if !exists {
				domains, active, resolveErr := p.resolveNLBCertificateDomains(ctx, client, listener)
				cached = nlbCertificateResult{domains: domains, active: active, err: resolveErr}
				certificateCache[cacheKey] = cached
			}
			if cached.err != nil || len(cached.domains) == 0 {
				partial = true
				if firstError == nil {
					firstError = cached.err
				}
				continue
			}
			resource, ok := buildNLBResource(deploymentType, region, loadBalancer, listener, cached.domains, cached.active)
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

// listNLBLoadBalancers 按 NextToken 分页读取 NLB 实例，可按实例 ID 精确过滤。
func listNLBLoadBalancers(ctx context.Context, client nlbClient, loadBalancerIDs []*string) ([]*clbapi.LoadBalancerForDescribeNetworkLoadBalancersOutput, string, error) {
	items := make([]*clbapi.LoadBalancerForDescribeNetworkLoadBalancersOutput, 0)
	requestID := ""
	nextToken := ""
	seenTokens := make(map[string]struct{})
	for page := 1; page <= maxPages; page++ {
		input := &clbapi.DescribeNetworkLoadBalancersInput{
			LoadBalancerIds: loadBalancerIDs,
			MaxResults:      volcengine.Int64(pageSize),
		}
		if nextToken != "" {
			input.NextToken = volcengine.String(nextToken)
		}
		output, err := client.DescribeNetworkLoadBalancersWithContext(ctx, input)
		if err != nil {
			return items, firstNonEmpty(requestIDFromError(err), requestID), err
		}
		if output == nil {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 实例列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(outputRequestID(output.RequestId, output.Metadata), requestID)
		items = append(items, output.LoadBalancers...)
		if len(items) > maxResources {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 实例数量超过安全上限", false, requestID, nil)
		}
		next := strings.TrimSpace(stringValue(output.NextToken))
		if next == "" {
			return items, requestID, nil
		}
		if len(output.LoadBalancers) == 0 {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 实例分页结果不完整", true, requestID, nil)
		}
		if _, exists := seenTokens[next]; exists {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 实例分页游标重复", true, requestID, nil)
		}
		seenTokens[next] = struct{}{}
		nextToken = next
	}
	return items, requestID, providers.NewDeploymentError("火山引擎 NLB 实例目录超过安全分页上限", false, requestID, nil)
}

// listNLBListeners 按 NextToken 分页读取一个 NLB 实例的 TLS 监听器。
func listNLBListeners(ctx context.Context, client nlbClient, loadBalancerID string) ([]*clbapi.ListenerForDescribeNLBListenersOutput, string, error) {
	items := make([]*clbapi.ListenerForDescribeNLBListenersOutput, 0)
	requestID := ""
	nextToken := ""
	seenTokens := make(map[string]struct{})
	for page := 1; page <= maxPages; page++ {
		input := &clbapi.DescribeNLBListenersInput{
			LoadBalancerId: volcengine.String(loadBalancerID),
			Protocol:       volcengine.String(nlbTLSProtocol),
			MaxResults:     volcengine.Int64(pageSize),
		}
		if nextToken != "" {
			input.NextToken = volcengine.String(nextToken)
		}
		output, err := client.DescribeNLBListenersWithContext(ctx, input)
		if err != nil {
			return items, firstNonEmpty(requestIDFromError(err), requestID), err
		}
		if output == nil {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 监听器列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(outputRequestID(output.RequestId, output.Metadata), requestID)
		items = append(items, output.Listeners...)
		if len(items) > maxResources {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 监听器数量超过安全上限", false, requestID, nil)
		}
		next := strings.TrimSpace(stringValue(output.NextToken))
		if next == "" {
			return items, requestID, nil
		}
		if len(output.Listeners) == 0 {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 监听器分页结果不完整", true, requestID, nil)
		}
		if _, exists := seenTokens[next]; exists {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 监听器分页游标重复", true, requestID, nil)
		}
		seenTokens[next] = struct{}{}
		nextToken = next
	}
	return items, requestID, providers.NewDeploymentError("火山引擎 NLB 监听器目录超过安全分页上限", false, requestID, nil)
}

// listNLBListenerCertificates 按 NextToken 分页读取监听器的默认和附加证书关联。
func listNLBListenerCertificates(ctx context.Context, client nlbClient, listenerID string) ([]*clbapi.CertificateForDescribeNLBListenerCertificatesOutput, string, error) {
	items := make([]*clbapi.CertificateForDescribeNLBListenerCertificatesOutput, 0)
	requestID := ""
	nextToken := ""
	seenTokens := make(map[string]struct{})
	for page := 1; page <= maxPages; page++ {
		input := &clbapi.DescribeNLBListenerCertificatesInput{
			ListenerId: volcengine.String(listenerID),
			MaxResults: volcengine.Int64(pageSize),
		}
		if nextToken != "" {
			input.NextToken = volcengine.String(nextToken)
		}
		output, err := client.DescribeNLBListenerCertificatesWithContext(ctx, input)
		if err != nil {
			return items, firstNonEmpty(requestIDFromError(err), requestID), err
		}
		if output == nil {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 证书关联列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(outputRequestID(output.RequestId, output.Metadata), requestID)
		if responseListenerID := stringValue(output.ListenerId); responseListenerID != "" && responseListenerID != listenerID {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 证书关联回读监听器不一致", false, requestID, nil)
		}
		items = append(items, output.Certificates...)
		if len(items) > maxResources {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 证书关联数量超过安全上限", false, requestID, nil)
		}
		next := strings.TrimSpace(stringValue(output.NextToken))
		if next == "" {
			return items, requestID, nil
		}
		if len(output.Certificates) == 0 {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 证书关联分页结果不完整", true, requestID, nil)
		}
		if _, exists := seenTokens[next]; exists {
			return items, requestID, providers.NewDeploymentError("火山引擎 NLB 证书关联分页游标重复", true, requestID, nil)
		}
		seenTokens[next] = struct{}{}
		nextToken = next
	}
	return items, requestID, providers.NewDeploymentError("火山引擎 NLB 证书关联目录超过安全分页上限", false, requestID, nil)
}

// nlbCertificateCacheKey 返回监听器当前默认证书引用的缓存键。
func nlbCertificateCacheKey(listener *clbapi.ListenerForDescribeNLBListenersOutput) string {
	if listener == nil {
		return ""
	}
	return stringValue(listener.ListenerId) + "\x00" + strings.ToLower(stringValue(listener.CertificateSource)) + "\x00" + stringValue(listener.CertificateId)
}

// resolveNLBCertificateDomains 回读默认证书关联，并按证书来源解析覆盖域名。
func (p *Provider) resolveNLBCertificateDomains(ctx context.Context, client nlbClient, listener *clbapi.ListenerForDescribeNLBListenersOutput) ([]string, bool, error) {
	if listener == nil {
		return nil, false, providers.NewDeploymentError("火山引擎 NLB 监听器为空", false, "", nil)
	}
	listenerID := stringValue(listener.ListenerId)
	certificateID := stringValue(listener.CertificateId)
	certificateSource := strings.ToLower(stringValue(listener.CertificateSource))
	if listenerID == "" || certificateID == "" {
		return nil, false, providers.NewDeploymentError("火山引擎 NLB 监听器缺少默认证书引用", false, "", nil)
	}
	certificates, requestID, err := listNLBListenerCertificates(ctx, client, listenerID)
	if err != nil {
		return nil, false, err
	}
	certificate, err := findDefaultNLBCertificate(certificates, certificateID, certificateSource)
	if err != nil {
		return nil, false, providers.NewDeploymentError("火山引擎 NLB 默认证书关联不可用", false, requestID, err)
	}
	active := strings.EqualFold(stringValue(certificate.Status), "Active")
	if certificateSource == loadBalancerCertificateSource {
		domains, domainErr := p.certificateCenterDomains(ctx, certificateID)
		return domains, active, domainErr
	}
	domains := parseVolcengineCertificateDomains(stringValue(certificate.Domain))
	if len(domains) == 0 {
		return nil, active, providers.NewDeploymentError("火山引擎 NLB 默认证书记录缺少可识别域名", false, requestID, nil)
	}
	return domains, active, nil
}

// findDefaultNLBCertificate 在证书关联目录中唯一匹配指定来源和 ID 的默认证书。
func findDefaultNLBCertificate(certificates []*clbapi.CertificateForDescribeNLBListenerCertificatesOutput, certificateID, certificateSource string) (*clbapi.CertificateForDescribeNLBListenerCertificatesOutput, error) {
	var matched *clbapi.CertificateForDescribeNLBListenerCertificatesOutput
	for _, certificate := range certificates {
		if certificate == nil || certificate.IsDefault == nil || !*certificate.IsDefault {
			continue
		}
		if stringValue(certificate.CertificateId) != certificateID {
			continue
		}
		if certificateSource != "" && !strings.EqualFold(stringValue(certificate.CertificateSource), certificateSource) {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("默认证书关联回读结果不唯一")
		}
		matched = certificate
	}
	if matched == nil {
		return nil, fmt.Errorf("未找到目标默认证书关联")
	}
	return matched, nil
}

// buildNLBResource 将 NLB TLS 监听器默认证书槽位转换为稳定资源引用。
func buildNLBResource(deploymentType deployPB.DeploymentType, region string, loadBalancer *clbapi.LoadBalancerForDescribeNetworkLoadBalancersOutput, listener *clbapi.ListenerForDescribeNLBListenersOutput, domains []string, certificateActive bool) (providers.DeploymentResource, bool) {
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
	ready := certificateActive && nlbReady(stringValue(loadBalancer.Status), stringValue(loadBalancer.BillingStatus), stringValue(listener.Status), listener.Enabled)
	loadBalancerName := firstNonEmpty(stringValue(loadBalancer.LoadBalancerName), loadBalancerID)
	listenerName := firstNonEmpty(stringValue(listener.ListenerName), listenerID)
	return providers.DeploymentResource{
		TargetRef:      providers.BuildTargetRef("volcengine", deploymentType, region, loadBalancerID, loadBalancerCreatedAt, listenerID, listenerCreatedAt, loadBalancerDefaultSlot),
		Label:          fmt.Sprintf("%s:%d 默认 (%s)", listenerName, port, strings.Join(domains, ", ")),
		Domain:         domains[0],
		Domains:        append([]string(nil), domains...),
		Group:          loadBalancerName,
		Region:         region,
		Protocol:       nlbTLSProtocol,
		Status:         strings.ToLower(stringValue(listener.Status)),
		Availability:   loadBalancerAvailability(ready),
		LoadBalancerID: loadBalancerID,
		ListenerPort:   int(port),
		ListenerID:     listenerID,
		ResourceID:     loadBalancerDefaultSlot,
		CreatedAt:      loadBalancerLifecycle(loadBalancerCreatedAt, listenerCreatedAt),
	}, true
}

// deployNLB 切换精确 NLB TLS 监听器的默认证书，并回读监听器和默认证书关联。
func (p *Provider) deployNLB(ctx context.Context, resource providers.DeploymentResource, certificateID, requestID string) (string, error) {
	client := p.nlbClients[strings.ToLower(strings.TrimSpace(resource.Region))]
	if client == nil {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 目标地域客户端未初始化", false, requestID, nil)
	}
	loadBalancer, loadBalancerRequestID, err := describeNLBLoadBalancer(ctx, client, resource.LoadBalancerID)
	requestID = firstNonEmpty(loadBalancerRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	listener, listenerRequestID, err := describeNLBListener(ctx, client, resource.ListenerID)
	requestID = firstNonEmpty(listenerRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	if !sameNLBIdentity(resource, loadBalancer, listener) {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 监听器身份已变化，请重新关联资源", false, requestID, nil)
	}
	if !nlbReady(stringValue(loadBalancer.Status), stringValue(loadBalancer.BillingStatus), stringValue(listener.Status), listener.Enabled) {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 监听器当前不可部署", nlbTransitioning(stringValue(loadBalancer.Status), stringValue(listener.Status)), requestID, nil)
	}
	if strings.EqualFold(stringValue(listener.CertificateSource), loadBalancerCertificateSource) && stringValue(listener.CertificateId) == certificateID {
		return verifyNLBDefaultCertificate(ctx, client, resource.ListenerID, certificateID, requestID)
	}

	writeOutput, err := client.ModifyNLBListenerAttributesWithContext(ctx, &clbapi.ModifyNLBListenerAttributesInput{
		ListenerId:        volcengine.String(resource.ListenerID),
		CertificateSource: volcengine.String(loadBalancerCertificateSource),
		CertificateId:     volcengine.String(certificateID),
	})
	if err != nil {
		return firstNonEmpty(requestIDFromError(err), requestID), err
	}
	if writeOutput == nil {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 监听器更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(outputRequestID(writeOutput.RequestId, writeOutput.Metadata), requestID)

	readback, readbackRequestID, err := describeNLBListener(ctx, client, resource.ListenerID)
	requestID = firstNonEmpty(readbackRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	if !sameNLBIdentity(resource, loadBalancer, readback) {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 监听器回读身份不一致", false, requestID, nil)
	}
	if !strings.EqualFold(stringValue(readback.CertificateSource), loadBalancerCertificateSource) || stringValue(readback.CertificateId) != certificateID || !nlbReady(stringValue(loadBalancer.Status), stringValue(loadBalancer.BillingStatus), stringValue(readback.Status), readback.Enabled) {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 监听器证书尚未生效", true, requestID, nil)
	}
	return verifyNLBDefaultCertificate(ctx, client, resource.ListenerID, certificateID, requestID)
}

// verifyNLBDefaultCertificate 确认新证书已成为唯一且 Active 的监听器默认证书。
func verifyNLBDefaultCertificate(ctx context.Context, client nlbClient, listenerID, certificateID, requestID string) (string, error) {
	certificates, readbackRequestID, err := listNLBListenerCertificates(ctx, client, listenerID)
	requestID = firstNonEmpty(readbackRequestID, requestID)
	if err != nil {
		return requestID, err
	}
	certificate, err := findDefaultNLBCertificate(certificates, certificateID, loadBalancerCertificateSource)
	if err != nil {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 默认证书尚未生效", true, requestID, err)
	}
	if !strings.EqualFold(stringValue(certificate.Status), "Active") {
		return requestID, providers.NewDeploymentError("火山引擎 NLB 默认证书仍在配置中", true, requestID, nil)
	}
	return requestID, nil
}

// describeNLBLoadBalancer 精确读取一个 NLB 实例。
func describeNLBLoadBalancer(ctx context.Context, client nlbClient, loadBalancerID string) (*clbapi.LoadBalancerForDescribeNetworkLoadBalancersOutput, string, error) {
	items, requestID, err := listNLBLoadBalancers(ctx, client, []*string{volcengine.String(loadBalancerID)})
	if err != nil {
		return nil, requestID, err
	}
	var matched *clbapi.LoadBalancerForDescribeNetworkLoadBalancersOutput
	for _, item := range items {
		if item == nil || stringValue(item.LoadBalancerId) != loadBalancerID {
			continue
		}
		if matched != nil {
			return nil, requestID, providers.NewDeploymentError("火山引擎 NLB 实例回读结果不唯一", false, requestID, nil)
		}
		matched = item
	}
	if matched == nil {
		return nil, requestID, providers.NewDeploymentError("火山引擎 NLB 实例已失效，请重新关联资源", false, requestID, nil)
	}
	return matched, requestID, nil
}

// describeNLBListener 精确读取一个 NLB 监听器详情。
func describeNLBListener(ctx context.Context, client nlbClient, listenerID string) (*clbapi.DescribeNLBListenerAttributesOutput, string, error) {
	output, err := client.DescribeNLBListenerAttributesWithContext(ctx, &clbapi.DescribeNLBListenerAttributesInput{ListenerId: volcengine.String(listenerID)})
	if err != nil {
		return nil, requestIDFromError(err), err
	}
	if output == nil {
		return nil, "", providers.NewDeploymentError("火山引擎 NLB 监听器详情响应为空", true, "", nil)
	}
	requestID := outputRequestID(output.RequestId, output.Metadata)
	return output, requestID, nil
}

// sameNLBIdentity 校验 NLB 实例、监听器、端口和创建时间未发生变化。
func sameNLBIdentity(resource providers.DeploymentResource, loadBalancer *clbapi.LoadBalancerForDescribeNetworkLoadBalancersOutput, listener *clbapi.DescribeNLBListenerAttributesOutput) bool {
	if loadBalancer == nil || listener == nil || resource.ResourceID != loadBalancerDefaultSlot {
		return false
	}
	return stringValue(loadBalancer.LoadBalancerId) == resource.LoadBalancerID &&
		stringValue(listener.LoadBalancerId) == resource.LoadBalancerID &&
		stringValue(listener.ListenerId) == resource.ListenerID &&
		int64Value(listener.Port) == int64(resource.ListenerPort) &&
		strings.EqualFold(stringValue(listener.Protocol), nlbTLSProtocol) &&
		loadBalancerLifecycle(stringValue(loadBalancer.CreateTime), stringValue(listener.CreateTime)) == resource.CreatedAt
}

// nlbReady 判断 NLB 实例、计费和 TLS 监听器是否均处于官方可部署终态。
func nlbReady(loadBalancerStatus, billingStatus, listenerStatus string, enabled *bool) bool {
	return strings.EqualFold(strings.TrimSpace(loadBalancerStatus), "Active") &&
		strings.EqualFold(strings.TrimSpace(billingStatus), "Normal") &&
		strings.EqualFold(strings.TrimSpace(listenerStatus), "Active") &&
		enabled != nil && *enabled
}

// nlbTransitioning 判断 NLB 实例或监听器是否处于官方异步过渡状态。
func nlbTransitioning(loadBalancerStatus, listenerStatus string) bool {
	loadBalancerStatus = strings.ToLower(strings.TrimSpace(loadBalancerStatus))
	listenerStatus = strings.ToLower(strings.TrimSpace(listenerStatus))
	return loadBalancerStatus == "creating" || loadBalancerStatus == "provisioning" || loadBalancerStatus == "configuring" || listenerStatus == "creating"
}
