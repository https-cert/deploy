package huawei

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/basic"
	sdkconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	elbapi "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3"
	elbmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/model"
	elbregion "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/elb/v3/region"
)

const elbPageSize = 2000

// elbClient 是华为云 ELB 资源发现和证书更新闭环所需的最小官方 SDK 接口。
type elbClient interface {
	ListLoadBalancers(request *elbmodel.ListLoadBalancersRequest) (*elbmodel.ListLoadBalancersResponse, error)
	ListListeners(request *elbmodel.ListListenersRequest) (*elbmodel.ListListenersResponse, error)
	ListCertificates(request *elbmodel.ListCertificatesRequest) (*elbmodel.ListCertificatesResponse, error)
	ShowCertificate(request *elbmodel.ShowCertificateRequest) (*elbmodel.ShowCertificateResponse, error)
	UpdateCertificate(request *elbmodel.UpdateCertificateRequest) (*elbmodel.UpdateCertificateResponse, error)
}

// elbCertificateBinding 聚合一个 ELB 证书影响的监听器和负载均衡器。
type elbCertificateBinding struct {
	certificate       elbmodel.CertificateInfo // certificate 是被监听器引用的 ELB 证书记录。
	listenerIDs       map[string]struct{}      // listenerIDs 保存引用该证书的监听器 ID。
	loadBalancerIDs   map[string]struct{}      // loadBalancerIDs 保存受影响的负载均衡器 ID。
	loadBalancerNames map[string]struct{}      // loadBalancerNames 保存脱敏展示名称。
	protocols         map[string]struct{}      // protocols 保存引用监听器协议。
	ready             bool                     // ready 表示所有已发现引用均处于可部署状态。
}

// newELBClients 为每个配置地域创建一个官方 ELB 客户端。
func newELBClients(accessKey, secretKey string, regions []string) (map[string]elbClient, error) {
	clients := make(map[string]elbClient, len(regions))
	for _, region := range regions {
		serviceRegion, err := elbregion.SafeValueOf(region)
		if err != nil {
			return nil, fmt.Errorf("华为云 ELB 地域无效[%s]: %w", region, err)
		}
		credential, err := basic.NewCredentialsBuilder().WithAk(accessKey).WithSk(secretKey).SafeBuild()
		if err != nil {
			return nil, fmt.Errorf("创建华为云 ELB 凭据失败[%s]: %w", region, err)
		}
		httpClient, err := elbapi.ElbClientBuilder().
			WithRegion(serviceRegion).
			WithCredential(credential).
			WithHttpConfig(sdkconfig.DefaultHttpConfig().WithTimeout(sdkTimeout)).
			SafeBuild()
		if err != nil {
			return nil, fmt.Errorf("创建华为云 ELB 客户端失败[%s]: %w", region, err)
		}
		clients[region] = elbapi.NewElbClient(httpClient)
	}
	return clients, nil
}

// discoverELBResources 跨配置地域发现被 TLS 监听器引用的证书资源。
func (p *Provider) discoverELBResources(ctx context.Context, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	resources := make([]providers.DeploymentResource, 0)
	partial := false
	var firstError error
	for _, region := range p.regions {
		if err := ctx.Err(); err != nil {
			return resources, true, err
		}
		client := p.elbClients[region]
		if client == nil {
			partial = true
			continue
		}
		regionResources, regionPartial, err := p.discoverELBRegion(ctx, client, region, deploymentType)
		resources = append(resources, regionResources...)
		partial = partial || regionPartial
		if err != nil {
			partial = true
			if firstError == nil {
				firstError = err
			}
		}
		if len(resources) > maxResources {
			return resources, true, providers.NewDeploymentError("华为云 ELB 资源数量超过安全上限", false, requestIDFromError(firstError), firstError)
		}
	}
	sort.Slice(resources, func(left, right int) bool {
		if resources[left].Region == resources[right].Region {
			return resources[left].Label < resources[right].Label
		}
		return resources[left].Region < resources[right].Region
	})
	if firstError != nil && len(resources) == 0 {
		return resources, partial, firstError
	}
	return resources, partial, nil
}

// discoverELBRegion 读取单个地域的负载均衡器、监听器和证书后聚合引用。
func (p *Provider) discoverELBRegion(ctx context.Context, client elbClient, region string, deploymentType deployPB.DeploymentType) ([]providers.DeploymentResource, bool, error) {
	loadBalancers, _, err := listELBLoadBalancers(ctx, client)
	if err != nil {
		return nil, false, err
	}
	listeners, _, err := listELBListeners(ctx, client)
	if err != nil {
		return nil, false, err
	}
	certificates, _, err := listELBCertificates(ctx, client)
	if err != nil {
		return nil, false, err
	}

	loadBalancerByID := make(map[string]elbmodel.LoadBalancer, len(loadBalancers))
	for _, loadBalancer := range loadBalancers {
		if strings.TrimSpace(loadBalancer.Id) != "" {
			loadBalancerByID[loadBalancer.Id] = loadBalancer
		}
	}
	certificateByID := make(map[string]elbmodel.CertificateInfo, len(certificates))
	for _, certificate := range certificates {
		if strings.TrimSpace(certificate.Id) != "" && strings.EqualFold(strings.TrimSpace(certificate.Type), "server") {
			certificateByID[certificate.Id] = certificate
		}
	}

	bindings := make(map[string]*elbCertificateBinding)
	partial := false
	for _, listener := range listeners {
		if !isELBTLSProtocol(listener.Protocol) || len(listener.Loadbalancers) != 1 {
			continue
		}
		loadBalancerID := stringPointerValue(listener.Loadbalancers[0].Id)
		loadBalancer, exists := loadBalancerByID[loadBalancerID]
		if !exists {
			partial = true
			continue
		}
		certificateIDs := append([]string{listener.DefaultTlsContainerRef}, listener.SniContainerRefs...)
		seenCertificates := make(map[string]struct{}, len(certificateIDs))
		for _, rawCertificateID := range certificateIDs {
			certificateID := strings.TrimSpace(rawCertificateID)
			if certificateID == "" {
				continue
			}
			if _, duplicate := seenCertificates[certificateID]; duplicate {
				continue
			}
			seenCertificates[certificateID] = struct{}{}
			certificate, exists := certificateByID[certificateID]
			if !exists {
				partial = true
				continue
			}
			binding := bindings[certificateID]
			if binding == nil {
				binding = &elbCertificateBinding{
					certificate:       certificate,
					listenerIDs:       make(map[string]struct{}),
					loadBalancerIDs:   make(map[string]struct{}),
					loadBalancerNames: make(map[string]struct{}),
					protocols:         make(map[string]struct{}),
					ready:             true,
				}
				bindings[certificateID] = binding
			}
			binding.listenerIDs[listener.Id] = struct{}{}
			binding.loadBalancerIDs[loadBalancerID] = struct{}{}
			binding.loadBalancerNames[firstNonEmpty(loadBalancer.Name, "未命名负载均衡器")] = struct{}{}
			binding.protocols[strings.ToUpper(strings.TrimSpace(listener.Protocol))] = struct{}{}
			binding.ready = binding.ready && listener.AdminStateUp && loadBalancer.AdminStateUp && strings.EqualFold(loadBalancer.ProvisioningStatus, "ACTIVE") && strings.EqualFold(loadBalancer.OperatingStatus, "ONLINE")
		}
	}

	resources := make([]providers.DeploymentResource, 0, len(bindings))
	for _, binding := range bindings {
		resource, ok := buildELBResource(deploymentType, region, binding)
		if !ok {
			partial = true
			continue
		}
		resources = append(resources, resource)
	}
	return resources, partial, nil
}

// buildELBResource 将共享证书引用聚合为一个不会隐藏影响范围的资源。
func buildELBResource(deploymentType deployPB.DeploymentType, region string, binding *elbCertificateBinding) (providers.DeploymentResource, bool) {
	if binding == nil || strings.TrimSpace(binding.certificate.Id) == "" || strings.TrimSpace(binding.certificate.CreatedAt) == "" {
		return providers.DeploymentResource{}, false
	}
	domains := elbCertificateDomains(binding.certificate)
	if len(domains) == 0 || len(binding.listenerIDs) == 0 || len(binding.loadBalancerIDs) == 0 {
		return providers.DeploymentResource{}, false
	}
	listenerIDs := sortedSet(binding.listenerIDs)
	loadBalancerIDs := sortedSet(binding.loadBalancerIDs)
	loadBalancerNames := sortedSet(binding.loadBalancerNames)
	protocols := sortedSet(binding.protocols)
	availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
	status := "stopped"
	if binding.ready {
		availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
		status = "online"
	}
	label := strings.TrimSpace(binding.certificate.Name)
	if label == "" {
		label = domains[0]
	}
	return providers.DeploymentResource{
		TargetRef:      providers.BuildTargetRef("huawei", deploymentType, region, binding.certificate.Id, binding.certificate.CreatedAt),
		Label:          fmt.Sprintf("%s (%s)", label, strings.Join(domains, ", ")),
		Domain:         domains[0],
		Domains:        domains,
		Group:          strings.Join(loadBalancerNames, ", "),
		Region:         region,
		Protocol:       strings.Join(protocols, ","),
		Status:         status,
		Availability:   availability,
		LoadBalancerID: loadBalancerIDs[0],
		ListenerID:     listenerIDs[0],
		ResourceID:     binding.certificate.Id,
		CreatedAt:      binding.certificate.CreatedAt,
	}, true
}

// deployELB 原地更新监听器引用的 ELB 证书记录并回读 PEM 指纹。
func (p *Provider) deployELB(ctx context.Context, certificate providers.CertificateMaterial, resource providers.DeploymentResource, scmCertificateID, requestID string) (string, error) {
	region := strings.ToLower(strings.TrimSpace(resource.Region))
	client := p.elbClients[region]
	if client == nil {
		return requestID, providers.NewDeploymentError("华为云 ELB 目标地域客户端未初始化", false, requestID, nil)
	}
	certificateID := strings.TrimSpace(resource.ResourceID)
	if certificateID == "" || strings.TrimSpace(resource.CreatedAt) == "" {
		return requestID, providers.NewDeploymentError("华为云 ELB 目标缺少证书 ID 或创建时间", false, requestID, nil)
	}
	preflight, err := showELBCertificate(ctx, client, certificateID)
	if err != nil {
		return requestIDFromError(err), err
	}
	requestID = firstNonEmpty(preflight.requestID, requestID)
	if preflight.certificate.Id != certificateID || preflight.certificate.CreatedAt != resource.CreatedAt || !strings.EqualFold(preflight.certificate.Type, "server") {
		return requestID, providers.NewDeploymentError("华为云 ELB 证书身份已变化，请重新关联资源", false, requestID, nil)
	}

	source := "scm"
	domain := strings.Join(resource.Domains, ",")
	name := strings.TrimSpace(preflight.certificate.Name)
	updateOption := &elbmodel.UpdateCertificateOption{
		Certificate:      &certificate.CertificatePEM,
		PrivateKey:       &certificate.PrivateKeyPEM,
		Domain:           &domain,
		ScmCertificateId: &scmCertificateID,
		Source:           &source,
	}
	if name != "" {
		updateOption.Name = &name
	}
	response, err := client.UpdateCertificate(&elbmodel.UpdateCertificateRequest{
		CertificateId: certificateID,
		Body:          &elbmodel.UpdateCertificateRequestBody{Certificate: updateOption},
	})
	if err != nil {
		return requestIDFromError(err), err
	}
	if response == nil || response.Certificate == nil {
		return requestID, providers.NewDeploymentError("华为云 ELB 证书更新响应为空", true, requestID, nil)
	}
	requestID = firstNonEmpty(stringPointerValue(response.RequestId), requestID)
	if err := verifyELBCertificate(*response.Certificate, certificateID, resource.CreatedAt, scmCertificateID, certificate.CertificatePEM); err != nil {
		return requestID, providers.NewDeploymentError("华为云 ELB 更新响应校验失败", true, requestID, err)
	}

	readback, err := showELBCertificate(ctx, client, certificateID)
	if err != nil {
		return requestIDFromError(err), err
	}
	requestID = firstNonEmpty(readback.requestID, requestID)
	if err := verifyELBCertificate(readback.certificate, certificateID, resource.CreatedAt, scmCertificateID, certificate.CertificatePEM); err != nil {
		return requestID, providers.NewDeploymentError("华为云 ELB 证书回读尚未生效", true, requestID, err)
	}
	return requestID, nil
}

// elbCertificateReadback 封装 ELB 证书详情及请求 ID。
type elbCertificateReadback struct {
	certificate elbmodel.CertificateInfo // certificate 是回读到的证书记录。
	requestID   string                   // requestID 是本次详情请求编号。
}

// showELBCertificate 按证书 ID 读取 ELB 证书详情。
func showELBCertificate(ctx context.Context, client elbClient, certificateID string) (elbCertificateReadback, error) {
	if err := ctx.Err(); err != nil {
		return elbCertificateReadback{}, err
	}
	response, err := client.ShowCertificate(&elbmodel.ShowCertificateRequest{CertificateId: certificateID})
	if err != nil {
		return elbCertificateReadback{}, err
	}
	if response == nil || response.Certificate == nil {
		return elbCertificateReadback{}, providers.NewDeploymentError("华为云 ELB 证书详情响应为空", true, "", nil)
	}
	return elbCertificateReadback{certificate: *response.Certificate, requestID: stringPointerValue(response.RequestId)}, nil
}

// verifyELBCertificate 校验 ELB 证书生命周期、SCM 引用和叶证书指纹。
func verifyELBCertificate(certificate elbmodel.CertificateInfo, certificateID, createdAt, scmCertificateID, certificatePEM string) error {
	if strings.TrimSpace(certificate.Id) != certificateID || strings.TrimSpace(certificate.CreatedAt) != createdAt {
		return fmt.Errorf("ELB 证书生命周期不一致")
	}
	if stringPointerValue(certificate.ScmCertificateId) != scmCertificateID || !strings.EqualFold(stringPointerValue(certificate.Source), "scm") {
		return fmt.Errorf("ELB SCM 证书引用不一致")
	}
	if err := providers.VerifyLeafCertificateSHA256(certificatePEM, certificate.Certificate); err != nil {
		return err
	}
	return nil
}

// listELBLoadBalancers 分页读取 ELB 实例目录。
func listELBLoadBalancers(ctx context.Context, client elbClient) ([]elbmodel.LoadBalancer, string, error) {
	result := make([]elbmodel.LoadBalancer, 0)
	marker := ""
	requestID := ""
	limit := int32(elbPageSize)
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return result, requestID, err
		}
		request := &elbmodel.ListLoadBalancersRequest{Limit: &limit}
		if marker != "" {
			request.Marker = &marker
		}
		response, err := client.ListLoadBalancers(request)
		if err != nil {
			return result, requestIDFromError(err), err
		}
		if response == nil {
			return result, requestID, providers.NewDeploymentError("华为云 ELB 实例列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(stringPointerValue(response.RequestId), requestID)
		if response.Loadbalancers != nil {
			result = append(result, (*response.Loadbalancers)...)
		}
		nextMarker, done, err := nextELBMarker(response.PageInfo, marker)
		if err != nil {
			return result, requestID, err
		}
		if done {
			return result, requestID, nil
		}
		marker = nextMarker
	}
	return result, requestID, providers.NewDeploymentError("华为云 ELB 实例分页超过安全上限", false, requestID, nil)
}

// listELBListeners 分页读取 ELB 监听器目录。
func listELBListeners(ctx context.Context, client elbClient) ([]elbmodel.Listener, string, error) {
	result := make([]elbmodel.Listener, 0)
	marker := ""
	requestID := ""
	limit := int32(elbPageSize)
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return result, requestID, err
		}
		request := &elbmodel.ListListenersRequest{Limit: &limit}
		if marker != "" {
			request.Marker = &marker
		}
		response, err := client.ListListeners(request)
		if err != nil {
			return result, requestIDFromError(err), err
		}
		if response == nil {
			return result, requestID, providers.NewDeploymentError("华为云 ELB 监听器列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(stringPointerValue(response.RequestId), requestID)
		if response.Listeners != nil {
			result = append(result, (*response.Listeners)...)
		}
		nextMarker, done, err := nextELBMarker(response.PageInfo, marker)
		if err != nil {
			return result, requestID, err
		}
		if done {
			return result, requestID, nil
		}
		marker = nextMarker
	}
	return result, requestID, providers.NewDeploymentError("华为云 ELB 监听器分页超过安全上限", false, requestID, nil)
}

// listELBCertificates 分页读取 ELB 证书目录。
func listELBCertificates(ctx context.Context, client elbClient) ([]elbmodel.CertificateInfo, string, error) {
	result := make([]elbmodel.CertificateInfo, 0)
	marker := ""
	requestID := ""
	limit := int32(elbPageSize)
	for page := 0; page < maxPages; page++ {
		if err := ctx.Err(); err != nil {
			return result, requestID, err
		}
		request := &elbmodel.ListCertificatesRequest{Limit: &limit}
		if marker != "" {
			request.Marker = &marker
		}
		response, err := client.ListCertificates(request)
		if err != nil {
			return result, requestIDFromError(err), err
		}
		if response == nil {
			return result, requestID, providers.NewDeploymentError("华为云 ELB 证书列表响应为空", true, requestID, nil)
		}
		requestID = firstNonEmpty(stringPointerValue(response.RequestId), requestID)
		if response.Certificates != nil {
			result = append(result, (*response.Certificates)...)
		}
		nextMarker, done, err := nextELBMarker(response.PageInfo, marker)
		if err != nil {
			return result, requestID, err
		}
		if done {
			return result, requestID, nil
		}
		marker = nextMarker
	}
	return result, requestID, providers.NewDeploymentError("华为云 ELB 证书分页超过安全上限", false, requestID, nil)
}

// nextELBMarker 读取下一页游标并拒绝游标循环。
func nextELBMarker(pageInfo *elbmodel.PageInfo, current string) (string, bool, error) {
	if pageInfo == nil || pageInfo.NextMarker == nil || strings.TrimSpace(*pageInfo.NextMarker) == "" {
		return "", true, nil
	}
	next := strings.TrimSpace(*pageInfo.NextMarker)
	if next == current {
		return "", false, providers.NewDeploymentError("华为云 ELB 分页游标循环", false, "", nil)
	}
	return next, false, nil
}

// elbCertificateDomains 归一化证书主域名和 SAN 列表。
func elbCertificateDomains(certificate elbmodel.CertificateInfo) []string {
	rawDomains := make([]string, 0)
	for _, domain := range strings.Split(certificate.Domain, ",") {
		rawDomains = append(rawDomains, domain)
	}
	if certificate.CommonName != nil {
		rawDomains = append(rawDomains, *certificate.CommonName)
	}
	if certificate.SubjectAlternativeNames != nil {
		rawDomains = append(rawDomains, (*certificate.SubjectAlternativeNames)...)
	}
	return providers.NormalizeDomains(rawDomains...)
}

// isELBTLSProtocol 判断监听器是否使用服务器证书。
func isELBTLSProtocol(protocol string) bool {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTPS", "TERMINATED_HTTPS", "QUIC", "TLS":
		return true
	default:
		return false
	}
}

// sortedSet 将字符串集合转换为稳定排序切片。
func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}
