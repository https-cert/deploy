package cloud_tencent

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	tencentclb "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"
	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

const (
	// tencentCLBHost 是腾讯云 CLB API 的固定服务端点。
	tencentCLBHost = "clb.tencentcloudapi.com"
	// tencentCLBHTTPS 是 CLB 七层 HTTPS 监听器协议。
	tencentCLBHTTPS = "HTTPS"
	// tencentCLBTCPSSL 是 CLB 四层 TCP_SSL 监听器协议。
	tencentCLBTCPSSL = "TCP_SSL"
	// tencentCLBQUIC 是 CLB QUIC 监听器协议。
	tencentCLBQUIC = "QUIC"
	// tencentCLBSNIEnabled 表示 HTTPS 监听器已开启 SNI。
	tencentCLBSNIEnabled int64 = 1
	// tencentCLBSNIDisabled 表示 HTTPS 监听器未开启 SNI。
	tencentCLBSNIDisabled int64 = 0
	// tencentCLBTaskPollInterval 是腾讯云异步任务状态轮询间隔。
	tencentCLBTaskPollInterval = 2 * time.Second
	// tencentCLBTaskPollTimeout 是没有调用方 deadline 时的最大等待时长。
	tencentCLBTaskPollTimeout = 2 * time.Minute
)

// clbClient 定义腾讯云 CLB 证书部署所需的最小 SDK 调用集合。
type clbClient interface {
	// DescribeLoadBalancersWithContext 分页查询指定地域的负载均衡实例。
	DescribeLoadBalancersWithContext(ctx context.Context, request *tencentclb.DescribeLoadBalancersRequest) (*tencentclb.DescribeLoadBalancersResponse, error)
	// DescribeListenersWithContext 查询指定实例和监听器的协议、SNI、规则及证书。
	DescribeListenersWithContext(ctx context.Context, request *tencentclb.DescribeListenersRequest) (*tencentclb.DescribeListenersResponse, error)
	// ModifyDomainAttributesWithContext 更新 HTTPS SNI 域名规则的服务器证书。
	ModifyDomainAttributesWithContext(ctx context.Context, request *tencentclb.ModifyDomainAttributesRequest) (*tencentclb.ModifyDomainAttributesResponse, error)
	// ModifyListenerWithContext 更新 HTTPS、TCP_SSL 或 QUIC 监听器的服务器证书。
	ModifyListenerWithContext(ctx context.Context, request *tencentclb.ModifyListenerRequest) (*tencentclb.ModifyListenerResponse, error)
	// DescribeTaskStatusWithContext 查询异步证书更新任务状态。
	DescribeTaskStatusWithContext(ctx context.Context, request *tencentclb.DescribeTaskStatusRequest) (*tencentclb.DescribeTaskStatusResponse, error)
}

// clbClientFactory 创建绑定到指定地域的腾讯云 CLB SDK 客户端。
type clbClientFactory func(secretID, secretKey, region string) (clbClient, error)

// sdkCLBClient 将官方 CLB SDK 客户端适配为可替换的最小接口。
type sdkCLBClient struct {
	client *tencentclb.Client // client 是绑定到一个腾讯云地域的 CLB SDK 客户端。
}

// defaultCLBClientFactory 基于官方 SDK 构建指定地域的 CLB 客户端。
func defaultCLBClientFactory(secretID, secretKey, region string) (clbClient, error) {
	clientProfile := newTencentClientProfile(tencentCLBHost)
	client, err := tencentclb.NewClient(tencentcommon.NewCredential(secretID, secretKey), region, clientProfile)
	if err != nil {
		return nil, err
	}
	return &sdkCLBClient{client: client}, nil
}

// DescribeListenersWithContext 查询 CLB 监听器配置。
func (c *sdkCLBClient) DescribeListenersWithContext(ctx context.Context, request *tencentclb.DescribeListenersRequest) (*tencentclb.DescribeListenersResponse, error) {
	return c.client.DescribeListenersWithContext(ctx, request)
}

// DescribeLoadBalancersWithContext 查询 CLB 实例目录。
func (c *sdkCLBClient) DescribeLoadBalancersWithContext(ctx context.Context, request *tencentclb.DescribeLoadBalancersRequest) (*tencentclb.DescribeLoadBalancersResponse, error) {
	return c.client.DescribeLoadBalancersWithContext(ctx, request)
}

// ModifyDomainAttributesWithContext 更新 CLB SNI 域名证书。
func (c *sdkCLBClient) ModifyDomainAttributesWithContext(ctx context.Context, request *tencentclb.ModifyDomainAttributesRequest) (*tencentclb.ModifyDomainAttributesResponse, error) {
	return c.client.ModifyDomainAttributesWithContext(ctx, request)
}

// ModifyListenerWithContext 更新 CLB 监听器证书。
func (c *sdkCLBClient) ModifyListenerWithContext(ctx context.Context, request *tencentclb.ModifyListenerRequest) (*tencentclb.ModifyListenerResponse, error) {
	return c.client.ModifyListenerWithContext(ctx, request)
}

// DescribeTaskStatusWithContext 查询 CLB 异步任务状态。
func (c *sdkCLBClient) DescribeTaskStatusWithContext(ctx context.Context, request *tencentclb.DescribeTaskStatusRequest) (*tencentclb.DescribeTaskStatusResponse, error) {
	return c.client.DescribeTaskStatusWithContext(ctx, request)
}

// getCLBClient 获取或初始化指定地域的 CLB SDK 客户端。
func (p *Provider) getCLBClient(target providers.DeploymentResource) (clbClient, error) {
	region := strings.TrimSpace(target.Region)
	if client := p.clbClients[region]; client != nil {
		return client, nil
	}
	if p.newCLBClient == nil {
		p.newCLBClient = defaultCLBClientFactory
	}
	client, err := p.newCLBClient(p.SecretId, p.SecretKey, region)
	if err != nil {
		return nil, fmt.Errorf("初始化腾讯云 CLB SDK 客户端失败: %w", err)
	}
	if p.clbClients == nil {
		p.clbClients = make(map[string]clbClient)
	}
	p.clbClients[region] = client
	return client, nil
}

// clbCertificateSlot 保存自动识别出的 CLB 默认或 SNI 证书槽位。
type clbCertificateSlot struct {
	Listener           *tencentclb.Listener          // Listener 是经校验的监听器配置。
	Rule               *tencentclb.RuleOutput        // Rule 是 SNI 模式下经校验的域名规则。
	Certificate        *tencentclb.CertificateOutput // Certificate 是当前服务器证书和双向认证配置。
	CurrentCertificate string                        // CurrentCertificate 是当前服务器证书 ID。
	MatchedDomain      string                        // MatchedDomain 是 SNI 写请求使用的实际规则域名。
}

// clbRuleMatch 保存一个规则命中的实际域名，用于合并同域名的多条 URL 转发规则。
type clbRuleMatch struct {
	Rule   *tencentclb.RuleOutput // Rule 是命中域名的一条 CLB 转发规则。
	Domain string                 // Domain 是精确域名或实际命中的通配符规则域名。
}

// deployCLBCertificate 将证书部署到腾讯云 CLB 的精确监听器或 SNI 域名槽位。
func (p *Provider) deployCLBCertificate(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	client, err := p.getCLBClient(target)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 CLB 客户端", err)
	}

	listener, requestID, err := describeCLBListener(ctx, client, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	slot, err := selectCLBCertificateSlot(target.Domain, listener)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CLB 证书槽位校验失败", false, requestID, err)
	}

	sslClient, err := p.getClient()
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("初始化 SSL 客户端", err)
	}
	if err := validateCLBCurrentCertificate(ctx, sslClient, slot, target.Domain); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CLB 现有证书校验失败", false, requestID, err)
	}

	uploaded, err := p.uploadCertificateForDeployment(ctx, certificate, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	if strings.EqualFold(slot.CurrentCertificate, uploaded.CertificateID) {
		fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, uploaded.CertificateID, certificate.CertificatePEM)
		if err != nil {
			return providers.DeploymentResult{}, err
		}
		return providers.DeploymentResult{
			RequestID: firstTencentRequestID(uploaded.RequestID, requestID, fingerprintRequestID),
			Message:   "腾讯云 CLB 监听器已配置当前证书",
		}, nil
	}

	writeRequestID, err := modifyCLBCertificate(ctx, client, target, slot, uploaded.CertificateID)
	if err != nil {
		return providers.DeploymentResult{}, newTencentDeploymentError("更新 CLB 服务器证书", err)
	}
	if err := waitForCLBTask(ctx, client, writeRequestID); err != nil {
		return providers.DeploymentResult{}, err
	}

	readBack, readRequestID, err := describeCLBListener(ctx, client, target)
	if err != nil {
		return providers.DeploymentResult{}, err
	}
	confirmed, err := selectCLBCertificateSlot(target.Domain, readBack)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CLB 证书回读校验失败", true, readRequestID, err)
	}
	if !strings.EqualFold(confirmed.CurrentCertificate, uploaded.CertificateID) {
		return providers.DeploymentResult{}, providers.NewDeploymentError("腾讯云 CLB 证书回读尚未生效", true, firstTencentRequestID(writeRequestID, readRequestID), nil)
	}
	fingerprintRequestID, err := p.verifyCertificateFingerprint(ctx, confirmed.CurrentCertificate, certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, err
	}

	return providers.DeploymentResult{
		RequestID: firstTencentRequestID(writeRequestID, uploaded.RequestID, readRequestID, fingerprintRequestID),
		Message:   "腾讯云 CLB 监听器证书部署成功",
	}, nil
}

// describeCLBListener 精确查询配置实例和监听器，并校验云端响应身份。
func describeCLBListener(ctx context.Context, client clbClient, target providers.DeploymentResource) (*tencentclb.Listener, string, error) {
	request := tencentclb.NewDescribeListenersRequest()
	request.LoadBalancerId = tencentcommon.StringPtr(strings.TrimSpace(target.LoadBalancerID))
	request.ListenerIds = []*string{tencentcommon.StringPtr(strings.TrimSpace(target.ListenerID))}
	response, err := client.DescribeListenersWithContext(ctx, request)
	if err != nil {
		return nil, "", newTencentDeploymentError("查询 CLB 监听器", err)
	}
	if response == nil || response.Response == nil {
		return nil, "", providers.NewDeploymentError("腾讯云 CLB 查询响应格式异常", true, "", nil)
	}
	requestID := strings.TrimSpace(stringValue(response.Response.RequestId))
	if len(response.Response.Listeners) != 1 || response.Response.Listeners[0] == nil {
		return nil, requestID, providers.NewDeploymentError("腾讯云 CLB 未找到唯一配置监听器", false, requestID, nil)
	}
	listener := response.Response.Listeners[0]
	if !strings.EqualFold(strings.TrimSpace(stringValue(listener.ListenerId)), strings.TrimSpace(target.ListenerID)) {
		return nil, requestID, providers.NewDeploymentError("腾讯云 CLB 返回监听器 ID 不匹配", false, requestID, nil)
	}
	protocol := strings.ToUpper(strings.TrimSpace(stringValue(listener.Protocol)))
	if protocol != tencentCLBHTTPS && protocol != tencentCLBTCPSSL && protocol != tencentCLBQUIC {
		return nil, requestID, providers.NewDeploymentError("腾讯云 CLB 监听器不是支持的 TLS 协议", false, requestID, nil)
	}
	return listener, requestID, nil
}

// selectCLBCertificateSlot 按精确域名优先、唯一通配符次之选择 CLB 证书槽位。
func selectCLBCertificateSlot(domain string, listener *tencentclb.Listener) (clbCertificateSlot, error) {
	if listener == nil {
		return clbCertificateSlot{}, fmt.Errorf("监听器配置为空")
	}
	protocol := strings.ToUpper(strings.TrimSpace(stringValue(listener.Protocol)))
	if protocol == tencentCLBHTTPS {
		if listener.SniSwitch == nil {
			return clbCertificateSlot{}, fmt.Errorf("HTTPS 监听器缺少明确的 SNI 开关状态")
		}
		if *listener.SniSwitch != tencentCLBSNIDisabled && *listener.SniSwitch != tencentCLBSNIEnabled {
			return clbCertificateSlot{}, fmt.Errorf("HTTPS 监听器返回未知的 SNI 开关状态")
		}
	}
	if protocol == tencentCLBHTTPS && listener.SniSwitch != nil && *listener.SniSwitch == tencentCLBSNIEnabled {
		exactMatches := make([]clbRuleMatch, 0, 1)
		wildcardMatches := make([]clbRuleMatch, 0, 1)
		target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		for _, rule := range listener.Rules {
			if rule == nil {
				continue
			}
			matchedWildcard := ""
			for _, candidate := range tencentCLBRuleDomains(rule) {
				if candidate == target {
					exactMatches = append(exactMatches, clbRuleMatch{Rule: rule, Domain: candidate})
					matchedWildcard = ""
					break
				}
				if matchedWildcard == "" && tencentCLBWildcardCoversDomain(candidate, target) {
					matchedWildcard = candidate
				}
			}
			if matchedWildcard != "" {
				wildcardMatches = append(wildcardMatches, clbRuleMatch{Rule: rule, Domain: matchedWildcard})
			}
		}
		var err error
		exactMatches, err = collapseCLBRuleMatches(exactMatches)
		if err != nil {
			return clbCertificateSlot{}, err
		}
		if len(exactMatches) > 1 {
			return clbCertificateSlot{}, fmt.Errorf("存在多个精确域名 SNI 转发规则")
		}
		if len(exactMatches) == 1 {
			return newCLBRuleSlot(listener, exactMatches[0].Rule, exactMatches[0].Domain)
		}
		wildcardMatches, err = collapseCLBRuleMatches(wildcardMatches)
		if err != nil {
			return clbCertificateSlot{}, err
		}
		if len(wildcardMatches) > 1 {
			return clbCertificateSlot{}, fmt.Errorf("存在多个同优先级通配符 SNI 转发规则")
		}
		if len(wildcardMatches) == 1 {
			return newCLBRuleSlot(listener, wildcardMatches[0].Rule, wildcardMatches[0].Domain)
		}
		return clbCertificateSlot{}, fmt.Errorf("未找到配置域名对应的 SNI 转发规则")
	}
	return clbCertificateSlot{}, fmt.Errorf("仅支持已开启 SNI 的 HTTPS 域名规则")
}

// collapseCLBRuleMatches 按实际域名合并多路径规则，并拒绝同域名下不一致的证书配置。
func collapseCLBRuleMatches(matches []clbRuleMatch) ([]clbRuleMatch, error) {
	byDomain := make(map[string]clbRuleMatch, len(matches))
	for _, match := range matches {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(match.Domain), "."))
		if domain == "" || match.Rule == nil {
			continue
		}
		if existing, exists := byDomain[domain]; exists {
			if clbCertificateOutputSignature(existing.Rule.Certificate) != clbCertificateOutputSignature(match.Rule.Certificate) {
				return nil, fmt.Errorf("同一域名的 SNI 转发规则证书配置不一致")
			}
			continue
		}
		match.Domain = domain
		byDomain[domain] = match
	}

	domains := make([]string, 0, len(byDomain))
	for domain := range byDomain {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	result := make([]clbRuleMatch, 0, len(domains))
	for _, domain := range domains {
		result = append(result, byDomain[domain])
	}
	return result, nil
}

// clbCertificateOutputSignature 生成证书槽位配置签名，用于安全合并同域名的多路径规则。
func clbCertificateOutputSignature(certificate *tencentclb.CertificateOutput) string {
	if certificate == nil {
		return "<nil>"
	}
	extendedIDs := make([]string, 0, len(certificate.ExtCertIds))
	for _, certificateID := range certificate.ExtCertIds {
		if certificateID != nil {
			extendedIDs = append(extendedIDs, strings.TrimSpace(*certificateID))
		}
	}
	sort.Strings(extendedIDs)
	return strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(stringValue(certificate.SSLMode))),
		strings.ToUpper(strings.TrimSpace(stringValue(certificate.SSLVerifyClient))),
		strings.TrimSpace(stringValue(certificate.CertId)),
		strings.TrimSpace(stringValue(certificate.CertCaId)),
		strings.Join(extendedIDs, "\x1f"),
	}, "\x00")
}

// tencentCLBRuleDomains 返回规则内去重并排序后的单域名和多域名列表。
func tencentCLBRuleDomains(rule *tencentclb.RuleOutput) []string {
	if rule == nil {
		return nil
	}
	seen := make(map[string]struct{})
	values := make([]string, 0, len(rule.Domains)+1)
	appendDomain := func(raw string) {
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if domain == "" {
			return
		}
		if _, exists := seen[domain]; exists {
			return
		}
		seen[domain] = struct{}{}
		values = append(values, domain)
	}
	appendDomain(stringValue(rule.Domain))
	for _, domain := range rule.Domains {
		if domain != nil {
			appendDomain(*domain)
		}
	}
	sort.Strings(values)
	return values
}

// newCLBRuleSlot 创建 SNI 域名规则证书槽位并拒绝多算法证书组合。
func newCLBRuleSlot(listener *tencentclb.Listener, rule *tencentclb.RuleOutput, matchedDomain string) (clbCertificateSlot, error) {
	if rule == nil || rule.Certificate == nil {
		return clbCertificateSlot{}, fmt.Errorf("SNI 转发规则缺少服务器证书")
	}
	if len(rule.Certificate.ExtCertIds) > 0 {
		return clbCertificateSlot{}, fmt.Errorf("SNI 转发规则配置了多算法服务器证书，首期不支持自动替换")
	}
	return clbCertificateSlot{
		Listener:           listener,
		Rule:               rule,
		Certificate:        rule.Certificate,
		CurrentCertificate: strings.TrimSpace(stringValue(rule.Certificate.CertId)),
		MatchedDomain:      matchedDomain,
	}, nil
}

// validateCLBCurrentCertificate 使用 SSL 证书详情校验当前槽位覆盖目标域名且未启用多算法证书。
func validateCLBCurrentCertificate(ctx context.Context, client sslClient, slot clbCertificateSlot, domain string) error {
	if slot.Certificate == nil || len(slot.Certificate.ExtCertIds) > 0 {
		return fmt.Errorf("CLB 槽位配置了多算法服务器证书，首期不支持自动替换")
	}
	if slot.CurrentCertificate == "" {
		return fmt.Errorf("CLB 槽位缺少服务器证书 ID")
	}
	request := ssl.NewDescribeCertificateDetailRequest()
	request.CertificateId = tencentcommon.StringPtr(slot.CurrentCertificate)
	response, err := client.DescribeCertificateDetailWithContext(ctx, request)
	if err != nil {
		return err
	}
	if response == nil || response.Response == nil {
		return fmt.Errorf("SSL 证书详情响应格式异常")
	}
	detail := response.Response
	if !strings.EqualFold(strings.TrimSpace(stringValue(detail.CertificateId)), slot.CurrentCertificate) {
		return fmt.Errorf("SSL 证书详情 ID 与监听器配置不匹配")
	}
	if !strings.EqualFold(strings.TrimSpace(stringValue(detail.CertificateType)), certificateTypeSVR) {
		return fmt.Errorf("CLB 当前证书不是服务器证书")
	}
	if !tencentCertificateCoversDomain(stringValue(detail.Domain), detail.SubjectAltName, domain) {
		return fmt.Errorf("当前服务器证书不覆盖配置域名")
	}
	return nil
}

// tencentCertificateCoversDomain 判断腾讯云 SSL 证书主域名或 SAN 是否覆盖目标域名。
func tencentCertificateCoversDomain(commonName string, sans []*string, target string) bool {
	names := make([]string, 0, len(sans)+1)
	for _, san := range sans {
		if san != nil && strings.TrimSpace(*san) != "" {
			names = append(names, *san)
		}
	}
	if len(names) == 0 {
		names = append(names, commonName)
	}
	for _, name := range names {
		candidate := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		wanted := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
		if candidate == wanted || tencentCLBWildcardCoversDomain(candidate, wanted) {
			return true
		}
	}
	return false
}

// tencentCLBWildcardCoversDomain 判断单左标签泛域名是否覆盖一个精确域名。
func tencentCLBWildcardCoversDomain(pattern, target string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	target = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*.")
	if suffix == "" || !strings.HasSuffix(target, "."+suffix) {
		return false
	}
	prefix := strings.TrimSuffix(target, "."+suffix)
	return prefix != "" && !strings.Contains(prefix, ".")
}

// modifyCLBCertificate 根据监听器协议和 SNI 状态选择最小写请求替换服务器证书。
func modifyCLBCertificate(ctx context.Context, client clbClient, target providers.DeploymentResource, slot clbCertificateSlot, certificateID string) (string, error) {
	sslMode := strings.TrimSpace(stringValue(slot.Certificate.SSLMode))
	if sslMode == "" {
		sslMode = "UNIDIRECTIONAL"
	}
	certInput := &tencentclb.CertificateInput{
		SSLMode: tencentcommon.StringPtr(sslMode),
		CertId:  tencentcommon.StringPtr(certificateID),
	}
	if certCaID := strings.TrimSpace(stringValue(slot.Certificate.CertCaId)); certCaID != "" {
		certInput.CertCaId = tencentcommon.StringPtr(certCaID)
	}
	if verifyClient := strings.TrimSpace(stringValue(slot.Certificate.SSLVerifyClient)); verifyClient != "" {
		certInput.SSLVerifyClient = tencentcommon.StringPtr(verifyClient)
	}

	if slot.Rule != nil {
		request := tencentclb.NewModifyDomainAttributesRequest()
		request.LoadBalancerId = tencentcommon.StringPtr(strings.TrimSpace(target.LoadBalancerID))
		request.ListenerId = tencentcommon.StringPtr(strings.TrimSpace(target.ListenerID))
		request.Domain = tencentcommon.StringPtr(strings.TrimSpace(slot.MatchedDomain))
		request.Certificate = certInput
		response, err := client.ModifyDomainAttributesWithContext(ctx, request)
		if err != nil {
			return "", err
		}
		if response == nil || response.Response == nil {
			return "", fmt.Errorf("ModifyDomainAttributes 响应格式异常")
		}
		return strings.TrimSpace(stringValue(response.Response.RequestId)), nil
	}

	request := tencentclb.NewModifyListenerRequest()
	request.LoadBalancerId = tencentcommon.StringPtr(strings.TrimSpace(target.LoadBalancerID))
	request.ListenerId = tencentcommon.StringPtr(strings.TrimSpace(target.ListenerID))
	request.Certificate = certInput
	response, err := client.ModifyListenerWithContext(ctx, request)
	if err != nil {
		return "", err
	}
	if response == nil || response.Response == nil {
		return "", fmt.Errorf("ModifyListener 响应格式异常")
	}
	return strings.TrimSpace(stringValue(response.Response.RequestId)), nil
}

// waitForCLBTask 轮询腾讯云 CLB 异步任务，0 成功、1 失败、2 继续等待。
func waitForCLBTask(ctx context.Context, client clbClient, taskID string) error {
	if strings.TrimSpace(taskID) == "" {
		return providers.NewDeploymentError("腾讯云 CLB 更新响应缺少 RequestId", true, "", nil)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	waitContext := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		waitContext, cancel = context.WithTimeout(ctx, tencentCLBTaskPollTimeout)
		defer cancel()
	}
	ticker := time.NewTicker(tencentCLBTaskPollInterval)
	defer ticker.Stop()
	for {
		status, requestID, message, err := describeCLBTask(waitContext, client, taskID)
		if err != nil {
			return err
		}
		switch status {
		case 0:
			return nil
		case 1:
			if message == "" {
				message = "云端未返回失败原因"
			}
			return providers.NewDeploymentError("腾讯云 CLB 异步更新失败", false, firstTencentRequestID(requestID, taskID), fmt.Errorf("%s", message))
		case 2:
		default:
			return providers.NewDeploymentError("腾讯云 CLB 返回未知异步状态", true, firstTencentRequestID(requestID, taskID), nil)
		}
		select {
		case <-waitContext.Done():
			return providers.NewDeploymentError("腾讯云 CLB 异步更新等待超时", true, taskID, waitContext.Err())
		case <-ticker.C:
		}
	}
}

// describeCLBTask 查询腾讯云 CLB 任务状态和脱敏错误说明。
func describeCLBTask(ctx context.Context, client clbClient, taskID string) (int64, string, string, error) {
	request := tencentclb.NewDescribeTaskStatusRequest()
	request.TaskId = tencentcommon.StringPtr(strings.TrimSpace(taskID))
	response, err := client.DescribeTaskStatusWithContext(ctx, request)
	if err != nil {
		return 0, "", "", newTencentDeploymentError("查询 CLB 异步任务", err)
	}
	if response == nil || response.Response == nil || response.Response.Status == nil {
		return 0, "", "", providers.NewDeploymentError("腾讯云 CLB 异步任务响应格式异常", true, taskID, nil)
	}
	return *response.Response.Status, strings.TrimSpace(stringValue(response.Response.RequestId)), strings.TrimSpace(stringValue(response.Response.Message)), nil
}

// firstTencentRequestID 返回第一个非空腾讯云请求标识。
func firstTencentRequestID(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
