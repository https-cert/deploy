package aliyun

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// clbDomainExtension 保存一个 CLB HTTPS 监听器的 SNI 扩展槽位。
type clbDomainExtension struct {
	Domain        string // Domain 是扩展槽位绑定的精确或泛域名。
	ExtensionID   string // ExtensionID 是更新扩展槽位所需的云端 ID。
	CertificateID string // CertificateID 是扩展槽位当前绑定的服务器证书 ID。
}

// clbCertificateMetadata 保存 CLB 返回的服务器证书脱敏元数据。
type clbCertificateMetadata struct {
	CertificateID           string   // CertificateID 是 CLB 服务器证书 ID。
	Fingerprint             string   // Fingerprint 是 CLB 返回的 SHA-1 指纹。
	CommonName              string   // CommonName 是证书主题通用名称。
	SubjectAlternativeNames []string // SubjectAlternativeNames 是证书备用域名列表。
}

// clbCertificateSlot 描述本次部署自动识别出的默认或 SNI 证书槽位。
type clbCertificateSlot struct {
	ExtensionID          string // ExtensionID 非空时表示 SNI 扩展槽位。
	CurrentCertificateID string // CurrentCertificateID 是槽位当前绑定的服务器证书 ID。
}

// deployCLB 将证书安全部署到配置的阿里云 CLB HTTPS 监听器槽位。
func (p *Provider) deployCLB(ctx context.Context, certificate providers.CertificateMaterial, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if p == nil || p.deploymentAPI == nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 部署客户端未初始化", false, "", nil)
	}

	listener, err := p.describeCLBHTTPSListener(ctx, target)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentError("读取 CLB HTTPS 监听器", err)
	}
	defaultCertificateID, err := validateCLBHTTPSListener(listener.Body, target)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 监听器校验失败", false, listener.RequestID, newSafeAliyunCause("CLB 监听器校验", err))
	}

	extensionsResponse, err := p.describeCLBDomainExtensions(ctx, target, "")
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("读取 CLB SNI 扩展", listener.RequestID, err)
	}
	extensions, err := parseCLBDomainExtensions(extensionsResponse.Body)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB SNI 扩展响应无效", false, firstNonEmpty(extensionsResponse.RequestID, listener.RequestID), newSafeAliyunCause("CLB SNI 扩展校验", err))
	}
	slot, err := selectCLBCertificateSlot(target.Domain, defaultCertificateID, extensions)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 证书槽位不唯一", false, firstNonEmpty(extensionsResponse.RequestID, listener.RequestID), newSafeAliyunCause("CLB 证书槽位选择", err))
	}

	certificatesResponse, err := p.describeCLBServerCertificates(ctx, target.Region)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("读取 CLB 服务器证书", firstNonEmpty(extensionsResponse.RequestID, listener.RequestID), err)
	}
	certificates, err := parseCLBServerCertificates(certificatesResponse.Body)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 服务器证书响应无效", false, certificatesResponse.RequestID, newSafeAliyunCause("CLB 服务器证书校验", err))
	}
	if slot.ExtensionID == "" {
		currentCertificate, found := findCLBCertificateByID(certificates, slot.CurrentCertificateID)
		if !found || !clbCertificateCoversDomain(currentCertificate, target.Domain) {
			return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 默认证书不覆盖配置域名", false, certificatesResponse.RequestID, nil)
		}
	}

	fingerprint, err := clbCertificateSHA1Fingerprint(certificate.CertificatePEM)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 证书指纹计算失败", false, certificatesResponse.RequestID, newSafeAliyunCause("CLB 证书指纹", err))
	}
	serverCertificateID := selectReusableCLBCertificateID(certificates, fingerprint, slot.CurrentCertificateID)
	uploadRequestID := ""
	if serverCertificateID == "" {
		uploaded, uploadErr := p.uploadCLBServerCertificate(ctx, target.Region, certificate)
		if uploadErr != nil {
			return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("上传 CLB 服务器证书", certificatesResponse.RequestID, uploadErr)
		}
		serverCertificateID = strings.TrimSpace(mapString(uploaded.Body, "ServerCertificateId"))
		if serverCertificateID == "" {
			return providers.DeploymentResult{}, providers.NewDeploymentError("阿里云 CLB 上传响应缺少证书 ID", false, uploaded.RequestID, nil)
		}
		uploadRequestID = uploaded.RequestID
	}

	if strings.EqualFold(strings.TrimSpace(slot.CurrentCertificateID), serverCertificateID) {
		return providers.DeploymentResult{
			RequestID: firstNonEmpty(certificatesResponse.RequestID, extensionsResponse.RequestID, listener.RequestID),
			Message:   "阿里云 CLB 监听器已配置当前证书",
		}, nil
	}

	written, err := p.setCLBCertificateSlot(ctx, target, slot, serverCertificateID)
	if err != nil {
		return providers.DeploymentResult{}, newAliyunDeploymentErrorWithRequestID("更新 CLB 监听器证书", uploadRequestID, err)
	}
	readbackRequestID, err := p.confirmCLBCertificateSlot(ctx, target, slot, serverCertificateID)
	if err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError(
			"阿里云 CLB 控制面尚未确认新证书",
			true,
			firstNonEmpty(written.RequestID, readbackRequestID, uploadRequestID),
			newSafeAliyunCause("CLB 控制面回读", err),
		)
	}

	return providers.DeploymentResult{
		RequestID: firstNonEmpty(written.RequestID, readbackRequestID, uploadRequestID),
		Message:   "阿里云 CLB 监听器证书部署成功",
	}, nil
}

// describeCLBHTTPSListener 查询配置实例和端口对应的 HTTPS 监听器属性。
func (p *Provider) describeCLBHTTPSListener(ctx context.Context, target providers.DeploymentResource) (cloudAPIResponse, error) {
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunSLBEndpoint,
		Action:   "DescribeLoadBalancerHTTPSListenerAttribute",
		Version:  aliyunSLBVersion,
		Method:   "POST",
		Query: map[string]string{
			"RegionId":       target.Region,
			"LoadBalancerId": target.LoadBalancerID,
			"ListenerPort":   strconv.Itoa(target.ListenerPort),
		},
	})
}

// describeCLBDomainExtensions 查询监听器的 SNI 扩展，extensionID 非空时只回读指定扩展。
func (p *Provider) describeCLBDomainExtensions(ctx context.Context, target providers.DeploymentResource, extensionID string) (cloudAPIResponse, error) {
	query := map[string]string{
		"RegionId":       target.Region,
		"LoadBalancerId": target.LoadBalancerID,
		"ListenerPort":   strconv.Itoa(target.ListenerPort),
	}
	if strings.TrimSpace(extensionID) != "" {
		query["DomainExtensionId"] = extensionID
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunSLBEndpoint,
		Action:   "DescribeDomainExtensions",
		Version:  aliyunSLBVersion,
		Method:   "POST",
		Query:    query,
	})
}

// describeCLBServerCertificates 查询目标地域的全部 CLB 服务器证书脱敏元数据。
func (p *Provider) describeCLBServerCertificates(ctx context.Context, region string) (cloudAPIResponse, error) {
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunSLBEndpoint,
		Action:   "DescribeServerCertificates",
		Version:  aliyunSLBVersion,
		Method:   "POST",
		Query: map[string]string{
			"RegionId": region,
		},
	})
}

// uploadCLBServerCertificate 上传一个尚未按 SHA-1 指纹复用到的 CLB 服务器证书。
func (p *Provider) uploadCLBServerCertificate(ctx context.Context, region string, certificate providers.CertificateMaterial) (cloudAPIResponse, error) {
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunSLBEndpoint,
		Action:   "UploadServerCertificate",
		Version:  aliyunSLBVersion,
		Method:   "POST",
		Query: map[string]string{
			"RegionId":              region,
			"ServerCertificate":     certificate.CertificatePEM,
			"PrivateKey":            certificate.PrivateKeyPEM,
			"ServerCertificateName": deploymentCertificateName(certificate),
		},
	})
}

// setCLBCertificateSlot 更新自动识别出的默认或 SNI 扩展证书槽位。
func (p *Provider) setCLBCertificateSlot(ctx context.Context, target providers.DeploymentResource, slot clbCertificateSlot, serverCertificateID string) (cloudAPIResponse, error) {
	query := map[string]string{
		"RegionId":            target.Region,
		"ServerCertificateId": serverCertificateID,
	}
	action := "SetDomainExtensionAttribute"
	if slot.ExtensionID != "" {
		query["DomainExtensionId"] = slot.ExtensionID
	} else {
		action = "SetLoadBalancerHTTPSListenerAttribute"
		query["LoadBalancerId"] = target.LoadBalancerID
		query["ListenerPort"] = strconv.Itoa(target.ListenerPort)
	}
	return p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunSLBEndpoint,
		Action:   action,
		Version:  aliyunSLBVersion,
		Method:   "POST",
		Query:    query,
	})
}

// confirmCLBCertificateSlot 回读并严格确认目标槽位已经绑定新证书 ID。
func (p *Provider) confirmCLBCertificateSlot(ctx context.Context, target providers.DeploymentResource, slot clbCertificateSlot, serverCertificateID string) (string, error) {
	if slot.ExtensionID == "" {
		response, err := p.describeCLBHTTPSListener(ctx, target)
		if err != nil {
			return "", err
		}
		currentCertificateID, validationErr := validateCLBHTTPSListener(response.Body, target)
		if validationErr != nil {
			return response.RequestID, validationErr
		}
		if !strings.EqualFold(strings.TrimSpace(currentCertificateID), strings.TrimSpace(serverCertificateID)) {
			return response.RequestID, fmt.Errorf("默认证书 ID 尚未更新")
		}
		return response.RequestID, nil
	}

	response, err := p.describeCLBDomainExtensions(ctx, target, slot.ExtensionID)
	if err != nil {
		return "", err
	}
	extensions, err := parseCLBDomainExtensions(response.Body)
	if err != nil {
		return response.RequestID, err
	}
	for _, extension := range extensions {
		if strings.EqualFold(extension.ExtensionID, slot.ExtensionID) && strings.EqualFold(extension.CertificateID, serverCertificateID) {
			return response.RequestID, nil
		}
	}
	return response.RequestID, fmt.Errorf("SNI 扩展证书 ID 尚未更新")
}

// validateCLBHTTPSListener 确认云端返回的是配置的实例和 HTTPS 监听端口。
func validateCLBHTTPSListener(body map[string]any, target providers.DeploymentResource) (string, error) {
	if !strings.EqualFold(mapString(body, "LoadBalancerId"), strings.TrimSpace(target.LoadBalancerID)) {
		return "", fmt.Errorf("云端返回的负载均衡实例不匹配")
	}
	portValue, found := getMapValue(body, "ListenerPort")
	port, validPort := anyToInt64(portValue)
	if !found || !validPort || port != int64(target.ListenerPort) {
		return "", fmt.Errorf("云端返回的监听端口不匹配")
	}
	serverCertificateID := strings.TrimSpace(mapString(body, "ServerCertificateId"))
	if serverCertificateID == "" {
		return "", fmt.Errorf("HTTPS 监听器缺少默认证书")
	}
	return serverCertificateID, nil
}

// parseCLBDomainExtensions 解析 DescribeDomainExtensions 返回的 SNI 扩展列表。
func parseCLBDomainExtensions(body map[string]any) ([]clbDomainExtension, error) {
	containerValue, found := getMapValue(body, "DomainExtensions")
	if !found {
		return nil, nil
	}
	container, ok := normalizeToMap(containerValue)
	if !ok {
		return nil, fmt.Errorf("DomainExtensions 格式异常")
	}
	records := mapSlice(container, "DomainExtension")
	extensions := make([]clbDomainExtension, 0, len(records))
	for _, record := range records {
		extension := clbDomainExtension{
			Domain:        strings.ToLower(strings.TrimSuffix(mapString(record, "Domain"), ".")),
			ExtensionID:   strings.TrimSpace(mapString(record, "DomainExtensionId")),
			CertificateID: strings.TrimSpace(mapString(record, "ServerCertificateId")),
		}
		if extension.Domain == "" || extension.ExtensionID == "" || extension.CertificateID == "" {
			return nil, fmt.Errorf("SNI 扩展缺少域名、扩展 ID 或证书 ID")
		}
		extensions = append(extensions, extension)
	}
	return extensions, nil
}

// selectCLBCertificateSlot 按精确域名优先、唯一通配符次之选择证书槽位。
func selectCLBCertificateSlot(targetDomain, defaultCertificateID string, extensions []clbDomainExtension) (clbCertificateSlot, error) {
	target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(targetDomain), "."))
	exactMatches := make([]clbDomainExtension, 0, 1)
	wildcardMatches := make([]clbDomainExtension, 0, 1)
	for _, extension := range extensions {
		if strings.EqualFold(extension.Domain, target) {
			exactMatches = append(exactMatches, extension)
			continue
		}
		if clbWildcardCoversDomain(extension.Domain, target) {
			wildcardMatches = append(wildcardMatches, extension)
		}
	}
	if len(exactMatches) > 1 {
		return clbCertificateSlot{}, fmt.Errorf("存在多个精确域名 SNI 扩展")
	}
	if len(exactMatches) == 1 {
		return clbCertificateSlot{ExtensionID: exactMatches[0].ExtensionID, CurrentCertificateID: exactMatches[0].CertificateID}, nil
	}
	if len(wildcardMatches) > 1 {
		return clbCertificateSlot{}, fmt.Errorf("存在多个同优先级通配符 SNI 扩展")
	}
	if len(wildcardMatches) == 1 {
		return clbCertificateSlot{ExtensionID: wildcardMatches[0].ExtensionID, CurrentCertificateID: wildcardMatches[0].CertificateID}, nil
	}
	return clbCertificateSlot{}, fmt.Errorf("未找到配置域名对应的 SNI 扩展")
}

// parseCLBServerCertificates 解析 DescribeServerCertificates 返回的证书元数据。
func parseCLBServerCertificates(body map[string]any) ([]clbCertificateMetadata, error) {
	containerValue, found := getMapValue(body, "ServerCertificates")
	if !found {
		return nil, fmt.Errorf("响应缺少 ServerCertificates")
	}
	container, ok := normalizeToMap(containerValue)
	if !ok {
		return nil, fmt.Errorf("ServerCertificates 格式异常")
	}
	records := mapSlice(container, "ServerCertificate")
	certificates := make([]clbCertificateMetadata, 0, len(records))
	for _, record := range records {
		certificateID := strings.TrimSpace(mapString(record, "ServerCertificateId"))
		if certificateID == "" {
			return nil, fmt.Errorf("服务器证书记录缺少证书 ID")
		}
		certificates = append(certificates, clbCertificateMetadata{
			CertificateID:           certificateID,
			Fingerprint:             strings.TrimSpace(mapString(record, "Fingerprint")),
			CommonName:              strings.TrimSpace(mapString(record, "CommonName")),
			SubjectAlternativeNames: parseCLBSubjectAlternativeNames(record),
		})
	}
	return certificates, nil
}

// parseCLBSubjectAlternativeNames 兼容 SAN 直接数组和元素内嵌 JSON 数组两种返回形态。
func parseCLBSubjectAlternativeNames(record map[string]any) []string {
	containerValue, found := getMapValue(record, "SubjectAlternativeNames")
	if !found {
		return nil
	}
	container, ok := normalizeToMap(containerValue)
	if !ok {
		return nil
	}
	value, found := getMapValue(container, "SubjectAlternativeName")
	if !found {
		return nil
	}
	return flattenCLBStringValues(value)
}

// flattenCLBStringValues 将嵌套数组或 JSON 字符串归一化为普通字符串列表。
func flattenCLBStringValues(value any) []string {
	normalized := normalizeValue(value)
	switch typedValue := normalized.(type) {
	case []any:
		result := make([]string, 0, len(typedValue))
		for _, item := range typedValue {
			result = append(result, flattenCLBStringValues(item)...)
		}
		return result
	case string:
		trimmed := strings.TrimSpace(typedValue)
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	default:
		return nil
	}
}

// findCLBCertificateByID 按服务器证书 ID 查找证书元数据。
func findCLBCertificateByID(certificates []clbCertificateMetadata, certificateID string) (clbCertificateMetadata, bool) {
	for _, certificate := range certificates {
		if strings.EqualFold(certificate.CertificateID, strings.TrimSpace(certificateID)) {
			return certificate, true
		}
	}
	return clbCertificateMetadata{}, false
}

// selectReusableCLBCertificateID 优先复用当前槽位证书，否则稳定选择相同 SHA-1 指纹的最小证书 ID。
func selectReusableCLBCertificateID(certificates []clbCertificateMetadata, fingerprint, currentCertificateID string) string {
	normalizedFingerprint := normalizeCLBFingerprint(fingerprint)
	matchedIDs := make([]string, 0)
	for _, certificate := range certificates {
		if normalizeCLBFingerprint(certificate.Fingerprint) != normalizedFingerprint {
			continue
		}
		if strings.EqualFold(certificate.CertificateID, strings.TrimSpace(currentCertificateID)) {
			return certificate.CertificateID
		}
		matchedIDs = append(matchedIDs, certificate.CertificateID)
	}
	if len(matchedIDs) == 0 {
		return ""
	}
	sort.Strings(matchedIDs)
	return matchedIDs[0]
}

// clbCertificateCoversDomain 使用 CLB 元数据确认当前默认证书覆盖目标域名。
func clbCertificateCoversDomain(certificate clbCertificateMetadata, targetDomain string) bool {
	names := certificate.SubjectAlternativeNames
	if len(names) == 0 {
		names = []string{certificate.CommonName}
	}
	for _, name := range names {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(name), "."), strings.TrimSuffix(strings.TrimSpace(targetDomain), ".")) || clbWildcardCoversDomain(name, targetDomain) {
			return true
		}
	}
	return false
}

// clbWildcardCoversDomain 判断左侧单标签通配符是否覆盖目标精确域名。
func clbWildcardCoversDomain(pattern, targetDomain string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(targetDomain), "."))
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

// clbCertificateSHA1Fingerprint 计算 CLB 使用的叶证书小写冒号分隔 SHA-1 指纹。
func clbCertificateSHA1Fingerprint(certificatePEM string) (string, error) {
	rest := []byte(certificatePEM)
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if !strings.EqualFold(strings.TrimSpace(block.Type), "CERTIFICATE") {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("解析叶证书失败: %w", err)
		}
		digest := sha1.Sum(certificate.Raw)
		parts := make([]string, len(digest))
		for index, value := range digest {
			parts[index] = fmt.Sprintf("%02x", value)
		}
		return strings.Join(parts, ":"), nil
	}
	return "", fmt.Errorf("证书内容中未找到 CERTIFICATE 块")
}

// normalizeCLBFingerprint 删除 SHA-1 指纹分隔符并转换为小写十六进制。
func normalizeCLBFingerprint(fingerprint string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(strings.TrimSpace(fingerprint)) {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') {
			builder.WriteRune(char)
		}
	}
	normalized := builder.String()
	if len(normalized) != sha1.Size*2 {
		return ""
	}
	return normalized
}
