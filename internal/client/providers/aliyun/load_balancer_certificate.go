package aliyun

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

const (
	casCertificatePageSize = 100
	casCertificateMaxPages = 100
)

// casCertificateMetadata 保存负载均衡证书槽位识别所需的 CAS 脱敏元数据。
type casCertificateMetadata struct {
	CertificateID     int64    // CertificateID 是 CAS 返回的证书数字 ID。
	SHA256Fingerprint string   // SHA256Fingerprint 是证书叶节点的 SHA-256 指纹。
	CommonName        string   // CommonName 是证书主题通用名称。
	SubjectAltNames   []string // SubjectAltNames 是证书包含的备用域名。
	Expired           bool     // Expired 表示 CAS 已将证书标记为过期。
}

// listenerCertificateMetadata 保存 ALB/NLB 监听器返回的证书关联状态。
type listenerCertificateMetadata struct {
	CertificateID string // CertificateID 是监听器关联的全局证书 ID。
	IsDefault     bool   // IsDefault 表示该证书是否占用默认服务器证书槽位。
	Status        string // Status 是证书关联的异步状态。
}

// classifyLoadBalancerListenerStatus 判断监听器是否处于可修改或应稍后重试的状态。
func classifyLoadBalancerListenerStatus(status string) (usable, retryable bool) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "stopped":
		return true, false
	case "provisioning", "configuring", "starting", "stopping":
		return false, true
	default:
		return false, false
	}
}

// loadBalancerCertificateSlot 描述自动识别出的默认或 SNI 扩展证书槽位。
type loadBalancerCertificateSlot struct {
	IsDefault            bool   // IsDefault 表示应更新监听器默认服务器证书。
	CurrentCertificateID string // CurrentCertificateID 是现有槽位证书 ID；新扩展槽位为空。
}

// validateListenerCertificatesStable 确认证书关联列表已经完成异步变更。
func validateListenerCertificatesStable(certificates []listenerCertificateMetadata) error {
	for _, certificate := range certificates {
		status := strings.ToLower(strings.TrimSpace(certificate.Status))
		if status == "associated" {
			continue
		}
		if status == "associating" || status == "dissociating" || status == "diassociating" || status == "disassociating" {
			return fmt.Errorf("监听器证书关联仍在处理中")
		}
		return fmt.Errorf("监听器证书关联状态无效")
	}
	return nil
}

// selectLoadBalancerCertificateSlot 按 SNI 精确、SNI 通配符、默认证书顺序选择唯一槽位。
func selectLoadBalancerCertificateSlot(targetDomain, region string, defaultCertificateIDs []string, listenerCertificates []listenerCertificateMetadata, casCertificates []casCertificateMetadata) (loadBalancerCertificateSlot, error) {
	if len(defaultCertificateIDs) == 0 {
		return loadBalancerCertificateSlot{}, fmt.Errorf("监听器缺少默认服务器证书")
	}
	if len(defaultCertificateIDs) > 1 {
		return loadBalancerCertificateSlot{}, fmt.Errorf("监听器使用多算法默认服务器证书，当前版本不支持")
	}
	defaultCertificateID := strings.TrimSpace(defaultCertificateIDs[0])
	if defaultCertificateID == "" {
		return loadBalancerCertificateSlot{}, fmt.Errorf("监听器默认服务器证书 ID 为空")
	}

	seenIDs := make(map[string]struct{}, len(listenerCertificates))
	defaultCount := 0
	exactMatches := make([]listenerCertificateMetadata, 0, 1)
	wildcardMatches := make([]listenerCertificateMetadata, 0, 1)
	var defaultCertificate casCertificateMetadata
	defaultMetadataFound := false
	for _, listenerCertificate := range listenerCertificates {
		certificateID := strings.TrimSpace(listenerCertificate.CertificateID)
		if certificateID == "" {
			return loadBalancerCertificateSlot{}, fmt.Errorf("监听器证书记录缺少证书 ID")
		}
		normalizedID := strings.ToLower(certificateID)
		if _, exists := seenIDs[normalizedID]; exists {
			return loadBalancerCertificateSlot{}, fmt.Errorf("监听器返回重复证书记录")
		}
		seenIDs[normalizedID] = struct{}{}

		certificate, matchCount := findCASCertificateByListenerID(casCertificates, region, certificateID)
		if matchCount == 0 {
			return loadBalancerCertificateSlot{}, fmt.Errorf("监听器证书无法映射到当前 CAS 证书")
		}
		if matchCount > 1 {
			return loadBalancerCertificateSlot{}, fmt.Errorf("监听器证书在 CAS 列表中不唯一")
		}
		if listenerCertificate.IsDefault {
			defaultCount++
			if !casCertificateIDMatches(certificate.CertificateID, region, defaultCertificateID) {
				return loadBalancerCertificateSlot{}, fmt.Errorf("监听器默认服务器证书响应不一致")
			}
			defaultCertificate = certificate
			defaultMetadataFound = true
			continue
		}

		switch casCertificateDomainPriority(certificate, targetDomain) {
		case 2:
			exactMatches = append(exactMatches, listenerCertificate)
		case 1:
			wildcardMatches = append(wildcardMatches, listenerCertificate)
		}
	}
	if defaultCount != 1 || !defaultMetadataFound {
		return loadBalancerCertificateSlot{}, fmt.Errorf("监听器没有唯一默认服务器证书记录")
	}
	if len(exactMatches) > 1 {
		return loadBalancerCertificateSlot{}, fmt.Errorf("存在多个同优先级精确域名 SNI 证书")
	}
	if len(exactMatches) == 1 {
		return loadBalancerCertificateSlot{CurrentCertificateID: exactMatches[0].CertificateID}, nil
	}
	if len(wildcardMatches) > 1 {
		return loadBalancerCertificateSlot{}, fmt.Errorf("存在多个同优先级通配符 SNI 证书")
	}
	if len(wildcardMatches) == 1 {
		return loadBalancerCertificateSlot{CurrentCertificateID: wildcardMatches[0].CertificateID}, nil
	}
	_ = defaultCertificate
	return loadBalancerCertificateSlot{}, nil
}

// listCASCertificates 分页读取有效及已过期证书，分别用于证书复用和旧槽位识别。
func (p *Provider) listCASCertificates(ctx context.Context) ([]casCertificateMetadata, string, error) {
	certificates := make([]casCertificateMetadata, 0)
	seenCertificateIDs := make(map[int64]struct{})
	lastRequestID := ""
	for _, status := range []string{"", "EXPIRED"} {
		statusCount := int64(0)
		for page := 1; page <= casCertificateMaxPages; page++ {
			query := map[string]string{
				"CurrentPage": strconv.Itoa(page),
				"OrderType":   "CERT",
				"ShowSize":    strconv.Itoa(casCertificatePageSize),
			}
			if status != "" {
				query["Status"] = status
			}
			response, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
				Endpoint: aliyunCASEndpoint,
				Action:   "ListUserCertificateOrder",
				Version:  aliyunCASVersion,
				Method:   "POST",
				Query:    query,
			})
			if err != nil {
				return nil, lastRequestID, err
			}
			lastRequestID = firstNonEmpty(response.RequestID, lastRequestID)
			records := mapSlice(response.Body, "CertificateOrderList")
			parsed, err := parseCASCertificateRecords(records)
			if err != nil {
				return nil, lastRequestID, err
			}
			statusCount += int64(len(parsed))
			for _, certificate := range parsed {
				// EXPIRED 过滤结果不依赖响应中的可选 Expired 字段，确保不会被指纹复用。
				if status == "EXPIRED" {
					certificate.Expired = true
				}
				if _, exists := seenCertificateIDs[certificate.CertificateID]; exists {
					return nil, lastRequestID, fmt.Errorf("CAS 证书列表返回重复证书 ID")
				}
				seenCertificateIDs[certificate.CertificateID] = struct{}{}
				certificates = append(certificates, certificate)
			}

			totalCount, hasTotalCount := mapInt64(response.Body, "TotalCount")
			if len(records) == 0 || len(records) < casCertificatePageSize || (hasTotalCount && statusCount >= totalCount) {
				break
			}
			if page == casCertificateMaxPages {
				return nil, lastRequestID, fmt.Errorf("CAS 证书列表超过安全分页上限")
			}
		}
	}
	return certificates, lastRequestID, nil
}

// parseCASCertificateRecords 将 CAS 列表响应转换为稳定的证书元数据。
func parseCASCertificateRecords(records []map[string]any) ([]casCertificateMetadata, error) {
	certificates := make([]casCertificateMetadata, 0, len(records))
	for _, record := range records {
		certificateID, ok := mapInt64(record, "CertificateId")
		if !ok || certificateID <= 0 {
			return nil, fmt.Errorf("CAS 证书记录缺少有效证书 ID")
		}
		certificates = append(certificates, casCertificateMetadata{
			CertificateID:     certificateID,
			SHA256Fingerprint: normalizeSHA256Fingerprint(mapString(record, "Sha2")),
			CommonName:        normalizeCertificateDomain(mapString(record, "CommonName")),
			SubjectAltNames:   parseCASSANs(mapString(record, "Sans")),
			Expired:           mapBool(record, "Expired"),
		})
	}
	return certificates, nil
}

// findOrUploadCASCertificate 按叶证书 SHA-256 指纹复用已读取的 CAS 证书，未找到时上传一次。
func (p *Provider) findOrUploadCASCertificate(ctx context.Context, certificate providers.CertificateMaterial, region, currentCertificateID string, certificates []casCertificateMetadata) (certificateID, requestID string, err error) {
	fingerprint, _, err := extractCertFingerprintAndSerial(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	if certificateID := selectReusableCASCertificateID(certificates, fingerprint, region, currentCertificateID); certificateID != "" {
		return certificateID, "", nil
	}

	uploaded, err := p.deploymentAPI.Call(ctx, cloudAPIRequest{
		Endpoint: aliyunCASEndpoint,
		Action:   "UploadUserCertificate",
		Version:  aliyunCASVersion,
		Method:   "POST",
		Query: map[string]string{
			"Name": deploymentCertificateName(certificate),
			"Cert": certificate.CertificatePEM,
			"Key":  certificate.PrivateKeyPEM,
		},
	})
	if err != nil {
		return "", "", err
	}
	certificateIDValue, ok := mapInt64(uploaded.Body, "CertId")
	if !ok || certificateIDValue <= 0 {
		return "", uploaded.RequestID, fmt.Errorf("CAS 上传响应缺少有效证书 ID")
	}
	return casGlobalCertificateID(certificateIDValue, region), uploaded.RequestID, nil
}

// verifyCASCertificateFingerprint 在监听器回读后再次从 CAS 目录核对证书叶节点 SHA-256 指纹。
func (p *Provider) verifyCASCertificateFingerprint(ctx context.Context, certificateID, region, certificatePEM string) (string, error) {
	certificates, requestID, err := p.listCASCertificates(ctx)
	if err != nil {
		return requestID, newAliyunDeploymentErrorWithRequestID("回读 CAS 证书", requestID, err)
	}
	certificate, matchCount := findCASCertificateByListenerID(certificates, region, certificateID)
	if matchCount != 1 {
		return requestID, providers.NewDeploymentError("阿里云 CAS 未返回唯一的监听器证书", true, requestID, nil)
	}
	expectedFingerprint, _, err := extractCertFingerprintAndSerial(certificatePEM)
	if err != nil {
		return requestID, providers.NewDeploymentError("阿里云 CAS 提交证书指纹计算失败", false, requestID, newSafeAliyunCause("CAS 证书指纹", err))
	}
	if certificate.SHA256Fingerprint == "" || certificate.SHA256Fingerprint != normalizeSHA256Fingerprint(expectedFingerprint) {
		return requestID, providers.NewDeploymentError("阿里云 CAS 证书指纹回读校验失败", false, requestID, nil)
	}
	return requestID, nil
}

// selectReusableCASCertificateID 优先复用当前槽位证书，否则稳定选择相同指纹的最小证书 ID。
func selectReusableCASCertificateID(certificates []casCertificateMetadata, fingerprint, region, currentCertificateID string) string {
	targetFingerprint := normalizeSHA256Fingerprint(fingerprint)
	if targetFingerprint == "" {
		return ""
	}
	matched := make([]casCertificateMetadata, 0)
	for _, certificate := range certificates {
		if certificate.Expired || certificate.SHA256Fingerprint != targetFingerprint {
			continue
		}
		if casCertificateIDMatches(certificate.CertificateID, region, currentCertificateID) {
			return strings.TrimSpace(currentCertificateID)
		}
		matched = append(matched, certificate)
	}
	if len(matched) == 0 {
		return ""
	}
	sort.Slice(matched, func(left, right int) bool {
		return matched[left].CertificateID < matched[right].CertificateID
	})
	return casGlobalCertificateID(matched[0].CertificateID, region)
}

// casGlobalCertificateID 生成 ALB/NLB 要求的全局证书 ID。
func casGlobalCertificateID(certificateID int64, region string) string {
	return fmt.Sprintf("%d-%s", certificateID, strings.ToLower(strings.TrimSpace(region)))
}

// casCertificateIDMatches 判断监听器返回的证书 ID 是否对应指定 CAS 数字 ID。
func casCertificateIDMatches(certificateID int64, region, listenerCertificateID string) bool {
	listenerID := strings.TrimSpace(listenerCertificateID)
	if listenerID == "" {
		return false
	}
	rawID := strconv.FormatInt(certificateID, 10)
	return strings.EqualFold(listenerID, rawID) || strings.EqualFold(listenerID, casGlobalCertificateID(certificateID, region))
}

// findCASCertificateByListenerID 将监听器证书 ID 映射到 CAS 元数据并返回匹配数量。
func findCASCertificateByListenerID(certificates []casCertificateMetadata, region, listenerCertificateID string) (casCertificateMetadata, int) {
	var matched casCertificateMetadata
	matchCount := 0
	for _, certificate := range certificates {
		// 过期证书仍可能保留在监听器上，需要先读取其域名来安全决定替换槽位；
		// 过期状态只在复用证书时排除，不能阻止旧证书被替换。
		if casCertificateIDMatches(certificate.CertificateID, region, listenerCertificateID) {
			matched = certificate
			matchCount++
		}
	}
	return matched, matchCount
}

// casCertificateDomainPriority 返回证书域名与目标的匹配优先级：精确为 2，通配符为 1。
func casCertificateDomainPriority(certificate casCertificateMetadata, targetDomain string) int {
	target := normalizeCertificateDomain(targetDomain)
	names := append([]string{}, certificate.SubjectAltNames...)
	// SAN 存在时按标准证书校验语义忽略 Common Name，避免错误识别旧 SNI 槽位。
	if len(names) == 0 && certificate.CommonName != "" {
		names = append(names, certificate.CommonName)
	}
	priority := 0
	for _, name := range names {
		if strings.EqualFold(normalizeCertificateDomain(name), target) {
			return 2
		}
		if clbWildcardCoversDomain(name, target) {
			priority = 1
		}
	}
	return priority
}

// parseCASSANs 解析 CAS 使用逗号分隔的证书备用域名。
func parseCASSANs(value string) []string {
	parts := strings.FieldsFunc(value, func(char rune) bool {
		return char == ',' || char == ';' || char == '\n' || char == '\r'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if domain := normalizeCertificateDomain(part); domain != "" {
			result = append(result, domain)
		}
	}
	return result
}

// normalizeCertificateDomain 规范化证书元数据中的域名用于大小写不敏感比较。
func normalizeCertificateDomain(value string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
}

// normalizeSHA256Fingerprint 删除常见分隔符并校验 SHA-256 指纹长度。
func normalizeSHA256Fingerprint(value string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(strings.TrimSpace(value)) {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') {
			builder.WriteRune(char)
		}
	}
	normalized := builder.String()
	if len(normalized) != sha256.Size*2 {
		return ""
	}
	return normalized
}

// mapInt64 从响应 map 中读取一个可转换为 int64 的字段。
func mapInt64(data map[string]any, key string) (int64, bool) {
	value, found := getMapValue(data, key)
	if !found {
		return 0, false
	}
	return anyToInt64(value)
}

// mapBool 从响应 map 中读取布尔字段，兼容布尔值和字符串返回形态。
func mapBool(data map[string]any, key string) bool {
	value, found := getMapValue(data, key)
	if !found {
		return false
	}
	switch typedValue := normalizeValue(value).(type) {
	case bool:
		return typedValue
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typedValue))
		return err == nil && parsed
	default:
		return false
	}
}
