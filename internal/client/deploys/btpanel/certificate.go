package btpanel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TestBTPanelCertificateConnection 通过兼容入口测试宝塔证书库权限。
func TestBTPanelCertificateConnection() error {
	return TestBTPanelCertificateConnectionWithContext(context.Background())
}

// TestBTPanelCertificateConnectionWithContext 使用调用方 context 测试宝塔证书库权限。
func TestBTPanelCertificateConnectionWithContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig(ctx)
	if err != nil {
		return err
	}
	operationContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()
	if _, err := listBTPanelCertificates(operationContext, apiURL, apiKey, insecureSkipVerify); err != nil {
		return fmt.Errorf("读取宝塔证书库失败: %w", err)
	}
	return nil
}

// DeployCertificateToBTPanelCertificateStore 将证书保存到宝塔证书库并回读元数据校验。
func DeployCertificateToBTPanelCertificateStore(ctx context.Context, certificatePEM, privateKeyPEM string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig(ctx)
	if err != nil {
		return err
	}
	leaf, err := validateBTPanelCertificatePair(certificatePEM, privateKeyPEM)
	if err != nil {
		return err
	}

	var response btPanelCertificateSaveResponse
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelCertificateSavePath, url.Values{
		"key": {privateKeyPEM},
		"csr": {certificatePEM},
	}, &response); err != nil {
		return fmt.Errorf("上传证书到宝塔证书库失败: %w", err)
	}
	if !response.Status {
		message := strings.TrimSpace(response.Msg)
		if message == "" {
			message = "面板拒绝保存证书"
		}
		return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("上传证书到宝塔证书库失败: %s", message)}
	}
	if strings.TrimSpace(response.SSLHash) == "" {
		return fmt.Errorf("宝塔保存证书响应缺少证书摘要")
	}
	details, err := getBTPanelCertificateDetails(ctx, apiURL, apiKey, insecureSkipVerify, response.SSLHash)
	if err != nil {
		return fmt.Errorf("回读宝塔证书库失败: %w", err)
	}
	actual, err := btPanelCertificateFingerprint(details.FullChain)
	if err != nil {
		return fmt.Errorf("解析宝塔证书库回读证书失败: %w", err)
	}
	expected := sha256.Sum256(leaf.Raw)
	if actual != expected {
		return fmt.Errorf("宝塔证书库回读证书指纹不一致")
	}
	return nil
}

// listBTPanelCertificates 通过宝塔只读接口读取证书库的脱敏摘要。
func listBTPanelCertificates(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool) ([]btPanelCertificateSummary, error) {
	var raw json.RawMessage
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSSLPath, url.Values{
		"action": {"get_cert_list"},
	}, &raw); err != nil {
		return nil, fmt.Errorf("读取宝塔证书列表失败: %w", err)
	}
	var certificates []btPanelCertificateSummary
	if err := json.Unmarshal(raw, &certificates); err == nil {
		return certificates, nil
	}
	var envelope struct {
		Status *bool                       `json:"status"` // Status 表示面板是否接受请求。
		Msg    string                      `json:"msg"`    // Msg 是仅供 deploy 本地日志使用的诊断信息。
		Data   []btPanelCertificateSummary `json:"data"`   // Data 是证书摘要列表。
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("解析宝塔证书列表失败: %w", err)
	}
	if envelope.Status != nil && !*envelope.Status {
		message := strings.TrimSpace(envelope.Msg)
		if message == "" {
			message = "面板拒绝读取证书列表"
		}
		return nil, &btPanelRequestError{Retryable: false, Cause: errors.New(message)}
	}
	return envelope.Data, nil
}

// validateBTPanelCertificatePair 校验证书和私钥匹配，并返回叶证书。
func validateBTPanelCertificatePair(certificatePEM, privateKeyPEM string) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("宝塔证书和私钥不匹配: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("宝塔证书内容为空")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("解析宝塔证书失败: %w", err)
	}
	return leaf, nil
}

// getBTPanelCertificateDetails 读取宝塔证书库中指定摘要的证书详情。
func getBTPanelCertificateDetails(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool, sslHash string) (*btPanelCertificateDetails, error) {
	var details btPanelCertificateDetails
	var raw json.RawMessage
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSSLPath, url.Values{
		"action":   {"get_cert_info"},
		"ssl_hash": {strings.TrimSpace(sslHash)},
	}, &raw); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil, fmt.Errorf("解析宝塔证书详情失败: %w", err)
	}
	if strings.TrimSpace(details.FullChain) == "" {
		return nil, fmt.Errorf("宝塔证书详情未返回证书链")
	}
	return &details, nil
}

// btPanelCertificateFingerprint 解析证书链中的叶证书并计算 SHA-256 指纹。
func btPanelCertificateFingerprint(certificatePEM string) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	data := []byte(certificatePEM)
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return empty, err
		}
		return sha256.Sum256(certificate.Raw), nil
	}
	return empty, fmt.Errorf("未找到 PEM 叶证书")
}

// validateBTPanelWebsiteCertificate 校验证书、私钥、有效期，并要求覆盖网站任一绑定域名。
func validateBTPanelWebsiteCertificate(certificatePEM, privateKeyPEM string, domains []string, now time.Time) (*x509.Certificate, [sha256.Size]byte, error) {
	var emptyFingerprint [sha256.Size]byte
	pair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return nil, emptyFingerprint, fmt.Errorf("宝塔网站证书和私钥无效: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, emptyFingerprint, fmt.Errorf("宝塔网站证书不包含叶证书")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, emptyFingerprint, fmt.Errorf("解析宝塔网站证书失败: %w", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, emptyFingerprint, fmt.Errorf("宝塔网站证书不在有效期内")
	}
	if len(domains) == 0 {
		return nil, emptyFingerprint, fmt.Errorf("宝塔网站没有可校验的绑定域名")
	}
	matched := false
	for _, domain := range domains {
		if verifyBTPanelCertificateDomain(leaf, domain) == nil {
			matched = true
			break
		}
	}
	if !matched {
		return nil, emptyFingerprint, fmt.Errorf("证书未覆盖宝塔网站的任何绑定域名")
	}
	return leaf, sha256.Sum256(leaf.Raw), nil
}

// verifyBTPanelCertificateDomain 校验普通域名/IP，并允许同名通配符 SAN 精确匹配。
func verifyBTPanelCertificateDomain(certificate *x509.Certificate, domain string) error {
	trimmed := strings.TrimSpace(domain)
	if !strings.HasPrefix(trimmed, "*.") {
		return certificate.VerifyHostname(normalizeBTPanelDomain(trimmed))
	}
	wildcard := normalizeBTPanelDomain(trimmed)
	for _, certificateDomain := range certificate.DNSNames {
		if normalizeBTPanelDomain(certificateDomain) == wildcard {
			return nil
		}
	}
	return fmt.Errorf("证书未覆盖通配符域名")
}

// verifyBTPanelCertificateMetadata 使用宝塔回读的指纹或证书元数据确认新证书已生效。
func verifyBTPanelCertificateMetadata(certData map[string]any, expected *x509.Certificate, expectedFingerprint [sha256.Size]byte) error {
	if len(certData) == 0 || expected == nil {
		return fmt.Errorf("宝塔面板未返回证书元数据")
	}
	if fingerprint := findBTPanelMetadataString(certData, "sha256", "fingerprint_sha256", "fingerprint"); fingerprint != "" {
		normalized := strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(fingerprint))
		if normalized != hex.EncodeToString(expectedFingerprint[:]) {
			return fmt.Errorf("宝塔网站证书回读指纹不一致")
		}
		return nil
	}

	returnedDomains := findBTPanelMetadataStrings(certData, "dns", "domains")
	domainMatched := false
	for _, domain := range returnedDomains {
		if verifyBTPanelCertificateDomain(expected, domain) == nil {
			domainMatched = true
			break
		}
	}
	if !domainMatched {
		return fmt.Errorf("宝塔回读证书域名与新证书不一致")
	}
	if notAfter := findBTPanelMetadataString(certData, "notafter", "not_after", "endtime"); notAfter != "" && !btPanelCertificateExpiryMatches(notAfter, expected.NotAfter) {
		return fmt.Errorf("宝塔回读证书有效期与新证书不一致")
	}
	return nil
}

// findBTPanelMetadataString 按不区分大小写的键读取单个证书元数据字符串。
func findBTPanelMetadataString(data map[string]any, keys ...string) string {
	for key, value := range data {
		for _, expectedKey := range keys {
			if strings.EqualFold(key, expectedKey) {
				switch typed := value.(type) {
				case string:
					return strings.TrimSpace(typed)
				case json.Number:
					return typed.String()
				case float64:
					return strconv.FormatFloat(typed, 'f', -1, 64)
				}
			}
		}
	}
	return ""
}

// findBTPanelMetadataStrings 按不区分大小写的键读取证书域名字符串数组。
func findBTPanelMetadataStrings(data map[string]any, keys ...string) []string {
	for key, value := range data {
		matched := false
		for _, expectedKey := range keys {
			matched = matched || strings.EqualFold(key, expectedKey)
		}
		if !matched {
			continue
		}
		switch typed := value.(type) {
		case []any:
			values := make([]string, 0, len(typed))
			for _, item := range typed {
				if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
					values = append(values, strings.TrimSpace(text))
				}
			}
			return values
		case []string:
			return append([]string(nil), typed...)
		case string:
			return strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
		}
	}
	return nil
}

// btPanelCertificateExpiryMatches 兼容宝塔常见日期格式并校验叶证书到期时间。
func btPanelCertificateExpiryMatches(raw string, expected time.Time) bool {
	trimmed := strings.TrimSpace(raw)
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
	for _, layout := range layouts {
		parsed, err := time.ParseInLocation(layout, trimmed, time.Local)
		if err != nil {
			continue
		}
		if layout == "2006-01-02" {
			return parsed.Format(layout) == expected.In(time.Local).Format(layout) || parsed.Format(layout) == expected.UTC().Format(layout)
		}
		return parsed.Equal(expected) || parsed.UTC().Equal(expected.UTC())
	}
	// 某些版本把 endtime 作为剩余天数返回，无法用于精确身份校验。
	if _, err := strconv.Atoi(trimmed); err == nil {
		return true
	}
	return false
}
