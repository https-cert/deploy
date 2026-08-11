package deploys

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	safeLineRequestTimeout      = 30 * time.Second
	safeLineMaxResponseBodySize = 4 * 1024 * 1024
	safeLineCertificatePath     = "/api/open/cert"
	safeLineManualType          = 2
)

// safeLineClient 保存仅供本机请求雷池 OpenAPI 使用的连接信息。
type safeLineClient struct {
	baseURL    string       // baseURL 是规范化后的雷池管理端地址。
	apiToken   string       // apiToken 是不会发送到 ANSSL 后端的雷池鉴权 Token。
	httpClient *http.Client // httpClient 限制超时、TLS 版本和重定向行为。
}

// safeLineAPIResponse 是雷池 OpenAPI 的通用响应包络。
type safeLineAPIResponse struct {
	Data json.RawMessage `json:"data"` // Data 是具体接口响应数据。
	Err  string          `json:"err"`  // Err 是雷池返回的业务错误。
	Msg  string          `json:"msg"`  // Msg 是雷池返回的补充消息。
}

// safeLineCertificateList 是雷池证书列表响应数据。
type safeLineCertificateList struct {
	Total int                       `json:"total"` // Total 是雷池证书总数。
	Nodes []safeLineCertificateItem `json:"nodes"` // Nodes 是当前返回的证书记录。
}

// safeLineCertificateItem 保存证书匹配所需的最小字段。
type safeLineCertificateItem struct {
	ID      int64    `json:"id"`      // ID 是雷池证书记录 ID。
	Domains []string `json:"domains"` // Domains 是证书覆盖的域名集合。
}

// safeLineCertificateManual 保存手动证书的 PEM 内容。
type safeLineCertificateManual struct {
	Certificate string `json:"crt"` // Certificate 是完整 PEM 证书链。
	PrivateKey  string `json:"key"` // PrivateKey 是 PEM 私钥。
}

// safeLineCertificateRequest 是雷池手动证书新增或更新请求。
type safeLineCertificateRequest struct {
	ID     int64                     `json:"id,omitempty"` // ID 非零时更新已有证书，为零时新增。
	Type   int                       `json:"type"`         // Type 固定为雷池手动证书类型 2。
	Manual safeLineCertificateManual `json:"manual"`       // Manual 是证书与私钥内容。
}

// TestSafeLineConnection 通过只读证书列表接口验证雷池地址、Token 和证书读取权限。
func TestSafeLineConnection() error {
	client, err := newSafeLineClient()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), safeLineRequestTimeout)
	defer cancel()
	if _, err := client.listCertificates(ctx); err != nil {
		return fmt.Errorf("雷池连接测试失败: %w", err)
	}
	return nil
}

// DeployToSafeLine 按完整证书域名集合更新雷池已有证书，未匹配时新增证书。
func (cd *CertDeployer) DeployToSafeLine(sourceDir, domain string) error {
	if err := ValidateCertificateFiles(sourceDir, domain); err != nil {
		return fmt.Errorf("雷池部署前证书校验失败: %w", err)
	}

	certificatePath := filepath.Join(sourceDir, "cert.pem")
	privateKeyPath := filepath.Join(sourceDir, "privateKey.key")
	certificatePEM, err := os.ReadFile(certificatePath)
	if err != nil {
		return fmt.Errorf("读取雷池证书文件失败: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("读取雷池私钥文件失败: %w", err)
	}
	domains, err := safeLineCertificateDomains(certificatePath)
	if err != nil {
		return err
	}

	client, err := newSafeLineClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	certificates, err := client.listCertificates(ctx)
	if err != nil {
		return fmt.Errorf("读取雷池证书列表失败: %w", err)
	}

	request := safeLineCertificateRequest{
		Type: safeLineManualType,
		Manual: safeLineCertificateManual{
			Certificate: string(certificatePEM),
			PrivateKey:  string(privateKeyPEM),
		},
	}
	matchedIDs := matchingSafeLineCertificateIDs(certificates, domains)
	if len(matchedIDs) == 0 {
		if err := client.upsertCertificate(ctx, request); err != nil {
			return fmt.Errorf("新增雷池证书失败: %w", err)
		}
		logger.Info("雷池证书已新增", "domain", domain)
		return nil
	}

	for _, certificateID := range matchedIDs {
		request.ID = certificateID
		if err := client.upsertCertificate(ctx, request); err != nil {
			return fmt.Errorf("更新雷池证书失败: %w", err)
		}
	}
	logger.Info("雷池证书已更新", "domain", domain, "count", len(matchedIDs))
	return nil
}

// DeployCertificateToSafeLine 下载并校验证书归档后仅部署到雷池 WAF。
func (cd *CertDeployer) DeployCertificateToSafeLine(domain, downloadURL string) error {
	if _, err := newSafeLineClient(); err != nil {
		return err
	}

	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := cd.DeployToSafeLine(extractDir, canonicalDomain); err != nil {
		return err
	}
	logger.Info("雷池证书部署完成", "domain", canonicalDomain)
	return nil
}

// newSafeLineClient 从本地配置创建隔离的雷池 HTTP 客户端。
func newSafeLineClient() (*safeLineClient, error) {
	configuration := config.GetConfig()
	if configuration == nil || configuration.SSL == nil || configuration.SSL.SafeLine == nil {
		return nil, errors.New("未配置雷池 WAF (ssl.safeLine)")
	}

	safeLine := configuration.SSL.SafeLine
	baseURL := strings.TrimRight(strings.TrimSpace(safeLine.URL), "/")
	apiToken := strings.TrimSpace(safeLine.APIToken)
	if baseURL == "" {
		return nil, errors.New("雷池 API 地址未配置 (ssl.safeLine.url)")
	}
	if apiToken == "" {
		return nil, errors.New("雷池 API Token 未配置 (ssl.safeLine.apiToken)")
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, errors.New("雷池 API 地址必须是合法的 HTTP 或 HTTPS 地址")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return nil, errors.New("雷池 API 地址不能包含用户凭据、查询参数或片段")
	}
	if safeLine.InsecureSkipVerify && parsedURL.Scheme != "https" {
		return nil, errors.New("雷池 insecureSkipVerify 仅适用于 HTTPS 地址")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: safeLine.InsecureSkipVerify, //nolint:gosec // 仅在用户显式信任雷池自签名证书时启用。
	}
	httpClient := &http.Client{
		Timeout:   safeLineRequestTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// 不跟随重定向，避免 API Token 被带到配置地址之外。
			return http.ErrUseLastResponse
		},
	}
	return &safeLineClient{
		baseURL:    baseURL,
		apiToken:   apiToken,
		httpClient: httpClient,
	}, nil
}

// listCertificates 获取雷池证书列表并校验响应包络。
func (client *safeLineClient) listCertificates(ctx context.Context) ([]safeLineCertificateItem, error) {
	var certificateList safeLineCertificateList
	if err := client.request(ctx, http.MethodGet, safeLineCertificatePath, nil, &certificateList); err != nil {
		return nil, err
	}
	return certificateList.Nodes, nil
}

// upsertCertificate 新增证书或按 ID 更新雷池已有证书。
func (client *safeLineClient) upsertCertificate(ctx context.Context, request safeLineCertificateRequest) error {
	return client.request(ctx, http.MethodPost, safeLineCertificatePath, request, nil)
}

// request 使用统一鉴权方式调用雷池 OpenAPI，并限制响应体与错误暴露范围。
func (client *safeLineClient) request(ctx context.Context, method, endpoint string, requestBody, responseData any) error {
	var body io.Reader
	if requestBody != nil {
		payload, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("序列化雷池请求失败: %w", err)
		}
		body = bytes.NewReader(payload)
	}

	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+endpoint, body)
	if err != nil {
		return fmt.Errorf("创建雷池请求失败: %w", err)
	}
	request.Header.Set("X-SLCE-API-TOKEN", client.apiToken)
	request.Header.Set("Accept", "application/json")
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("请求雷池 API 失败: %w", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, safeLineMaxResponseBodySize+1))
	if err != nil {
		return fmt.Errorf("读取雷池响应失败: %w", err)
	}
	if len(responseBody) > safeLineMaxResponseBodySize {
		return errors.New("雷池响应体超过最大限制")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("雷池 API 返回 HTTP %d", response.StatusCode)
	}

	var apiResponse safeLineAPIResponse
	if err := json.Unmarshal(responseBody, &apiResponse); err != nil {
		return fmt.Errorf("解析雷池响应失败: %w", err)
	}
	if strings.TrimSpace(apiResponse.Err) != "" {
		message := strings.TrimSpace(apiResponse.Msg)
		if message == "" {
			message = strings.TrimSpace(apiResponse.Err)
		}
		return fmt.Errorf("雷池 API 返回错误: %s", message)
	}
	if responseData == nil {
		return nil
	}
	if len(bytes.TrimSpace(apiResponse.Data)) == 0 || bytes.Equal(bytes.TrimSpace(apiResponse.Data), []byte("null")) {
		return errors.New("雷池 API 响应缺少 data")
	}
	if err := json.Unmarshal(apiResponse.Data, responseData); err != nil {
		return fmt.Errorf("解析雷池响应数据失败: %w", err)
	}
	return nil
}

// safeLineCertificateDomains 读取叶子证书并返回稳定排序的完整 DNS 域名集合。
func safeLineCertificateDomains(certificatePath string) ([]string, error) {
	certificate, err := parseLeafCertificate(certificatePath)
	if err != nil {
		return nil, fmt.Errorf("解析雷池证书域名失败: %w", err)
	}
	domains := certificate.DNSNames
	if len(domains) == 0 && strings.TrimSpace(certificate.Subject.CommonName) != "" {
		domains = []string{certificate.Subject.CommonName}
	}
	normalized := normalizeSafeLineDomains(domains)
	if len(normalized) == 0 {
		return nil, errors.New("证书没有可用于雷池匹配的 DNS 域名")
	}
	return normalized, nil
}

// matchingSafeLineCertificateIDs 返回与新证书域名集合完全一致的去重证书 ID。
func matchingSafeLineCertificateIDs(certificates []safeLineCertificateItem, domains []string) []int64 {
	matchedIDs := make([]int64, 0)
	seenIDs := make(map[int64]struct{})
	for _, certificate := range certificates {
		if certificate.ID <= 0 || !equalStringSlices(normalizeSafeLineDomains(certificate.Domains), domains) {
			continue
		}
		if _, exists := seenIDs[certificate.ID]; exists {
			continue
		}
		seenIDs[certificate.ID] = struct{}{}
		matchedIDs = append(matchedIDs, certificate.ID)
	}
	sort.Slice(matchedIDs, func(left, right int) bool {
		return matchedIDs[left] < matchedIDs[right]
	})
	return matchedIDs
}

// normalizeSafeLineDomains 统一大小写、末尾点和重复项，便于按集合精确比较。
func normalizeSafeLineDomains(domains []string) []string {
	seen := make(map[string]struct{}, len(domains))
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		value := strings.TrimSuffix(normalizeCertificateDomain(domain), ".")
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return normalized
}

// equalStringSlices 判断两个已排序字符串切片是否完全一致。
func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
