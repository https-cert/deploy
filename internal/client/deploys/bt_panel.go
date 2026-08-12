package deploys

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/idna"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	btPanelRequestTimeout       = 30 * time.Second
	btPanelDiscoveryTimeout     = 20 * time.Second
	btPanelMaxResponseBodySize  = 4 * 1024 * 1024
	btPanelWebsitePageSize      = 100
	btPanelWebsiteMaxPages      = 100
	btPanelWebsiteDomainWorkers = 4
	btPanelWebsiteTargetPrefix  = "btpanel-site-"
	btPanelDataPath             = "/data"
	btPanelSitePath             = "/site"
	btPanelSSLPath              = "/ssl"
	btPanelCertificateSavePath  = "/ssl/cert/save_cert"
	btPanelStatusRunning        = "Running"
	btPanelStatusStopped        = "Stopped"
	btPanelProtocolHTTP         = "HTTP"
	btPanelProtocolHTTPS        = "HTTPS"
)

// BTPanelWebsiteResource 是可以安全上报到 anSSL 后端的脱敏宝塔网站资源。
type BTPanelWebsiteResource struct {
	TargetRef string   // TargetRef 是客户端生成的不透明稳定引用。
	Label     string   // Label 是网站备注或主域名。
	Domain    string   // Domain 是网站主域名。
	Domains   []string // Domains 是网站绑定的全部规范化域名。
	Protocol  string   // Protocol 是网站当前的 HTTP 或 HTTPS 状态。
	Status    string   // Status 是网站当前运行状态。
}

// btPanelWebsiteSummary 描述宝塔网站列表中的本地身份和展示字段。
type btPanelWebsiteSummary struct {
	ID      uint64          `json:"id"`      // ID 是仅保留在 deploy 本地的宝塔网站 ID。
	Name    string          `json:"name"`    // Name 是宝塔网站主名称，也是 SetSSL 的 siteName。
	Remark  string          `json:"rname"`   // Remark 是宝塔网站备注名称。
	Legacy  string          `json:"ps"`      // Legacy 兼容旧版宝塔网站备注字段。
	Status  json.RawMessage `json:"status"`  // Status 是兼容字符串或数字的启停状态。
	SSL     json.RawMessage `json:"ssl"`     // SSL 是网站列表中的证书启用标记。
	AddTime string          `json:"addtime"` // AddTime 用于区分删除后重新创建的网站。
}

// btPanelWebsitePage 描述宝塔数据查询接口的网站分页响应。
type btPanelWebsitePage struct {
	Data   []btPanelWebsiteSummary `json:"data"`   // Data 是当前页网站记录。
	Status *bool                   `json:"status"` // Status 在宝塔返回错误包络时为 false。
	Msg    string                  `json:"msg"`    // Msg 是错误包络中的本地诊断信息。
}

// btPanelWebsiteDomain 描述宝塔网站绑定的一个域名记录。
type btPanelWebsiteDomain struct {
	Name string `json:"name"` // Name 是可能带端口的域名或 IP 地址。
}

// btPanelWebsiteDomains 描述宝塔网站域名接口响应。
type btPanelWebsiteDomains struct {
	Domains []btPanelWebsiteDomain `json:"domains"` // Domains 是网站绑定域名列表。
	Status  *bool                  `json:"status"`  // Status 在宝塔返回错误包络时为 false。
	Msg     string                 `json:"msg"`     // Msg 是错误包络中的本地诊断信息。
}

// btPanelWebsiteSSL 描述宝塔网站当前证书和 HTTPS 状态。
type btPanelWebsiteSSL struct {
	Status      bool           `json:"status"`      // Status 表示网站是否已部署 SSL。
	HTTPToHTTPS bool           `json:"httpTohttps"` // HTTPToHTTPS 表示是否强制跳转 HTTPS。
	CertData    map[string]any `json:"cert_data"`   // CertData 是宝塔解析后的证书元数据，不含私钥。
}

// btPanelCertificateSummary 描述宝塔证书库中证书的脱敏元数据。
type btPanelCertificateSummary struct {
	ID      uint64                 `json:"id"`      // ID 是宝塔证书记录 ID，仅供面板内部使用。
	Hash    string                 `json:"hash"`    // Hash 是宝塔证书库的稳定摘要。
	Domains []string               `json:"dns"`     // Domains 是宝塔解析出的证书域名集合。
	Subject string                 `json:"subject"` // Subject 是证书主域名。
	Info    btPanelCertificateInfo `json:"info"`    // Info 是证书签发者和到期信息。
}

// btPanelCertificateInfo 描述宝塔证书库证书的有限元数据。
type btPanelCertificateInfo struct {
	Issuer   string `json:"issuer"`   // Issuer 是证书签发者名称。
	NotAfter string `json:"notAfter"` // NotAfter 是证书到期日期。
}

// btPanelCertificateSaveResponse 描述宝塔保存证书接口的响应。
type btPanelCertificateSaveResponse struct {
	Status  bool   `json:"status"`   // Status 表示保存是否成功。
	Msg     string `json:"msg"`      // Msg 是仅供 deploy 本地日志使用的诊断信息。
	SSLHash string `json:"ssl_hash"` // SSLHash 是新建或已存在证书的宝塔摘要。
}

// btPanelCertificateDetails 描述宝塔证书详情接口返回的本地证书内容。
type btPanelCertificateDetails struct {
	FullChain string `json:"fullchain"` // FullChain 是宝塔证书库中的完整证书链。
}

// btPanelActionResponse 描述宝塔写操作的统一成功状态。
type btPanelActionResponse struct {
	Status bool   `json:"status"` // Status 表示写操作是否成功。
	Msg    string `json:"msg"`    // Msg 是仅供 deploy 本地日志使用的诊断信息。
}

// btPanelWebsiteRecord 在 deploy 内部关联脱敏资源和真实宝塔网站身份。
type btPanelWebsiteRecord struct {
	ID       uint64                 // ID 是真实网站 ID，只能在 deploy 本地使用。
	SiteName string                 // SiteName 是宝塔 API 定位网站时使用的名称。
	Resource BTPanelWebsiteResource // Resource 是可以上报的脱敏资源。
}

// btPanelRequestError 保存仅供 deploy 本地判断重试属性的 API 错误。
type btPanelRequestError struct {
	Retryable bool  // Retryable 表示网络或服务端错误可以稍后重试。
	Cause     error // Cause 不得写入 WebSocket 响应；在线日志必须先经过统一脱敏。
}

// Error 返回宝塔面板本地诊断信息。
func (e *btPanelRequestError) Error() string {
	if e == nil || e.Cause == nil {
		return "宝塔面板请求失败"
	}
	return e.Cause.Error()
}

// Unwrap 返回原始错误，供 errors.Is 和 errors.As 使用。
func (e *btPanelRequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// IsBTPanelConfigured 判断宝塔面板地址和 API 密钥是否已成对配置。
func IsBTPanelConfigured() bool {
	configuration := config.GetConfig()
	return configuration != nil && configuration.SSL != nil && configuration.SSL.BTPanel != nil &&
		strings.TrimSpace(configuration.SSL.BTPanel.URL) != "" && strings.TrimSpace(configuration.SSL.BTPanel.APIKey) != ""
}

// DiscoverBTPanelWebsiteResources 动态读取全部宝塔网站的脱敏目录。
func DiscoverBTPanelWebsiteResources(ctx context.Context) ([]BTPanelWebsiteResource, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()

	records, err := loadBTPanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	resources := make([]BTPanelWebsiteResource, 0, len(records))
	for _, record := range records {
		resource := record.Resource
		resource.Domains = append([]string(nil), record.Resource.Domains...)
		resources = append(resources, resource)
	}
	return resources, nil
}

// TestBTPanelWebsiteConnection 只读确认 targetRef 对应网站仍存在并能读取 SSL 配置。
func TestBTPanelWebsiteConnection(ctx context.Context, targetRef string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("宝塔网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()

	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig()
	if err != nil {
		return err
	}
	record, err := findBTPanelWebsiteByTargetRef(discoveryContext, targetRef)
	if err != nil {
		return err
	}
	if record.Resource.Status == btPanelStatusStopped {
		return fmt.Errorf("宝塔网站未运行")
	}
	if _, err := getBTPanelWebsiteSSL(discoveryContext, apiURL, apiKey, insecureSkipVerify, record.SiteName); err != nil {
		return fmt.Errorf("读取宝塔网站 SSL 配置失败: %w", err)
	}
	return nil
}

// TestBTPanelCertificateConnection 通过只读证书列表接口测试宝塔证书库权限。
func TestBTPanelCertificateConnection() error {
	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), btPanelDiscoveryTimeout)
	defer cancel()
	if _, err := listBTPanelCertificates(ctx, apiURL, apiKey, insecureSkipVerify); err != nil {
		return fmt.Errorf("读取宝塔证书库失败: %w", err)
	}
	return nil
}

// DeployCertificateToBTPanelCertificateStore 将证书保存到宝塔证书库并回读元数据校验。
func DeployCertificateToBTPanelCertificateStore(ctx context.Context, certificatePEM, privateKeyPEM string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig()
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

// DeployCertificateToBTPanelCertificateStoreFromURL 下载证书归档后上传到宝塔证书库。
func (cd *CertDeployer) DeployCertificateToBTPanelCertificateStoreFromURL(domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	certificatePEM, err := os.ReadFile(filepath.Join(extractDir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("读取宝塔证书文件失败: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(extractDir, "privateKey.key"))
	if err != nil {
		return fmt.Errorf("读取宝塔私钥文件失败: %w", err)
	}
	if err := DeployCertificateToBTPanelCertificateStore(context.Background(), string(certificatePEM), string(privateKeyPEM)); err != nil {
		return err
	}
	logger.Info("宝塔证书库上传完成", "domain", canonicalDomain)
	return nil
}

// DeployCertificateToBTPanelWebsite 精确部署 targetRef 对应宝塔网站的证书，并回读结果确认。
func DeployCertificateToBTPanelWebsite(ctx context.Context, targetRef, certificatePEM, privateKeyPEM string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("宝塔网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig()
	if err != nil {
		return err
	}
	record, err := findBTPanelWebsiteByTargetRef(ctx, targetRef)
	if err != nil {
		return err
	}
	if record.Resource.Status == btPanelStatusStopped {
		return fmt.Errorf("宝塔网站未运行")
	}
	leaf, expectedFingerprint, err := validateBTPanelWebsiteCertificate(certificatePEM, privateKeyPEM, record.Resource.Domains, time.Now())
	if err != nil {
		return err
	}

	var response btPanelActionResponse
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSitePath, url.Values{
		"action":   {"SetSSL"},
		"siteName": {record.SiteName},
		"key":      {privateKeyPEM},
		"csr":      {certificatePEM},
	}, &response); err != nil {
		return fmt.Errorf("更新宝塔网站证书失败: %w", err)
	}
	if !response.Status {
		message := strings.TrimSpace(response.Msg)
		if message == "" {
			message = "面板拒绝写入证书"
		}
		return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("更新宝塔网站证书失败: %s", message)}
	}

	updated, err := getBTPanelWebsiteSSL(ctx, apiURL, apiKey, insecureSkipVerify, record.SiteName)
	if err != nil {
		return fmt.Errorf("回读宝塔网站 SSL 配置失败: %w", err)
	}
	if !updated.Status {
		return fmt.Errorf("宝塔网站证书写入后仍未启用 SSL")
	}
	if err := verifyBTPanelCertificateMetadata(updated.CertData, leaf, expectedFingerprint); err != nil {
		return fmt.Errorf("校验宝塔回读证书失败: %w", err)
	}
	return nil
}

// IsBTPanelErrorRetryable 判断宝塔面板操作是否适合由后端稍后重试。
func IsBTPanelErrorRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var requestError *btPanelRequestError
	if errors.As(err, &requestError) {
		return requestError.Retryable
	}
	var networkError net.Error
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

// getBTPanelConfig 读取并校验本地宝塔面板配置。
func getBTPanelConfig() (string, string, bool, error) {
	configuration := config.GetConfig()
	if configuration == nil || configuration.SSL == nil || configuration.SSL.BTPanel == nil {
		return "", "", false, fmt.Errorf("未配置宝塔面板 (ssl.btPanel)")
	}
	btPanel := configuration.SSL.BTPanel
	apiURL := strings.TrimRight(strings.TrimSpace(btPanel.URL), "/")
	apiKey := strings.TrimSpace(btPanel.APIKey)
	if apiURL == "" || apiKey == "" {
		return "", "", false, fmt.Errorf("宝塔面板地址或 API 密钥未配置")
	}
	parsedURL, err := url.Parse(apiURL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return "", "", false, fmt.Errorf("宝塔面板地址必须是合法的 HTTP 或 HTTPS 地址")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", "", false, fmt.Errorf("宝塔面板地址不能包含用户凭据、查询参数或片段")
	}
	return apiURL, apiKey, btPanel.InsecureSkipVerify, nil
}

// requestBTPanelAPI 使用双重 MD5 鉴权调用宝塔 API，并限制重定向和响应体大小。
func requestBTPanelAPI(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool, endpoint string, values url.Values, responseData any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	requestTime := strconv.FormatInt(time.Now().Unix(), 10)
	values = cloneBTPanelValues(values)
	values.Set("request_time", requestTime)
	values.Set("request_token", btPanelMD5(requestTime+btPanelMD5(apiKey)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL+endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("创建宝塔面板请求失败: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := newBTPanelHTTPClient(insecureSkipVerify)
	resp, err := client.Do(req)
	if err != nil {
		return &btPanelRequestError{Retryable: true, Cause: fmt.Errorf("请求宝塔面板 API 失败: %w", err)}
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, btPanelMaxResponseBodySize+1))
	if err != nil {
		return &btPanelRequestError{Retryable: true, Cause: fmt.Errorf("读取宝塔面板响应失败: %w", err)}
	}
	if len(responseBody) > btPanelMaxResponseBodySize {
		return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("宝塔面板响应体超过最大限制")}
	}
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
		return &btPanelRequestError{Retryable: retryable, Cause: fmt.Errorf("宝塔面板 API 返回 HTTP %d", resp.StatusCode)}
	}
	if responseData == nil {
		return nil
	}
	if err := json.Unmarshal(responseBody, responseData); err != nil {
		var message string
		if stringErr := json.Unmarshal(responseBody, &message); stringErr == nil && strings.TrimSpace(message) != "" {
			return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("宝塔面板 API 返回错误: %s", strings.TrimSpace(message))}
		}
		return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("解析宝塔面板响应失败: %w", err)}
	}
	return nil
}

// newBTPanelHTTPClient 为宝塔面板配置独立 TLS 策略，避免影响其他 HTTP 客户端。
func newBTPanelHTTPClient(insecureSkipVerify bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecureSkipVerify} //nolint:gosec // 仅在用户显式配置后允许自签名面板。
	return &http.Client{
		Timeout:   btPanelRequestTimeout,
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// cloneBTPanelValues 复制表单字段，避免注入鉴权参数时修改调用方数据。
func cloneBTPanelValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values)+2)
	for key, items := range values {
		cloned[key] = append([]string(nil), items...)
	}
	return cloned
}

// btPanelMD5 计算宝塔 API 鉴权协议要求的 MD5 摘要。
func btPanelMD5(value string) string {
	digest := md5.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}

// listBTPanelWebsiteSummaries 分页读取全部宝塔网站。
func listBTPanelWebsiteSummaries(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool) ([]btPanelWebsiteSummary, error) {
	websites := make([]btPanelWebsiteSummary, 0)
	for page := 1; page <= btPanelWebsiteMaxPages; page++ {
		var pageData btPanelWebsitePage
		if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelDataPath, url.Values{
			"action": {"getData"},
			"table":  {"sites"},
			"type":   {"-1"},
			"p":      {strconv.Itoa(page)},
			"limit":  {strconv.Itoa(btPanelWebsitePageSize)},
		}, &pageData); err != nil {
			return nil, fmt.Errorf("读取宝塔网站列表失败: %w", err)
		}
		if err := validateBTPanelReadEnvelope(pageData.Status, pageData.Msg, "读取宝塔网站列表"); err != nil {
			return nil, err
		}
		websites = append(websites, pageData.Data...)
		if len(pageData.Data) < btPanelWebsitePageSize {
			return websites, nil
		}
	}
	return nil, fmt.Errorf("宝塔网站分页超过安全上限")
}

// loadBTPanelWebsiteRecords 读取全部宝塔网站及其域名，并用有限并发控制面板压力。
func loadBTPanelWebsiteRecords(ctx context.Context) ([]btPanelWebsiteRecord, error) {
	apiURL, apiKey, insecureSkipVerify, err := getBTPanelConfig()
	if err != nil {
		return nil, err
	}
	websites, err := listBTPanelWebsiteSummaries(ctx, apiURL, apiKey, insecureSkipVerify)
	if err != nil {
		return nil, err
	}
	if len(websites) == 0 {
		return nil, nil
	}
	for _, website := range websites {
		if website.ID == 0 || strings.TrimSpace(website.Name) == "" || strings.TrimSpace(website.AddTime) == "" {
			return nil, fmt.Errorf("宝塔网站缺少生成稳定引用所需的身份字段")
		}
	}

	workerCount := btPanelWebsiteDomainWorkers
	if len(websites) < workerCount {
		workerCount = len(websites)
	}
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type websiteJob struct {
		Index   int                   // Index 是结果数组中的稳定位置。
		Website btPanelWebsiteSummary // Website 是待加载域名的网站。
	}
	jobs := make(chan websiteJob)
	records := make([]btPanelWebsiteRecord, len(websites))
	valid := make([]bool, len(websites))
	errorChannel := make(chan error, 1)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for job := range jobs {
				domains, loadErr := loadBTPanelWebsiteDomains(workerContext, apiURL, apiKey, insecureSkipVerify, job.Website)
				if loadErr != nil {
					select {
					case errorChannel <- loadErr:
						cancel()
					default:
					}
					continue
				}
				if len(domains) == 0 {
					continue
				}
				primaryDomain := normalizeBTPanelDomain(job.Website.Name)
				if primaryDomain == "" {
					primaryDomain = domains[0]
				}
				label := firstBTPanelText(job.Website.Remark, job.Website.Legacy, primaryDomain)
				records[job.Index] = btPanelWebsiteRecord{
					ID:       job.Website.ID,
					SiteName: strings.TrimSpace(job.Website.Name),
					Resource: BTPanelWebsiteResource{
						TargetRef: buildBTPanelWebsiteTargetRef(apiURL, job.Website),
						Label:     label,
						Domain:    primaryDomain,
						Domains:   domains,
						Protocol:  btPanelWebsiteProtocol(job.Website.SSL),
						Status:    btPanelWebsiteStatus(job.Website.Status),
					},
				}
				valid[job.Index] = true
			}
		}()
	}
sendJobs:
	for index, website := range websites {
		select {
		case jobs <- websiteJob{Index: index, Website: website}:
		case <-workerContext.Done():
			break sendJobs
		}
	}
	close(jobs)
	waitGroup.Wait()
	select {
	case loadErr := <-errorChannel:
		return nil, loadErr
	default:
	}

	filtered := make([]btPanelWebsiteRecord, 0, len(records))
	for index, record := range records {
		if valid[index] {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

// loadBTPanelWebsiteDomains 读取一个宝塔网站的域名并规范化、去重和排序。
func loadBTPanelWebsiteDomains(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool, website btPanelWebsiteSummary) ([]string, error) {
	var response btPanelWebsiteDomains
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSitePath, url.Values{
		"action": {"GetSiteDomains"},
		"id":     {strconv.FormatUint(website.ID, 10)},
	}, &response); err != nil {
		return nil, fmt.Errorf("读取宝塔网站域名失败: %w", err)
	}
	if err := validateBTPanelReadEnvelope(response.Status, response.Msg, "读取宝塔网站域名"); err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(response.Domains)+1)
	seen := make(map[string]struct{}, len(response.Domains)+1)
	appendDomain := func(raw string) {
		domain := normalizeBTPanelDomain(raw)
		if domain == "" {
			return
		}
		if _, exists := seen[domain]; exists {
			return
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	appendDomain(website.Name)
	for _, domain := range response.Domains {
		appendDomain(domain.Name)
	}
	sort.Strings(domains)
	return domains, nil
}

// validateBTPanelReadEnvelope 拒绝只读接口返回的 status=false 错误包络，避免误判为空目录。
func validateBTPanelReadEnvelope(status *bool, message, operation string) error {
	if status == nil || *status {
		return nil
	}
	detail := strings.TrimSpace(message)
	if detail == "" {
		detail = "面板拒绝请求"
	}
	return &btPanelRequestError{Retryable: false, Cause: fmt.Errorf("%s失败: %s", operation, detail)}
}

// getBTPanelWebsiteSSL 读取指定宝塔网站的当前 SSL 状态和证书元数据。
func getBTPanelWebsiteSSL(ctx context.Context, apiURL, apiKey string, insecureSkipVerify bool, siteName string) (*btPanelWebsiteSSL, error) {
	var response btPanelWebsiteSSL
	if err := requestBTPanelAPI(ctx, apiURL, apiKey, insecureSkipVerify, btPanelSitePath, url.Values{
		"action":   {"GetSSL"},
		"siteName": {siteName},
	}, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// findBTPanelWebsiteByTargetRef 重新发现宝塔网站并要求 targetRef 唯一匹配。
func findBTPanelWebsiteByTargetRef(ctx context.Context, targetRef string) (*btPanelWebsiteRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, btPanelDiscoveryTimeout)
	defer cancel()
	records, err := loadBTPanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	var matched *btPanelWebsiteRecord
	for index := range records {
		if records[index].Resource.TargetRef != targetRef {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("宝塔网站 targetRef 不唯一，请重新配置部署目标")
		}
		record := records[index]
		matched = &record
	}
	if matched == nil {
		return nil, fmt.Errorf("宝塔网站不存在或已重新创建，请重新配置部署目标")
	}
	return matched, nil
}

// buildBTPanelWebsiteTargetRef 根据实例、网站身份和创建时间生成稳定的不透明引用。
func buildBTPanelWebsiteTargetRef(apiURL string, website btPanelWebsiteSummary) string {
	identity := strings.Join([]string{
		"ansslCli",
		"EXECUTE_BUSINES_ANSSL_CLI_BT_PANEL_WEBSITE_CERT",
		normalizeBTPanelOrigin(apiURL),
		strconv.FormatUint(website.ID, 10),
		strings.TrimSpace(website.AddTime),
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return btPanelWebsiteTargetPrefix + hex.EncodeToString(digest[:12])
}

// normalizeBTPanelOrigin 规范化仅用于本地哈希的面板来源，不返回或记录该值。
func normalizeBTPanelOrigin(apiURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(apiURL))
	if err != nil {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(apiURL), "/"))
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(hostname, port)
	} else if strings.Contains(hostname, ":") {
		parsed.Host = "[" + hostname + "]"
	} else {
		parsed.Host = hostname
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

// normalizeBTPanelDomain 将面板域名规范化为不带端口的小写 ASCII 主机名或 IP。
func normalizeBTPanelDomain(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	wildcard := strings.HasPrefix(value, "*.")
	if wildcard {
		value = strings.TrimPrefix(value, "*.")
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}
	if parsed, err := url.Parse("//" + value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" {
		return ""
	}
	if ip := net.ParseIP(value); ip != nil {
		if wildcard {
			return ""
		}
		return ip.String()
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return ""
	}
	normalized := strings.ToLower(strings.TrimSuffix(ascii, "."))
	if wildcard && normalized != "" {
		return "*." + normalized
	}
	return normalized
}

// btPanelWebsiteStatus 将宝塔数字或字符串状态转换为稳定运行状态。
func btPanelWebsiteStatus(raw json.RawMessage) string {
	value := strings.Trim(strings.TrimSpace(string(raw)), "\"")
	if value == "1" || strings.EqualFold(value, "running") {
		return btPanelStatusRunning
	}
	return btPanelStatusStopped
}

// btPanelWebsiteProtocol 将宝塔网站列表中的 SSL 标记转换为稳定协议名称。
func btPanelWebsiteProtocol(raw json.RawMessage) string {
	value := strings.Trim(strings.TrimSpace(string(raw)), "\"")
	if value != "" && value != "-1" && value != "0" && !strings.EqualFold(value, "false") && value != "null" {
		return btPanelProtocolHTTPS
	}
	return btPanelProtocolHTTP
}

// firstBTPanelText 返回首个非空的宝塔网站展示字段。
func firstBTPanelText(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return "宝塔网站"
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
