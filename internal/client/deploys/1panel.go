package deploys

import (
	"bytes"
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
	onePanelRequestTimeout          = 30 * time.Second
	onePanelDiscoveryTimeout        = 15 * time.Second
	onePanelMaxResponseBodySize     = 4 * 1024 * 1024
	onePanelWebsitePageSize         = 100
	onePanelWebsiteMaxPages         = 1000
	onePanelWebsiteDomainWorkers    = 4
	onePanelSSLSearchPath           = "/api/v2/websites/ssl/search"
	onePanelSSLUploadPath           = "/api/v2/websites/ssl/upload"
	onePanelWebsiteSearchPath       = "/api/v2/websites/search"
	onePanelWebsiteDomainsPath      = "/api/v2/websites/domains/%d"
	onePanelWebsiteHTTPSPath        = "/api/v2/websites/%d/https"
	onePanelWebsiteTargetRefPrefix  = "onepanel-site-"
	onePanelWebsiteDescription      = "由 anSSL 自动部署"
	onePanelDefaultHTTPConfig       = "HTTPToHTTPS"
	onePanelWebsiteProtocolHTTP     = "HTTP"
	onePanelWebsiteProtocolHTTPS    = "HTTPS"
	onePanelWebsiteStatusRunning    = "Running"
	onePanelWebsiteStatusStopped    = "Stopped"
	onePanelWebsiteResourceProvider = "ansslCli"
)

// onePanelHTTPClient 禁止自动跟随重定向，避免把面板鉴权头发送到非预期地址。
var onePanelHTTPClient = &http.Client{
	Timeout: onePanelRequestTimeout,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// OnePanelAPIResponse 描述 1Panel v2 API 的统一响应外壳。
type OnePanelAPIResponse struct {
	Code    int             `json:"code"`    // Code 是 1Panel 业务状态码，200 表示成功。
	Message string          `json:"message"` // Message 是仅供 deploy 本地日志使用的诊断信息。
	Data    json.RawMessage `json:"data"`    // Data 是具体接口返回的数据。
}

// OnePanelWebsiteResource 是可以安全上报到 anSSL 后端的脱敏网站资源。
type OnePanelWebsiteResource struct {
	TargetRef string   // TargetRef 是客户端生成的不透明稳定引用。
	Label     string   // Label 是网站别名或主域名。
	Domain    string   // Domain 是网站主域名。
	Domains   []string // Domains 是网站绑定的全部规范化域名。
	Protocol  string   // Protocol 是安全展示的当前协议，仅用于判断首次 HTTPS 部署。
	Status    string   // Status 是安全展示的当前运行状态，仅用于阻止停止网站部署。
}

// onePanelWebsiteSummary 描述网站分页接口中生成资源引用所需的字段。
type onePanelWebsiteSummary struct {
	ID            uint64 `json:"id"`            // ID 是仅保留在 deploy 本地的 1Panel 网站 ID。
	CreatedAt     string `json:"createdAt"`     // CreatedAt 用于区分删除后重新创建的网站。
	Protocol      string `json:"protocol"`      // Protocol 表示网站是否已经启用 HTTPS。
	Status        string `json:"status"`        // Status 表示网站是否正在运行。
	PrimaryDomain string `json:"primaryDomain"` // PrimaryDomain 是 1Panel 网站主域名。
	Alias         string `json:"alias"`         // Alias 是网站展示别名。
}

// onePanelWebsitePage 描述网站分页数据。
type onePanelWebsitePage struct {
	Total int64                    `json:"total"` // Total 是当前查询的网站总数。
	Items []onePanelWebsiteSummary `json:"items"` // Items 是当前页网站。
}

// onePanelWebsiteDomain 描述 1Panel 网站绑定的一个域名记录。
type onePanelWebsiteDomain struct {
	Domain string `json:"domain"` // Domain 是可能带端口的域名或 IP 地址。
}

// onePanelWebsiteRecord 在 deploy 内部关联脱敏资源和真实网站 ID。
type onePanelWebsiteRecord struct {
	ID       uint64                  // ID 是真实网站 ID，只能在 deploy 本地使用。
	Resource OnePanelWebsiteResource // Resource 是可以上报的脱敏资源。
}

// onePanelWebsiteSSL 描述 HTTPS 配置当前绑定的证书。
type onePanelWebsiteSSL struct {
	PEM string `json:"pem"` // PEM 是当前网站证书链，仅用于本地指纹回读。
}

// onePanelWebsiteHTTPS 描述需要保留的 1Panel 网站 HTTPS 参数。
type onePanelWebsiteHTTPS struct {
	Enable                bool               `json:"enable"`                // Enable 表示网站当前是否启用 HTTPS。
	HTTPConfig            string             `json:"httpConfig"`            // HTTPConfig 是 HTTP 与 HTTPS 的跳转模式。
	SSL                   onePanelWebsiteSSL `json:"SSL"`                   // SSL 是网站当前绑定的证书。
	SSLProtocol           []string           `json:"SSLProtocol"`           // SSLProtocol 是启用的 TLS 协议列表。
	Algorithm             string             `json:"algorithm"`             // Algorithm 是 1Panel 保存的加密套件配置。
	HSTS                  bool               `json:"hsts"`                  // HSTS 表示是否启用严格传输安全。
	HSTSIncludeSubDomains bool               `json:"hstsIncludeSubDomains"` // HSTSIncludeSubDomains 表示 HSTS 是否覆盖子域名。
	HTTPSPorts            []int              `json:"httpsPorts"`            // HTTPSPorts 是网站当前 HTTPS 监听端口。
	HTTPSPort             string             `json:"httpsPort"`             // HTTPSPort 兼容旧版逗号分隔端口字段。
	HTTP3                 bool               `json:"http3"`                 // HTTP3 表示是否启用 HTTP/3。
}

// onePanelWebsiteHTTPSUpdate 是精确替换单个网站证书的请求体。
type onePanelWebsiteHTTPSUpdate struct {
	WebsiteID             uint64   `json:"websiteId"`             // WebsiteID 是目标网站 ID。
	Enable                bool     `json:"enable"`                // Enable 保持网站 HTTPS 开启。
	WebsiteSSLID          uint64   `json:"websiteSSLId"`          // WebsiteSSLID 在手动证书模式下保持为零。
	Type                  string   `json:"type"`                  // Type 固定为 manual，避免修改共享证书记录。
	PrivateKey            string   `json:"privateKey"`            // PrivateKey 是本次部署的私钥。
	Certificate           string   `json:"certificate"`           // Certificate 是本次部署的完整证书链。
	PrivateKeyPath        string   `json:"privateKeyPath"`        // PrivateKeyPath 在粘贴模式下为空。
	CertificatePath       string   `json:"certificatePath"`       // CertificatePath 在粘贴模式下为空。
	ImportType            string   `json:"importType"`            // ImportType 固定为 paste。
	HTTPConfig            string   `json:"httpConfig"`            // HTTPConfig 保留网站原有跳转模式。
	SSLProtocol           []string `json:"SSLProtocol"`           // SSLProtocol 保留网站原有 TLS 协议。
	Algorithm             string   `json:"algorithm"`             // Algorithm 保留网站原有加密套件。
	HSTS                  bool     `json:"hsts"`                  // HSTS 保留网站原有设置。
	HSTSIncludeSubDomains bool     `json:"hstsIncludeSubDomains"` // HSTSIncludeSubDomains 保留网站原有设置。
	HTTPSPorts            []int    `json:"httpsPorts"`            // HTTPSPorts 保留网站原有监听端口。
	HTTP3                 bool     `json:"http3"`                 // HTTP3 保留网站原有设置。
}

// onePanelRequestError 保存仅供 deploy 本地判断重试属性的 API 错误。
type onePanelRequestError struct {
	Retryable bool  // Retryable 表示网络或服务端错误可以稍后重试。
	Cause     error // Cause 不得写入 WebSocket 响应；在线日志必须先经过统一脱敏。
}

// Error 返回 1Panel 本地诊断信息。
func (e *onePanelRequestError) Error() string {
	if e == nil || e.Cause == nil {
		return "1Panel 请求失败"
	}
	return e.Cause.Error()
}

// Unwrap 返回原始错误，供 errors.Is 和 errors.As 使用。
func (e *onePanelRequestError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// IsOnePanelConfigured 判断 1Panel 地址和 API 密钥是否已成对配置。
func IsOnePanelConfigured() bool {
	configuration := config.GetConfig()
	return configuration != nil && configuration.SSL != nil && configuration.SSL.OnePanel != nil &&
		strings.TrimSpace(configuration.SSL.OnePanel.URL) != "" && strings.TrimSpace(configuration.SSL.OnePanel.APIKey) != ""
}

// TestOnePanelConnection 通过只读证书列表接口验证面板地址、API 密钥和证书管理权限。
func TestOnePanelConnection() error {
	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return err
	}

	requestBody := map[string]any{
		"page":     1,
		"pageSize": 1,
	}
	if err := requestOnePanelAPI(context.Background(), apiURL, apiKey, http.MethodPost, onePanelSSLSearchPath, requestBody, nil); err != nil {
		return fmt.Errorf("1Panel 连接测试失败: %w", err)
	}
	return nil
}

// DiscoverOnePanelWebsiteResources 动态读取全部 1Panel 网站的脱敏目录。
func DiscoverOnePanelWebsiteResources(ctx context.Context) ([]OnePanelWebsiteResource, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, onePanelDiscoveryTimeout)
	defer cancel()

	records, err := loadOnePanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	resources := make([]OnePanelWebsiteResource, 0, len(records))
	for _, record := range records {
		resource := record.Resource
		resource.Domains = append([]string(nil), record.Resource.Domains...)
		resources = append(resources, resource)
	}
	return resources, nil
}

// TestOnePanelWebsiteConnection 只读确认 targetRef 对应网站仍存在、正在运行且 HTTPS 配置可访问。
func TestOnePanelWebsiteConnection(ctx context.Context, targetRef string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("1Panel 网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, onePanelDiscoveryTimeout)
	defer cancel()

	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return err
	}
	record, err := findOnePanelWebsiteByTargetRef(discoveryContext, targetRef)
	if err != nil {
		return err
	}
	if isOnePanelWebsiteStopped(record.Resource.Status) {
		return fmt.Errorf("1Panel 网站未运行")
	}
	if _, err := getOnePanelWebsiteHTTPS(discoveryContext, apiURL, apiKey, record.ID); err != nil {
		return fmt.Errorf("读取 1Panel 网站 HTTPS 配置失败: %w", err)
	}
	return nil
}

// DeployCertificateTo1PanelWebsite 精确部署 targetRef 对应网站的证书，并回读指纹确认。
func DeployCertificateTo1PanelWebsite(ctx context.Context, targetRef, certificatePEM, privateKeyPEM string) error {
	targetRef = strings.TrimSpace(targetRef)
	if targetRef == "" {
		return fmt.Errorf("1Panel 网站 targetRef 不能为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return err
	}
	record, err := findOnePanelWebsiteByTargetRef(ctx, targetRef)
	if err != nil {
		return err
	}
	if isOnePanelWebsiteStopped(record.Resource.Status) {
		return fmt.Errorf("1Panel 网站未运行")
	}
	expectedFingerprint, err := validateOnePanelWebsiteCertificate(certificatePEM, privateKeyPEM, record.Resource.Domains, time.Now())
	if err != nil {
		return err
	}

	current, err := getOnePanelWebsiteHTTPS(ctx, apiURL, apiKey, record.ID)
	if err != nil {
		return fmt.Errorf("读取 1Panel 网站 HTTPS 配置失败: %w", err)
	}
	requestBody := buildOnePanelWebsiteHTTPSUpdate(record.ID, current, certificatePEM, privateKeyPEM)
	endpoint := fmt.Sprintf(onePanelWebsiteHTTPSPath, record.ID)
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodPost, endpoint, requestBody, nil); err != nil {
		return fmt.Errorf("更新 1Panel 网站证书失败: %w", err)
	}

	updated, err := getOnePanelWebsiteHTTPS(ctx, apiURL, apiKey, record.ID)
	if err != nil {
		return fmt.Errorf("回读 1Panel 网站 HTTPS 配置失败: %w", err)
	}
	actualFingerprint, err := onePanelCertificateFingerprint(updated.SSL.PEM)
	if err != nil {
		return fmt.Errorf("解析 1Panel 回读证书失败: %w", err)
	}
	if actualFingerprint != expectedFingerprint {
		return fmt.Errorf("1Panel 网站证书回读指纹不一致")
	}
	return nil
}

// IsOnePanelErrorRetryable 判断 1Panel 操作是否适合由后端稍后重试。
func IsOnePanelErrorRetryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var requestError *onePanelRequestError
	if errors.As(err, &requestError) {
		return requestError.Retryable
	}
	var networkError net.Error
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

// DeployTo1Panel 上传证书到 1Panel 证书库，保留原有非网站级行为。
func (cd *CertDeployer) DeployTo1Panel(sourceDir, domain string) error {
	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return err
	}

	certContent, err := osReadFile(sourceDir, "cert.pem")
	if err != nil {
		return fmt.Errorf("读取证书文件失败: %w", err)
	}
	keyContent, err := osReadFile(sourceDir, "privateKey.key")
	if err != nil {
		return fmt.Errorf("读取私钥文件失败: %w", err)
	}
	certData := map[string]any{
		"type":        "paste",
		"certificate": string(certContent),
		"privateKey":  string(keyContent),
		"description": onePanelWebsiteDescription,
	}
	if err := requestOnePanelAPI(context.Background(), apiURL, apiKey, http.MethodPost, onePanelSSLUploadPath, certData, nil); err != nil {
		return err
	}
	logger.Info("证书已上传到 1Panel 证书库", "domain", domain)
	return nil
}

// osReadFile 读取证书目录下的固定文件名，便于集中约束路径拼接。
func osReadFile(sourceDir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(sourceDir, name))
}

// md5Sum 计算 1Panel 鉴权协议要求的 MD5 摘要。
func md5Sum(data string) string {
	h := md5.New()
	_, _ = h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// getOnePanelConfig 读取并校验本地 1Panel API 配置，避免鉴权信息被拼接到异常 URL。
func getOnePanelConfig() (string, string, error) {
	configuration := config.GetConfig()
	if configuration == nil || configuration.SSL == nil || configuration.SSL.OnePanel == nil {
		return "", "", fmt.Errorf("未配置 1Panel (ssl.onePanel)")
	}

	apiURL := strings.TrimRight(strings.TrimSpace(configuration.SSL.OnePanel.URL), "/")
	apiKey := strings.TrimSpace(configuration.SSL.OnePanel.APIKey)
	if apiURL == "" {
		return "", "", fmt.Errorf("1Panel API 地址未配置 (ssl.onePanel.url)")
	}
	if apiKey == "" {
		return "", "", fmt.Errorf("1Panel API 密钥未配置 (ssl.onePanel.apiKey)")
	}
	parsedURL, err := url.Parse(apiURL)
	if err != nil || parsedURL.Host == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return "", "", fmt.Errorf("1Panel API 地址必须是合法的 HTTP 或 HTTPS 地址")
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return "", "", fmt.Errorf("1Panel API 地址不能包含用户凭据、查询参数或片段")
	}
	return apiURL, apiKey, nil
}

// requestOnePanelAPI 使用统一鉴权方式调用 1Panel API，并限制响应大小和重定向行为。
func requestOnePanelAPI(ctx context.Context, apiURL, apiKey, method, endpoint string, requestBody, responseData any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var body io.Reader
	if requestBody != nil {
		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			return fmt.Errorf("序列化 1Panel 请求失败: %w", err)
		}
		body = bytes.NewReader(jsonData)
	}
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	token := md5Sum("1panel" + apiKey + timestamp)
	req, err := http.NewRequestWithContext(ctx, method, apiURL+endpoint, body)
	if err != nil {
		return fmt.Errorf("创建 1Panel 请求失败: %w", err)
	}
	req.Header.Set("1Panel-Token", token)
	req.Header.Set("1Panel-Timestamp", timestamp)
	req.Header.Set("Accept", "application/json")
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := onePanelHTTPClient.Do(req)
	if err != nil {
		return &onePanelRequestError{Retryable: true, Cause: fmt.Errorf("请求 1Panel API 失败: %w", err)}
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, onePanelMaxResponseBodySize+1))
	if err != nil {
		return &onePanelRequestError{Retryable: true, Cause: fmt.Errorf("读取 1Panel 响应失败: %w", err)}
	}
	if len(responseBody) > onePanelMaxResponseBodySize {
		return &onePanelRequestError{Retryable: false, Cause: fmt.Errorf("1Panel 响应体超过最大限制")}
	}
	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
		return &onePanelRequestError{Retryable: retryable, Cause: fmt.Errorf("1Panel API 返回 HTTP %d", resp.StatusCode)}
	}

	var apiResponse OnePanelAPIResponse
	if err := json.Unmarshal(responseBody, &apiResponse); err != nil {
		return &onePanelRequestError{Retryable: false, Cause: fmt.Errorf("解析 1Panel 响应失败: %w", err)}
	}
	if apiResponse.Code != http.StatusOK {
		message := strings.TrimSpace(apiResponse.Message)
		if message == "" {
			message = "未知错误"
		}
		retryable := apiResponse.Code == http.StatusTooManyRequests || apiResponse.Code >= http.StatusInternalServerError
		return &onePanelRequestError{Retryable: retryable, Cause: fmt.Errorf("1Panel API 返回错误: %s", message)}
	}
	if responseData != nil && len(apiResponse.Data) > 0 && string(apiResponse.Data) != "null" {
		if err := json.Unmarshal(apiResponse.Data, responseData); err != nil {
			return &onePanelRequestError{Retryable: false, Cause: fmt.Errorf("解析 1Panel 数据失败: %w", err)}
		}
	}
	return nil
}

// listOnePanelWebsiteSummaries 分页读取全部网站，避免单次响应随网站数量无限增长。
func listOnePanelWebsiteSummaries(ctx context.Context, apiURL, apiKey string) ([]onePanelWebsiteSummary, error) {
	websites := make([]onePanelWebsiteSummary, 0)
	for page := 1; page <= onePanelWebsiteMaxPages; page++ {
		requestBody := map[string]any{
			"page":           page,
			"pageSize":       onePanelWebsitePageSize,
			"name":           "",
			"orderBy":        "created_at",
			"order":          "ascending",
			"websiteGroupId": 0,
			"type":           "",
		}
		var pageData onePanelWebsitePage
		if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodPost, onePanelWebsiteSearchPath, requestBody, &pageData); err != nil {
			return nil, fmt.Errorf("读取 1Panel 网站列表失败: %w", err)
		}
		websites = append(websites, pageData.Items...)
		if len(pageData.Items) == 0 || int64(len(websites)) >= pageData.Total {
			return websites, nil
		}
	}
	return nil, fmt.Errorf("1Panel 网站分页超过安全上限")
}

// loadOnePanelWebsiteRecords 读取全部网站及其域名，并用有限并发控制面板压力。
func loadOnePanelWebsiteRecords(ctx context.Context) ([]onePanelWebsiteRecord, error) {
	apiURL, apiKey, err := getOnePanelConfig()
	if err != nil {
		return nil, err
	}
	websites, err := listOnePanelWebsiteSummaries(ctx, apiURL, apiKey)
	if err != nil {
		return nil, err
	}
	eligibleWebsites := make([]onePanelWebsiteSummary, 0, len(websites))
	for _, website := range websites {
		if !isOnePanelWebsiteCertificateCapable(website.Protocol) {
			continue
		}
		if website.ID == 0 || strings.TrimSpace(website.CreatedAt) == "" {
			return nil, fmt.Errorf("1Panel 网站缺少生成稳定引用所需的身份字段")
		}
		eligibleWebsites = append(eligibleWebsites, website)
	}
	if len(eligibleWebsites) == 0 {
		return nil, nil
	}

	workerCount := onePanelWebsiteDomainWorkers
	if len(eligibleWebsites) < workerCount {
		workerCount = len(eligibleWebsites)
	}
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	type websiteJob struct {
		Index   int                    // Index 是结果数组中的稳定位置。
		Website onePanelWebsiteSummary // Website 是待加载域名的网站。
	}
	jobs := make(chan websiteJob)
	records := make([]onePanelWebsiteRecord, len(eligibleWebsites))
	valid := make([]bool, len(eligibleWebsites))
	errorChannel := make(chan error, 1)
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for job := range jobs {
				domains, loadErr := loadOnePanelWebsiteDomains(workerContext, apiURL, apiKey, job.Website)
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
				primaryDomain := normalizeOnePanelDomain(job.Website.PrimaryDomain)
				if primaryDomain == "" {
					primaryDomain = domains[0]
				}
				label := strings.TrimSpace(job.Website.Alias)
				if label == "" {
					label = primaryDomain
				}
				records[job.Index] = onePanelWebsiteRecord{
					ID: job.Website.ID,
					Resource: OnePanelWebsiteResource{
						TargetRef: buildOnePanelWebsiteTargetRef(apiURL, job.Website),
						Label:     label,
						Domain:    primaryDomain,
						Domains:   domains,
						Protocol:  normalizeOnePanelWebsiteProtocol(job.Website.Protocol),
						Status:    normalizeOnePanelWebsiteStatus(job.Website.Status),
					},
				}
				valid[job.Index] = true
			}
		}()
	}
sendJobs:
	for index, website := range eligibleWebsites {
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

	filtered := make([]onePanelWebsiteRecord, 0, len(records))
	for index, record := range records {
		if valid[index] {
			filtered = append(filtered, record)
		}
	}
	return filtered, nil
}

// loadOnePanelWebsiteDomains 读取一个网站的域名并进行规范化、去重和排序。
func loadOnePanelWebsiteDomains(ctx context.Context, apiURL, apiKey string, website onePanelWebsiteSummary) ([]string, error) {
	var domainRecords []onePanelWebsiteDomain
	endpoint := fmt.Sprintf(onePanelWebsiteDomainsPath, website.ID)
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodGet, endpoint, nil, &domainRecords); err != nil {
		return nil, fmt.Errorf("读取 1Panel 网站域名失败: %w", err)
	}
	domains := make([]string, 0, len(domainRecords)+1)
	seen := make(map[string]struct{}, len(domainRecords)+1)
	appendDomain := func(raw string) {
		domain := normalizeOnePanelDomain(raw)
		if domain == "" {
			return
		}
		if _, exists := seen[domain]; exists {
			return
		}
		seen[domain] = struct{}{}
		domains = append(domains, domain)
	}
	appendDomain(website.PrimaryDomain)
	for _, domainRecord := range domainRecords {
		appendDomain(domainRecord.Domain)
	}
	sort.Strings(domains)
	return domains, nil
}

// normalizeOnePanelDomain 将面板域名规范化为不带端口的小写 ASCII 主机名或 IP。
func normalizeOnePanelDomain(raw string) string {
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

// buildOnePanelWebsiteTargetRef 根据实例、网站身份和创建时间生成稳定的不透明引用。
func buildOnePanelWebsiteTargetRef(apiURL string, website onePanelWebsiteSummary) string {
	identity := strings.Join([]string{
		onePanelWebsiteResourceProvider,
		"EXECUTE_BUSINES_ANSSL_CLI_1PANEL_WEBSITE_CERT",
		normalizeOnePanelOrigin(apiURL),
		strconv.FormatUint(website.ID, 10),
		strings.TrimSpace(website.CreatedAt),
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return onePanelWebsiteTargetRefPrefix + hex.EncodeToString(digest[:12])
}

// normalizeOnePanelOrigin 规范化仅用于本地哈希的面板来源，不返回或记录该值。
func normalizeOnePanelOrigin(apiURL string) string {
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

// findOnePanelWebsiteByTargetRef 重新发现网站并要求 targetRef 唯一匹配。
func findOnePanelWebsiteByTargetRef(ctx context.Context, targetRef string) (*onePanelWebsiteRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	discoveryContext, cancel := context.WithTimeout(ctx, onePanelDiscoveryTimeout)
	defer cancel()

	records, err := loadOnePanelWebsiteRecords(discoveryContext)
	if err != nil {
		return nil, err
	}
	var matched *onePanelWebsiteRecord
	for index := range records {
		if records[index].Resource.TargetRef != targetRef {
			continue
		}
		if matched != nil {
			return nil, fmt.Errorf("1Panel 网站 targetRef 不唯一，请重新配置部署目标")
		}
		record := records[index]
		matched = &record
	}
	if matched == nil {
		return nil, fmt.Errorf("1Panel 网站不存在或已重新创建，请重新配置部署目标")
	}
	return matched, nil
}

// getOnePanelWebsiteHTTPS 读取一个网站的当前 HTTPS 配置。
func getOnePanelWebsiteHTTPS(ctx context.Context, apiURL, apiKey string, websiteID uint64) (*onePanelWebsiteHTTPS, error) {
	var httpsConfig onePanelWebsiteHTTPS
	endpoint := fmt.Sprintf(onePanelWebsiteHTTPSPath, websiteID)
	if err := requestOnePanelAPI(ctx, apiURL, apiKey, http.MethodGet, endpoint, nil, &httpsConfig); err != nil {
		return nil, err
	}
	return &httpsConfig, nil
}

// onePanelHTTPSPorts 合并新版数组字段和旧版逗号字段，确保更新时不改变监听端口。
func onePanelHTTPSPorts(config *onePanelWebsiteHTTPS) []int {
	if config == nil {
		return nil
	}
	ports := append([]int(nil), config.HTTPSPorts...)
	seen := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		seen[port] = struct{}{}
	}
	for _, rawPort := range strings.Split(config.HTTPSPort, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(rawPort))
		if err != nil || port < 1 || port > 65535 {
			continue
		}
		if _, exists := seen[port]; exists {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// buildOnePanelWebsiteHTTPSUpdate 保留现有 HTTPS 参数，或为首次部署采用 1Panel 的安全默认值。
func buildOnePanelWebsiteHTTPSUpdate(websiteID uint64, current *onePanelWebsiteHTTPS, certificatePEM, privateKeyPEM string) onePanelWebsiteHTTPSUpdate {
	httpConfig := ""
	sslProtocol := []string(nil)
	algorithm := ""
	hsts := false
	hstsIncludeSubDomains := false
	httpsPorts := []int(nil)
	http3 := false

	if current != nil && current.Enable {
		httpConfig = strings.TrimSpace(current.HTTPConfig)
		sslProtocol = append([]string(nil), current.SSLProtocol...)
		algorithm = current.Algorithm
		hsts = current.HSTS
		hstsIncludeSubDomains = current.HSTSIncludeSubDomains
		httpsPorts = onePanelHTTPSPorts(current)
		http3 = current.HTTP3
	}
	if httpConfig == "" {
		// 1Panel 空 HTTPS 配置没有可保留的跳转策略，首次部署统一升级 HTTP 请求。
		httpConfig = onePanelDefaultHTTPConfig
	}

	return onePanelWebsiteHTTPSUpdate{
		WebsiteID:             websiteID,
		Enable:                true,
		Type:                  "manual",
		PrivateKey:            privateKeyPEM,
		Certificate:           certificatePEM,
		ImportType:            "paste",
		HTTPConfig:            httpConfig,
		SSLProtocol:           sslProtocol,
		Algorithm:             algorithm,
		HSTS:                  hsts,
		HSTSIncludeSubDomains: hstsIncludeSubDomains,
		HTTPSPorts:            httpsPorts,
		HTTP3:                 http3,
	}
}

// normalizeOnePanelWebsiteProtocol 只保留可通过 HTTPS 接口部署证书的网站协议。
func normalizeOnePanelWebsiteProtocol(protocol string) string {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case onePanelWebsiteProtocolHTTP:
		return onePanelWebsiteProtocolHTTP
	case onePanelWebsiteProtocolHTTPS:
		return onePanelWebsiteProtocolHTTPS
	default:
		return ""
	}
}

// isOnePanelWebsiteCertificateCapable 判断网站是否为支持 HTTPS 证书部署的 HTTP 服务。
func isOnePanelWebsiteCertificateCapable(protocol string) bool {
	return normalizeOnePanelWebsiteProtocol(protocol) != ""
}

// normalizeOnePanelWebsiteStatus 只暴露网页选择器需要的稳定运行状态。
func normalizeOnePanelWebsiteStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case strings.ToLower(onePanelWebsiteStatusRunning):
		return onePanelWebsiteStatusRunning
	case strings.ToLower(onePanelWebsiteStatusStopped):
		return onePanelWebsiteStatusStopped
	default:
		return ""
	}
}

// isOnePanelWebsiteStopped 仅在面板明确报告停止时阻止连接测试或证书部署。
func isOnePanelWebsiteStopped(status string) bool {
	return normalizeOnePanelWebsiteStatus(status) == onePanelWebsiteStatusStopped
}

// validateOnePanelWebsiteCertificate 校验证书、私钥、有效期，并要求至少覆盖网站的一个绑定域名。
func validateOnePanelWebsiteCertificate(certificatePEM, privateKeyPEM string, domains []string, now time.Time) ([sha256.Size]byte, error) {
	var emptyFingerprint [sha256.Size]byte
	keyPair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		return emptyFingerprint, fmt.Errorf("1Panel 网站证书和私钥无效: %w", err)
	}
	if len(keyPair.Certificate) == 0 {
		return emptyFingerprint, fmt.Errorf("1Panel 网站证书不包含叶证书")
	}
	leaf, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return emptyFingerprint, fmt.Errorf("解析 1Panel 网站证书失败: %w", err)
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return emptyFingerprint, fmt.Errorf("1Panel 网站证书不在有效期内")
	}
	if len(domains) == 0 {
		return emptyFingerprint, fmt.Errorf("1Panel 网站没有可校验的绑定域名")
	}
	for _, domain := range domains {
		if err := verifyOnePanelCertificateDomain(leaf, domain); err == nil {
			return sha256.Sum256(leaf.Raw), nil
		}
	}
	return emptyFingerprint, fmt.Errorf("证书未覆盖 1Panel 网站的任何绑定域名")
}

// verifyOnePanelCertificateDomain 校验普通域名/IP，并允许网站通配符与证书 SAN 精确匹配。
func verifyOnePanelCertificateDomain(certificate *x509.Certificate, domain string) error {
	if certificate == nil {
		return fmt.Errorf("证书为空")
	}
	trimmedDomain := strings.TrimSpace(domain)
	if !strings.HasPrefix(trimmedDomain, "*.") {
		normalized := normalizeOnePanelDomain(trimmedDomain)
		if normalized == "" {
			return fmt.Errorf("网站域名无效")
		}
		return certificate.VerifyHostname(normalized)
	}
	wildcardDomain := normalizeOnePanelWildcardDomain(trimmedDomain)
	if wildcardDomain == "" {
		return fmt.Errorf("网站通配符域名无效")
	}
	for _, certificateDomain := range certificate.DNSNames {
		if normalizeOnePanelWildcardDomain(certificateDomain) == wildcardDomain {
			return nil
		}
	}
	return fmt.Errorf("证书 SAN 不包含 %s", wildcardDomain)
}

// normalizeOnePanelWildcardDomain 规范化证书 SAN 中的通配符域名。
func normalizeOnePanelWildcardDomain(raw string) string {
	return normalizeOnePanelDomain(raw)
}

// onePanelCertificateFingerprint 解析回读证书并计算叶证书 SHA-256 指纹。
func onePanelCertificateFingerprint(certificatePEM string) ([sha256.Size]byte, error) {
	var emptyFingerprint [sha256.Size]byte
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
			return emptyFingerprint, err
		}
		return sha256.Sum256(certificate.Raw), nil
	}
	return emptyFingerprint, fmt.Errorf("未找到 PEM 叶证书")
}

// DeployCertificateTo1Panel 仅上传证书到 1Panel 证书库。
func (cd *CertDeployer) DeployCertificateTo1Panel(domain, downloadURL string) error {
	canonicalDomain, _, extractDir, cleanup, err := cd.prepareCertificateArchive(domain, downloadURL)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := cd.DeployTo1Panel(extractDir, canonicalDomain); err != nil {
		return err
	}
	logger.Info("1Panel 证书库上传完成", "domain", canonicalDomain)
	return nil
}
