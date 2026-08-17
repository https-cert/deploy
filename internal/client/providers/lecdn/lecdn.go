// Package lecdn implements LeCDN certificate discovery and in-place CDN deployment.
package lecdn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	pageSize            = 100
	maxPages            = 100
	maxResources        = 10000
	defaultHTTPTimeout  = 30 * time.Second
	defaultSyncTimeout  = 2 * time.Minute
	defaultPollInterval = 2 * time.Second
	maxResponseBytes    = 8 << 20
)

var (
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
	_ providers.ConnectionTester           = (*Provider)(nil)
)

// HTTPClient 是 LeCDN provider 使用的最小 HTTP 客户端接口。
type HTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

// Options 提供测试可替换的 HTTP 客户端和同步轮询参数。
type Options struct {
	HTTPClient   HTTPClient    // HTTPClient 执行 LeCDN 控制面请求。
	PollInterval time.Duration // PollInterval 是同步状态轮询间隔。
	SyncTimeout  time.Duration // SyncTimeout 是单个站点同步等待上限。
}

// Provider 保存 LeCDN API Token 和控制面访问参数。
type Provider struct {
	apiBaseURL   string        // apiBaseURL 是包含 /prod-api 或 /api/client 的完整前缀。
	apiToken     string        // apiToken 是通过 Authorization 原样发送的 API Token。
	httpClient   HTTPClient    // httpClient 执行带上下文的 HTTP 请求。
	pollInterval time.Duration // pollInterval 控制同步状态读取频率。
	syncTimeout  time.Duration // syncTimeout 限制单个站点同步等待时间。
}

// apiEnvelope 是 LeCDN 统一业务响应外层。
type apiEnvelope struct {
	Code    int             `json:"code"`    // Code 为 0 或 200 时表示业务成功。
	Message string          `json:"message"` // Message 是业务失败诊断信息。
	Data    json.RawMessage `json:"data"`    // Data 保存具体接口响应。
}

// pageResult 是 LeCDN 通用分页响应。
type pageResult[T any] struct {
	Items       []T `json:"items"`        // Items 是当前页记录。
	Total       int `json:"total"`        // Total 是全部记录数。
	CurrentPage int `json:"current_page"` // CurrentPage 是响应页码。
	PageSize    int `json:"page_size"`    // PageSize 是响应每页数量。
}

// siteItem 保存发现域名所需的站点字段。
type siteItem struct {
	ID           flexibleID `json:"id"`            // ID 是站点稳定标识。
	DomainName   any        `json:"domain_name"`   // DomainName 是站点主域名展示值。
	DomainStatus string     `json:"domain_status"` // DomainStatus 是站点运行状态。
}

// siteDomainItem 保存证书引用聚合所需的站点域名字段。
type siteDomainItem struct {
	ID                flexibleID `json:"id"`                 // ID 是站点域名记录标识。
	SiteID            flexibleID `json:"site_id"`            // SiteID 是所属站点标识。
	DomainName        string     `json:"domain_name"`        // DomainName 是证书服务域名。
	CertificateEnable bool       `json:"certificate_enable"` // CertificateEnable 表示该域名启用证书。
	CertificateID     flexibleID `json:"certificate_id"`     // CertificateID 是域名当前引用的证书标识。
}

// syncStatus 保存站点边缘同步状态。
type syncStatus struct {
	Status string     `json:"status"`  // Status 是 wait、running、success 或 fail。
	TaskID flexibleID `json:"task_id"` // TaskID 是可用于诊断的同步任务标识。
}

// certificateResource 是一个 certificate_id 的全部站点和域名引用。
type certificateResource struct {
	CertificateID string              // CertificateID 是被原地更新的证书标识。
	Domains       map[string]struct{} // Domains 保存证书覆盖要求的规范化域名。
	SiteIDs       map[string]struct{} // SiteIDs 保存更新后必须强制同步的站点。
}

// apiError 保存 LeCDN 请求的重试分类和脱敏诊断信息。
type apiError struct {
	Operation string // Operation 是失败的控制面操作。
	Status    int    // Status 是 HTTP 状态码，传输失败时为零。
	Code      int    // Code 是 LeCDN 业务响应码。
	RequestID string // RequestID 是 LeCDN 或网关请求编号。
	Retryable bool   // Retryable 表示重试是否可能恢复。
	Cause     error  // Cause 保存底层网络或解析错误。
}

// Error 返回不包含 Token、证书或完整响应体的本地诊断。
func (e *apiError) Error() string {
	if e == nil {
		return ""
	}
	if e.Status > 0 {
		return fmt.Sprintf("LeCDN %s 失败: HTTP %d, code=%d", e.Operation, e.Status, e.Code)
	}
	return fmt.Sprintf("LeCDN %s 失败", e.Operation)
}

// Unwrap 暴露底层错误供 errors.Is 和 errors.As 使用。
func (e *apiError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// flexibleID 接受 LeCDN 接口中的数字或字符串 ID。
type flexibleID string

// UnmarshalJSON 将数字或字符串 ID 统一归一化为字符串。
func (id *flexibleID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return errors.New("LeCDN ID 接收器不能为空")
	}
	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err == nil {
		*id = flexibleID(strings.TrimSpace(stringValue))
		return nil
	}
	var number json.Number
	if err := json.Unmarshal(data, &number); err != nil {
		return fmt.Errorf("LeCDN ID 格式无效: %w", err)
	}
	*id = flexibleID(number.String())
	return nil
}

// New 创建使用生产控制面参数的 LeCDN provider。
func New(apiBaseURL, apiToken string) *Provider {
	return NewWithOptions(apiBaseURL, apiToken, nil)
}

// NewWithOptions 创建支持注入 HTTP 客户端和轮询参数的 LeCDN provider。
func NewWithOptions(apiBaseURL, apiToken string, options *Options) *Provider {
	resolved := Options{}
	if options != nil {
		resolved = *options
	}
	if resolved.HTTPClient == nil {
		resolved.HTTPClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if resolved.PollInterval <= 0 {
		resolved.PollInterval = defaultPollInterval
	}
	if resolved.SyncTimeout <= 0 {
		resolved.SyncTimeout = defaultSyncTimeout
	}
	return &Provider{
		apiBaseURL:   strings.TrimRight(strings.TrimSpace(apiBaseURL), "/"),
		apiToken:     strings.TrimSpace(apiToken),
		httpClient:   resolved.HTTPClient,
		pollInterval: resolved.PollInterval,
		syncTimeout:  resolved.SyncTimeout,
	}
}

// TestConnection 验证 API Token 可以读取 LeCDN 证书目录。
func (p *Provider) TestConnection() (bool, error) {
	if err := p.validateConfiguration(); err != nil {
		return false, err
	}
	query := url.Values{"current_page": {"1"}, "page_size": {"1"}}
	_, _, err := p.request(context.Background(), "测试连接", http.MethodGet, "/certificate?"+query.Encode(), nil)
	return err == nil, toDeploymentError("测试连接", err)
}

// DiscoverResources 按 certificate_id 聚合全部已启用的站点域名引用。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateConfiguration(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	resources, partial, err := p.discoverCertificateResources(ctx)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		var requestError *apiError
		if errors.As(err, &requestError) && (requestError.Status == http.StatusUnauthorized || requestError.Status == http.StatusForbidden) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Status: status, Error: err}
	}
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if partial {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL
	} else if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新发现资源并按不透明 targetRef 唯一解析。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("LeCDN 资源目录不可用", false, "", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认证书引用仍存在且证书详情可读取。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("LeCDN 资源当前不可部署", false, "", err)
	}
	_, _, err = p.getCertificate(ctx, resource.ResourceID)
	return toDeploymentError("读取证书详情", err)
}

// DeployCertificate 原地更新 certificate_id，回读证书后同步全部引用站点。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.ResourceID) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 部署资源缺少 targetRef 或 certificate_id", false, "", nil)
	}
	if len(resource.Domains) == 0 || len(resource.SiteIDs) == 0 {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 证书没有可验证的域名或站点引用", false, "", nil)
	}
	if err := providers.ValidateCertificateForDomains(certificate, resource.Domains, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 证书未覆盖全部引用域名", false, "", err)
	}

	detail, requestID, err := p.getCertificate(ctx, resource.ResourceID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("读取证书详情", err)
	}
	if strings.TrimSpace(stringValue(detail["name"])) == "" {
		detail["name"] = firstNonEmpty(certificate.Name, resource.Label, resource.Domain)
	}
	detail["ssl_pem"] = base64.StdEncoding.EncodeToString([]byte(certificate.CertificatePEM))
	detail["ssl_key"] = base64.StdEncoding.EncodeToString([]byte(certificate.PrivateKeyPEM))
	delete(detail, "id")

	writeRequestID, err := p.updateCertificate(ctx, resource.ResourceID, detail)
	requestID = firstNonEmpty(writeRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("更新证书", err)
	}
	readback, readRequestID, err := p.getCertificate(ctx, resource.ResourceID)
	requestID = firstNonEmpty(readRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读证书", err)
	}
	if err := verifyCertificateReadback(certificate.CertificatePEM, readback); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("LeCDN 证书回读尚未生效", true, requestID, err)
	}

	for _, siteID := range resource.SiteIDs {
		forceRequestID, err := p.forceSync(ctx, siteID)
		requestID = firstNonEmpty(forceRequestID, requestID)
		if err != nil {
			return providers.DeploymentResult{}, toDeploymentError("触发站点同步", err)
		}
		statusRequestID, err := p.waitForSync(ctx, siteID)
		requestID = firstNonEmpty(statusRequestID, requestID)
		if err != nil {
			return providers.DeploymentResult{}, toDeploymentError("等待站点同步", err)
		}
	}

	return providers.DeploymentResult{RequestID: requestID, Message: "LeCDN CDN 证书部署并同步成功"}, nil
}

// discoverCertificateResources 分页读取站点并聚合全部证书引用。
func (p *Provider) discoverCertificateResources(ctx context.Context) ([]providers.DeploymentResource, bool, error) {
	aggregated := make(map[string]*certificateResource)
	partial := false
	seenSites := 0
	for page := 1; page <= maxPages && seenSites < maxResources; page++ {
		sites, total, requestID, err := p.listSites(ctx, page)
		if err != nil {
			if len(aggregated) > 0 {
				partial = true
				break
			}
			return nil, false, withRequestID(err, requestID)
		}
		for _, site := range sites {
			siteID := strings.TrimSpace(string(site.ID))
			if siteID == "" {
				partial = true
				continue
			}
			domains, _, err := p.listSiteDomains(ctx, siteID)
			if err != nil {
				partial = true
				continue
			}
			for _, domain := range domains {
				if !domain.CertificateEnable {
					continue
				}
				certificateID := strings.TrimSpace(string(domain.CertificateID))
				normalizedDomain, normalizeErr := providers.NormalizeDomain(domain.DomainName)
				if certificateID == "" || certificateID == "0" || normalizeErr != nil {
					continue
				}
				entry := aggregated[certificateID]
				if entry == nil {
					entry = &certificateResource{CertificateID: certificateID, Domains: make(map[string]struct{}), SiteIDs: make(map[string]struct{})}
					aggregated[certificateID] = entry
				}
				entry.Domains[normalizedDomain] = struct{}{}
				entry.SiteIDs[siteID] = struct{}{}
			}
		}
		seenSites += len(sites)
		if len(sites) < pageSize || seenSites >= total {
			break
		}
		if page == maxPages || seenSites >= maxResources {
			partial = true
		}
	}

	resources := make([]providers.DeploymentResource, 0, len(aggregated))
	for _, entry := range aggregated {
		domains := sortedKeys(entry.Domains)
		siteIDs := sortedKeys(entry.SiteIDs)
		if len(domains) == 0 || len(siteIDs) == 0 {
			continue
		}
		resources = append(resources, providers.DeploymentResource{
			TargetRef:    providers.BuildTargetRef("lecdn", deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, entry.CertificateID),
			Label:        fmt.Sprintf("LeCDN 证书 #%s (%s)", entry.CertificateID, strings.Join(domains, ", ")),
			Domain:       domains[0],
			Domains:      domains,
			Group:        fmt.Sprintf("%d 个站点", len(siteIDs)),
			Protocol:     "HTTPS",
			Status:       "bound",
			Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY,
			ResourceID:   entry.CertificateID,
			SiteIDs:      siteIDs,
		})
	}
	sort.Slice(resources, func(left, right int) bool {
		return resources[left].TargetRef < resources[right].TargetRef
	})
	return resources, partial, nil
}

// listSites 读取一页 LeCDN 站点目录。
func (p *Provider) listSites(ctx context.Context, page int) ([]siteItem, int, string, error) {
	query := url.Values{"current_page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}}
	data, requestID, err := p.request(ctx, "读取站点列表", http.MethodGet, "/site?"+query.Encode(), nil)
	if err != nil {
		return nil, 0, requestID, err
	}
	var result pageResult[siteItem]
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, 0, requestID, &apiError{Operation: "解析站点列表", RequestID: requestID, Retryable: true, Cause: err}
	}
	return result.Items, result.Total, requestID, nil
}

// listSiteDomains 读取一个站点的全部域名及证书引用。
func (p *Provider) listSiteDomains(ctx context.Context, siteID string) ([]siteDomainItem, string, error) {
	data, requestID, err := p.request(ctx, "读取站点域名", http.MethodGet, "/site/"+url.PathEscape(siteID)+"/domain_name", nil)
	if err != nil {
		return nil, requestID, err
	}
	var domains []siteDomainItem
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, requestID, &apiError{Operation: "解析站点域名", RequestID: requestID, Retryable: true, Cause: err}
	}
	return domains, requestID, nil
}

// getCertificate 读取证书详情并保留未知字段供原地更新。
func (p *Provider) getCertificate(ctx context.Context, certificateID string) (map[string]any, string, error) {
	data, requestID, err := p.request(ctx, "读取证书详情", http.MethodGet, "/certificate/"+url.PathEscape(certificateID), nil)
	if err != nil {
		return nil, requestID, err
	}
	var detail map[string]any
	if err := json.Unmarshal(data, &detail); err != nil {
		return nil, requestID, &apiError{Operation: "解析证书详情", RequestID: requestID, Retryable: true, Cause: err}
	}
	if detail == nil {
		return nil, requestID, &apiError{Operation: "读取证书详情", RequestID: requestID, Retryable: true}
	}
	return detail, requestID, nil
}

// updateCertificate 使用相同 certificate_id 原地更新证书材料。
func (p *Provider) updateCertificate(ctx context.Context, certificateID string, detail map[string]any) (string, error) {
	body, err := json.Marshal(detail)
	if err != nil {
		return "", &apiError{Operation: "编码证书更新请求", Retryable: false, Cause: err}
	}
	_, requestID, err := p.request(ctx, "更新证书", http.MethodPut, "/certificate/"+url.PathEscape(certificateID), body)
	return requestID, err
}

// forceSync 强制创建一个站点同步任务。
func (p *Provider) forceSync(ctx context.Context, siteID string) (string, error) {
	_, requestID, err := p.request(ctx, "触发站点同步", http.MethodPost, "/site/"+url.PathEscape(siteID)+"/force_sync", []byte("{}"))
	return requestID, err
}

// waitForSync 轮询站点同步状态直到明确成功、失败或超时。
func (p *Provider) waitForSync(ctx context.Context, siteID string) (string, error) {
	waitContext, cancel := context.WithTimeout(ctx, p.syncTimeout)
	defer cancel()
	requestID := ""
	for {
		data, currentRequestID, err := p.request(waitContext, "读取站点同步状态", http.MethodGet, "/site/"+url.PathEscape(siteID)+"/sync_status", nil)
		requestID = firstNonEmpty(currentRequestID, requestID)
		if err != nil {
			return requestID, err
		}
		var status syncStatus
		if err := json.Unmarshal(data, &status); err != nil {
			return requestID, &apiError{Operation: "解析站点同步状态", RequestID: requestID, Retryable: true, Cause: err}
		}
		switch strings.ToLower(strings.TrimSpace(status.Status)) {
		case "success":
			return requestID, nil
		case "fail":
			return requestID, &apiError{Operation: "等待站点同步", RequestID: firstNonEmpty(string(status.TaskID), requestID), Retryable: false}
		case "wait", "running":
			// 正常中间态继续等待。
		default:
			return requestID, &apiError{Operation: "等待站点同步未知状态", RequestID: firstNonEmpty(string(status.TaskID), requestID), Retryable: true}
		}

		timer := time.NewTimer(p.pollInterval)
		select {
		case <-waitContext.Done():
			timer.Stop()
			return requestID, &apiError{Operation: "等待站点同步超时", RequestID: requestID, Retryable: true, Cause: waitContext.Err()}
		case <-timer.C:
		}
	}
}

// request 执行 LeCDN 请求并校验 HTTP 与业务响应码。
func (p *Provider) request(ctx context.Context, operation, method, endpoint string, body []byte) (json.RawMessage, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	requestURL := p.apiBaseURL + endpoint
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, "", &apiError{Operation: operation, Retryable: false, Cause: err}
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", p.apiToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, "", &apiError{Operation: operation, Retryable: true, Cause: err}
	}
	defer response.Body.Close()
	requestID := responseRequestID(response.Header)
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: true, Cause: readErr}
	}
	if len(responseBody) > maxResponseBytes {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: false}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError}
	}
	var envelope apiEnvelope
	if err := json.Unmarshal(responseBody, &envelope); err != nil {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: true, Cause: err}
	}
	if envelope.Code != 0 && envelope.Code != 200 {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, Code: envelope.Code, RequestID: requestID, Retryable: false}
	}
	return envelope.Data, requestID, nil
}

// validateConfiguration 拒绝空 Token 和不安全的控制面 URL。
func (p *Provider) validateConfiguration() error {
	if p == nil || strings.TrimSpace(p.apiBaseURL) == "" || strings.TrimSpace(p.apiToken) == "" {
		return providers.NewDeploymentError("LeCDN apiBaseUrl 或 apiToken 未配置", false, "", nil)
	}
	parsedURL, err := url.Parse(p.apiBaseURL)
	if err != nil || parsedURL.Hostname() == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return providers.NewDeploymentError("LeCDN apiBaseUrl 格式无效", false, "", err)
	}
	if parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return providers.NewDeploymentError("LeCDN apiBaseUrl 不能包含用户凭据、查询参数或片段", false, "", nil)
	}
	if strings.ContainsAny(p.apiToken, "\r\n\x00") {
		return providers.NewDeploymentError("LeCDN apiToken 格式无效", false, "", nil)
	}
	return nil
}

// verifyCertificateReadback 解码 LeCDN 证书并核对叶证书指纹和状态。
func verifyCertificateReadback(expectedCertificatePEM string, detail map[string]any) error {
	encodedPEM := strings.TrimSpace(stringValue(detail["ssl_pem"]))
	if encodedPEM == "" {
		return errors.New("LeCDN 证书详情缺少 ssl_pem")
	}
	actualPEM, err := base64.StdEncoding.DecodeString(encodedPEM)
	if err != nil {
		return fmt.Errorf("LeCDN ssl_pem Base64 解码失败: %w", err)
	}
	if err := providers.VerifyLeafCertificateSHA256(expectedCertificatePEM, string(actualPEM)); err != nil {
		return err
	}
	status := strings.ToLower(strings.TrimSpace(stringValue(detail["status"])))
	if status != "" && status != "active" {
		return fmt.Errorf("LeCDN 证书状态异常: %s", status)
	}
	if strings.TrimSpace(stringValue(detail["not_after"])) == "" {
		return errors.New("LeCDN 证书详情缺少 not_after")
	}
	return nil
}

// toDeploymentError 将 LeCDN API 错误转换为统一重试和 request ID 语义。
func toDeploymentError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}
	var requestError *apiError
	if errors.As(err, &requestError) {
		return providers.NewDeploymentError("LeCDN "+operation+"失败", requestError.Retryable, requestError.RequestID, err)
	}
	return providers.NewDeploymentError("LeCDN "+operation+"失败", false, "", err)
}

// withRequestID 为尚未携带 request ID 的 API 错误补充响应编号。
func withRequestID(err error, requestID string) error {
	var requestError *apiError
	if errors.As(err, &requestError) && requestError.RequestID == "" {
		requestError.RequestID = strings.TrimSpace(requestID)
	}
	return err
}

// responseRequestID 从常见网关响应头提取请求编号。
func responseRequestID(header http.Header) string {
	for _, key := range []string{"X-Request-Id", "X-Request-ID", "Request-Id", "Request-ID"} {
		if value := strings.TrimSpace(header.Get(key)); value != "" {
			return value
		}
	}
	return ""
}

// sortedKeys 将字符串集合转换为稳定排序切片。
func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// stringValue 将 API map 中的常见标量转换为字符串。
func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
