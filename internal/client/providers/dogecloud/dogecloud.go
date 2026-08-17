// Package dogecloud implements DogeCloud certificate upload and CDN deployment.
package dogecloud

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

const (
	defaultAPIBaseURL = "https://api.dogecloud.com"
	maxResponseBytes  = 8 << 20
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceProvider = (*Provider)(nil)
)

// HTTPClient 是多吉云 provider 使用的最小 HTTP 客户端接口。
type HTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

// Options 提供测试可替换的 HTTP 客户端和 API 地址。
type Options struct {
	HTTPClient HTTPClient // HTTPClient 执行多吉云控制面请求。
	APIBaseURL string     // APIBaseURL 覆盖多吉云默认 API 地址。
}

// Provider 保存多吉云 API 密钥和请求客户端。
type Provider struct {
	accessKey    string     // accessKey 是多吉云公开 AccessKey。
	accessSecret string     // accessSecret 是只用于 HMAC 签名的 SecretKey。
	apiBaseURL   string     // apiBaseURL 是多吉云控制面地址。
	httpClient   HTTPClient // httpClient 执行签名后的请求。
}

// apiEnvelope 是多吉云统一业务响应外层。
type apiEnvelope struct {
	Code int             `json:"code"` // Code 为 200 时表示业务成功。
	Msg  string          `json:"msg"`  // Msg 是业务响应信息。
	Data json.RawMessage `json:"data"` // Data 保存具体业务结果。
}

// domainRecord 保存 CDN 域名及当前证书引用。
type domainRecord struct {
	ID            string // ID 是域名记录稳定标识，旧接口可能缺失。
	Name          string // Name 是 CDN 加速域名。
	CertificateID string // CertificateID 是域名当前绑定证书 ID。
	Status        string // Status 是域名运行状态。
}

// certificateRecord 保存证书中心幂等匹配所需字段。
type certificateRecord struct {
	ID   string `json:"-"`    // ID 是多吉云证书 ID。
	Note string `json:"note"` // Note 是由证书指纹构造的备注。
}

// apiError 保存多吉云错误的重试分类和请求编号。
type apiError struct {
	Operation string // Operation 是失败操作名称。
	Status    int    // Status 是 HTTP 状态码。
	Code      int    // Code 是多吉云业务响应码。
	RequestID string // RequestID 是网关请求编号。
	Retryable bool   // Retryable 表示请求是否可以安全重试。
	Cause     error  // Cause 保存底层错误。
}

// Error 返回不包含证书和密钥的脱敏诊断。
func (e *apiError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("多吉云 %s 失败: HTTP %d, code=%d", e.Operation, e.Status, e.Code)
}

// Unwrap 暴露底层错误供 errors.Is 和 errors.As 使用。
func (e *apiError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// New 创建使用多吉云生产 API 地址的 provider。
func New(accessKey, accessSecret string) *Provider {
	return NewWithOptions(accessKey, accessSecret, nil)
}

// NewWithOptions 创建支持测试注入的多吉云 provider。
func NewWithOptions(accessKey, accessSecret string, options *Options) *Provider {
	resolved := Options{}
	if options != nil {
		resolved = *options
	}
	if resolved.HTTPClient == nil {
		resolved.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if strings.TrimSpace(resolved.APIBaseURL) == "" {
		resolved.APIBaseURL = defaultAPIBaseURL
	}
	return &Provider{
		accessKey:    strings.TrimSpace(accessKey),
		accessSecret: strings.TrimSpace(accessSecret),
		apiBaseURL:   strings.TrimRight(strings.TrimSpace(resolved.APIBaseURL), "/"),
		httpClient:   resolved.HTTPClient,
	}
}

// TestConnection 验证多吉云密钥可以读取 CDN 域名目录。
func (p *Provider) TestConnection() (bool, error) {
	if err := p.validateCredentials(); err != nil {
		return false, err
	}
	_, _, err := p.listDomains(context.Background())
	return err == nil, toDeploymentError("测试连接", err)
}

// UploadCertificate 将证书上传到多吉云证书中心，并按叶证书指纹复用已有证书。
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	certificate := providers.CertificateMaterial{Name: name, Domain: domain, CertificatePEM: cert, PrivateKeyPEM: key}
	if err := providers.ValidateCertificateMaterial(certificate, domain, time.Now()); err != nil {
		return providers.NewDeploymentError("多吉云上传证书校验失败", false, "", err)
	}
	_, _, err := p.ensureCertificate(context.Background(), certificate)
	return toDeploymentError("上传证书", err)
}

// DiscoverResources 实时读取多吉云 CDN 域名目录。
func (p *Provider) DiscoverResources(ctx context.Context, deploymentType deployPB.DeploymentType) providers.ResourceCatalogResult {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE}
	}
	if err := p.validateCredentials(); err != nil {
		return providers.ResourceCatalogResult{Status: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED, Error: err}
	}
	domains, _, err := p.listDomains(ctx)
	if err != nil {
		status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE
		var requestError *apiError
		if errors.As(err, &requestError) && (requestError.Status == http.StatusUnauthorized || requestError.Status == http.StatusForbidden) {
			status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED
		}
		return providers.ResourceCatalogResult{Status: status, Error: err}
	}
	resources := make([]providers.DeploymentResource, 0, len(domains))
	for _, record := range domains {
		domain, normalizeErr := providers.NormalizeDomain(record.Name)
		if normalizeErr != nil {
			continue
		}
		identity := firstNonEmpty(record.ID, domain)
		availability := deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY
		if status := strings.ToLower(strings.TrimSpace(record.Status)); status != "" && status != "online" && status != "enabled" && status != "running" {
			availability = deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_STOPPED
		}
		resources = append(resources, providers.DeploymentResource{
			TargetRef:    providers.BuildTargetRef("dogecloud", deploymentType, identity),
			Label:        domain,
			Domain:       domain,
			Domains:      []string{domain},
			Protocol:     "HTTPS",
			Status:       record.Status,
			Availability: availability,
			ResourceID:   identity,
		})
	}
	sort.Slice(resources, func(left, right int) bool { return resources[left].Domain < resources[right].Domain })
	status := deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY
	if len(resources) == 0 {
		status = deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY
	}
	return providers.ResourceCatalogResult{Resources: resources, Status: status}
}

// ResolveResource 重新读取目录并按 targetRef 唯一解析域名。
func (p *Provider) ResolveResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) (providers.DeploymentResource, error) {
	catalog := p.DiscoverResources(ctx, deploymentType)
	if catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED ||
		catalog.Status == deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		return providers.DeploymentResource{}, providers.NewDeploymentError("多吉云资源目录不可用", false, "", catalog.Error)
	}
	return providers.FindResourceByTargetRef(catalog.Resources, targetRef)
}

// TestResource 确认多吉云域名仍存在且当前状态可部署。
func (p *Provider) TestResource(ctx context.Context, deploymentType deployPB.DeploymentType, targetRef string) error {
	resource, err := p.ResolveResource(ctx, deploymentType, targetRef)
	if err != nil {
		return err
	}
	if err := providers.EnsureResourceReady(resource); err != nil {
		return providers.NewDeploymentError("多吉云 CDN 域名当前不可部署", false, "", err)
	}
	return nil
}

// DeployCertificate 上传或复用证书，绑定精确域名并回读证书 ID。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, deploymentType deployPB.DeploymentType, resource providers.DeploymentResource) (providers.DeploymentResult, error) {
	if deploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN {
		return providers.DeploymentResult{}, providers.NewDeploymentError("多吉云不支持该部署业务", false, "", nil)
	}
	if strings.TrimSpace(resource.TargetRef) == "" || strings.TrimSpace(resource.Domain) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("多吉云 CDN 目标缺少 targetRef 或域名", false, "", nil)
	}
	if err := providers.ValidateCertificateMaterial(certificate, resource.Domain, time.Now()); err != nil {
		return providers.DeploymentResult{}, providers.NewDeploymentError("多吉云 CDN 证书校验失败", false, "", err)
	}
	certificateID, requestID, err := p.ensureCertificate(ctx, certificate)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("上传证书", err)
	}
	bindRequestID, err := p.bindCertificate(ctx, certificateID, resource.Domain)
	requestID = firstNonEmpty(bindRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("绑定 CDN 证书", err)
	}
	domains, readRequestID, err := p.listDomains(ctx)
	requestID = firstNonEmpty(readRequestID, requestID)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError("回读 CDN 域名", err)
	}
	for _, domain := range domains {
		normalized, normalizeErr := providers.NormalizeDomain(domain.Name)
		if normalizeErr == nil && normalized == resource.Domain {
			if strings.TrimSpace(domain.CertificateID) == "" {
				return providers.DeploymentResult{}, providers.NewDeploymentError("多吉云 CDN 回读缺少证书 ID", true, requestID, nil)
			}
			if domain.CertificateID != certificateID {
				return providers.DeploymentResult{}, providers.NewDeploymentError("多吉云 CDN 证书回读尚未生效", true, requestID, nil)
			}
			return providers.DeploymentResult{RequestID: requestID, Message: "多吉云 CDN 证书部署成功"}, nil
		}
	}
	return providers.DeploymentResult{}, providers.NewDeploymentError("多吉云 CDN 域名回读失败", true, requestID, nil)
}

// ensureCertificate 按叶证书指纹备注复用或上传证书。
func (p *Provider) ensureCertificate(ctx context.Context, certificate providers.CertificateMaterial) (string, string, error) {
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		return "", "", err
	}
	note := "anssl-" + fingerprint
	certificates, requestID, err := p.listCertificates(ctx)
	if err != nil {
		return "", requestID, err
	}
	for _, existing := range certificates {
		if existing.Note == note && existing.ID != "" {
			return existing.ID, requestID, nil
		}
	}
	payload := map[string]any{"cert": certificate.CertificatePEM, "private": certificate.PrivateKeyPEM, "note": note}
	data, uploadRequestID, err := p.request(ctx, "上传证书", "/cdn/cert/upload.json", payload)
	if err != nil {
		return "", firstNonEmpty(uploadRequestID, requestID), err
	}
	certificateID := firstNonEmpty(scalarString(data["id"]), scalarString(data["certId"]), scalarString(data["cert_id"]))
	if certificateID == "" {
		return "", firstNonEmpty(uploadRequestID, requestID), &apiError{Operation: "上传证书", RequestID: uploadRequestID, Retryable: false}
	}
	readback, readbackRequestID, err := p.listCertificates(ctx)
	requestID = firstNonEmpty(readbackRequestID, uploadRequestID, requestID)
	if err != nil {
		return "", requestID, err
	}
	for _, existing := range readback {
		if existing.ID == certificateID && existing.Note == note {
			return certificateID, requestID, nil
		}
	}
	return "", requestID, &apiError{Operation: "回读上传证书", RequestID: requestID, Retryable: true}
}

// listCertificates 读取多吉云证书中心目录。
func (p *Provider) listCertificates(ctx context.Context) ([]certificateRecord, string, error) {
	data, requestID, err := p.request(ctx, "读取证书列表", "/cdn/cert/list.json", map[string]any{})
	if err != nil {
		return nil, requestID, err
	}
	items, ok := data["certs"].([]any)
	if !ok {
		return nil, requestID, &apiError{Operation: "解析证书列表", RequestID: requestID, Retryable: true}
	}
	result := make([]certificateRecord, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, certificateRecord{ID: scalarString(entry["id"]), Note: strings.TrimSpace(scalarString(entry["note"]))})
	}
	return result, requestID, nil
}

// listDomains 读取多吉云 CDN 域名和当前证书引用。
func (p *Provider) listDomains(ctx context.Context) ([]domainRecord, string, error) {
	data, requestID, err := p.request(ctx, "读取 CDN 域名", "/cdn/domain/list.json", map[string]any{})
	if err != nil {
		return nil, requestID, err
	}
	items, ok := data["domains"].([]any)
	if !ok {
		return nil, requestID, &apiError{Operation: "解析 CDN 域名", RequestID: requestID, Retryable: true}
	}
	result := make([]domainRecord, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, domainRecord{
			ID:            firstNonEmpty(scalarString(entry["id"]), scalarString(entry["domainId"]), scalarString(entry["domain_id"])),
			Name:          firstNonEmpty(scalarString(entry["name"]), scalarString(entry["domain"])),
			CertificateID: firstNonEmpty(scalarString(entry["certId"]), scalarString(entry["cert_id"]), scalarString(entry["certificateId"])),
			Status:        firstNonEmpty(scalarString(entry["status"]), scalarString(entry["state"])),
		})
	}
	return result, requestID, nil
}

// bindCertificate 将证书 ID 绑定到一个精确 CDN 域名。
func (p *Provider) bindCertificate(ctx context.Context, certificateID, domain string) (string, error) {
	_, requestID, err := p.request(ctx, "绑定 CDN 证书", "/cdn/cert/bind.json", map[string]any{"id": certificateID, "domain": domain})
	return requestID, err
}

// request 对请求体计算 HMAC-SHA1 签名并校验多吉云业务响应。
func (p *Provider) request(ctx context.Context, operation, apiPath string, payload map[string]any) (map[string]any, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", &apiError{Operation: operation, Retryable: false, Cause: err}
	}
	signature := hmac.New(sha1.New, []byte(p.accessSecret))
	_, _ = signature.Write([]byte(apiPath + "\n" + string(body)))
	authorization := "TOKEN " + p.accessKey + ":" + hex.EncodeToString(signature.Sum(nil))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.apiBaseURL+apiPath, bytes.NewReader(body))
	if err != nil {
		return nil, "", &apiError{Operation: operation, Retryable: false, Cause: err}
	}
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, "", &apiError{Operation: operation, Retryable: true, Cause: err}
	}
	defer response.Body.Close()
	requestID := responseRequestID(response.Header)
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(responseBody) > maxResponseBytes {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: err != nil, Cause: err}
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError}
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.UseNumber()
	var envelope apiEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, RequestID: requestID, Retryable: true, Cause: err}
	}
	if envelope.Code != http.StatusOK {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, Code: envelope.Code, RequestID: requestID, Retryable: false}
	}
	data := make(map[string]any)
	dataDecoder := json.NewDecoder(bytes.NewReader(envelope.Data))
	dataDecoder.UseNumber()
	if err := dataDecoder.Decode(&data); err != nil {
		return nil, requestID, &apiError{Operation: operation, Status: response.StatusCode, Code: envelope.Code, RequestID: requestID, Retryable: true, Cause: err}
	}
	return data, requestID, nil
}

// validateCredentials 拒绝空密钥和可污染请求头的控制字符。
func (p *Provider) validateCredentials() error {
	if p == nil || strings.TrimSpace(p.accessKey) == "" || strings.TrimSpace(p.accessSecret) == "" {
		return providers.NewDeploymentError("多吉云 accessKey 或 accessSecret 未配置", false, "", nil)
	}
	if strings.ContainsAny(p.accessKey+p.accessSecret, "\r\n\x00") {
		return providers.NewDeploymentError("多吉云密钥格式无效", false, "", nil)
	}
	return nil
}

// toDeploymentError 将多吉云 API 错误转换成统一部署错误。
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
		return providers.NewDeploymentError("多吉云 "+operation+"失败", requestError.Retryable, requestError.RequestID, err)
	}
	return providers.NewDeploymentError("多吉云 "+operation+"失败", false, "", err)
}

// scalarString 将 JSON 标量稳定转换为字符串。
func scalarString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

// responseRequestID 提取常见网关请求编号。
func responseRequestID(header http.Header) string {
	for _, key := range []string{"X-Request-Id", "X-Request-ID", "Request-Id", "Request-ID"} {
		if value := strings.TrimSpace(header.Get(key)); value != "" {
			return value
		}
	}
	return ""
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
