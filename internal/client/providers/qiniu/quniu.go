/*
Package qiniu implements certificate upload and exact-domain certificate
deployment for Qiniu CDN products.

The certificate API and domain API use different hosts and authentication
schemes. Keeping the request construction here makes it possible to sign the
same bytes that are ultimately sent to the domain API.
*/
package qiniu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/qiniu/go-sdk/v7/auth"
)

const (
	defaultAPIBaseURL    = "https://api.qiniu.com"
	defaultFusionBaseURL = "https://fusion.qiniuapi.com"
	maxResponseBodySize  = 1024 * 1024
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceDeployer = (*Provider)(nil)
)

// Product identifies the Qiniu domain product that owns a custom domain.
type Product string

const (
	// ProductCDN identifies a Qiniu CDN custom domain.
	ProductCDN Product = "cdn"
	// ProductDCDN identifies a Qiniu DCDN custom domain.
	ProductDCDN Product = "dcdn"
)

// HTTPClient is the subset of http.Client used by Provider.
// It allows unit tests to inject an httptest client without global state.
type HTTPClient interface {
	// Do sends one HTTP request and returns its response.
	Do(*http.Request) (*http.Response, error)
}

// Options configures a Provider instance.
type Options struct {
	// HTTPClient sends signed API requests. A timeout-enabled default is used when nil.
	HTTPClient HTTPClient
	// APIBaseURL overrides the Qiniu domain API host. It is intended for tests.
	APIBaseURL string
	// FusionBaseURL overrides the Qiniu certificate API host. It is intended for tests.
	FusionBaseURL string
}

// Provider owns the Qiniu credentials and HTTP transport used for certificate operations.
type Provider struct {
	// AccessKey is retained for compatibility with existing callers. Do not log it.
	AccessKey string
	// AccessSecret is retained for compatibility with existing callers. Do not log it.
	AccessSecret string
	// credentials signs QBox and Qiniu V2 requests.
	credentials *auth.Credentials
	// httpClient sends requests after they have been signed.
	httpClient HTTPClient
	// apiBaseURL is the Qiniu domain API base URL.
	apiBaseURL string
	// fusionBaseURL is the Qiniu certificate API base URL.
	fusionBaseURL string
}

// CertificateUploadResult contains the certificate identity returned by Qiniu.
type CertificateUploadResult struct {
	// CertificateID is Qiniu's certID and is required by the domain binding API.
	CertificateID string
	// ProviderRequestID is Qiniu's request identifier for the upload operation.
	ProviderRequestID string
}

// TargetDeploymentResult describes one exact-domain certificate deployment at the Qiniu API layer.
type TargetDeploymentResult struct {
	// CertificateID is the Qiniu certID bound to the custom domain.
	CertificateID string
	// Domain is the exact custom domain that was verified and updated.
	Domain string
	// Product is the Qiniu product validated before the update.
	Product Product
	// UploadRequestID identifies the certificate upload request when this method uploaded a certificate.
	UploadRequestID string
	// ProviderRequestID identifies the domain update request.
	ProviderRequestID string
}

// APIError carries enough provider context for a later caller to decide whether to retry.
type APIError struct {
	// Operation identifies the failed Qiniu API operation.
	Operation string
	// StatusCode is the provider HTTP status code, or zero before a response exists.
	StatusCode int
	// ProviderRequestID is Qiniu's request identifier when the response included one.
	ProviderRequestID string
	// Retryable reports whether retrying the operation may succeed without configuration changes.
	Retryable bool
	// Message is a sanitized provider or local failure description.
	Message string
	// Cause retains the underlying transport or parsing error.
	Cause error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("七牛 %s 失败: HTTP %d: %s", e.Operation, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("七牛 %s 失败: %s", e.Operation, e.Message)
}

// Unwrap exposes the underlying cause for errors.Is and errors.As.
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// New creates a Provider using Qiniu production API endpoints.
func New(accessKey, accessSecret string) *Provider {
	return NewWithOptions(accessKey, accessSecret, nil)
}

// NewWithOptions creates a Provider with an injectable HTTP transport and API endpoints.
func NewWithOptions(accessKey, accessSecret string, options *Options) *Provider {
	providerOptions := Options{}
	if options != nil {
		providerOptions = *options
	}

	if providerOptions.HTTPClient == nil {
		providerOptions.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if strings.TrimSpace(providerOptions.APIBaseURL) == "" {
		providerOptions.APIBaseURL = defaultAPIBaseURL
	}
	if strings.TrimSpace(providerOptions.FusionBaseURL) == "" {
		providerOptions.FusionBaseURL = defaultFusionBaseURL
	}

	return &Provider{
		AccessKey:     accessKey,
		AccessSecret:  accessSecret,
		credentials:   auth.New(accessKey, accessSecret),
		httpClient:    providerOptions.HTTPClient,
		apiBaseURL:    strings.TrimRight(providerOptions.APIBaseURL, "/"),
		fusionBaseURL: strings.TrimRight(providerOptions.FusionBaseURL, "/"),
	}
}

// TestConnection tests QBox credentials against the Qiniu certificate API.
func (p *Provider) TestConnection() (bool, error) {
	return p.TestConnectionWithContext(context.Background())
}

// TestConnectionWithContext tests QBox credentials while respecting caller cancellation.
func (p *Provider) TestConnectionWithContext(ctx context.Context) (bool, error) {
	if err := p.validateCredentials("测试连接"); err != nil {
		return false, err
	}

	_, err := p.execute(ctx, "获取证书列表", http.MethodGet, p.fusionBaseURL, "/sslcert", authorizationQBox, nil)
	if err != nil {
		return false, err
	}
	return true, nil
}

// UploadCertificate uploads a certificate for the legacy ProviderHandler interface.
// Call UploadCertificateWithContext when the caller needs Qiniu's certID.
func (p *Provider) UploadCertificate(name, domain, cert, key string) error {
	_, err := p.UploadCertificateWithContext(context.Background(), name, domain, cert, key)
	return err
}

// UploadCertificateWithContext uploads a PEM certificate with QBox authentication and retains certID.
func (p *Provider) UploadCertificateWithContext(ctx context.Context, name, domain, cert, key string) (*CertificateUploadResult, error) {
	if err := p.validateCertificateInput("上传证书", name, domain, cert, key); err != nil {
		return nil, err
	}
	if err := p.validateCredentials("上传证书"); err != nil {
		return nil, err
	}

	body, err := json.Marshal(certificateUploadRequest{
		Name:        name,
		PrivateKey:  key,
		Certificate: cert,
	})
	if err != nil {
		return nil, newLocalError("编码证书上传请求", err)
	}

	response, err := p.execute(ctx, "上传证书", http.MethodPost, p.fusionBaseURL, "/sslcert", authorizationQBox, body)
	if err != nil {
		return nil, err
	}

	var uploadResponse certificateUploadResponse
	if err := json.Unmarshal(response.Body, &uploadResponse); err != nil {
		return nil, newLocalError("解析证书上传响应", err)
	}
	if strings.TrimSpace(uploadResponse.CertificateID) == "" {
		return nil, &APIError{
			Operation:         "上传证书",
			StatusCode:        response.StatusCode,
			ProviderRequestID: response.ProviderRequestID,
			Retryable:         false,
			Message:           "响应中缺少 certID",
		}
	}

	return &CertificateUploadResult{
		CertificateID:     uploadResponse.CertificateID,
		ProviderRequestID: response.ProviderRequestID,
	}, nil
}

// DeployCertificate 为明确的七牛 CDN 或 DCDN 业务部署精确域名证书。
func (p *Provider) DeployCertificate(ctx context.Context, certificate providers.CertificateMaterial, business deployPB.ExecuteBusinesType, target providers.DeploymentResource) (providers.DeploymentResult, error) {
	if strings.TrimSpace(target.TargetRef) == "" {
		return providers.DeploymentResult{}, providers.NewDeploymentError("七牛云 targetRef 不能为空", false, "", nil)
	}
	var product Product
	switch business {
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_CDN:
		product = ProductCDN
	case deployPB.ExecuteBusinesType_EXECUTE_BUSINES_DCDN:
		product = ProductDCDN
	default:
		return providers.DeploymentResult{}, providers.NewDeploymentError("七牛云不支持该部署业务", false, "", nil)
	}

	certificateName := strings.TrimSpace(certificate.Name)
	if certificateName == "" {
		certificateName = strings.TrimSpace(target.Label)
	}
	if certificateName == "" {
		certificateName = strings.TrimSpace(target.Domain)
	}

	result, err := p.DeployTargetCertificate(
		ctx,
		product,
		certificateName,
		target.Domain,
		certificate.CertificatePEM,
		certificate.PrivateKeyPEM,
	)
	if err != nil {
		return providers.DeploymentResult{}, toDeploymentError(err)
	}

	productName := "CDN"
	if product == ProductDCDN {
		productName = "DCDN"
	}
	return providers.DeploymentResult{
		RequestID: result.ProviderRequestID,
		Message:   fmt.Sprintf("七牛云 %s 域名证书部署成功", productName),
	}, nil
}

// DeployTargetCertificate validates one exact Qiniu domain, uploads a certificate, binds it, and reads it back.
func (p *Provider) DeployTargetCertificate(ctx context.Context, product Product, name, domain, cert, key string) (*TargetDeploymentResult, error) {
	if err := p.validateProduct(product); err != nil {
		return nil, err
	}
	if err := p.validateCertificateInput("部署证书", name, domain, cert, key); err != nil {
		return nil, err
	}
	if err := p.validateCredentials("部署证书"); err != nil {
		return nil, err
	}

	if _, err := p.readAndValidateDomain(ctx, product, domain); err != nil {
		return nil, err
	}

	uploaded, err := p.UploadCertificateWithContext(ctx, name, domain, cert, key)
	if err != nil {
		return nil, err
	}

	result, err := p.bindValidatedCertificate(ctx, product, domain, uploaded.CertificateID)
	if err != nil {
		return nil, err
	}
	result.UploadRequestID = uploaded.ProviderRequestID
	return result, nil
}

// BindCertificate validates one exact Qiniu domain, binds an existing certID, and reads it back.
func (p *Provider) BindCertificate(ctx context.Context, product Product, certID, domain string) (*TargetDeploymentResult, error) {
	if err := p.validateProduct(product); err != nil {
		return nil, err
	}
	if strings.TrimSpace(certID) == "" {
		return nil, newValidationError("绑定证书", "certID 不能为空")
	}
	if strings.TrimSpace(domain) == "" {
		return nil, newValidationError("绑定证书", "域名不能为空")
	}
	if err := p.validateCredentials("绑定证书"); err != nil {
		return nil, err
	}

	if _, err := p.readAndValidateDomain(ctx, product, domain); err != nil {
		return nil, err
	}
	return p.bindValidatedCertificate(ctx, product, domain, certID)
}

// readAndValidateDomain reads the exact domain and rejects a mismatched product or non-HTTPS configuration.
func (p *Provider) readAndValidateDomain(ctx context.Context, product Product, domain string) (*domainInfo, error) {
	domainInfo, err := p.getDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if domainInfo.Name != "" && !strings.EqualFold(strings.TrimSpace(domainInfo.Name), strings.TrimSpace(domain)) {
		return nil, newValidationError("读取域名配置", "七牛返回的域名与目标域名不一致")
	}
	if !strings.EqualFold(strings.TrimSpace(domainInfo.Product), string(product)) {
		return nil, newValidationError("读取域名配置", fmt.Sprintf("目标域名产品类型为 %q，不是 %q", domainInfo.Product, product))
	}
	if !strings.EqualFold(strings.TrimSpace(domainInfo.Protocol), "https") {
		return nil, newValidationError("读取域名配置", "目标域名未启用 HTTPS")
	}
	return domainInfo, nil
}

// bindValidatedCertificate updates a domain already checked by readAndValidateDomain and verifies its certID.
func (p *Provider) bindValidatedCertificate(ctx context.Context, product Product, domain, certID string) (*TargetDeploymentResult, error) {
	body, err := json.Marshal(httpsConfigurationRequest{CertificateID: certID})
	if err != nil {
		return nil, newLocalError("编码 HTTPS 配置请求", err)
	}

	response, err := p.execute(ctx, "更新域名 HTTPS 证书", http.MethodPut, p.apiBaseURL, domainHTTPSConfigurationPath(domain), authorizationQiniuV2, body)
	if err != nil {
		return nil, err
	}

	domainInfo, err := p.getDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(domainInfo.HTTPS.CertificateID), strings.TrimSpace(certID)) {
		return nil, &APIError{
			Operation:         "验证域名 HTTPS 证书",
			StatusCode:        response.StatusCode,
			ProviderRequestID: response.ProviderRequestID,
			Retryable:         true,
			Message:           "控制面回读的 certId 与提交值不一致",
		}
	}

	return &TargetDeploymentResult{
		CertificateID:     certID,
		Domain:            domain,
		Product:           product,
		ProviderRequestID: response.ProviderRequestID,
	}, nil
}

// toDeploymentError converts Qiniu provider metadata into the shared cloud deployment error contract.
func toDeploymentError(err error) error {
	var apiError *APIError
	if errors.As(err, &apiError) {
		return providers.NewDeploymentError(
			apiError.Error(),
			apiError.Retryable,
			apiError.ProviderRequestID,
			apiError,
		)
	}
	return providers.NewDeploymentError("七牛云资源部署失败", false, "", err)
}

// getDomain reads one exact Qiniu domain with Qiniu V2 authentication.
func (p *Provider) getDomain(ctx context.Context, domain string) (*domainInfo, error) {
	if strings.TrimSpace(domain) == "" {
		return nil, newValidationError("读取域名配置", "域名不能为空")
	}
	response, err := p.execute(ctx, "读取域名配置", http.MethodGet, p.apiBaseURL, domainPath(domain), authorizationQiniuV2, nil)
	if err != nil {
		return nil, err
	}

	var domainInfo domainInfo
	if err := json.Unmarshal(response.Body, &domainInfo); err != nil {
		return nil, newLocalError("解析域名配置响应", err)
	}
	return &domainInfo, nil
}

// execute creates, signs, sends, and decodes one Qiniu API request.
func (p *Provider) execute(ctx context.Context, operation, method, baseURL, path string, authorization authorizationMode, body []byte) (*apiResponse, error) {
	requestURL, err := buildRequestURL(baseURL, path)
	if err != nil {
		return nil, newLocalError(operation, err)
	}

	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, newLocalError(operation, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")
	// V2 includes Host in its canonical string. Set it before signing so the signed value is sent too.
	request.Host = request.URL.Host

	if err := p.addAuthorization(request, authorization, body); err != nil {
		return nil, newLocalError(operation, err)
	}

	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, newTransportError(operation, err)
	}
	defer response.Body.Close()

	responseBody, err := readResponseBody(response.Body)
	if err != nil {
		return nil, newTransportError(operation, err)
	}
	apiResponse := &apiResponse{
		StatusCode:        response.StatusCode,
		ProviderRequestID: qiniuRequestID(response.Header),
		Body:              responseBody,
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, &APIError{
			Operation:         operation,
			StatusCode:        response.StatusCode,
			ProviderRequestID: apiResponse.ProviderRequestID,
			Retryable:         isRetryableStatus(response.StatusCode),
			Message:           responseMessage(responseBody),
		}
	}
	return apiResponse, nil
}

// addAuthorization attaches the authentication header and restores the exact body bytes after signing.
func (p *Provider) addAuthorization(request *http.Request, mode authorizationMode, body []byte) error {
	var (
		token string
		err   error
	)
	switch mode {
	case authorizationQBox:
		token, err = p.credentials.SignRequest(request)
		if err == nil {
			request.Header.Set("Authorization", auth.AuthorizationPrefixQBox+token)
		}
	case authorizationQiniuV2:
		token, err = p.credentials.SignRequestV2(request)
		if err == nil {
			request.Header.Set("Authorization", auth.AuthorizationPrefixQiniu+token)
		}
	default:
		return fmt.Errorf("未知的七牛鉴权方式")
	}
	if err != nil {
		return fmt.Errorf("生成鉴权签名: %w", err)
	}
	// SignRequestV2 consumes and recreates Body internally. Replacing it with the original buffer
	// makes the signed JSON and transmitted JSON provably identical.
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	return nil
}

// validateCredentials rejects incomplete local credentials before any provider request is made.
func (p *Provider) validateCredentials(operation string) error {
	if p == nil || p.credentials == nil || strings.TrimSpace(p.AccessKey) == "" || strings.TrimSpace(p.AccessSecret) == "" {
		return newValidationError(operation, "AccessKey 或 AccessSecret 不能为空")
	}
	return nil
}

// validateCertificateInput rejects incomplete deployment material before any provider request is made.
func (p *Provider) validateCertificateInput(operation, name, domain, cert, key string) error {
	if strings.TrimSpace(name) == "" {
		return newValidationError(operation, "证书名称不能为空")
	}
	if strings.TrimSpace(domain) == "" {
		return newValidationError(operation, "域名不能为空")
	}
	if strings.TrimSpace(cert) == "" {
		return newValidationError(operation, "证书内容不能为空")
	}
	if strings.TrimSpace(key) == "" {
		return newValidationError(operation, "私钥内容不能为空")
	}
	return nil
}

// validateProduct restricts deployments to the two Qiniu products supported by this package.
func (p *Provider) validateProduct(product Product) error {
	switch product {
	case ProductCDN, ProductDCDN:
		return nil
	default:
		return newValidationError("部署证书", fmt.Sprintf("不支持的七牛产品类型 %q", product))
	}
}

// buildRequestURL joins a provider base URL with a fixed API path.
func buildRequestURL(baseURL, path string) (string, error) {
	base, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil {
		return "", fmt.Errorf("解析 API 地址: %w", err)
	}
	if base.Scheme != "https" && base.Scheme != "http" {
		return "", fmt.Errorf("API 地址必须使用 HTTP 或 HTTPS")
	}
	if base.Host == "" {
		return "", fmt.Errorf("API 地址缺少主机名")
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimRight(base.String(), "/") + path, nil
}

// domainPath returns the escaped path used to retrieve one exact Qiniu domain.
func domainPath(domain string) string {
	return "/domain/" + url.PathEscape(strings.TrimSpace(domain))
}

// domainHTTPSConfigurationPath returns the escaped path used to update one exact Qiniu domain certificate.
func domainHTTPSConfigurationPath(domain string) string {
	return domainPath(domain) + "/httpsconf"
}

// readResponseBody bounds provider response reads so a malformed endpoint cannot consume unbounded memory.
func readResponseBody(body io.Reader) ([]byte, error) {
	responseBody, err := io.ReadAll(io.LimitReader(body, maxResponseBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("读取响应体: %w", err)
	}
	if len(responseBody) > maxResponseBodySize {
		return nil, fmt.Errorf("响应体超过最大限制")
	}
	return responseBody, nil
}

// qiniuRequestID extracts Qiniu's request identifier without depending on header casing.
func qiniuRequestID(headers http.Header) string {
	return strings.TrimSpace(headers.Get("X-Reqid"))
}

// responseMessage extracts a compact, non-sensitive provider error message.
func responseMessage(body []byte) string {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err == nil {
		for _, key := range []string{"error", "message", "code"} {
			value, ok := payload[key]
			if !ok {
				continue
			}
			var message string
			if json.Unmarshal(value, &message) == nil && strings.TrimSpace(message) != "" {
				return compactMessage(message)
			}
		}
	}
	if len(body) == 0 {
		return "七牛返回空错误响应"
	}
	return compactMessage(string(body))
}

// compactMessage strips control whitespace and limits an error message suitable for logs and ACKs.
func compactMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	if len(message) > 1024 {
		return message[:1024]
	}
	return message
}

// isRetryableStatus classifies transient HTTP failures from the provider control plane.
func isRetryableStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout || statusCode == http.StatusTooManyRequests || statusCode >= http.StatusInternalServerError
}

// newValidationError creates a non-retryable local configuration error.
func newValidationError(operation, message string) *APIError {
	return &APIError{
		Operation: operation,
		Retryable: false,
		Message:   message,
	}
}

// newLocalError creates a non-retryable local request construction or response parsing error.
func newLocalError(operation string, cause error) *APIError {
	return &APIError{
		Operation: operation,
		Retryable: false,
		Message:   cause.Error(),
		Cause:     cause,
	}
}

// newTransportError creates a transport error and preserves cancellation semantics for callers.
func newTransportError(operation string, cause error) *APIError {
	return &APIError{
		Operation: operation,
		Retryable: !errors.Is(cause, context.Canceled),
		Message:   cause.Error(),
		Cause:     cause,
	}
}

// authorizationMode selects the Qiniu authentication scheme required by an endpoint.
type authorizationMode int

const (
	// authorizationQBox signs certificate API requests with QBox credentials.
	authorizationQBox authorizationMode = iota
	// authorizationQiniuV2 signs domain API requests with Qiniu V2 credentials.
	authorizationQiniuV2
)

// apiResponse is the bounded, decoded-independent response used by provider operations.
type apiResponse struct {
	// StatusCode is the HTTP status received from Qiniu.
	StatusCode int
	// ProviderRequestID is Qiniu's request identifier.
	ProviderRequestID string
	// Body is the original response body after size validation.
	Body []byte
}

// certificateUploadRequest is the exact lowercase JSON schema expected by fusion.qiniuapi.com/sslcert.
type certificateUploadRequest struct {
	// Name is Qiniu's human-readable certificate name.
	Name string `json:"name"`
	// PrivateKey is the PEM private key sent as pri.
	PrivateKey string `json:"pri"`
	// Certificate is the PEM certificate chain sent as ca.
	Certificate string `json:"ca"`
}

// certificateUploadResponse is the minimal response required from the Qiniu certificate API.
type certificateUploadResponse struct {
	// CertificateID is Qiniu's certID value.
	CertificateID string `json:"certID"`
}

// httpsConfigurationRequest is the minimal update schema that preserves all unrelated domain HTTPS settings.
type httpsConfigurationRequest struct {
	// CertificateID is the Qiniu certID to bind to the exact domain.
	CertificateID string `json:"certId"`
}

// domainHTTPSConfig contains the certificate identifier returned by the domain read API.
type domainHTTPSConfig struct {
	// CertificateID is the current HTTPS certId configured for the domain.
	CertificateID string `json:"certId"`
}

// domainInfo contains the fields used to validate and read back one exact Qiniu domain.
type domainInfo struct {
	// Name is the custom domain name returned by Qiniu.
	Name string `json:"name"`
	// Product identifies the Qiniu CDN product that owns the domain.
	Product string `json:"product"`
	// Protocol is the enabled protocol configuration reported by Qiniu.
	Protocol string `json:"protocol"`
	// HTTPS contains the currently configured custom certificate identifier.
	HTTPS domainHTTPSConfig `json:"https"`
}
