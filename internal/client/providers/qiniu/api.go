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

	"github.com/qiniu/go-sdk/v7/auth"
)

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
