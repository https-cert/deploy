package lecdn

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

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
