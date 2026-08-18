package onepanel

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/deploys/shared"
)

// onePanelHTTPClient 禁止自动跟随重定向，避免把面板鉴权头发送到非预期地址。
var onePanelHTTPClient = &http.Client{
	Timeout: onePanelRequestTimeout,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// IsOnePanelConfigured 判断兼容入口是否带有可用的 1Panel 配置。
func IsOnePanelConfigured() bool {
	return IsOnePanelConfiguredWithContext(context.Background())
}

// IsOnePanelConfiguredWithContext 从 context 快照判断 1Panel 是否已配置。
func IsOnePanelConfiguredWithContext(ctx context.Context) bool {
	configuration := shared.ConfigurationFromContext(ctx)
	return configuration != nil && configuration.SSL != nil && configuration.SSL.OnePanel != nil &&
		strings.TrimSpace(configuration.SSL.OnePanel.URL) != "" && strings.TrimSpace(configuration.SSL.OnePanel.APIKey) != ""
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
	//lint:ignore SA1019 保留历史网络错误的重试分类语义。
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

// md5Sum 计算 1Panel 鉴权协议要求的 MD5 摘要。
func md5Sum(data string) string {
	h := md5.New()
	_, _ = h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// getOnePanelConfig 读取并校验当前操作快照中的 1Panel API 配置。
func getOnePanelConfig(ctx context.Context) (string, string, error) {
	configuration := shared.ConfigurationFromContext(ctx)
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
