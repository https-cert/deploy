package btpanel

import (
	"context"
	"crypto/md5"
	"crypto/tls"
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

// IsBTPanelConfigured 判断兼容入口是否带有可用的宝塔面板配置。
func IsBTPanelConfigured() bool {
	return IsBTPanelConfiguredWithContext(context.Background())
}

// IsBTPanelConfiguredWithContext 从 context 快照判断宝塔面板是否已配置。
func IsBTPanelConfiguredWithContext(ctx context.Context) bool {
	configuration := shared.ConfigurationFromContext(ctx)
	return configuration != nil && configuration.SSL != nil && configuration.SSL.BTPanel != nil &&
		strings.TrimSpace(configuration.SSL.BTPanel.URL) != "" && strings.TrimSpace(configuration.SSL.BTPanel.APIKey) != ""
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
	//lint:ignore SA1019 保留历史网络错误的重试分类语义。
	return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary())
}

// getBTPanelConfig 读取并校验当前操作快照中的宝塔面板配置。
func getBTPanelConfig(ctx context.Context) (string, string, bool, error) {
	configuration := shared.ConfigurationFromContext(ctx)
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
