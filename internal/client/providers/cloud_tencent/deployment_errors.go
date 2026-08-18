package cloud_tencent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
	tencenterrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentyun/cos-go-sdk-v5"
)

// newTencentDeploymentError 将 SDK、网络和 context 错误转换为统一的重试语义。
func newTencentDeploymentError(action string, err error) error {
	if err == nil {
		return nil
	}
	var deploymentError *providers.DeploymentError
	if errors.As(err, &deploymentError) {
		return err
	}

	requestID := ""
	retryable := isRetryableTransportError(err)
	message := fmt.Sprintf("腾讯云%s失败", action)
	var sdkError *tencenterrors.TencentCloudSDKError
	if errors.As(err, &sdkError) {
		code := strings.TrimSpace(sdkError.GetCode())
		requestID = strings.TrimSpace(sdkError.GetRequestId())
		retryable = isRetryableTencentCode(code)
		if code != "" {
			message = fmt.Sprintf("腾讯云%s失败(code=%s)", action, code)
		}
	}
	return providers.NewDeploymentError(message, retryable, requestID, err)
}

// newCOSDeploymentError 将 COS SDK 错误转换为统一的重试语义和请求 ID。
func newCOSDeploymentError(action string, err error) error {
	if err == nil {
		return nil
	}
	requestID := ""
	retryable := isRetryableTransportError(err)
	message := fmt.Sprintf("腾讯云%s失败", action)
	var responseError *cos.ErrorResponse
	if errors.As(err, &responseError) {
		requestID = strings.TrimSpace(responseError.RequestID)
		statusCode := 0
		if responseError.Response != nil {
			statusCode = responseError.Response.StatusCode
			if requestID == "" {
				requestID = strings.TrimSpace(responseError.Response.Header.Get("X-Cos-Request-Id"))
			}
		}
		retryable = isRetryableHTTPStatus(statusCode)
		code := strings.TrimSpace(responseError.Code)
		if code != "" {
			message = fmt.Sprintf("腾讯云%s失败(code=%s)", action, code)
		}
	}
	return providers.NewDeploymentError(message, retryable, requestID, err)
}

// isRetryableTencentCode 判断腾讯云 API 错误码是否适合由任务队列重试。
func isRetryableTencentCode(code string) bool {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if strings.HasPrefix(normalized, "internalerror") ||
		strings.HasPrefix(normalized, "requestlimitexceeded") ||
		strings.HasPrefix(normalized, "limitexceeded") {
		return true
	}
	return strings.Contains(normalized, "inprogress") ||
		strings.Contains(normalized, "toooften") ||
		strings.Contains(normalized, "timeout") ||
		strings.Contains(normalized, "temporarilyunavailable")
}

// isRetryableTransportError 判断 context deadline 或临时网络错误是否适合重试。
func isRetryableTransportError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

// isRetryableHTTPStatus 判断 COS HTTP 状态码是否表示临时失败。
func isRetryableHTTPStatus(statusCode int) bool {
	return statusCode == http.StatusRequestTimeout ||
		statusCode == http.StatusConflict ||
		statusCode == http.StatusTooManyRequests ||
		statusCode >= http.StatusInternalServerError
}

// cosRequestID 从 COS 成功响应头提取请求 ID。
func cosRequestID(response *cos.Response) string {
	if response == nil || response.Response == nil {
		return ""
	}
	return strings.TrimSpace(response.Header.Get("X-Cos-Request-Id"))
}
