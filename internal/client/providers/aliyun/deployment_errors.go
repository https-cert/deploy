package aliyun

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"reflect"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

type safeAliyunCause struct {
	// Operation 是不含资源定位信息的本地操作名称。
	Operation string
	// Cause 是底层错误，仅用于错误链判断。
	Cause error
}

// Error 返回不会回显证书、私钥、Bucket、Site ID 或 endpoint 的错误文本。
func (e *safeAliyunCause) Error() string {
	if e == nil || strings.TrimSpace(e.Operation) == "" {
		return "阿里云资源操作失败"
	}
	return "阿里云" + e.Operation + "失败"
}

// Unwrap 保留原始错误链，方便上层识别 context 和网络错误。
func (e *safeAliyunCause) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// newSafeAliyunCause 构建可安全记录的底层错误包装。
func newSafeAliyunCause(operation string, cause error) error {
	return &safeAliyunCause{Operation: operation, Cause: cause}
}

// newAliyunDeploymentError 根据 SDK、HTTP 和网络错误生成统一的云部署错误。
func newAliyunDeploymentError(operation string, err error) error {
	return newAliyunDeploymentErrorWithRequestID(operation, "", err)
}

// newAliyunDeploymentErrorWithRequestID 在已有写请求编号时保留该编号，避免回读错误覆盖它。
func newAliyunDeploymentErrorWithRequestID(operation, fallbackRequestID string, err error) error {
	retryable, requestID := classifyAliyunError(err)
	return providers.NewDeploymentError(
		"阿里云"+operation+"失败",
		retryable,
		firstNonEmpty(fallbackRequestID, requestID),
		newSafeAliyunCause(operation, err),
	)
}

// classifyAliyunError 识别可重试的网络、超时、限流和服务端临时错误。
func classifyAliyunError(err error) (retryable bool, requestID string) {
	if err == nil {
		return false, ""
	}
	if errors.Is(err, context.Canceled) {
		return false, ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true, ""
	}

	statusCode, code, requestID := aliyunErrorMetadata(err)
	if statusCode == 429 || statusCode >= 500 {
		return true, requestID
	}
	lowerCode := strings.ToLower(code)
	for _, token := range []string{"throttl", "limit", "timeout", "internal", "serviceunavailable", "systembusy", "temporar"} {
		if strings.Contains(lowerCode, token) {
			return true, requestID
		}
	}

	var networkError net.Error
	if errors.As(err, &networkError) {
		return true, requestID
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return true, requestID
	}
	return false, requestID
}

// aliyunErrorMetadata 从 SDK 或本地适配器错误中读取状态码、错误码和请求编号。
func aliyunErrorMetadata(err error) (statusCode int, code, requestID string) {
	var statusCodeError interface{ GetStatusCode() *int }
	if errors.As(err, &statusCodeError) && statusCodeError.GetStatusCode() != nil {
		statusCode = *statusCodeError.GetStatusCode()
	}
	var codeError interface{ GetCode() *string }
	if errors.As(err, &codeError) && codeError.GetCode() != nil {
		code = strings.TrimSpace(*codeError.GetCode())
	}
	var requestIDError interface{ GetRequestId() *string }
	if errors.As(err, &requestIDError) && requestIDError.GetRequestId() != nil {
		requestID = strings.TrimSpace(*requestIDError.GetRequestId())
	}
	reflectedStatusCode, reflectedCode, reflectedData := reflectedSDKErrorMetadata(err)
	if statusCode == 0 {
		statusCode = reflectedStatusCode
	}
	if code == "" {
		code = reflectedCode
	}
	if requestID == "" {
		requestID = requestIDFromSDKData(reflectedData)
	}
	return statusCode, code, requestID
}

// reflectedSDKErrorMetadata 读取 Darabonba SDKError 的导出字段，避免额外绑定 tea 的具体版本。
func reflectedSDKErrorMetadata(err error) (statusCode int, code, data string) {
	for current := err; current != nil; current = errors.Unwrap(current) {
		value := reflect.ValueOf(current)
		for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
			if value.IsNil() {
				break
			}
			value = value.Elem()
		}
		if !value.IsValid() || value.Kind() != reflect.Struct {
			continue
		}
		if statusCode == 0 {
			if field := value.FieldByName("StatusCode"); field.IsValid() && field.CanInterface() {
				if parsed, ok := anyToInt64(normalizeValue(field.Interface())); ok {
					statusCode = int(parsed)
				}
			}
		}
		if code == "" {
			if field := value.FieldByName("Code"); field.IsValid() && field.CanInterface() {
				code = strings.TrimSpace(anyToString(normalizeValue(field.Interface())))
			}
		}
		if data == "" {
			if field := value.FieldByName("Data"); field.IsValid() && field.CanInterface() {
				data = reflectedRawString(field)
			}
		}
	}
	return statusCode, code, data
}

// reflectedRawString 解引用 SDK 字段但保留 JSON 字符串原文，避免提前解析后无法提取 request ID。
func reflectedRawString(value reflect.Value) string {
	for value.IsValid() && (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) {
		if value.IsNil() {
			return ""
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return ""
	}
	if value.Kind() == reflect.String {
		return strings.TrimSpace(value.String())
	}
	if value.CanInterface() {
		return strings.TrimSpace(anyToString(normalizeValue(value.Interface())))
	}
	return ""
}

// requestIDFromSDKData 只从 SDK 的 JSON Data 中读取请求编号，不传播其他响应字段。
func requestIDFromSDKData(rawData string) string {
	var data map[string]any
	if err := json.Unmarshal([]byte(rawData), &data); err != nil {
		return ""
	}
	return firstNonEmpty(mapString(data, "RequestId"), mapString(data, "requestId"))
}
