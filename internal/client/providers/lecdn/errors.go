package lecdn

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

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
