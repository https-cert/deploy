package aliyun

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/https-cert/deploy/internal/client/providers"
)

// deploymentCertificateName 生成稳定、无资源标识的上传证书名称，用于 CDN/DCDN 的回读匹配。
func deploymentCertificateName(certificate providers.CertificateMaterial) string {
	sum := sha256.Sum256([]byte(certificate.CertificatePEM))
	return fmt.Sprintf("anssl-%x", sum[:8])
}

// mapString 从大小写不敏感的 map 中读取一个可转换为字符串的字段。
func mapString(data map[string]any, key string) string {
	value, found := getMapValue(data, key)
	if !found {
		return ""
	}
	return strings.TrimSpace(anyToString(value))
}

// getMapValue 以大小写不敏感的方式读取 map 字段。
func getMapValue(data map[string]any, key string) (any, bool) {
	for actualKey, value := range data {
		if strings.EqualFold(actualKey, key) {
			return value, true
		}
	}
	return nil, false
}

// mapSlice 将一个 map 字段归一化为 map 列表，兼容单项与数组两种响应形态。
func mapSlice(data map[string]any, key string) []map[string]any {
	value, found := getMapValue(data, key)
	if !found {
		return nil
	}
	normalized := normalizeValue(value)
	switch typedValue := normalized.(type) {
	case []any:
		result := make([]map[string]any, 0, len(typedValue))
		for _, item := range typedValue {
			if itemMap, ok := normalizeToMap(item); ok {
				result = append(result, itemMap)
			}
		}
		return result
	case map[string]any:
		return []map[string]any{typedValue}
	default:
		return nil
	}
}

// responseRequestID 从 OpenAPI 原始响应中提取请求编号。
func responseRequestID(data map[string]any) string {
	for _, key := range []string{"RequestId", "RequestID", "requestId", "requestID"} {
		if value, found := getMapValue(data, key); found {
			if requestID := strings.TrimSpace(anyToString(value)); requestID != "" {
				return requestID
			}
		}
	}
	if body, found := getMapValue(data, "body"); found {
		if bodyMap, ok := normalizeToMap(body); ok {
			return responseRequestID(bodyMap)
		}
	}
	return ""
}

// responseHasApplyingStatus 递归判断响应中是否已进入可接受的应用状态。
func responseHasApplyingStatus(value any) bool {
	normalized := normalizeValue(value)
	switch typedValue := normalized.(type) {
	case map[string]any:
		for key, child := range typedValue {
			if strings.EqualFold(key, "Status") && isApplyingStatus(anyToString(child)) {
				return true
			}
			if responseHasApplyingStatus(child) {
				return true
			}
		}
	case []any:
		for _, child := range typedValue {
			if responseHasApplyingStatus(child) {
				return true
			}
		}
	}
	return false
}

// isApplyingStatus 判断控制面状态是否表示写入已接受但仍在异步应用。
func isApplyingStatus(values ...string) bool {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "applying", "processing", "configuring", "associating", "dissociating", "diassociating", "disassociating":
			return true
		}
	}
	return false
}

// firstNonEmpty 返回第一个非空字符串，用于优先保留写操作请求编号。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
