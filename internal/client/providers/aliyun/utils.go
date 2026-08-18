package aliyun

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// normalizeToMap 将任意值规范化为 map[string]any
func normalizeToMap(value any) (map[string]any, bool) {
	normalized := normalizeValue(value)
	result, ok := normalized.(map[string]any)
	return result, ok
}

// normalizeValue 将复杂嵌套结构归一化为可遍历的基础类型
func normalizeValue(value any) any {
	if value == nil {
		return nil
	}

	typedValue := reflect.ValueOf(value)
	for typedValue.Kind() == reflect.Pointer || typedValue.Kind() == reflect.Interface {
		if typedValue.IsNil() {
			return nil
		}
		typedValue = typedValue.Elem()
	}

	switch typedValue.Kind() {
	case reflect.Map:
		result := make(map[string]any, typedValue.Len())
		iter := typedValue.MapRange()
		for iter.Next() {
			key := fmt.Sprintf("%v", iter.Key().Interface())
			result[key] = normalizeValue(iter.Value().Interface())
		}
		return result
	case reflect.Slice, reflect.Array:
		if typedValue.Type().Elem().Kind() == reflect.Uint8 {
			return normalizeJSONStringOrBytes(typedValue.Bytes())
		}
		result := make([]any, typedValue.Len())
		for index := 0; index < typedValue.Len(); index++ {
			result[index] = normalizeValue(typedValue.Index(index).Interface())
		}
		return result
	case reflect.String:
		return normalizeJSONStringOrBytes([]byte(typedValue.String()))
	default:
		return typedValue.Interface()
	}
}

// normalizeJSONStringOrBytes 尝试将 JSON 字符串或字节解析为结构化对象
func normalizeJSONStringOrBytes(raw []byte) any {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		return trimmed
	}

	var parsed any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		return trimmed
	}

	normalized := normalizeValue(parsed)
	if normalized == nil {
		return trimmed
	}
	return normalized
}

// extractCertFingerprintAndSerial 从 PEM 证书提取 SHA256 指纹与序列号
func extractCertFingerprintAndSerial(certPEM string) (string, string, error) {
	rest := []byte(certPEM)
	for {
		block, remain := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remain
		if !strings.EqualFold(strings.TrimSpace(block.Type), "CERTIFICATE") {
			continue
		}

		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", "", fmt.Errorf("解析证书失败: %w", err)
		}

		fingerprintSum := sha256.Sum256(parsedCert.Raw)
		fingerprint := fmt.Sprintf("%x", fingerprintSum[:])
		serial := strings.ToLower(parsedCert.SerialNumber.Text(16))
		return fingerprint, serial, nil
	}

	return "", "", fmt.Errorf("证书内容中未找到 CERTIFICATE 块")
}

// normalizeComparableToken 归一化用于比较的文本（小写、去符号、去前导0）
func normalizeComparableToken(raw string) string {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return ""
	}

	var builder strings.Builder
	for _, char := range trimmed {
		if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
			builder.WriteRune(char)
		}
	}

	normalized := strings.TrimLeft(builder.String(), "0")
	if normalized == "" {
		return "0"
	}
	return normalized
}

// anyToString 将任意类型转换为字符串
func anyToString(value any) string {
	switch typedValue := value.(type) {
	case nil:
		return ""
	case string:
		return typedValue
	case int:
		return strconv.Itoa(typedValue)
	case int8:
		return strconv.FormatInt(int64(typedValue), 10)
	case int16:
		return strconv.FormatInt(int64(typedValue), 10)
	case int32:
		return strconv.FormatInt(int64(typedValue), 10)
	case int64:
		return strconv.FormatInt(typedValue, 10)
	case uint:
		return strconv.FormatUint(uint64(typedValue), 10)
	case uint8:
		return strconv.FormatUint(uint64(typedValue), 10)
	case uint16:
		return strconv.FormatUint(uint64(typedValue), 10)
	case uint32:
		return strconv.FormatUint(uint64(typedValue), 10)
	case uint64:
		return strconv.FormatUint(typedValue, 10)
	case float32:
		return strconv.FormatFloat(float64(typedValue), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(typedValue, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", typedValue)
	}
}

// anyToInt64 将任意类型尽可能转换为 int64
func anyToInt64(value any) (int64, bool) {
	switch typedValue := value.(type) {
	case nil:
		return 0, false
	case int:
		return int64(typedValue), true
	case int8:
		return int64(typedValue), true
	case int16:
		return int64(typedValue), true
	case int32:
		return int64(typedValue), true
	case int64:
		return typedValue, true
	case uint:
		return int64(typedValue), true
	case uint8:
		return int64(typedValue), true
	case uint16:
		return int64(typedValue), true
	case uint32:
		return int64(typedValue), true
	case uint64:
		if typedValue > uint64(^uint64(0)>>1) {
			return 0, false
		}
		return int64(typedValue), true
	case float32:
		return int64(typedValue), true
	case float64:
		return int64(typedValue), true
	case string:
		trimmed := strings.TrimSpace(typedValue)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
