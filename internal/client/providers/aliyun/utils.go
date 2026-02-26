//go:build !windows

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
	"time"
	"unicode"
)

// buildUniqueESACertificateName 构建用于重名回退的唯一证书名称
func buildUniqueESACertificateName(name, domain string, now time.Time) string {
	baseName := "anssl"
	domainBase := sanitizeESACertificateNameBase(domain)
	if domainBase != "" {
		baseName = domainBase
	}
	remarkBase := sanitizeESACertificateNameBase(name)
	if remarkBase != "" {
		baseName = remarkBase
	}

	baseRunes := []rune(baseName)
	if len(baseRunes) > 12 {
		baseName = string(baseRunes[:12])
	}

	timeSuffix := now.UTC().Format("20060102150405")
	nanoSuffix := now.UTC().Nanosecond() / 1000
	return fmt.Sprintf("%s-%s-%06d", baseName, timeSuffix, nanoSuffix)
}

// sanitizeESACertificateNameBase 清洗证书名称基础字符串，移除非法字符
func sanitizeESACertificateNameBase(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	var builder strings.Builder
	lastDash := false
	for _, char := range trimmed {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '.' || char == '_' || char == '-' {
			builder.WriteRune(char)
			lastDash = false
			continue
		}

		if !lastDash {
			builder.WriteRune('-')
			lastDash = true
		}
	}

	result := strings.Trim(builder.String(), "-_.")
	result = strings.TrimSpace(result)
	return result
}

// parseESAListCertificatesResult 解析 ESA ListCertificates 返回的证书记录列表
func parseESAListCertificatesResult(resp map[string]any) ([]any, error) {
	normalizedResp, ok := normalizeToMap(resp)
	if !ok {
		return nil, fmt.Errorf("ESA ListCertificates 响应格式异常: %T", resp)
	}

	if result, ok := findCertificateRecords(normalizedResp); ok {
		return result, nil
	}

	for _, bodyKey := range []string{"body", "Body"} {
		bodyRaw, ok := normalizedResp[bodyKey]
		if !ok {
			continue
		}

		if result, ok := findCertificateRecords(bodyRaw); ok {
			return result, nil
		}
	}

	if totalCount, hasTotalCount := extractListTotalCount(normalizedResp); hasTotalCount && totalCount == 0 {
		return []any{}, nil
	}

	bodyValue, _ := getCaseInsensitiveValueFromCandidates(normalizedResp, []string{"body", "Body"})
	return nil, fmt.Errorf("ESA ListCertificates 返回缺少可识别证书列表字段，响应键: %s, bodyType=%T, bodyPreview=%s", strings.Join(mapKeys(normalizedResp), ","), bodyValue, previewAnyValue(bodyValue, 300))
}

// extractListTotalCount 从响应结构中提取 TotalCount 字段
func extractListTotalCount(data map[string]any) (int64, bool) {
	if value, ok := getCaseInsensitiveValueFromCandidates(data, []string{"TotalCount", "totalCount"}); ok {
		if totalCount, convertOK := anyToInt64(value); convertOK {
			return totalCount, true
		}
	}

	bodyValue, ok := getCaseInsensitiveValueFromCandidates(data, []string{"body", "Body"})
	if !ok {
		return 0, false
	}

	bodyMap, ok := normalizeToMap(bodyValue)
	if !ok {
		return 0, false
	}

	if value, ok := getCaseInsensitiveValueFromCandidates(bodyMap, []string{"TotalCount", "totalCount"}); ok {
		if totalCount, convertOK := anyToInt64(value); convertOK {
			return totalCount, true
		}
	}

	return 0, false
}

// findCertificateRecords 从任意嵌套结构中递归查找证书记录数组
func findCertificateRecords(value any) ([]any, bool) {
	normalized := normalizeValue(value)
	if normalized == nil {
		return nil, false
	}

	switch typedValue := normalized.(type) {
	case []any:
		if isCertificateRecordArray(typedValue) {
			return typedValue, true
		}
		for _, item := range typedValue {
			if result, ok := findCertificateRecords(item); ok {
				return result, true
			}
		}
		return nil, false
	case map[string]any:
		preferredKeys := []string{
			"Result", "result",
			"Certificates", "certificates",
			"CertificateList", "certificateList",
			"CertList", "certList",
			"Items", "items",
			"List", "list",
			"Data", "data",
		}
		for _, key := range preferredKeys {
			nextValue, ok := typedValue[key]
			if !ok {
				continue
			}
			if result, ok := findCertificateRecords(nextValue); ok {
				return result, true
			}
		}
		for _, nextValue := range typedValue {
			if result, ok := findCertificateRecords(nextValue); ok {
				return result, true
			}
		}
		return nil, false
	default:
		return nil, false
	}
}

// isCertificateRecordArray 判断数组是否为证书记录数组
func isCertificateRecordArray(items []any) bool {
	if len(items) == 0 {
		return false
	}
	for _, item := range items {
		record, ok := normalizeToMap(item)
		if !ok {
			return false
		}
		if !hasAnyCaseInsensitiveKey(record, []string{"Id", "CertId", "CertificateId"}) {
			return false
		}
	}
	return true
}

// hasCaseInsensitiveKey 判断 map 是否包含指定键（忽略大小写）
func hasCaseInsensitiveKey(data map[string]any, expectedKey string) bool {
	_, ok := getCaseInsensitiveValue(data, expectedKey)
	return ok
}

// hasAnyCaseInsensitiveKey 判断 map 是否包含任一候选键（忽略大小写）
func hasAnyCaseInsensitiveKey(data map[string]any, expectedKeys []string) bool {
	for _, expectedKey := range expectedKeys {
		if hasCaseInsensitiveKey(data, expectedKey) {
			return true
		}
	}
	return false
}

// getCaseInsensitiveValue 获取忽略大小写的 map 值
func getCaseInsensitiveValue(data map[string]any, expectedKey string) (any, bool) {
	for key, value := range data {
		if strings.EqualFold(key, expectedKey) {
			return value, true
		}
	}
	return nil, false
}

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

// mapKeys 返回 map 的所有键
func mapKeys(data map[string]any) []string {
	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	return keys
}

// previewAnyValue 返回任意值的截断预览字符串
func previewAnyValue(value any, limit int) string {
	if limit <= 0 {
		limit = 300
	}

	normalized := normalizeValue(value)
	encoded, err := json.Marshal(normalized)
	if err != nil {
		raw := fmt.Sprintf("%v", normalized)
		return limitString(raw, limit)
	}

	return limitString(string(encoded), limit)
}

// limitString 将字符串按指定长度截断
func limitString(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "..."
}

// selectESACertificateIDByName 按证书名称筛选唯一证书 ID
func selectESACertificateIDByName(result []any, name string) (string, error) {
	normalizedName := strings.TrimSpace(name)
	var matchedIDs []string

	for _, item := range result {
		itemMap, ok := item.(map[string]any)
		if !ok {
			continue
		}

		certNameValue, _ := getCaseInsensitiveValueFromCandidates(itemMap, []string{"Name", "CertName", "CertificateName"})
		certName := strings.TrimSpace(anyToString(certNameValue))
		if !strings.EqualFold(certName, normalizedName) {
			continue
		}

		certIDValue, _ := getCaseInsensitiveValueFromCandidates(itemMap, []string{"Id", "CertId", "CertificateId"})
		certID := strings.TrimSpace(anyToString(certIDValue))
		if certID == "" {
			return "", fmt.Errorf("ESA 证书记录缺少 Id: name=%s", certName)
		}

		certTypeValue, _ := getCaseInsensitiveValueFromCandidates(itemMap, []string{"Type", "CertType", "CertificateType"})
		certType := strings.ToLower(strings.TrimSpace(anyToString(certTypeValue)))
		if certType == "free" {
			return "", fmt.Errorf("ESA 同名证书类型为 free，无法通过 Id 更新，请调整证书名称后重试")
		}

		matchedIDs = append(matchedIDs, certID)
	}

	switch len(matchedIDs) {
	case 0:
		return "", fmt.Errorf("ESA 未找到同名证书: name=%s", normalizedName)
	case 1:
		return matchedIDs[0], nil
	default:
		return "", fmt.Errorf("ESA 找到多个同名证书，请手动清理后重试: name=%s, count=%d", normalizedName, len(matchedIDs))
	}
}

// selectESACertificateIDByFingerprintOrSerial 按指纹或序列号匹配证书 ID
func selectESACertificateIDByFingerprintOrSerial(result []any, targetFingerprint, targetSerial string) (string, error) {
	fingerprintMatches := make([]string, 0)
	serialMatches := make([]string, 0)
	normalizedTargetFingerprint := normalizeComparableToken(targetFingerprint)
	normalizedTargetSerial := normalizeComparableToken(targetSerial)

	for _, item := range result {
		itemMap, ok := normalizeToMap(item)
		if !ok {
			continue
		}

		certIDValue, _ := getCaseInsensitiveValueFromCandidates(itemMap, []string{"Id", "CertId", "CertificateId"})
		certID := strings.TrimSpace(anyToString(certIDValue))
		if certID == "" {
			continue
		}

		fingerprintValue, _ := getCaseInsensitiveValueFromCandidates(itemMap, []string{"FingerprintSha256", "Fingerprint", "CertFingerprint"})
		fingerprint := normalizeComparableToken(anyToString(fingerprintValue))
		if normalizedTargetFingerprint != "" && fingerprint != "" && fingerprint == normalizedTargetFingerprint {
			fingerprintMatches = append(fingerprintMatches, certID)
			continue
		}

		serialValue, _ := getCaseInsensitiveValueFromCandidates(itemMap, []string{"SerialNumber", "CertSerialNumber", "Serial"})
		serial := normalizeComparableToken(anyToString(serialValue))
		if normalizedTargetSerial != "" && serial != "" && serial == normalizedTargetSerial {
			serialMatches = append(serialMatches, certID)
		}
	}

	switch len(fingerprintMatches) {
	case 1:
		return fingerprintMatches[0], nil
	case 0:
	default:
		return "", fmt.Errorf("ESA 找到多个指纹匹配证书，请手动处理后重试: count=%d", len(fingerprintMatches))
	}

	switch len(serialMatches) {
	case 1:
		return serialMatches[0], nil
	case 0:
		return "", fmt.Errorf("ESA 未找到与当前证书匹配的记录(指纹/序列号)")
	default:
		return "", fmt.Errorf("ESA 找到多个序列号匹配证书，请手动处理后重试: count=%d", len(serialMatches))
	}
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

// getCaseInsensitiveValueFromCandidates 从多个候选键中获取首个匹配值
func getCaseInsensitiveValueFromCandidates(data map[string]any, expectedKeys []string) (any, bool) {
	for _, expectedKey := range expectedKeys {
		if value, ok := getCaseInsensitiveValue(data, expectedKey); ok {
			return value, true
		}
	}
	return nil, false
}

// isESAErrorCode 判断错误信息中是否包含指定 ESA 错误码
func isESAErrorCode(err error, code string) bool {
	if err == nil || strings.TrimSpace(code) == "" {
		return false
	}

	message := err.Error()
	return strings.Contains(message, "Code: "+code) || strings.Contains(message, "\"Code\":\""+code+"\"")
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
