package aliyun

import "strings"

// nestedMapSlice 从若干常见容器路径中读取记录数组。
func nestedMapSlice(body map[string]any, keys ...string) []map[string]any {
	for _, key := range keys {
		if records := mapSlice(body, key); len(records) > 0 {
			return records
		}
		value, found := getMapValue(body, key)
		if !found {
			continue
		}
		container, ok := normalizeToMap(value)
		if !ok {
			continue
		}
		for _, nestedKey := range keys {
			if records := mapSlice(container, nestedKey); len(records) > 0 {
				return records
			}
		}
	}
	return nil
}

// firstMapString 返回首个非空候选字段。
func firstMapString(data map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(mapString(data, key)); value != "" {
			return value
		}
	}
	return ""
}

// firstMapInt64 返回首个可解析的整数候选字段。
func firstMapInt64(data map[string]any, keys ...string) (int64, bool) {
	for _, key := range keys {
		if value, ok := mapInt64(data, key); ok {
			return value, true
		}
	}
	return 0, false
}

// isAliyunRunningStatus 将常见云产品状态归一为可部署判断。
func isAliyunRunningStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "online", "running", "active", "success", "enabled", "configured", "normal", "available", "stopped":
		return true
	default:
		return false
	}
}
