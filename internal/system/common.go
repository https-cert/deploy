package system

import (
	"os"
	"strings"
)

// readFileContent 读取文件内容
func readFileContent(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// isDummyUUID 检查是否为虚拟UUID
func isDummyUUID(s string) bool {
	dummyUUIDs := []string{
		"00000000-0000-0000-0000-000000000000",
		"ffffffff-ffff-ffff-ffff-ffffffffffff",
		"03000200-0400-0500-0006-000700080009",
		"00000000-0000-0000-0000-000000000001",
		"Not Available",
		"Not Specified",
		"System Product Name",
	}

	s = strings.TrimSpace(s)
	for _, dummy := range dummyUUIDs {
		if strings.EqualFold(s, dummy) {
			return true
		}
	}
	return false
}
