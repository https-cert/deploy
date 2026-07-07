package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckAccessKeyRejectsTemplate 验证模板 accessKey 会被诊断为失败。
func TestCheckAccessKeyRejectsTemplate(t *testing.T) {
	result := checkAccessKey("your_access_key_here")
	if result.OK {
		t.Fatalf("模板 accessKey 应诊断为失败: %+v", result)
	}
}

// TestCheckAccessKeyMasksSecret 验证 accessKey 输出会脱敏。
func TestCheckAccessKeyMasksSecret(t *testing.T) {
	result := checkAccessKey("1234567890abcdef")
	if !result.OK {
		t.Fatalf("有效 accessKey 应诊断为成功: %+v", result)
	}
	if strings.Contains(result.Message, "1234567890abcdef") {
		t.Fatalf("诊断信息不应包含完整 accessKey: %s", result.Message)
	}
	if result.Message != "1234********cdef" {
		t.Fatalf("脱敏结果不符合预期: %s", result.Message)
	}
}

// TestCheckDeployDirDoesNotCreateMissingTarget 验证目录探测不会创建缺失的目标目录。
func TestCheckDeployDirDoesNotCreateMissingTarget(t *testing.T) {
	parentDir := t.TempDir()
	targetDir := filepath.Join(parentDir, "missing", "target")

	result := checkDeployDir("测试目录", targetDir)
	if !result.OK {
		t.Fatalf("父目录可写时应诊断为成功: %+v", result)
	}
	if _, err := os.Stat(filepath.Join(parentDir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("诊断不应创建缺失目录，stat err=%v", err)
	}
}

// TestCheckDeployServerURLRejectsInvalidScheme 验证 deploy 服务地址协议校验。
func TestCheckDeployServerURLRejectsInvalidScheme(t *testing.T) {
	result := checkDeployServerURL("ftp://example.com/deploy")
	if result.OK {
		t.Fatalf("不支持的协议应诊断为失败: %+v", result)
	}
}

// TestWriteDoctorJSONResults 验证 JSON 输出包含稳定的结果结构。
func TestWriteDoctorJSONResults(t *testing.T) {
	var buffer bytes.Buffer
	results := []doctorResult{
		okDoctor("配置文件", "已加载"),
		failDoctor("AccessKey", "未配置"),
	}

	writeDoctorResults(&buffer, &doctorOptions{json: true}, results)

	var report doctorReport
	if err := json.Unmarshal(buffer.Bytes(), &report); err != nil {
		t.Fatalf("JSON 输出无法解析: %v\n%s", err, buffer.String())
	}
	if report.OK {
		t.Fatalf("存在失败项时 report.OK 应为 false: %+v", report)
	}
	if len(report.Results) != 2 {
		t.Fatalf("结果数量不符合预期: %+v", report)
	}
	if report.Results[1].Status != "FAIL" || report.Results[1].Name != "AccessKey" {
		t.Fatalf("失败项结构不符合预期: %+v", report.Results[1])
	}
}
