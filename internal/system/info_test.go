package system_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/orange-juzipi/cert-deploy/internal/system"
)

func TestGetSystemInfo(t *testing.T) {
	systemInfo, err := system.GetSystemInfo()
	if err != nil {
		t.Fatalf("获取系统信息失败: %v", err)
	}

	jsonData, err := json.MarshalIndent(systemInfo, "", "  ")
	if err != nil {
		t.Fatalf("序列化系统信息失败: %v", err)
	}

	t.Log(string(jsonData))
}

func TestGetClientID(t *testing.T) {
	clientID, err := system.GetUniqueClientID(context.Background())
	if err != nil {
		t.Fatalf("获取客户端 ID2失败: %v", err)
	}
	t.Log(clientID)
}
