//go:build darwin
// +build darwin

package system

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// macHardwareInfo 缓存 macOS 硬件信息
type macHardwareInfo struct {
	UUID   string
	Serial string
	once   sync.Once
}

var macInfo macHardwareInfo

// getMacStableHardwareID 获取macOS稳定的硬件ID
func getMacStableHardwareID() string {
	// 一次性获取所有硬件信息
	macInfo.once.Do(func() {
		macInfo.UUID, macInfo.Serial = getMacHardwareInfo()
	})

	// 1. 优先使用硬件UUID（最稳定）
	if macInfo.UUID != "" && !isDummyUUID(macInfo.UUID) {
		return "hw:" + macInfo.UUID
	}

	// 2. 尝试使用序列号
	if macInfo.Serial != "" {
		return "serial:" + macInfo.Serial
	}

	// 3. 使用第一个稳定的MAC地址
	if mac := getFirstStableMAC(); mac != "" {
		return "mac:" + mac
	}

	// 4. 最后使用基于系统信息的稳定ID
	return "sys:" + generateSystemBasedID()
}

// getMacHardwareInfo 一次性获取macOS的UUID和序列号（优化：合并重复调用）
func getMacHardwareInfo() (uuid, serial string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "system_profiler", "SPHardwareDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return "", ""
	}

	// 简单的JSON解析，查找hardware_uuid和serial_number
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// 查找 hardware_uuid
		if strings.Contains(line, "hardware_uuid") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				uuid = strings.Trim(strings.TrimSpace(parts[1]), "\",")
			}
		}
		// 查找 serial_number
		if strings.Contains(line, "serial_number") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				serial = strings.Trim(strings.TrimSpace(parts[1]), "\",")
			}
		}

		// 如果都找到了，提前退出
		if uuid != "" && serial != "" {
			break
		}
	}

	return uuid, serial
}

// getLinuxStableHardwareID Darwin 平台的占位函数
func getLinuxStableHardwareID() string {
	return ""
}
