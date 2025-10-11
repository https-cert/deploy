//go:build linux
// +build linux

package system

// getLinuxStableHardwareID 获取Linux稳定的硬件ID
func getLinuxStableHardwareID() string {
	// 1. 优先使用machine-id（最稳定）
	if machineID := readFileContent("/etc/machine-id"); machineID != "" {
		return "mid:" + machineID
	}

	// 2. 尝试读取dbus machine-id
	if dbusID := readFileContent("/var/lib/dbus/machine-id"); dbusID != "" {
		return "dbus:" + dbusID
	}

	// 3. 尝试读取DMI product_uuid（物理机和云主机）
	if uuid := readFileContent("/sys/class/dmi/id/product_uuid"); uuid != "" && !isDummyUUID(uuid) {
		return "dmi:" + uuid
	}

	// 4. 尝试读取主板序列号
	if serial := readFileContent("/sys/class/dmi/id/board_serial"); serial != "" && !isDummyUUID(serial) {
		return "board:" + serial
	}

	// 5. 使用第一个稳定的MAC地址
	if mac := getFirstStableMAC(); mac != "" {
		return "mac:" + mac
	}

	// 6. 最后使用基于系统信息的稳定ID
	return "sys:" + generateSystemBasedID()
}

// getMacStableHardwareID Linux 平台的占位函数
func getMacStableHardwareID() string {
	return ""
}
