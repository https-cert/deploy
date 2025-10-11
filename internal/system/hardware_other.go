//go:build !linux && !darwin
// +build !linux,!darwin

package system

// getLinuxStableHardwareID 其他平台的占位函数
func getLinuxStableHardwareID() string {
	return ""
}

// getMacStableHardwareID 其他平台的占位函数
func getMacStableHardwareID() string {
	return ""
}
