package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const cacheRelPath = "cert-deploy/client-id"

// SystemInfo 系统信息结构
type SystemInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// GetSystemInfo 获取系统信息
func GetSystemInfo() (*SystemInfo, error) {
	info := &SystemInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	// 获取主机名
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	}

	// 获取本机IP
	if ip := getLocalIP(); ip != "" {
		info.IP = ip
	}

	return info, nil
}

// ValidateSystemRequirements 验证系统要求
func ValidateSystemRequirements() error {
	// 检查nginx是否安装
	if _, err := exec.LookPath("nginx"); err != nil {
		return fmt.Errorf("nginx未安装或不在PATH中")
	}

	// 检查是否有权限执行nginx命令
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-t")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("无法执行nginx命令，请检查权限: %w", err)
	}

	return nil
}

// GetUniqueClientID 获取唯一客户端ID
// 确保同一台机器每次启动都获得相同的ID
func GetUniqueClientID(ctx context.Context) (string, error) {
	// 先尝试读取缓存
	if id := readCachedID(); id != "" {
		return id, nil
	}

	// 生成基于稳定硬件信息的唯一ID
	hwid := getStableHardwareID()

	// 组合系统信息和硬件ID
	sys, _ := GetSystemInfo()
	combined := fmt.Sprintf("%s|%s|%s|%s",
		sys.OS, sys.Arch, sys.Hostname, hwid)

	// 使用SHA256生成固定长度的哈希
	sum := sha256.Sum256([]byte(combined))
	id := hex.EncodeToString(sum[:])

	// 缓存结果，确保下次启动时使用相同的ID
	_ = writeCachedID(id)
	return id, nil
}

// getStableHardwareID 获取稳定的硬件ID，确保同一台机器每次启动都相同
func getStableHardwareID() string {
	switch runtime.GOOS {
	case "linux":
		return getLinuxStableHardwareID()
	case "darwin":
		return getMacStableHardwareID()
	default:
		// 其他平台使用MAC地址
		if mac := getFirstStableMAC(); mac != "" {
			return "mac:" + mac
		}
		// 如果连MAC地址都没有，生成一个基于系统信息的稳定ID
		return "sys:" + generateSystemBasedID()
	}
}

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

// getMacStableHardwareID 获取macOS稳定的硬件ID
func getMacStableHardwareID() string {
	// 1. 优先使用硬件UUID（最稳定）
	if uuid := getMacHardwareUUID(); uuid != "" && !isDummyUUID(uuid) {
		return "hw:" + uuid
	}

	// 2. 尝试获取序列号
	if serial := getMacSerialNumber(); serial != "" {
		return "serial:" + serial
	}

	// 3. 使用第一个稳定的MAC地址
	if mac := getFirstStableMAC(); mac != "" {
		return "mac:" + mac
	}

	// 4. 最后使用基于系统信息的稳定ID
	return "sys:" + generateSystemBasedID()
}

// getMacHardwareUUID 获取macOS硬件UUID
func getMacHardwareUUID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "system_profiler", "SPHardwareDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// 简单的JSON解析，查找hardware_uuid
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "hardware_uuid") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				uuid := strings.Trim(strings.TrimSpace(parts[1]), "\",")
				return uuid
			}
		}
	}
	return ""
}

// getMacSerialNumber 获取macOS序列号
func getMacSerialNumber() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "system_profiler", "SPHardwareDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// 简单的JSON解析，查找serial_number
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "serial_number") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				serial := strings.Trim(strings.TrimSpace(parts[1]), "\",")
				return serial
			}
		}
	}
	return ""
}

// getFirstStableMAC 获取第一个稳定的硬件MAC地址
func getFirstStableMAC() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	// 按优先级排序的网络接口名称
	preferredInterfaces := []string{"en0", "eth0", "en1", "eth1", "wlan0", "wifi0"}

	// 首先尝试预定义的接口
	for _, preferredName := range preferredInterfaces {
		for _, iface := range interfaces {
			if iface.Name == preferredName &&
				iface.Flags&net.FlagUp != 0 &&
				len(iface.HardwareAddr) == 6 &&
				!isZeroMAC(iface.HardwareAddr) {
				return iface.HardwareAddr.String()
			}
		}
	}

	// 如果没有找到预定义接口，使用第一个有效的物理接口
	for _, iface := range interfaces {
		// 跳过虚拟接口、回环接口和未启用的接口
		if iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagUp == 0 ||
			isVirtualInterface(iface.Name) {
			continue
		}

		// 检查MAC地址是否有效
		if len(iface.HardwareAddr) == 6 && !isZeroMAC(iface.HardwareAddr) {
			return iface.HardwareAddr.String()
		}
	}
	return ""
}

// isVirtualInterface 检查是否为虚拟网络接口
func isVirtualInterface(name string) bool {
	virtualPrefixes := []string{
		"docker", "veth", "br-", "virbr", "vmnet",
		"vboxnet", "tun", "tap", "ppp", "lo",
	}

	for _, prefix := range virtualPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// isZeroMAC 检查MAC地址是否为零地址
func isZeroMAC(mac net.HardwareAddr) bool {
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
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

// generateSystemBasedID 生成基于系统信息的稳定ID
func generateSystemBasedID() string {
	sys, _ := GetSystemInfo()
	// 使用系统信息生成稳定的哈希
	combined := fmt.Sprintf("%s|%s|%s|%s", sys.OS, sys.Arch, sys.Hostname, sys.IP)
	sum := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(sum[:8]) // 只取前8个字节，足够唯一
}

// getLocalIP 获取本机IP地址
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// readFileContent 读取文件内容
func readFileContent(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// 缓存相关函数
func cachePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, cacheRelPath), nil
}

func readCachedID() string {
	p, err := cachePath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(trimNL(b))
}

func writeCachedID(id string) error {
	p, err := cachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, append([]byte(id), '\n'), 0o600)
}

func trimNL(b []byte) []byte {
	if n := len(b); n > 0 && (b[n-1] == '\n' || b[n-1] == '\r') {
		return b[:n-1]
	}
	return b
}
