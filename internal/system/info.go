package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

const cacheRelPath = "anssl/client-id"

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

	// 获取IP地址（优先公网IP，失败则使用内网IP）
	if publicIP := getPublicIP(); publicIP != "" {
		info.IP = publicIP
	} else if localIP := getLocalIP(); localIP != "" {
		info.IP = localIP
	}

	return info, nil
}

// ValidateSystemRequirements 验证系统要求
func ValidateSystemRequirements() error {
	// 检查nginx是否安装（可选）
	if _, err := exec.LookPath("nginx"); err != nil {
		fmt.Println("警告: nginx未安装或不在PATH中，将跳过nginx相关操作")
		return nil
	}

	// 检查是否有权限执行nginx命令
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nginx", "-t")
	if err := cmd.Run(); err != nil {
		fmt.Printf("警告: 无法执行nginx命令，请检查权限: %v\n", err)
		return nil
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
	if err := writeCachedID(id); err != nil {
		// 缓存失败不影响主流程，仅记录错误
		fmt.Fprintf(os.Stderr, "警告: 缓存客户端ID失败: %v\n", err)
	}

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

// generateSystemBasedID 生成基于系统信息的稳定ID
func generateSystemBasedID() string {
	sys, _ := GetSystemInfo()
	// 使用系统信息生成稳定的哈希
	combined := fmt.Sprintf("%s|%s|%s|%s", sys.OS, sys.Arch, sys.Hostname, sys.IP)
	sum := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(sum[:8]) // 只取前8个字节，足够唯一
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
