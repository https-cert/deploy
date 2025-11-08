package system

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/config"
)

// 共享的 HTTP Client，避免重复创建
var publicIPClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 2,
	},
}

// getPublicIP 获取公网IP地址（使用并发请求优化）
func getPublicIP() string {
	// 使用多个服务提供商，并发请求，提高成功率和速度
	services := []string{
		"https://checkip.amazonaws.com",
		"https://ifconfig.me/ip",
		"https://api.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://api.ip.sb/ip",
	}

	// 创建一个通道来接收结果
	resultChan := make(chan string, len(services))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for _, serviceURL := range services {
		serviceURL := serviceURL // 捕获循环变量
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ip := getIPFromService(ctx, serviceURL); ip != "" {
				select {
				case resultChan <- ip:
				case <-ctx.Done():
				}
			}
		}()
	}

	// 启动一个 goroutine 来关闭通道
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 返回第一个成功的结果
	select {
	case ip := <-resultChan:
		if ip != "" {
			return ip
		}
	case <-ctx.Done():
	}

	// 如果所有请求都失败，等待一小段时间看是否有其他结果
	select {
	case ip := <-resultChan:
		if ip != "" {
			return ip
		}
	case <-time.After(1 * time.Second):
	}

	return ""
}

// getIPFromService 从指定服务获取IP地址
func getIPFromService(ctx context.Context, serviceURL string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", serviceURL, nil)
	if err != nil {
		return ""
	}

	// 使用配置的版本号
	req.Header.Set("User-Agent", "cert-deploy-client/"+config.Version)

	resp, err := publicIPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	ip := strings.TrimSpace(string(body))

	// 验证IP地址格式
	if net.ParseIP(ip) != nil {
		return ip
	}

	return ""
}

// getLocalIP 获取本机内网IP地址
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
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
