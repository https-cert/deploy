package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/https-cert/deploy/internal/config"
)

// 共享常量
const (
	downloadTimeout      = 30 * time.Second
	maxDownloadSize      = int64(64 << 20)  // 证书归档最大下载大小
	minReconnectDelay    = 1 * time.Second  // 最小重连延迟
	maxReconnectDelay    = 30 * time.Second // 最大重连延迟
	fastReconnectAttempt = 3                // 快速重连尝试次数
	heartbeatInterval    = 10 * time.Second // 应用层心跳间隔
	maxWSMessageSize     = int64(16 << 20)  // WebSocket 单条消息最大 16 MiB
	maxConcurrentOps     = 8                // 客户端最多并发执行的业务任务数
	// tcpKeepaliveInterval = 15 * time.Second // TCP keepalive 间隔
)

// waitForContext waits for a duration and returns false when the context is canceled first.
func waitForContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// 共享变量
var (
	isConnected atomic.Bool
)

// ClientInterface 客户端接口，用于复用业务逻辑
type ClientInterface interface {
	GetClientID() string
	GetAccessKey() string
	GetContext() context.Context
	GetHTTPClient() *http.Client
	downloadFile(downloadURL, filePath string) error
}

// DownloadFile 公共的文件下载函数，可被所有客户端复用
func DownloadFile(ctx context.Context, httpClient *http.Client, accessKey, downloadURL, filePath string) error {
	u, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("解析下载 URL 失败: %w", err)
	}
	if err := validateDownloadURL(u); err != nil {
		return err
	}

	// 添加 accessKey 参数
	query := u.Query()
	query.Set("accessKey", accessKey)
	u.RawQuery = query.Encode()

	// 创建带超时的请求
	reqCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", u.String(), nil)
	if err != nil {
		return err
	}

	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clientCopy := *httpClient
	originalRedirect := clientCopy.CheckRedirect
	clientCopy.CheckRedirect = func(nextReq *http.Request, via []*http.Request) error {
		if !sameDownloadOrigin(req.URL, nextReq.URL) {
			return fmt.Errorf("拒绝跨主机下载重定向")
		}
		if originalRedirect != nil {
			return originalRedirect(nextReq, via)
		}
		return nil
	}

	resp, err := clientCopy.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}
	if err := ensureDownloadContentType(resp); err != nil {
		return err
	}
	if resp.ContentLength > maxDownloadSize {
		return fmt.Errorf("下载文件超过大小限制")
	}

	// 确保目标目录存在
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}

	// 创建临时文件，确保部分下载不会污染最终文件
	tmpFile, err := os.CreateTemp(filepath.Dir(filePath), ".anssl-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	completed := false
	defer func() {
		tmpFile.Close()
		if !completed {
			os.Remove(tmpPath)
		}
	}()

	// 复制数据到临时文件
	written, err := io.Copy(tmpFile, io.LimitReader(resp.Body, maxDownloadSize+1))
	if err != nil {
		return err
	}
	if written > maxDownloadSize {
		return fmt.Errorf("下载文件超过大小限制")
	}

	// 确保数据刷盘
	if err := tmpFile.Sync(); err != nil {
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Windows 下如果目标文件存在需要先删除
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return err
	}

	completed = true
	return nil
}

// validateDownloadURL enforces the supported download schemes and local HTTP policy.
func validateDownloadURL(u *url.URL) error {
	if u == nil || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("下载 URL 必须包含合法主机且不能包含用户凭据")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		cfg := config.GetConfig()
		if cfg != nil && cfg.Server != nil && cfg.Server.Env == "local" && isLoopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("生产环境只允许 HTTPS 下载 URL")
	default:
		return fmt.Errorf("不支持的下载 URL 协议: %s", u.Scheme)
	}
}

// isLoopbackHost reports whether a hostname identifies the local machine.
func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameDownloadOrigin prevents credentials in the query string crossing download hosts.
func sameDownloadOrigin(first, next *url.URL) bool {
	if first == nil || next == nil {
		return false
	}
	return strings.EqualFold(first.Scheme, next.Scheme) && strings.EqualFold(first.Host, next.Host)
}

func ensureDownloadContentType(resp *http.Response) error {
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType == "" {
		return nil
	}

	invalidTypes := []string{
		"application/json",
		"text/html",
		"text/plain",
	}
	for _, invalidType := range invalidTypes {
		if strings.Contains(contentType, invalidType) {
			preview, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(preview))
			return fmt.Errorf("下载内容不是证书压缩包: content-type=%s body=%q", contentType, string(preview))
		}
	}

	return nil
}
