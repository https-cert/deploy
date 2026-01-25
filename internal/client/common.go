package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// 共享常量
const (
	downloadTimeout      = 30 * time.Second
	minReconnectDelay    = 1 * time.Second  // 最小重连延迟
	maxReconnectDelay    = 30 * time.Second // 最大重连延迟
	fastReconnectAttempt = 3                // 快速重连尝试次数
	heartbeatInterval    = 10 * time.Second // 应用层心跳间隔
	// tcpKeepaliveInterval = 15 * time.Second // TCP keepalive 间隔
)

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
	// 使用 net/url 安全地构建下载 URL
	u, err := url.Parse(downloadURL)
	if err != nil {
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

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
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
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return err
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
