package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/internal/system"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB/deployPBconnect"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
)

const (
	heartbeatInterval = 5 * time.Second
	downloadTimeout   = 5 * time.Minute
	maxReconnectDelay = 5 * time.Minute
)

var (
	isConnected atomic.Bool
)

type Client struct {
	clientID             string
	serverURL            string
	httpClient           *http.Client
	connectClient        deployPBconnect.DeployServiceClient
	ctx                  context.Context
	accessKey            string
	lastDisconnectLogged atomic.Bool // 记录是否已打印断开连接日志
}

func NewClient(ctx context.Context) (*Client, error) {
	cfg := config.GetConfig()

	// 生成客户端ID
	clientID, err := system.GetUniqueClientID(ctx)
	if err != nil {
		return nil, err
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
	}

	client := &Client{
		clientID:   clientID,
		serverURL:  config.URL,
		httpClient: httpClient,
		ctx:        ctx,
		accessKey:  cfg.Server.AccessKey,
	}

	client.connectClient = deployPBconnect.NewDeployServiceClient(httpClient, config.URL)

	// 注册客户端
	if err := client.register(); err != nil {
		return nil, err
	}

	return client, nil
}

// register 注册客户端到服务器
func (c *Client) register() error {
	// 获取系统信息
	systemInfo, err := system.GetSystemInfo()
	if err != nil {
		return fmt.Errorf("获取系统信息失败: %w", err)
	}

	_, err = c.connectClient.RegisterClient(c.ctx, &deployPB.RegisterClientRequest{
		ClientId:  c.clientID,
		Version:   config.Version,
		AccessKey: c.accessKey,
		SystemInfo: &deployPB.RegisterClientRequest_SystemInfo{
			Os:       systemInfo.OS,
			Arch:     systemInfo.Arch,
			Hostname: systemInfo.Hostname,
			Ip:       systemInfo.IP,
		},
	})
	if err != nil {
		return fmt.Errorf("注册客户端失败: %w", err)
	}

	// 如果连接已断开，则重新建立连接通知
	if !isConnected.Load() {
		go c.StartConnectNotify()
	}

	return nil
}

// StartConnectNotify 启动连接通知
func (c *Client) StartConnectNotify() {
	reconnectDelay := time.Second

	for {
		select {
		case <-c.ctx.Done():
			logger.Info("停止监听通知")
			return
		default:
		}

		stream, err := c.connectClient.Notify(c.ctx, &deployPB.NotifyRequest{
			AccessKey: c.accessKey,
			ClientId:  c.clientID,
		})
		if err != nil {
			// 只在状态变化时打印日志（从连接到断开）
			if !c.lastDisconnectLogged.Load() {
				logger.Error("建立连接通知失败，等待重连", err)
				c.lastDisconnectLogged.Store(true)
			}
			isConnected.Store(false)

			// 等待后重连（静默）
			time.Sleep(reconnectDelay)
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			continue
		}

		reconnectDelay = time.Second // 重置延迟

		// 处理消息
		if err := c.handleNotifyStream(stream); err != nil {
			// 只在状态变化时打印日志（从连接到断开）
			if !c.lastDisconnectLogged.Load() {
				logger.Error("连接中断，等待重连", err)
				c.lastDisconnectLogged.Store(true)
			}
			isConnected.Store(false)
			// 等待尝试重连（静默）
			time.Sleep(reconnectDelay)
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			continue
		}

		return
	}
}

// handleNotifyStream 处理通知流
func (c *Client) handleNotifyStream(stream *connect.ServerStreamForClient[deployPB.NotifyResponse]) error {
	for {
		select {
		case <-c.ctx.Done():
			return nil
		default:
		}

		if stream.Receive() {
			response := stream.Msg()

			// 设置连接成功
			wasDisconnected := !isConnected.Load()
			isConnected.Store(true)

			// 只在状态变化时打印连接成功日志（从断开到连接）
			if wasDisconnected && c.lastDisconnectLogged.Load() {
				logger.Info("连接服务器成功")
				c.lastDisconnectLogged.Store(false)
			}

			switch response.Type {
			case deployPB.NotifyResponse_TYPE_UNKNOWN:
				isConnected.Store(false)

			case deployPB.NotifyResponse_TYPE_CONNECT:

			case deployPB.NotifyResponse_TYPE_CERT:
				go c.deployCertificate(response.Domain, response.Url)
			}

		} else {
			// 检查是否有错误
			if err := stream.Err(); err != nil {
				return err
			}
			// 没有新消息，等待一段时间再检查
			time.Sleep(1 * time.Second)
		}
	}
}

// StartHeartbeat 启动心跳
func (c *Client) StartHeartbeat() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			logger.Info("停止发送心跳")
			return
		case <-ticker.C:
			if err := c.register(); err != nil {
				continue
			}
		}
	}
}

// deployCertificate 部署证书
func (c *Client) deployCertificate(domain, downloadURL string) {
	deployer := NewCertDeployer(c)
	if err := deployer.DeployCertificate(domain, downloadURL); err != nil {
		logger.Error("证书部署失败", "error", err, "domain", domain)
	}
}

// downloadFile 下载文件
func (c *Client) downloadFile(downloadURL, filepath string) error {
	// 使用 net/url 安全地构建下载 URL
	u, err := url.Parse(downloadURL)
	if err != nil {
		return err
	}

	// 添加 accessKey 参数
	query := u.Query()
	query.Set("accessKey", c.accessKey)
	u.RawQuery = query.Encode()

	// 创建带超时的请求
	ctx, cancel := context.WithTimeout(c.ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	// 创建文件
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// 复制数据到文件
	written, err := io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	logger.Info("文件下载完成", "size", formatBytes(written))
	return nil
}

// formatBytes 格式化字节大小
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// min 返回两个 time.Duration 中的较小值
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
