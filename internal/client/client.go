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

	"connectrpc.com/connect"
	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/internal/system"
	"github.com/orange-juzipi/cert-deploy/internal/updater"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB/deployPBconnect"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
	"golang.org/x/net/http2"
)

const (
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
		Transport: &http2.Transport{
			// 若连接在 30s 内无任何帧往来，自动发送 HTTP/2 PING
			ReadIdleTimeout: 30 * time.Second,
			// PING 发出后 15s 内没响应就视为断开
			PingTimeout: 10 * time.Second,
		},
		Timeout: 0,
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
				c.lastDisconnectLogged.Store(false)
			}

			switch response.Type {
			case deployPB.Type_UNKNOWN:
				isConnected.Store(false)

			case deployPB.Type_CONNECT:

			case deployPB.Type_CERT:
				go c.deployCertificate(response.Domain, response.Url)

			case deployPB.Type_UPDATE_VERSION:
				go c.handleUpdate()

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
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// min 返回两个 time.Duration 中的较小值
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// handleUpdate 处理版本更新
func (c *Client) handleUpdate() {
	logger.Info("收到更新通知")

	updateInfo, err := updater.CheckUpdate(c.ctx)
	if err != nil {
		logger.Error("检查更新失败", err)
		return
	}

	if !updateInfo.HasUpdate {
		return
	}

	logger.Info("发现新版本", "current", updateInfo.CurrentVersion, "latest", updateInfo.LatestVersion)

	if err := updater.PerformUpdate(c.ctx, updateInfo); err != nil {
		logger.Error("更新失败", err)
		return
	}

	logger.Info("更新完成，重启中...")

	// 创建更新标记文件
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	markerFile := filepath.Join(execDir, ".cert-deploy-updated")
	content := fmt.Sprintf("%s\n%s\n", updateInfo.LatestVersion, time.Now().Format(time.RFC3339))
	os.WriteFile(markerFile, []byte(content), 0644)

	time.Sleep(1 * time.Second)
	os.Exit(0)
}
