package client

import (
	"context"
	"errors"
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

	// 配置 HTTP 客户端
	httpClient := &http.Client{}
	if cfg.Server.Env == "local" {
		p := new(http.Protocols)
		p.SetUnencryptedHTTP2(true)
		httpClient = &http.Client{
			Transport: &http.Transport{
				Protocols: p,
			},
		}
	}

	client := &Client{
		clientID:   clientID,
		serverURL:  config.URL,
		httpClient: httpClient,
		ctx:        ctx,
		accessKey:  cfg.Server.AccessKey,
	}

	client.connectClient = deployPBconnect.NewDeployServiceClient(httpClient, config.URL)

	// 启动连接通知
	go client.StartConnectNotify()

	return client, nil
}

// StartConnectNotify 启动连接通知
func (c *Client) StartConnectNotify() {
	reconnectDelay := time.Second
	consecutiveFailures := 0

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// 建立双向流连接
		stream, err := c.connectClient.Notify(c.ctx)
		if err != nil {
			consecutiveFailures++

			// 只在状态变化时打印日志
			if isConnected.Load() || consecutiveFailures == 1 {
				logger.Error("连接失败", "error", err)
			}

			isConnected.Store(false)
			c.lastDisconnectLogged.Store(true)

			// 等待重连
			time.Sleep(reconnectDelay)
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			continue
		}

		// 连接成功，重置计数器
		consecutiveFailures = 0
		reconnectDelay = time.Second

		// 获取系统信息
		systemInfo, err := system.GetSystemInfo()
		if err != nil {
			logger.Error("获取系统信息失败: %v", err)
			stream.CloseRequest()
			time.Sleep(reconnectDelay)
			continue
		}

		// 构造注册请求
		registerReq := &deployPB.NotifyRequest{
			AccessKey: c.accessKey,
			ClientId:  c.clientID,
			Version:   config.Version,
			Data: &deployPB.NotifyRequest_RegisterResponse{
				RegisterResponse: &deployPB.RegisterResponse{
					SystemInfo: &deployPB.RegisterResponse_SystemInfo{
						Os:       systemInfo.OS,
						Arch:     systemInfo.Arch,
						Hostname: systemInfo.Hostname,
						Ip:       systemInfo.IP,
					},
				},
			},
		}

		// 注册客户端
		if err := stream.Send(registerReq); err != nil {
			// logger.Error("注册失败", "error", err)
			stream.CloseRequest()
			time.Sleep(reconnectDelay)
			continue
		}

		// 处理消息流
		err = c.handleNotifyStream(stream)

		// 流断开
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}

			isConnected.Store(false)
			c.lastDisconnectLogged.Store(true)

			// 等待后重连
			time.Sleep(reconnectDelay)
			reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			continue
		}

		return
	}
}

// handleNotifyStream 处理通知流
func (c *Client) handleNotifyStream(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse]) error {
	// 启动心跳 goroutine
	heartbeatCtx, cancelHeartbeat := context.WithCancel(c.ctx)
	defer cancelHeartbeat()

	go c.sendHeartbeat(heartbeatCtx, stream)

	receiveCount := 0
	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		// 阻塞接收消息
		req, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("服务器关闭了连接")
			}
			return fmt.Errorf("接收消息失败: %w", err)
		}

		receiveCount++

		// 首次收到消息，标记连接成功
		if !isConnected.Load() {
			isConnected.Store(true)

			if c.lastDisconnectLogged.Load() {
				c.lastDisconnectLogged.Store(false)
			}
		}

		// 处理消息
		c.handleMessage(stream, req)
	}
}

// handleMessage 处理单个消息
func (c *Client) handleMessage(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse], req *deployPB.NotifyResponse) {
	switch req.Type {
	case deployPB.Type_UNKNOWN:
		return

	case deployPB.Type_CONNECT:
		if connectReq, ok := req.Data.(*deployPB.NotifyResponse_ConnectRequest); ok {
			go c.handleConnect(stream, req.RequestId, connectReq.ConnectRequest)
		}

	case deployPB.Type_EXECUTE_BUSINES:
		if businesResp, ok := req.Data.(*deployPB.NotifyResponse_ExecuteBusinesResponse); ok {
			go c.executeBusines(stream, req.RequestId, businesResp.ExecuteBusinesResponse)
		}

	case deployPB.Type_UPDATE_VERSION:
		go c.handleUpdate()

	case deployPB.Type_GET_PROVIDER:
		go c.handleGetProvider(stream, req.RequestId)

	}
}

// sendHeartbeat 定期发送心跳（保持连接活跃）
func (c *Client) sendHeartbeat(ctx context.Context, stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse]) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 发送心跳消息
			err := stream.Send(&deployPB.NotifyRequest{
				AccessKey: c.accessKey,
				ClientId:  c.clientID,
				Version:   config.Version,
			})
			if err != nil {
				logger.Error("发送心跳失败: %v", err)
				return
			}
		}
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
