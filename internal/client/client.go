package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/server"
	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/https-cert/deploy/pb/deployPB/deployPBconnect"
	"github.com/https-cert/deploy/pkg/logger"
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
	lastDisconnectLogged atomic.Bool        // 记录是否已打印断开连接日志
	systemInfo           *system.SystemInfo // 缓存的系统信息
	systemInfoOnce       sync.Once          // 确保系统信息只获取一次
	httpServer           *server.HTTPServer // HTTP-01 验证服务器
}

func NewClient(ctx context.Context) (*Client, error) {
	cfg := config.GetConfig()

	// 生成客户端ID
	clientID, err := system.GetUniqueClientID(ctx)
	if err != nil {
		return nil, err
	}

	// 配置 HTTP 客户端
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	if cfg.Server.Env == "local" {
		p := new(http.Protocols)
		p.SetUnencryptedHTTP2(true)
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				Protocols:           p,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		}
	} else {
		httpClient.Transport = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
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

// getSystemInfo 获取系统信息（带缓存）
func (c *Client) getSystemInfo() (*system.SystemInfo, error) {
	var err error
	c.systemInfoOnce.Do(func() {
		c.systemInfo, err = system.GetSystemInfo()
	})
	return c.systemInfo, err
}

// SetHTTPServer 设置 HTTP 服务器（由 scheduler 调用）
func (c *Client) SetHTTPServer(httpServer *server.HTTPServer) {
	c.httpServer = httpServer
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

		// 获取系统信息（使用缓存）
		systemInfo, err := c.getSystemInfo()
		if err != nil {
			logger.Error("获取系统信息失败", "error", err)
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
			stream.CloseRequest()
			time.Sleep(reconnectDelay)
			continue
		}

		// 流断开，先检查主 context 是否被取消（而不是检查错误类型）
		// 因为错误链中可能包含 context.Canceled，但实际是连接断开导致的
		select {
		case <-c.ctx.Done():
			logger.Info("主 context 已取消，退出连接循环")
			return
		default:
		}

		// 处理消息流
		if err := c.handleNotifyStream(stream); err != nil {
			// logger.Error("连接断开", "error", err)
		}

		// 标记断开连接
		isConnected.Store(false)
		c.lastDisconnectLogged.Store(true)

		// 等待后重连
		time.Sleep(reconnectDelay)
		reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
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

			// 如果之前断开过连接，打印重连成功日志
			if c.lastDisconnectLogged.Load() {
				// logger.Info("重新连接成功")
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

	case deployPB.Type_CHALLENGE:
		if businesResp, ok := req.Data.(*deployPB.NotifyResponse_ExecuteBusinesResponse); ok {
			go c.handleChallenge(businesResp.ExecuteBusinesResponse)
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
				// logger.Error("发送心跳失败", "error", err)
				return
			}
		}
	}
}

// downloadFile 下载文件
func (c *Client) downloadFile(downloadURL, filePath string) error {
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

// handleChallenge 处理 ACME HTTP-01 challenge 通知
func (c *Client) handleChallenge(resp *deployPB.ExecuteBusinesResponse) {
	token := resp.ChallengeToken
	challengeResp := resp.ChallengeResponse
	domain := resp.Domain

	if c.httpServer == nil {
		logger.Error("HTTP 服务器未初始化，无法处理 ACME challenge")
		return
	}

	// 如果 token 为空，忽略
	if token == "" {
		return
	}

	// 如果 challengeResp 为空，表示后端要求删除此 challenge（过期/取消）
	if challengeResp == "" {
		c.httpServer.RemoveChallenge(token)
		return
	}

	// 正常情况：缓存新的 challenge
	c.httpServer.SetChallenge(token, challengeResp, domain)
}

// min 返回两个 time.Duration 中的较小值
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
