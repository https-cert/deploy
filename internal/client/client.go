package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	downloadTimeout      = 30 * time.Second
	minReconnectDelay    = 1 * time.Second  // 最小重连延迟
	maxReconnectDelay    = 30 * time.Second // 最大重连延迟
	fastReconnectAttempt = 3                // 快速重连尝试次数
	tcpKeepaliveInterval = 15 * time.Second // TCP keepalive 间隔
	heartbeatInterval    = 15 * time.Second // 应用层心跳间隔（缩短以避免60秒超时）
)

var (
	isConnected atomic.Bool
)

type Client struct {
	clientId             string
	serverURL            string
	httpClient           *http.Client
	connectClient        deployPBconnect.DeployServiceClient
	ctx                  context.Context
	accessKey            string
	lastDisconnectLogged atomic.Bool        // 记录是否已打印断开连接日志
	systemInfo           *system.SystemInfo // 缓存的系统信息
	systemInfoOnce       sync.Once          // 确保系统信息只获取一次
	httpServer           *server.HTTPServer // HTTP-01 验证服务器
	busyOperations       atomic.Int32       // 正在执行的业务操作数量
}

func NewClient(ctx context.Context) (*Client, error) {
	cfg := config.GetConfig()

	// 生成客户端ID
	clientId, err := system.GetUniqueClientId(ctx)
	if err != nil {
		return nil, err
	}

	// 配置 HTTP Transport
	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		DisableKeepAlives:     false,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: tcpKeepaliveInterval,
		}).DialContext,
	}

	if cfg.Server.Env == "local" {
		p := new(http.Protocols)
		p.SetUnencryptedHTTP2(true)
		transport.Protocols = p
	}

	httpClient := &http.Client{
		Timeout:   0,
		Transport: transport,
	}

	client := &Client{
		clientId:   clientId,
		serverURL:  config.URL,
		httpClient: httpClient,
		ctx:        ctx,
		accessKey:  cfg.Server.AccessKey,
	}

	// 创建 connect client
	client.connectClient = deployPBconnect.NewDeployServiceClient(httpClient, config.URL)

	return client, nil
}

// Start 启动客户端连接
func (c *Client) Start() {
	go c.StartConnectNotify()
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

// GetServerURL 获取服务器URL
func (c *Client) GetServerURL() string {
	return c.serverURL
}

// GetClientID 获取客户端ID
func (c *Client) GetClientID() string {
	return c.clientId
}

// GetAccessKey 获取访问密钥
func (c *Client) GetAccessKey() string {
	return c.accessKey
}

// StartConnectNotify 启动连接通知 - 建立持久连接并通过心跳保持
func (c *Client) StartConnectNotify() {
	reconnectDelay := minReconnectDelay
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
			if isConnected.Load() || consecutiveFailures == 1 {
				logger.Error("连接失败", "error", err, "attempt", consecutiveFailures)
			}

			isConnected.Store(false)
			c.lastDisconnectLogged.Store(true)

			// 指数退避重连
			if consecutiveFailures <= fastReconnectAttempt {
				reconnectDelay = minReconnectDelay
			} else {
				reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			}

			time.Sleep(reconnectDelay)
			continue
		}

		// 获取系统信息（使用缓存）
		systemInfo, err := c.getSystemInfo()
		if err != nil {
			logger.Error("获取系统信息失败", "error", err)
			stream.CloseRequest()
			time.Sleep(reconnectDelay)
			continue
		}

		// 构造并发送注册请求
		registerReq := &deployPB.NotifyRequest{
			AccessKey: c.accessKey,
			ClientId:  c.clientId,
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

		if err := stream.Send(registerReq); err != nil {
			consecutiveFailures++
			if isConnected.Load() || consecutiveFailures == 1 {
				logger.Error("注册失败", "error", err, "attempt", consecutiveFailures)
			}

			isConnected.Store(false)
			c.lastDisconnectLogged.Store(true)

			// 指数退避重连
			if consecutiveFailures <= fastReconnectAttempt {
				reconnectDelay = minReconnectDelay
			} else {
				reconnectDelay = min(reconnectDelay*2, maxReconnectDelay)
			}

			stream.CloseRequest()
			time.Sleep(reconnectDelay)
			continue
		}

		// 注册成功，重置失败计数
		consecutiveFailures = 0
		reconnectDelay = minReconnectDelay

		logger.Info("连接已建立，开始处理消息")

		// 处理消息流 - 正常情况下会因为心跳保持而永不返回
		streamErr := c.handleNotifyStream(stream)

		// 只有在异常情况下才会到这里（网络故障、服务端主动断开等）
		stream.CloseRequest()

		busyOps := c.busyOperations.Load()
		if busyOps > 0 {
			logger.Warn("连接意外断开(有业务正在执行)", "error", streamErr, "busyOps", busyOps)
		} else {
			logger.Info("连接断开，准备重连", "error", streamErr)
		}

		isConnected.Store(false)
		c.lastDisconnectLogged.Store(true)

		// 短暂延迟后重连
		time.Sleep(reconnectDelay)
	}
}

// handleNotifyStream 处理通知流
func (c *Client) handleNotifyStream(stream *connect.BidiStreamForClientSimple[deployPB.NotifyRequest, deployPB.NotifyResponse]) error {
	// 启动心跳 goroutine - 持续发送心跳保持连接活跃
	heartbeatCtx, cancelHeartbeat := context.WithCancel(c.ctx)
	defer cancelHeartbeat()

	go c.sendHeartbeat(heartbeatCtx, stream)

	// 简单的消息接收循环
	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		default:
		}

		// 阻塞接收消息 (无超时限制，依赖 TCP keepalive 和心跳保持连接)
		req, err := stream.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("服务器关闭了连接")
			}
			return fmt.Errorf("接收消息失败: %w", err)
		}

		// 首次收到消息，标记连接成功
		if !isConnected.Load() {
			isConnected.Store(true)
			if c.lastDisconnectLogged.Load() {
				logger.Info("重新连接成功")
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
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 发送心跳消息
			err := stream.Send(&deployPB.NotifyRequest{
				AccessKey: c.accessKey,
				ClientId:  c.clientId,
				Version:   config.Version,
			})
			if err != nil {
				logger.Debug("发送心跳失败", "error", err)
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
