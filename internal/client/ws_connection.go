package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pkg/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// isTemporaryError 判断错误是否为临时网络错误
func isTemporaryError(err error) bool {
	if err == nil {
		return false
	}

	// 检查是否为网络超时、连接拒绝等临时错误
	var netErr net.Error
	if errors.As(err, &netErr) {
		//lint:ignore SA1019 保留历史网络错误的重连分类语义。
		return netErr.Timeout() || netErr.Temporary()
	}

	// 检查是否为连接相关的错误
	errStr := strings.ToLower(err.Error())
	temporaryErrors := []string{
		"connection refused",
		"connection reset",
		"connection timed out",
		"timeout",
		"network is unreachable",
		"no such host",
		"expected handshake response status code 101", // WebSocket 握手错误（服务端未准备好）
		"failed to websocket dial",                    // WebSocket 连接失败
		"websocket",                                   // 所有 WebSocket 相关错误都视为临时错误
	}

	for _, tempErr := range temporaryErrors {
		if strings.Contains(errStr, tempErr) {
			return true
		}
	}

	return false
}

// buildWSURL 构建 WebSocket URL
func (c *WSClient) buildWSURL() string {
	u, _ := url.Parse(c.serverURL)
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}

	if u.Path == "" || u.Path == "/" {
		u.Path = "/deploy/v2/ws"
	} else {
		// 确保路径以 / 结尾，然后追加 ws
		if !strings.HasSuffix(u.Path, "/") {
			u.Path += "/"
		}
		u.Path += "v2/ws"
	}
	q := u.Query()
	q.Set("accessKey", c.accessKey)
	q.Set("clientId", c.clientId)
	u.RawQuery = q.Encode()
	return u.String()
}

// connect 建立 WebSocket 连接
func (c *WSClient) connect() error {
	wsURL := c.buildWSURL()

	// 使用 websocket 建立连接
	conn, _, err := websocket.Dial(c.ctx, wsURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return fmt.Errorf("WebSocket连接失败: %w", err)
	}

	conn.SetReadLimit(maxWSMessageSize)

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	// 连接成功后立即发送注册消息
	if err := c.sendRegister(); err != nil {
		c.connMu.Lock()
		if c.conn == conn {
			c.conn = nil
		}
		c.connMu.Unlock()
		_ = conn.Close(websocket.StatusInternalError, "deployment v2 注册失败")
		return fmt.Errorf("发送 deployment v2 注册消息失败: %w", err)
	}

	return nil
}

// startWebSocketLoop 启动 v2 WebSocket 连接和重连循环。
func (c *WSClient) startWebSocketLoop() {
	c.reconnectDelay = minReconnectDelay
	consecutiveFailures := 0

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			consecutiveFailures++
			// 只在第一次失败时打印错误日志
			if consecutiveFailures == 1 {
				logger.Info("WebSocket连接断开，尝试重连中...")
			}

			c.markReconnectPending()

			var reconnectDelay time.Duration
			// websocket 连接失败通常都是临时错误（服务端可能还未启动），使用较短的重连间隔
			if isTemporaryError(err) {
				if consecutiveFailures <= fastReconnectAttempt {
					reconnectDelay = minReconnectDelay
				} else {
					reconnectDelay = min(c.reconnectDelay*2, maxReconnectDelay)
				}
			} else {
				// 即使不是临时错误，也使用较长的延迟（服务端可能还未启动）
				reconnectDelay = minReconnectDelay * 2
			}

			c.reconnectDelay = reconnectDelay
			if !waitForContext(c.ctx, reconnectDelay) {
				return
			}
			continue
		}

		consecutiveFailures = 0
		c.reconnectDelay = minReconnectDelay

		if c.connectionLogged.CompareAndSwap(false, true) {
			logger.Info("WebSocket连接已建立，开始处理消息")
		}

		if err := c.handleWSMessages(); err != nil {
			busyOps := c.busyOperations.Load()
			if busyOps > 0 {
				logger.Warn("WebSocket连接意外断开(有业务正在执行)", "error", err, "busyOps", busyOps)
			} else {
				logger.Info("WebSocket连接断开", "error", err)
			}

			c.markReconnectPending()
		}

		if !waitForContext(c.ctx, c.reconnectDelay) {
			return
		}
	}
}

// markReconnectPending 只在客户端曾经建立过连接后标记重连，避免首次上线被误报为重连成功。
func (c *WSClient) markReconnectPending() {
	if c.connectionLogged.Load() {
		c.reconnectPending.Store(true)
	}
}

// Close 关闭 WebSocket 连接
func (c *WSClient) Close() error {
	if c == nil {
		return nil
	}
	var closeErr error
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		c.connMu.Lock()
		if c.conn != nil {
			// 连接可能已由读循环关闭；取消生命周期后底层 close 超时不应阻止客户端退出。
			_ = c.conn.Close(websocket.StatusNormalClosure, "客户端关闭")
			c.conn = nil
		}
		c.connMu.Unlock()
	})
	if c.started.Load() {
		if err := c.Wait(context.Background()); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	c.operationWG.Wait()
	return closeErr
}

// NewWSClient 使用显式运行时快照创建 WebSocket 客户端。
func NewWSClient(ctx context.Context, runtime *config.Runtime) (*WSClient, error) {
	return newWSClientWithDependencies(ctx, runtime, wsClientDependencies{})
}

// newWSClientWithDependencies 使用可替换依赖创建 WebSocket 客户端，供离线测试覆盖生命周期。
func newWSClientWithDependencies(ctx context.Context, runtime *config.Runtime, dependencies wsClientDependencies) (*WSClient, error) {
	if runtime == nil || runtime.Config == nil || runtime.Config.Server == nil {
		return nil, fmt.Errorf("运行时配置未初始化")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	clientCtx, cancel := context.WithCancel(ctx)
	cfg := runtime.Config

	uniqueClientID := dependencies.uniqueClientID
	if uniqueClientID == nil {
		uniqueClientID = system.GetUniqueClientId
	}
	clientId, err := uniqueClientID(clientCtx)
	if err != nil {
		cancel()
		return nil, err
	}

	transport := &http.Transport{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       120 * time.Second,
		DisableKeepAlives:     false,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	httpClient := dependencies.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:   0,
			Transport: transport,
		}
	}

	client := &WSClient{
		runtime:        runtime,
		clientId:       clientId,
		serverURL:      runtime.ServerURL,
		httpClient:     httpClient,
		ctx:            clientCtx,
		cancel:         cancel,
		accessKey:      cfg.Server.AccessKey,
		loadSystemInfo: dependencies.loadSystemInfo,
		reconnectDelay: minReconnectDelay,
		done:           make(chan struct{}),
		operationSem:   make(chan struct{}, maxConcurrentOps),
		operationLocks: make(map[string]*resourceOperationLock),
		protojsonMarshaler: protojson.MarshalOptions{
			UseProtoNames:   false, // 使用 camelCase 而非 snake_case
			EmitUnpopulated: false, // 不输出零值字段
		},
		protojsonUnmarshaler: protojson.UnmarshalOptions{
			DiscardUnknown: true, // 忽略未知字段
		},
	}

	// 初始化业务执行器（需要先创建 client，然后才能传递 downloadFile 方法）
	client.deploymentExecutor = NewDeploymentExecutor(client.downloadFile, runtime)
	newHandlerRegistry := dependencies.newHandlerRegistry
	if newHandlerRegistry == nil {
		newHandlerRegistry = NewDeploymentHandlerRegistry
	}
	client.deploymentHandlers, err = newHandlerRegistry(client)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("初始化 deployment v2 handler registry 失败: %w", err)
	}

	return client, nil
}
