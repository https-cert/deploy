package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pkg/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// wsCloseWaitTimeout 限制 Close 等待连接循环退出的最长时间。
const wsCloseWaitTimeout = 5 * time.Second

// stableConnectionThreshold 是判定「连接曾稳定运行」的时长门槛。
// 超过该时长后再次断线视为新的一轮故障，退避档位复位到最小值，
// 既避免抖动风暴，也让真实故障能快速重新连接。
const stableConnectionThreshold = 5 * time.Minute

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
	// uptime 是上一条成功连接维持的时长，用于区分「网络抖动」与「稳定运行后中断」。
	uptime := time.Duration(0)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if !c.reconnectSince.IsZero() {
			c.reconnectAttempts++
		}
		if err := c.connect(); err != nil {
			if c.ctx.Err() != nil {
				return
			}
			consecutiveFailures++

			// 上一次连接稳定运行过，说明这不是持续抖动，而是新的一轮故障，
			// 退避从最小档重新开始，避免上一轮积攒的 30s 拖慢本次恢复。
			if uptime >= stableConnectionThreshold {
				c.reconnectDelay = minReconnectDelay
			}

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
			c.logConnectionFailure(err, time.Now(), reconnectDelay)
			if !waitForContext(c.ctx, reconnectDelay) {
				return
			}
			continue
		}

		// 握手成功不代表连接可用：紧接着的读循环可能立刻失败。
		// 这里不清零退避，只有真正稳定运行够久才允许复位，否则「连上即断」
		// 会退化成 1 秒高频重连，把服务端日志刷满。
		consecutiveFailures = 0
		if c.connectionLogged.CompareAndSwap(false, true) && c.reconnectSince.IsZero() {
			logger.Info("服务端连接已建立，开始处理消息")
		}

		connectedAt := time.Now()
		err := c.handleWSMessages()
		uptime = time.Since(connectedAt)
		// 主动退出不属于连接故障，也不应触发告警上报。
		if c.ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("服务端已关闭连接")
		}

		// 连接刚建立就断开时继续按指数增长退避，连续抖动才不会变成重连风暴。
		// waitForContext 用的是同一个 delay，保证日志里的 retryIn 与实际等待一致。
		retryIn := c.nextReconnectDelay()
		c.logConnectionFailure(err, time.Now(), retryIn)
		if !waitForContext(c.ctx, retryIn) {
			return
		}
	}
}

// nextReconnectDelay 返回本轮断线后的等待时长，按 1s→2s→4s…指数增长到 30s 封顶。
// 退避档位不会因为一次握手成功而清零，只有连接稳定运行超过 stableConnectionThreshold
// 后再次失败才复位，避免「连上即断」退化为 1 秒高频重连。
func (c *WSClient) nextReconnectDelay() time.Duration {
	c.reconnectDelay = min(c.reconnectDelay*2, maxReconnectDelay)
	return c.reconnectDelay
}

// logConnectionFailure 每轮断线只告警一次，后续重试保持安静，直到收到有效消息确认恢复。
// retryIn 必须由调用方传入本轮真实等待时长，而不是读取 c.reconnectDelay，
// 否则日志会与实际退避不一致，排查时会被retryIn 误导。
func (c *WSClient) logConnectionFailure(err error, now time.Time, retryIn time.Duration) {
	c.markReconnectPending()
	if !c.reconnectSince.IsZero() {
		return
	}
	c.reconnectSince = now

	message := "服务端连接失败，将自动重试"
	if c.reconnectPending.Load() {
		message = "服务端连接中断，将自动重连"
	}
	// Dial 错误可能包含带 accessKey 的 URL；本机日志也不能回显认证值。
	reason := err.Error()
	if c.accessKey != "" {
		reason = strings.ReplaceAll(reason, url.QueryEscape(c.accessKey), "[已脱敏]")
		reason = strings.ReplaceAll(reason, c.accessKey, "[已脱敏]")
	}
	args := []any{"error", strconv.Quote(reason), "retryIn", retryIn}
	if busyOps := c.operations().Busy(); busyOps > 0 {
		args = append(args, "busyOps", busyOps)
	}
	logger.Warn(message, args...)
}

// logConnectionRecovery 收到有效协议消息后才确认恢复，统计包含成功连接的重试次数。
func (c *WSClient) logConnectionRecovery(now time.Time) {
	reconnecting := c.reconnectPending.Swap(false)
	if c.reconnectSince.IsZero() {
		return
	}
	message, durationKey := "服务端连接已建立", "duration"
	if reconnecting {
		message, durationKey = "服务端连接已恢复", "downtime"
	}
	logger.Info(message, durationKey, now.Sub(c.reconnectSince).Round(time.Second), "attempts", c.reconnectAttempts)
	c.reconnectSince = time.Time{}
	c.reconnectAttempts = 0
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
		waitCtx, waitCancel := context.WithTimeout(context.Background(), wsCloseWaitTimeout)
		if err := c.Wait(waitCtx); err != nil {
			closeErr = err
		}
		waitCancel()
	}
	c.operations().Wait()
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
		ops:            newOperationRunner(maxConcurrentOps),
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
	client.deployService = newDeploymentService(client)

	return client, nil
}
