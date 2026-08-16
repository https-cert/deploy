package client

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/https-cert/deploy/internal/server"
	"github.com/https-cert/deploy/internal/system"
	"github.com/https-cert/deploy/pkg/logger"
	"google.golang.org/protobuf/encoding/protojson"
)

// httpChallengeServer 描述 WebSocket challenge 处理依赖的本地 HTTP 服务能力。
type httpChallengeServer interface {
	// SetChallenge 缓存一条可由 HTTP 端点响应的 challenge。
	SetChallenge(token, response, domain string) error
	// RemoveChallenge 精确删除指定 token。
	RemoveChallenge(token string) error
}

type WSClient struct {
	clientId             string                            // clientId 是本机客户端唯一标识。
	serverURL            string                            // serverURL 是 deploy 服务基础地址。
	httpClient           *http.Client                      // httpClient 复用证书下载连接。
	ctx                  context.Context                   // ctx 控制客户端完整生命周期。
	accessKey            string                            // accessKey 是服务端鉴权令牌。
	connectionLogged     atomic.Bool                       // connectionLogged 保证连接建立日志只记录一次。
	registrationLogged   atomic.Bool                       // registrationLogged 保证 v2 注册成功日志只记录一次。
	reconnectPending     atomic.Bool                       // reconnectPending 标记是否发生过异常断线。
	connected            atomic.Bool                       // connected 表示当前消息循环是否已收到有效 v2 消息。
	systemInfo           *system.SystemInfo                // systemInfo 缓存本机系统信息。
	systemInfoOnce       sync.Once                         // systemInfoOnce 保证系统信息只采集一次。
	httpServer           httpChallengeServer               // httpServer 提供 HTTP-01 challenge 能力。
	busyOperations       atomic.Int32                      // busyOperations 记录正在执行的业务数量。
	conn                 *websocket.Conn                   // conn 是当前 WebSocket 连接。
	connMu               sync.Mutex                        // connMu 保护连接替换和关闭。
	writeMu              sync.Mutex                        // writeMu 保证 WebSocket 只有一个并发写入者。
	reconnectDelay       time.Duration                     // reconnectDelay 是当前重连退避时间。
	deploymentExecutor   *DeploymentExecutor               // deploymentExecutor 执行部署和 provider 业务。
	deploymentHandlers   *DeploymentHandlerRegistry        // deploymentHandlers 按 provider/type 路由 v2 业务。
	protojsonMarshaler   protojson.MarshalOptions          // protojsonMarshaler 序列化 WebSocket 消息。
	protojsonUnmarshaler protojson.UnmarshalOptions        // protojsonUnmarshaler 反序列化 WebSocket 消息。
	startOnce            sync.Once                         // startOnce 保证连接循环只启动一次。
	started              atomic.Bool                       // started 标记连接循环是否已经启动。
	done                 chan struct{}                     // done 在连接循环完全退出时关闭。
	operationSem         chan struct{}                     // operationSem 限制并发业务数量。
	operationOnce        sync.Once                         // operationOnce 惰性初始化并发限制器。
	operationLocksMu     sync.Mutex                        // operationLocksMu 保护资源操作锁表。
	operationLocks       map[string]*resourceOperationLock // operationLocks 保存正在使用的资源串行锁。
	systemInfoErr        error                             // systemInfoErr 缓存系统信息采集错误。
}

// resourceOperationLock 串行化同一个本地部署域名或精确部署资源的操作。
type resourceOperationLock struct {
	mu   sync.Mutex // mu 串行化同一个资源键的操作。
	refs int        // refs 记录使用者数量，以便清理空闲锁。
}

// Start starts the WebSocket lifecycle loop once.
func (c *WSClient) Start() {
	if c.done == nil {
		c.done = make(chan struct{})
	}
	c.operationOnce.Do(func() {
		if c.operationSem == nil {
			c.operationSem = make(chan struct{}, maxConcurrentOps)
		}
	})
	c.startOnce.Do(func() {
		c.started.Store(true)
		go func() {
			defer close(c.done)
			c.startWebSocketLoop()
		}()
	})
}

// getSystemInfo returns cached system information and preserves the first collection error.
func (c *WSClient) getSystemInfo() (*system.SystemInfo, error) {
	c.systemInfoOnce.Do(func() {
		c.systemInfo, c.systemInfoErr = system.GetSystemInfo()
	})
	return c.systemInfo, c.systemInfoErr
}

// Wait blocks until the WebSocket lifecycle loop exits or ctx is canceled.
func (c *WSClient) Wait(ctx context.Context) error {
	if !c.started.Load() {
		return nil
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runOperation starts a bounded asynchronous operation and invokes onBusy when capacity is exhausted.
func (c *WSClient) runOperation(name string, onBusy func(), operation func()) {
	c.operationOnce.Do(func() {
		if c.operationSem == nil {
			c.operationSem = make(chan struct{}, maxConcurrentOps)
		}
	})
	select {
	case c.operationSem <- struct{}{}:
		go func() {
			defer func() { <-c.operationSem }()
			operation()
		}()
	default:
		logger.Warn("客户端业务并发已达上限", "operation", name, "limit", maxConcurrentOps)
		if onBusy != nil {
			onBusy()
		}
	}
}

// lockOperation 获取一个按资源键引用计数的串行锁。
func (c *WSClient) lockOperation(resourceKey string) func() {
	c.operationLocksMu.Lock()
	if c.operationLocks == nil {
		c.operationLocks = make(map[string]*resourceOperationLock)
	}
	entry := c.operationLocks[resourceKey]
	if entry == nil {
		entry = &resourceOperationLock{}
		c.operationLocks[resourceKey] = entry
	}
	entry.refs++
	c.operationLocksMu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		c.operationLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(c.operationLocks, resourceKey)
		}
		c.operationLocksMu.Unlock()
	}
}

// SetHTTPServer configures the local HTTP-01 server dependency.
func (c *WSClient) SetHTTPServer(httpServer *server.HTTPServer) {
	c.httpServer = httpServer
}

// GetServerURL returns the deploy service URL.
func (c *WSClient) GetServerURL() string {
	return c.serverURL
}

// GetClientID returns the unique client identifier.
func (c *WSClient) GetClientID() string {
	return c.clientId
}

// GetAccessKey returns the deploy authentication key.
func (c *WSClient) GetAccessKey() string {
	return c.accessKey
}

// downloadFile downloads a certificate archive using the client lifecycle context.
func (c *WSClient) downloadFile(downloadURL, filePath string) error {
	return DownloadFile(c.ctx, c.httpClient, c.accessKey, downloadURL, filePath)
}
