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
	clientId             string                          // clientId 是本机客户端唯一标识。
	serverURL            string                          // serverURL 是 deploy 服务基础地址。
	httpClient           *http.Client                    // httpClient 复用证书下载连接。
	ctx                  context.Context                 // ctx 控制客户端完整生命周期。
	accessKey            string                          // accessKey 是服务端鉴权令牌。
	lastDisconnectLogged atomic.Bool                     // lastDisconnectLogged 标记是否需要记录重连成功。
	systemInfo           *system.SystemInfo              // systemInfo 缓存本机系统信息。
	systemInfoOnce       sync.Once                       // systemInfoOnce 保证系统信息只采集一次。
	httpServer           httpChallengeServer             // httpServer 提供 HTTP-01 challenge 能力。
	busyOperations       atomic.Int32                    // busyOperations 记录正在执行的业务数量。
	conn                 *websocket.Conn                 // conn 是当前 WebSocket 连接。
	connMu               sync.Mutex                      // connMu 保护连接替换和关闭。
	writeMu              sync.Mutex                      // writeMu 保证 WebSocket 只有一个并发写入者。
	reconnectDelay       time.Duration                   // reconnectDelay 是当前重连退避时间。
	businessExecutor     *BusinessExecutor               // businessExecutor 执行部署和 provider 业务。
	protojsonMarshaler   protojson.MarshalOptions        // protojsonMarshaler 序列化 WebSocket 消息。
	protojsonUnmarshaler protojson.UnmarshalOptions      // protojsonUnmarshaler 反序列化 WebSocket 消息。
	startOnce            sync.Once                       // startOnce 保证连接循环只启动一次。
	started              atomic.Bool                     // started 标记连接循环是否已经启动。
	done                 chan struct{}                   // done 在连接循环完全退出时关闭。
	operationSem         chan struct{}                   // operationSem 限制并发业务数量。
	operationOnce        sync.Once                       // operationOnce 惰性初始化并发限制器。
	domainLocksMu        sync.Mutex                      // domainLocksMu 保护域名锁表。
	domainLocks          map[string]*domainOperationLock // domainLocks 保存正在使用的同域名串行锁。
	systemInfoErr        error                           // systemInfoErr 缓存系统信息采集错误。
}

// domainOperationLock serializes operations that target the same canonical domain.
type domainOperationLock struct {
	mu   sync.Mutex // mu serializes operations for one domain.
	refs int        // refs tracks users so idle locks can be removed.
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
			c.StartWSNotify()
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

// lockDomain acquires a reference-counted lock for one canonical deployment domain.
func (c *WSClient) lockDomain(domain string) func() {
	c.domainLocksMu.Lock()
	if c.domainLocks == nil {
		c.domainLocks = make(map[string]*domainOperationLock)
	}
	entry := c.domainLocks[domain]
	if entry == nil {
		entry = &domainOperationLock{}
		c.domainLocks[domain] = entry
	}
	entry.refs++
	c.domainLocksMu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		c.domainLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(c.domainLocks, domain)
		}
		c.domainLocksMu.Unlock()
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
