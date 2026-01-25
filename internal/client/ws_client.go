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
	"google.golang.org/protobuf/encoding/protojson"
)

type WSClient struct {
	clientId             string
	serverURL            string
	httpClient           *http.Client
	ctx                  context.Context
	accessKey            string
	lastDisconnectLogged atomic.Bool
	systemInfo           *system.SystemInfo
	systemInfoOnce       sync.Once
	httpServer           *server.HTTPServer
	busyOperations       atomic.Int32
	conn                 *websocket.Conn
	connMu               sync.Mutex
	reconnectDelay       time.Duration
	businessExecutor     *BusinessExecutor // 业务执行器
	protojsonMarshaler   protojson.MarshalOptions
	protojsonUnmarshaler protojson.UnmarshalOptions
}

func (c *WSClient) Start() {
	go c.StartWSNotify()
}

func (c *WSClient) getSystemInfo() (*system.SystemInfo, error) {
	var err error
	c.systemInfoOnce.Do(func() {
		c.systemInfo, err = system.GetSystemInfo()
	})
	return c.systemInfo, err
}

func (c *WSClient) SetHTTPServer(httpServer *server.HTTPServer) {
	c.httpServer = httpServer
}

func (c *WSClient) GetServerURL() string {
	return c.serverURL
}

func (c *WSClient) GetClientID() string {
	return c.clientId
}

func (c *WSClient) GetAccessKey() string {
	return c.accessKey
}

func (c *WSClient) downloadFile(downloadURL, filePath string) error {
	return DownloadFile(c.ctx, c.httpClient, c.accessKey, downloadURL, filePath)
}
