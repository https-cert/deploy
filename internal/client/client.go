package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/internal/system"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB"
	"github.com/orange-juzipi/cert-deploy/pb/deployPB/deployPBconnect"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
	"github.com/orange-juzipi/cert-deploy/pkg/utils"
)

var (
	isConnected atomic.Bool
)

type Client struct {
	clientID      string
	serverURL     string
	httpClient    *http.Client
	connectClient deployPBconnect.DeployServiceClient
	ctx           context.Context
	accessKey     string
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
	stream, err := c.connectClient.Notify(c.ctx, &deployPB.NotifyRequest{
		AccessKey: c.accessKey,
		ClientId:  c.clientID,
	})
	if err != nil {
		logger.Error("建立连接通知失败", "error", err)
		return
	}

	logger.Info("建立连接通知成功，开始监听通知")

	for {
		select {
		case <-c.ctx.Done():
			logger.Info("停止监听通知")
			return
		default:
			if stream.Receive() {
				response := stream.Msg()

				// 设置连接成功
				isConnected.Store(true)

				switch response.Type {
				case deployPB.NotifyResponse_TYPE_UNKNOWN:
					isConnected.Store(false)

				case deployPB.NotifyResponse_TYPE_CONNECT:

				case deployPB.NotifyResponse_TYPE_CERT:
					fmt.Println("-------------收到证书部署通知-------------------")
					utils.PrintlnJson(response)
					fmt.Println("---------------开始下载证书-----------------")

					go c.deployCertificate(response.Domain, response.Url)
				}

			} else {
				// 检查是否有错误
				if err := stream.Err(); err != nil {
					isConnected.Store(false)
					logger.Error("连接中断", "error", err)
					return
				}
				// 没有新消息，等待一段时间再检查
				time.Sleep(1 * time.Second)
			}
		}
	}
}

// StartHeartbeat 启动心跳
func (c *Client) StartHeartbeat() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			logger.Info("停止发送心跳")
			return
		case <-ticker.C:
			if err := c.register(); err != nil {
				logger.Error("发送心跳失败", "error", err)
				continue
			}
		}
	}
}

// deployCertificate 部署证书
func (c *Client) deployCertificate(domain, url string) {
	deployer := NewCertDeployer(c)
	if err := deployer.DeployCertificate(domain, url); err != nil {
		logger.Error("证书部署失败", "error", err, "domain", domain)
	}
}

// downloadFile 下载文件
func (c *Client) downloadFile(url, filepath string) error {
	var downloadURL string
	if strings.Contains(url, "?") {
		downloadURL = url + "&accessKey=" + c.accessKey
	} else {
		downloadURL = url + "?accessKey=" + c.accessKey
	}

	resp, err := c.httpClient.Get(downloadURL)
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
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	// 复制数据到文件
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}
