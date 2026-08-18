package scheduler

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/server"
	"github.com/https-cert/deploy/pkg/logger"
)

// Scheduler 定时任务调度器
type Scheduler struct {
	runtime           *config.Runtime    // runtime 是本次进程使用的只读配置快照。
	client            *client.WSClient   // client 是 v2 WebSocket 客户端。
	httpServer        *server.HTTPServer // httpServer 提供 HTTP-01 challenge 服务。
	clientStarted     bool               // clientStarted 标记 WebSocket 是否已启动，用于失败清理。
	httpServerStarted bool               // httpServerStarted 标记 HTTP-01 服务是否成功监听。
}

// NewScheduler 创建调度器
func NewScheduler(runtime *config.Runtime, contexts ...context.Context) (*Scheduler, error) {
	if runtime == nil || runtime.Config == nil {
		return nil, errors.New("运行时配置不能为空")
	}
	clientContext := context.Background()
	if len(contexts) > 0 && contexts[0] != nil {
		clientContext = contexts[0]
	}
	client, err := client.NewWSClient(clientContext, runtime)
	if err != nil {
		return nil, err
	}

	// 设置日志上报器
	// 日志接口在 /api/logs，需要使用基础 URL（去掉 /deploy 后缀）
	serverURL := client.GetServerURL()
	baseURL := strings.TrimSuffix(serverURL, "/deploy")
	logger.SetReporter(&logger.LogReporter{
		ServerURL: baseURL,
		ClientID:  client.GetClientID(),
		AccessKey: client.GetAccessKey(),
	})
	logger.SetSensitiveValues(configuredSensitiveValues(runtime.Config)...)

	// 创建 HTTP-01 验证服务器
	httpServer := server.NewHTTPServer(runtime.Config.Server.Port)

	// 将 HTTP 服务器设置到 client 中
	client.SetHTTPServer(httpServer)

	return &Scheduler{
		runtime:    runtime,
		client:     client,
		httpServer: httpServer,
	}, nil
}

// configuredSensitiveValues 收集可能被第三方 SDK 回显的本地凭据，仅用于在线日志脱敏。
func configuredSensitiveValues(configuration *config.Configuration) []string {
	if configuration == nil {
		return nil
	}

	values := make([]string, 0, 16)
	if configuration.Server != nil {
		values = append(values, configuration.Server.AccessKey)
	}
	if configuration.SSL != nil {
		if configuration.SSL.OnePanel != nil {
			values = append(values, configuration.SSL.OnePanel.APIKey)
		}
		if configuration.SSL.BTPanel != nil {
			values = append(values, sensitiveHTTPConfigValues(configuration.SSL.BTPanel.URL)...)
			values = append(values, configuration.SSL.BTPanel.APIKey)
		}
		if configuration.SSL.SafeLine != nil {
			values = append(values, configuration.SSL.SafeLine.APIToken)
		}
		if configuration.SSL.FeiNiu != nil {
			values = append(values, configuration.SSL.FeiNiu.Password, configuration.SSL.FeiNiu.PrivateKeyPassphrase)
		}
		if configuration.SSL.RustFS != nil {
			values = append(values, configuration.SSL.RustFS.Password, configuration.SSL.RustFS.PrivateKeyPassphrase)
		}
	}
	for _, provider := range configuration.Provider {
		if provider == nil || provider.Auth == nil {
			continue
		}
		values = append(values,
			provider.Auth.AccessKeyId,
			provider.Auth.AccessKeySecret,
			provider.Auth.SecretId,
			provider.Auth.SecretKey,
			provider.Auth.AccessKey,
			provider.Auth.AccessSecret,
		)
	}
	return values
}

// sensitiveHTTPConfigValues 返回在线日志中需要清除的完整地址和主机名。
func sensitiveHTTPConfigValues(rawURL string) []string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil
	}
	values := []string{trimmed, strings.TrimRight(trimmed, "/")}
	parsed, err := url.Parse(trimmed)
	if err == nil {
		values = append(values, parsed.Host, parsed.Hostname())
	}
	return values
}

// Start 启动调度器；基础 HTTP-01 服务不可用时返回错误，不再连接 WebSocket。
func (s *Scheduler) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	scheduler := s
	if scheduler == nil {
		return errors.New("调度器不能为空")
	}
	if scheduler.client == nil {
		return errors.New("调度器客户端未初始化")
	}

	// 启动 HTTP-01 验证服务器，并通过错误通道阻止端口冲突的第二个进程继续连接。
	httpErr := make(chan error, 1)
	go func() {
		logger.Info("HTTP-01 验证服务启动", "port", scheduler.runtime.Config.Server.Port)
		httpErr <- scheduler.httpServer.Start()
	}()

	// HTTP 服务启动后再连接平台，避免刚上线就收到 challenge 却无法缓存。
	readyDeadline := time.NewTimer(5 * time.Second)
	readyTicker := time.NewTicker(20 * time.Millisecond)
	waiting := true
	for waiting {
		select {
		case <-ctx.Done():
			readyTicker.Stop()
			readyDeadline.Stop()
			scheduler.stop()
			return nil
		case err := <-httpErr:
			readyTicker.Stop()
			readyDeadline.Stop()
			scheduler.stop()
			return fmt.Errorf("HTTP-01 验证服务启动失败: %w", err)
		case <-readyDeadline.C:
			scheduler.stop()
			return errors.New("HTTP-01 验证服务未能在限定时间内启动")
		case <-readyTicker.C:
			if scheduler.httpServer.IsReady() {
				scheduler.httpServerStarted = true
				waiting = false
			}
		}
	}
	readyTicker.Stop()
	if !readyDeadline.Stop() {
		select {
		case <-readyDeadline.C:
		default:
		}
	}

	scheduler.client.Start()
	scheduler.clientStarted = true

	select {
	case <-ctx.Done():
		scheduler.stop()
		return nil
	case err := <-httpErr:
		scheduler.stop()
		if err != nil {
			return fmt.Errorf("HTTP-01 验证服务异常退出: %w", err)
		}
		return errors.New("HTTP-01 验证服务异常退出")
	}
}

// stop 停止调度器
func (s *Scheduler) stop() {
	started := s.clientStarted || s.httpServerStarted
	if started {
		logger.Info("正在停止调度器...")
	}

	// 关闭 WebSocket 客户端连接
	if s.client != nil && s.clientStarted {
		if err := s.client.Close(); err != nil {
			logger.Error("关闭 WebSocket 客户端失败", "error", err)
		} else {
			logger.Info("WebSocket 客户端已关闭")
		}
		waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := s.client.Wait(waitCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			logger.Warn("等待 WebSocket 客户端退出失败", "error", err)
		}
		cancel()
	}

	// 停止 HTTP 服务器
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Stop(ctx); err != nil {
			logger.Error("停止 HTTP-01 验证服务失败", "error", err)
		} else if s.httpServerStarted {
			logger.Info("HTTP-01 验证服务已停止")
		}
	}

	if started {
		logger.Info("调度器已停止")
	}
}
