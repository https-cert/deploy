package scheduler

import (
	"context"
	"errors"
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
	client     *client.WSClient
	httpServer *server.HTTPServer
	ticker     *time.Ticker
	ctx        context.Context
}

// NewScheduler 创建调度器
func NewScheduler(ctx context.Context) (*Scheduler, error) {
	client, err := client.NewWSClient(ctx)
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
	logger.SetSensitiveValues(configuredSensitiveValues(config.GetConfig())...)

	// 创建 HTTP-01 验证服务器
	httpServer := server.NewHTTPServer()

	// 将 HTTP 服务器设置到 client 中
	client.SetHTTPServer(httpServer)

	return &Scheduler{
		client:     client,
		httpServer: httpServer,
		ctx:        ctx,
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

// Start 启动调度器
func Start(ctx context.Context) {
	scheduler, err := NewScheduler(ctx)
	if err != nil {
		logger.Fatal("创建调度器失败", "error", err)
	}

	// 启动 HTTP-01 验证服务器
	go func() {
		cfg := config.GetConfig()
		logger.Info("HTTP-01 验证服务启动", "port", cfg.Server.Port)
		if err := scheduler.httpServer.Start(); err != nil {
			logger.Error("HTTP-01 验证服务启动失败", "error", err)
		}
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
			return
		case <-readyDeadline.C:
			logger.Error("HTTP-01 验证服务未能在限定时间内启动")
			waiting = false
		case <-readyTicker.C:
			if scheduler.httpServer.IsReady() {
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

	// 即使 HTTP 服务启动失败也保持平台连接，challenge 请求会收到明确失败 ACK。
	scheduler.client.Start()

	// 等待上下文取消
	<-ctx.Done()

	// 停止调度器
	scheduler.stop()
}

// stop 停止调度器
func (s *Scheduler) stop() {
	logger.Info("正在停止调度器...")

	if s.ticker != nil {
		s.ticker.Stop()
	}

	// 关闭 WebSocket 客户端连接
	if s.client != nil {
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
		} else {
			logger.Info("HTTP-01 验证服务已停止")
		}
	}

	logger.Info("调度器已停止")
}
