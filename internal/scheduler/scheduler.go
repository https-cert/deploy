package scheduler

import (
	"context"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client"
	"github.com/https-cert/deploy/internal/server"
	"github.com/https-cert/deploy/pkg/logger"
)

// Scheduler 定时任务调度器
type Scheduler struct {
	client     *client.Client
	httpServer *server.HTTPServer
	ticker     *time.Ticker
	ctx        context.Context
}

// NewScheduler 创建调度器
func NewScheduler(ctx context.Context) (*Scheduler, error) {
	client, err := client.NewClient(ctx)
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

	// 启动客户端连接
	client.Start()

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

// Start 启动调度器
func Start(ctx context.Context) {
	scheduler, err := NewScheduler(ctx)
	if err != nil {
		logger.Fatal("创建调度器失败", "error", err)
	}

	// 启动 HTTP-01 验证服务器
	go func() {
		if err := scheduler.httpServer.Start(); err != nil {
			logger.Error("HTTP-01 验证服务启动失败", "error", err)
		}
	}()

	// 等待上下文取消
	<-ctx.Done()

	// 停止调度器
	scheduler.stop()
}

// stop 停止调度器
func (s *Scheduler) stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}

	// 停止 HTTP 服务器
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.httpServer.Stop(ctx); err != nil {
			logger.Error("停止 HTTP-01 验证服务失败", "error", err)
		}
	}
}
