package scheduler

import (
	"context"
	"time"

	"github.com/https-cert/deploy/internal/client"
	"github.com/https-cert/deploy/pkg/logger"
)

// Scheduler 定时任务调度器
type Scheduler struct {
	client *client.Client
	ticker *time.Ticker
	ctx    context.Context
}

// NewScheduler 创建调度器
func NewScheduler(ctx context.Context) (*Scheduler, error) {
	client, err := client.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &Scheduler{
		client: client,
		ctx:    ctx,
	}, nil
}

// Start 启动调度器
func Start(ctx context.Context) {
	scheduler, err := NewScheduler(ctx)
	if err != nil {
		logger.Fatal("创建调度器失败", "error", err)
	}

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
}
