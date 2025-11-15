package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/internal/scheduler"
	"github.com/https-cert/deploy/pkg/logger"
	"github.com/spf13/cobra"
)

// CreateStartCmd 创建启动命令
func CreateStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "启动守护进程（前台运行）",
		Long:  "在前台启动证书部署守护进程，用于调试",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Init()

			if err := config.Init(ConfigFile); err != nil {
				return fmt.Errorf("初始化配置失败: %w", err)
			}

			// 检查更新标记并清理（程序同级目录）
			execPath, _ := os.Executable()
			execDir := filepath.Dir(execPath)
			markerFile := filepath.Join(execDir, ".anssl-updated")
			if _, err := os.Stat(markerFile); err == nil {
				logger.Info("更新成功")
				os.Remove(markerFile)
			}

			logger.Info("启动守护进程")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			scheduler.Start(ctx)

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			<-sigChan
			logger.Info("停止中...")
			cancel()
			logger.Info("已停止")
			return nil
		},
	}
}
