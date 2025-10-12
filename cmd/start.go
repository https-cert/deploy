package cmd

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/internal/scheduler"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
	"github.com/spf13/cobra"
)

// CreateStartCmd 创建启动命令
func CreateStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "启动守护进程（前台运行）",
		Long:  "在前台启动证书部署守护进程，用于调试",
		Run: func(cmd *cobra.Command, args []string) {
			if err := config.Init(ConfigFile); err != nil {
				logger.Fatal("初始化配置失败", "error", err)
			}

			logger.Init()

			// 检查更新标记并清理（程序同级目录）
			execPath, _ := os.Executable()
			execDir := filepath.Dir(execPath)
			markerFile := filepath.Join(execDir, ".cert-deploy-updated")
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
		},
	}
}
