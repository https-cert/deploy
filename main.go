package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/internal/scheduler"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
	"github.com/spf13/cobra"
)

var (
	configFile string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "cert-deploy",
		Short: "证书自动部署工具",
		Long:  "一个用于自动部署证书并重载nginx的工具",
	}

	// 添加子命令
	rootCmd.AddCommand(createDaemonCmd())

	// 全局标志
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "config.yaml", "配置文件路径")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "执行命令失败: %v\n", err)
		os.Exit(1)
	}
}

// createDaemonCmd 创建守护进程命令
func createDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "启动守护进程模式",
		Long:  "启动定时任务，定期检查并部署证书",
		Run: func(cmd *cobra.Command, args []string) {
			// 初始化配置
			if err := config.Init(configFile); err != nil {
				logger.Fatal("初始化配置失败", "error", err)
			}

			// 初始化日志
			logger.Init()

			logger.Info("启动证书部署守护进程")

			// 创建上下文
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// 启动定时任务
			scheduler.Start(ctx)

			// 监听系统信号
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			// 等待信号
			<-sigChan
			logger.Info("收到停止信号，正在关闭...")

			// 取消上下文
			cancel()

			logger.Info("守护进程已停止")
		},
	}
}
