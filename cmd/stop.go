package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// CreateStopCmd 创建停止命令
func CreateStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止守护进程",
		Long:  "停止正在运行的证书部署守护进程",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !IsRunning() {
				fmt.Println("守护进程未运行")
				return nil
			}

			if err := StopDaemon(); err != nil {
				return fmt.Errorf("停止守护进程失败: %w", err)
			}

			fmt.Println("守护进程已停止")
			return nil
		},
	}
}
