package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// CreateStopCmd 创建停止命令
func CreateStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止守护进程",
		Long:  "停止正在运行的证书部署守护进程",
		Run: func(cmd *cobra.Command, args []string) {
			if !IsRunning() {
				fmt.Println("守护进程未运行")
				return
			}

			if err := StopDaemon(); err != nil {
				fmt.Printf("停止失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("守护进程已停止")
		},
	}
}
