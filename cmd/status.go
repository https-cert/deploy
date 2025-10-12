package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// CreateStatusCmd 创建状态命令
func CreateStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看守护进程状态",
		Long:  "查看证书部署守护进程的运行状态",
		Run: func(cmd *cobra.Command, args []string) {
			pidFile := GetPIDFile()
			fmt.Printf("PID文件: %s\n", pidFile)

			if IsRunning() {
				pid := GetPID()
				fmt.Printf("守护进程正在运行 (PID: %s)\n", pid)
			} else {
				fmt.Println("守护进程未运行")
				if _, err := os.Stat(pidFile); err == nil {
					fmt.Println("PID文件存在但进程未运行")
				}
			}
		},
	}
}
