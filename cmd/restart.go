package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/spf13/cobra"
)

// CreateRestartCmd 创建重启命令
func CreateRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "重启守护进程",
		Long:  "重启证书部署守护进程",
		Run: func(cmd *cobra.Command, args []string) {
			if IsRunning() {
				if err := StopDaemon(); err != nil {
					fmt.Printf("停止失败: %v\n", err)
					os.Exit(1)
				}
				time.Sleep(2 * time.Second)
			}

			execPath, err := os.Executable()
			if err != nil {
				fmt.Printf("获取可执行文件路径失败: %v\n", err)
				os.Exit(1)
			}

			supervisorCmd := exec.Command(execPath, "_supervisor", "-c", ConfigFile)
			if err := supervisorCmd.Start(); err != nil {
				fmt.Printf("启动失败: %v\n", err)
				os.Exit(1)
			}

			time.Sleep(500 * time.Millisecond)

			if !IsRunning() {
				fmt.Println("启动失败")
				os.Exit(1)
			}

			fmt.Println("守护进程已重启")
		},
	}
}
