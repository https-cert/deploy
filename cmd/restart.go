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
		RunE: func(cmd *cobra.Command, args []string) error {
			if IsRunning() {
				if err := StopDaemon(); err != nil {
					return fmt.Errorf("停止守护进程失败: %w", err)
				}
				time.Sleep(2 * time.Second)
			}

			execPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("获取可执行文件路径失败: %w", err)
			}

			supervisorCmd := exec.Command(execPath, "_supervisor", "-c", ConfigFile)
			if err := supervisorCmd.Start(); err != nil {
				return fmt.Errorf("启动守护进程失败: %w", err)
			}

			time.Sleep(500 * time.Millisecond)

			if !IsRunning() {
				return fmt.Errorf("守护进程启动失败")
			}

			fmt.Println("守护进程已重启")
			return nil
		},
	}
}
