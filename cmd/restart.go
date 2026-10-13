package cmd

import (
	"fmt"
	"time"

	"github.com/https-cert/deploy/internal/config"
	"github.com/spf13/cobra"
)

// CreateRestartCmd 创建重启命令
func CreateRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "重启守护进程",
		Long:  "重启证书部署守护进程",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 新配置必须先通过校验，避免误配置导致原本正常的守护进程被停止。
			runtime, err := config.Load(ConfigFile)
			if err != nil {
				return fmt.Errorf("初始化配置失败: %w", err)
			}
			releaseLock, err := acquireDaemonStartLock()
			if err != nil {
				return err
			}
			defer releaseLock()

			if IsRunning() {
				if err := StopDaemon(); err != nil {
					return fmt.Errorf("停止守护进程失败: %w", err)
				}
				time.Sleep(2 * time.Second)
			}

			if err := startDaemon(runtime); err != nil {
				return err
			}

			fmt.Println("守护进程已重启")
			return nil
		},
	}
}
