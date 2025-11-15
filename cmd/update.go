package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/updater"
	"github.com/spf13/cobra"
)

// CreateCheckUpdateCmd 创建检查更新命令
func CreateCheckUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-update",
		Short: "检查是否有新版本",
		Long:  "检查 GitHub 是否有新版本可用",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			fmt.Println("正在检查更新...")
			info, err := updater.CheckUpdate(ctx)
			if err != nil {
				return fmt.Errorf("检查更新失败: %w", err)
			}

			fmt.Printf("当前版本: %s\n", info.CurrentVersion)
			fmt.Printf("最新版本: %s\n", info.LatestVersion)

			if info.HasUpdate {
				fmt.Println("\n发现新版本！")
				fmt.Println("执行 './cert-deploy update' 进行更新")
			} else {
				fmt.Println("\n当前已是最新版本")
			}
			return nil
		},
	}
}

// CreateUpdateCmd 创建更新命令
func CreateUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "更新到最新版本",
		Long:  "从 GitHub Release 下载并更新到最新版本，如果守护进程正在运行则自动重启",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			fmt.Println("正在检查更新...")
			info, err := updater.CheckUpdate(ctx)
			if err != nil {
				return fmt.Errorf("检查更新失败: %w", err)
			}

				if !info.HasUpdate {
					fmt.Println("当前已是最新版本")
					return nil
				}

			fmt.Printf("发现新版本: %s -> %s\n", info.CurrentVersion, info.LatestVersion)

			wasRunning := IsRunning()
			if wasRunning {
				fmt.Println("正在停止守护进程...")
				if err := StopDaemon(); err != nil {
					return fmt.Errorf("停止守护进程失败，请手动停止后再更新: %w", err)
				}
				time.Sleep(2 * time.Second)
			}

			if err := updater.PerformUpdate(ctx, info); err != nil {
				return fmt.Errorf("更新失败: %w", err)
			}

			fmt.Println("\n更新成功！")

			if wasRunning {
				fmt.Println("正在重启守护进程...")

				execPath, err := os.Executable()
				if err != nil {
					return fmt.Errorf("获取可执行文件路径失败，请手动启动: cert-deploy daemon: %w", err)
				}

				restartCmd := exec.Command(execPath, "daemon", "-c", ConfigFile)
				if err := restartCmd.Start(); err != nil {
					return fmt.Errorf("守护进程启动失败，请手动启动: cert-deploy daemon: %w", err)
				}

				time.Sleep(1 * time.Second)

				if !IsRunning() {
					return fmt.Errorf("守护进程启动失败，请手动启动: cert-deploy daemon")
				}
				fmt.Println("守护进程已重启")
			}
			return nil
		},
	}
}
