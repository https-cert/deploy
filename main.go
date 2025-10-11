package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/internal/scheduler"
	"github.com/orange-juzipi/cert-deploy/internal/updater"
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
	rootCmd.AddCommand(createStartCmd())
	rootCmd.AddCommand(createStopCmd())
	rootCmd.AddCommand(createStatusCmd())
	rootCmd.AddCommand(createRestartCmd())
	rootCmd.AddCommand(createLogCmd())
	rootCmd.AddCommand(createCheckUpdateCmd())
	rootCmd.AddCommand(createUpdateCmd())

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
		Short: "启动守护进程（后台运行）",
		Long:  "在后台启动证书部署守护进程",
		Run: func(cmd *cobra.Command, args []string) {
			// 检查更新
			go checkUpdateSilently()

			// 检查是否已经在运行
			if isRunning() {
				fmt.Println("证书部署守护进程已经在运行，正在重启...")

				// 先停止现有进程
				if err := stopDaemon(); err != nil {
					fmt.Printf("停止现有进程失败: %v\n", err)
					os.Exit(1)
				}

				// 等待进程完全停止
				time.Sleep(2 * time.Second)
			}

			// 启动后台进程
			if err := startDaemon(); err != nil {
				fmt.Printf("启动守护进程失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("证书部署守护进程已启动")
		},
	}
}

// createStartCmd 创建启动命令
func createStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "启动守护进程（前台运行）",
		Long:  "在前台启动证书部署守护进程，用于调试",
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

// createStopCmd 创建停止命令
func createStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止守护进程",
		Long:  "停止正在运行的证书部署守护进程",
		Run: func(cmd *cobra.Command, args []string) {
			if !isRunning() {
				fmt.Println("证书部署守护进程未运行")
				return
			}

			if err := stopDaemon(); err != nil {
				fmt.Printf("停止守护进程失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("证书部署守护进程已停止")
		},
	}
}

// createStatusCmd 创建状态命令
func createStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看守护进程状态",
		Long:  "查看证书部署守护进程的运行状态",
		Run: func(cmd *cobra.Command, args []string) {
			pidFile := getPIDFile()
			fmt.Printf("PID文件路径: %s\n", pidFile)

			if isRunning() {
				pid := getPID()
				fmt.Printf("证书部署守护进程正在运行 (PID: %s)\n", pid)
			} else {
				fmt.Println("证书部署守护进程未运行")
				// 检查PID文件是否存在
				if _, err := os.Stat(pidFile); err == nil {
					fmt.Println("PID文件存在但进程未运行，可能进程已异常退出")
				} else {
					fmt.Println("PID文件不存在")
				}
			}
		},
	}
}

// createRestartCmd 创建重启命令
func createRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "重启守护进程",
		Long:  "重启证书部署守护进程",
		Run: func(cmd *cobra.Command, args []string) {
			// 检查更新（后台，不阻塞重启）
			go checkUpdateSilently()

			// 先停止
			if isRunning() {
				if err := stopDaemon(); err != nil {
					fmt.Printf("停止守护进程失败: %v\n", err)
					os.Exit(1)
				}
				time.Sleep(2 * time.Second) // 等待进程完全停止
			}

			// 再启动
			if err := startDaemon(); err != nil {
				fmt.Printf("启动守护进程失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("证书部署守护进程已重启")
		},
	}
}

// createLogCmd 创建日志查看命令
func createLogCmd() *cobra.Command {
	var follow bool

	cmd := &cobra.Command{
		Use:   "log",
		Short: "查看守护进程日志",
		Long:  "查看证书部署守护进程的日志输出",
		Run: func(cmd *cobra.Command, args []string) {
			logFile := getLogFile()
			if _, err := os.Stat(logFile); os.IsNotExist(err) {
				fmt.Println("日志文件不存在")
				return
			}

			if follow {
				// 实时查看日志
				followLogs(logFile)
			} else {
				// 读取并显示日志文件内容
				content, err := os.ReadFile(logFile)
				if err != nil {
					fmt.Printf("读取日志文件失败: %v\n", err)
					return
				}

				fmt.Println("=== 守护进程日志 ===")
				fmt.Print(string(content))
			}
		},
	}

	// 添加 -f 参数
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "实时跟踪日志输出")

	return cmd
}

// 守护进程管理函数

// getPIDFile 获取PID文件路径
func getPIDFile() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".cert-deploy.pid")
}

// getLogFile 获取日志文件路径（与配置文件同一目录）
func getLogFile() string {
	// 获取配置文件所在目录
	configDir := filepath.Dir(configFile)
	return filepath.Join(configDir, "cert-deploy.log")
}

// isRunning 检查守护进程是否在运行
func isRunning() bool {
	pidFile := getPIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return false
	}

	// 检查进程是否存在
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// 发送信号0来检查进程是否存在
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// getPID 获取守护进程PID
func getPID() string {
	pidFile := getPIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

// startDaemon 启动守护进程
func startDaemon() error {
	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	// 构建命令，使用 start 子命令来运行前台进程
	cmd := exec.Command(execPath, "start", "-c", configFile)

	// 重定向输出到日志文件（与配置文件同一目录）
	logFile, err := os.OpenFile(getLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("创建日志文件失败: %w", err)
	}

	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// 启动进程
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("启动守护进程失败: %w", err)
	}

	// 保存PID
	pidFile := getPIDFile()
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		// 如果保存PID失败，尝试杀死进程
		cmd.Process.Kill()
		logFile.Close()
		return fmt.Errorf("保存PID文件失败: %w", err)
	}

	// 不关闭日志文件句柄，让子进程继续使用
	// 启动一个goroutine来等待进程结束，然后关闭文件
	go func() {
		cmd.Wait()
		logFile.Close()
	}()

	return nil
}

// stopDaemon 停止守护进程
func stopDaemon() error {
	pidFile := getPIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("读取PID文件失败: %w", err)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("无效的PID: %w", err)
	}

	// 发送TERM信号
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("查找进程失败: %w", err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("发送停止信号失败: %w", err)
	}

	// 等待进程结束
	for i := 0; i < 10; i++ {
		if !isRunning() {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// 如果进程还在运行，强制杀死
	if isRunning() {
		if err := process.Signal(syscall.SIGKILL); err != nil {
			return fmt.Errorf("强制停止进程失败: %w", err)
		}
	}

	// 删除PID文件
	os.Remove(pidFile)

	return nil
}

// followLogs 实时跟踪日志文件
func followLogs(logFile string) {
	fmt.Println("=== 实时日志跟踪 (按 Ctrl+C 退出) ===")

	// 首先显示现有内容
	content, err := os.ReadFile(logFile)
	if err == nil && len(content) > 0 {
		fmt.Print(string(content))
	}

	// 监听系统信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 打开文件进行跟踪
	file, err := os.Open(logFile)
	if err != nil {
		fmt.Printf("打开日志文件失败: %v\n", err)
		return
	}
	defer file.Close()

	// 移动到文件末尾
	file.Seek(0, 2)

	// 创建缓冲区
	buffer := make([]byte, 1024)

	// 启动读取goroutine
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				n, err := file.Read(buffer)
				if err != nil {
					if err == io.EOF {
						// 文件没有新内容，等待一下
						time.Sleep(100 * time.Millisecond)
						continue
					}
					// 其他错误，退出
					done <- true
					return
				}

				if n > 0 {
					fmt.Print(string(buffer[:n]))
				}
			}
		}
	}()

	// 等待信号
	<-sigChan
	fmt.Println("\n停止日志跟踪")
	done <- true
}

// createCheckUpdateCmd 创建检查更新命令
func createCheckUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check-update",
		Short: "检查是否有新版本",
		Long:  "检查 GitHub 是否有新版本可用",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			fmt.Println("正在检查更新...")
			info, err := updater.CheckUpdate(ctx)
			if err != nil {
				fmt.Printf("检查更新失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("当前版本: %s\n", info.CurrentVersion)
			fmt.Printf("最新版本: %s\n", info.LatestVersion)

			if info.HasUpdate {
				fmt.Println("\n✨ 发现新版本！")
				// fmt.Println("\n更新说明:")
				// fmt.Println(info.ReleaseNotes)
				fmt.Println("\n执行以下命令进行更新:")
				fmt.Println("  ./cert-deploy-linux update")
			} else {
				fmt.Println("\n✓ 当前已是最新版本")
			}
		},
	}
}

// createUpdateCmd 创建更新命令
func createUpdateCmd() *cobra.Command {
	var autoRestart bool

	cmd := &cobra.Command{
		Use:   "update",
		Short: "更新到最新版本",
		Long:  "从 GitHub Release 下载并更新到最新版本",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := context.Background()

			// 检查更新
			fmt.Println("正在检查更新...")
			info, err := updater.CheckUpdate(ctx)
			if err != nil {
				fmt.Printf("检查更新失败: %v\n", err)
				os.Exit(1)
			}

			if !info.HasUpdate {
				fmt.Println("当前已是最新版本，无需更新")
				return
			}

			fmt.Printf("发现新版本: %s -> %s\n", info.CurrentVersion, info.LatestVersion)

			// 如果守护进程正在运行，先停止
			wasRunning := isRunning()
			if wasRunning {
				fmt.Println("检测到守护进程正在运行，正在停止...")
				if err := stopDaemon(); err != nil {
					fmt.Printf("停止守护进程失败: %v\n", err)
					fmt.Println("请手动停止守护进程后再执行更新")
					os.Exit(1)
				}
				time.Sleep(2 * time.Second)
			}

			// 执行更新
			if err := updater.PerformUpdate(ctx, info); err != nil {
				fmt.Printf("更新失败: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("\n✓ 更新成功！")

			// 如果之前在运行且设置了自动重启，则重启
			if wasRunning && autoRestart {
				fmt.Println("正在重启守护进程...")
				if err := startDaemon(); err != nil {
					fmt.Printf("重启守护进程失败: %v\n", err)
					fmt.Println("请手动启动守护进程:")
					fmt.Println("  cert-deploy daemon")
					os.Exit(1)
				}
				fmt.Println("守护进程已重启")
			} else if wasRunning {
				fmt.Println("\n请手动重启守护进程:")
				fmt.Println("  cert-deploy restart")
			}
		},
	}

	// 添加自动重启标志
	cmd.Flags().BoolVarP(&autoRestart, "restart", "r", false, "更新后自动重启守护进程")

	return cmd
}

// checkUpdateSilently 静默检查更新（后台运行，不阻塞主流程）
func checkUpdateSilently() {
	// 创建带超时的 context，避免检查更新阻塞太久
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 等待一小段时间再检查，避免影响启动速度
	time.Sleep(1 * time.Second)

	info, err := updater.CheckUpdate(ctx)
	if err != nil {
		return
	}

	if info.HasUpdate {
		fmt.Println()
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Printf("📢 发现新版本: %s -> %s\n", info.CurrentVersion, info.LatestVersion)
		fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println("执行以下命令进行更新:")
		fmt.Println("  cert-deploy update -r")
		fmt.Println()
	}
}
