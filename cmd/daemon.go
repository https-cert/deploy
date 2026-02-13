package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/https-cert/deploy/internal/updater"
	"github.com/spf13/cobra"
)

// CreateDaemonCmd 创建守护进程命令
func CreateDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "启动守护进程（后台运行）",
		Long:  "在后台启动证书部署守护进程，进程崩溃或更新后将自动重启",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 检查是否已经在运行，如果是则先停止
			if IsRunning() {
				fmt.Println("守护进程已在运行，正在重启...")
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

			fmt.Println("守护进程已启动")

			// 异步检查更新
			go func() {
				time.Sleep(1 * time.Second)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				info, err := updater.CheckUpdate(ctx)
				if err == nil && info.HasUpdate {
					fmt.Printf("\n发现新版本: %s -> %s\n", info.CurrentVersion, info.LatestVersion)
					fmt.Println("执行 './anssl update' 进行更新")
				}
			}()

			time.Sleep(100 * time.Millisecond)
			return nil
		},
	}
}

// createSupervisorCmd 创建 supervisor 命令（内部使用）
func createSupervisorCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "_supervisor",
		Hidden: true,
		Short:  "运行守护进程监控器（内部命令）",
		Run: func(cmd *cobra.Command, args []string) {
			runSupervisor()
		},
	}
}

// runSupervisor 运行守护进程监控器
func runSupervisor() {
	execPath, err := os.Executable()
	if err != nil {
		fmt.Printf("获取可执行文件路径失败: %v\n", err)
		return
	}

	supervisorLogFile, err := os.OpenFile(GetLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Printf("打开日志文件失败: %v\n", err)
		return
	}
	defer supervisorLogFile.Close()

	logSupervisor := func(format string, args ...interface{}) {
		msg := fmt.Sprintf("[Supervisor %s] ", time.Now().Format("15:04:05"))
		msg += fmt.Sprintf(format, args...)
		msg += "\n"
		supervisorLogFile.WriteString(msg)
		supervisorLogFile.Sync()
	}

	// 将 supervisor 自身的 PID 写入 PID 文件
	pidFile := GetPIDFile()
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		fmt.Printf("写入PID文件失败: %v\n", err)
		return
	}

	logSupervisor("已启动 (PID: %d)", os.Getpid())

	// 信号处理：收到 SIGTERM/SIGINT 时杀掉子进程并退出
	var currentChild *os.Process
	var childMu sync.Mutex

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logSupervisor("收到信号 %v，正在停止...", sig)
		childMu.Lock()
		child := currentChild
		childMu.Unlock()
		if child != nil {
			child.Signal(syscall.SIGTERM)
			// 等待子进程退出，最多 5 秒后强杀
			for i := 0; i < 50; i++ {
				time.Sleep(100 * time.Millisecond)
				if err := child.Signal(syscall.Signal(0)); err != nil {
					break // 子进程已退出
				}
			}
			// 如果还活着，强杀
			child.Kill()
		}
		os.Remove(pidFile)
		os.Remove(filepath.Join(getHomeDir(), ".anssl-stop"))
		os.Exit(0)
	}()

	restartDelay := 1 * time.Second
	maxRestartDelay := 30 * time.Second
	consecutiveFailures := 0

	for {
		if shouldStopSupervisor() {
			logSupervisor("停止")
			os.Remove(pidFile)
			return
		}

		cmd := exec.Command(execPath, "start", "-c", ConfigFile)

		logFile, err := os.OpenFile(GetLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			time.Sleep(restartDelay)
			continue
		}

		cmd.Stdout = logFile
		cmd.Stderr = logFile

		startTime := time.Now()
		if err := cmd.Start(); err != nil {
			logFile.Close()
			consecutiveFailures++
			time.Sleep(restartDelay)
			continue
		}

		childMu.Lock()
		currentChild = cmd.Process
		childMu.Unlock()

		err = cmd.Wait()
		logFile.Close()

		childMu.Lock()
		currentChild = nil
		childMu.Unlock()

		uptime := time.Since(startTime)

		if err != nil {
			consecutiveFailures++
			logSupervisor("异常退出: %v", err)

			if uptime < 10*time.Second {
				restartDelay = time.Duration(consecutiveFailures) * time.Second
				if restartDelay > maxRestartDelay {
					restartDelay = maxRestartDelay
				}
				logSupervisor("等待 %v 后重启", restartDelay)
				time.Sleep(restartDelay)
			} else {
				consecutiveFailures = 0
			}
		} else {
			// 检查更新标记（程序同级目录）
			execDir := filepath.Dir(execPath)
			updateMarker := filepath.Join(execDir, ".anssl-updated")
			if _, err := os.Stat(updateMarker); err == nil {
				logSupervisor("应用更新，重启中...")
				os.Remove(updateMarker)
				consecutiveFailures = 0
				time.Sleep(1 * time.Second)
			} else {
				logSupervisor("正常退出")
				os.Remove(pidFile)
				return
			}
		}
	}
}

// shouldStopSupervisor 检查是否应该停止监控器
func shouldStopSupervisor() bool {
	stopMarker := filepath.Join(getHomeDir(), ".anssl-stop")
	if _, err := os.Stat(stopMarker); err == nil {
		os.Remove(stopMarker)
		return true
	}
	return false
}

// getHomeDir 获取用户主目录，失败时返回当前目录
func getHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return homeDir
}

// StopDaemon 停止守护进程
func StopDaemon() error {
	// 保留 stop marker 作为备用停止机制
	stopMarker := filepath.Join(getHomeDir(), ".anssl-stop")
	os.WriteFile(stopMarker, []byte("stop"), 0600)

	pidFile := GetPIDFile()
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("读取PID文件失败: %w", err)
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("无效的PID: %w", err)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("查找进程失败: %w", err)
	}

	// 发送 SIGTERM，supervisor 的信号处理会级联杀掉 worker
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// 进程可能已经退出
		os.Remove(pidFile)
		os.Remove(stopMarker)
		return nil
	}

	// 等待 supervisor 退出
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		if err := process.Signal(syscall.Signal(0)); err != nil {
			// 进程已退出
			os.Remove(pidFile)
			os.Remove(stopMarker)
			return nil
		}
	}

	// 超时，强制杀死
	process.Signal(syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)

	os.Remove(pidFile)
	os.Remove(stopMarker)

	return nil
}
