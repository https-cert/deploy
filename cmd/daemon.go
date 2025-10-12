package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/updater"
	"github.com/spf13/cobra"
)

// CreateDaemonCmd 创建守护进程命令
func CreateDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "启动守护进程（后台运行）",
		Long:  "在后台启动证书部署守护进程，进程崩溃或更新后将自动重启",
		Run: func(cmd *cobra.Command, args []string) {
			// 检查是否已经在运行，如果是则先停止
			if IsRunning() {
				fmt.Println("守护进程已在运行，正在重启...")
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

			fmt.Println("守护进程已启动")

			// 异步检查更新
			go func() {
				time.Sleep(1 * time.Second)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				info, err := updater.CheckUpdate(ctx)
				if err == nil && info.HasUpdate {
					fmt.Printf("\n发现新版本: %s -> %s\n", info.CurrentVersion, info.LatestVersion)
					fmt.Println("执行 './cert-deploy update' 进行更新")
				}
			}()

			time.Sleep(100 * time.Millisecond)
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

	supervisorLogFile, err := os.OpenFile(GetLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

	logSupervisor("已启动")

	restartDelay := 1 * time.Second
	maxRestartDelay := 30 * time.Second
	consecutiveFailures := 0

	for {
		if shouldStopSupervisor() {
			logSupervisor("停止")
			return
		}

		cmd := exec.Command(execPath, "start", "-c", ConfigFile)

		logFile, err := os.OpenFile(GetLogFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

		pidFile := GetPIDFile()
		if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
			cmd.Process.Kill()
			logFile.Close()
			time.Sleep(restartDelay)
			continue
		}

		err = cmd.Wait()
		logFile.Close()
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
			updateMarker := filepath.Join(execDir, ".cert-deploy-updated")
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
	homeDir, _ := os.UserHomeDir()
	stopMarker := filepath.Join(homeDir, ".cert-deploy-stop")
	if _, err := os.Stat(stopMarker); err == nil {
		os.Remove(stopMarker)
		return true
	}
	return false
}

// StopDaemon 停止守护进程
func StopDaemon() error {
	homeDir, _ := os.UserHomeDir()
	stopMarker := filepath.Join(homeDir, ".cert-deploy-stop")
	os.WriteFile(stopMarker, []byte("stop"), 0644)

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

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("发送停止信号失败: %w", err)
	}

	for i := 0; i < 10; i++ {
		if !IsRunning() {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// 如果进程还在运行，强制杀死
	if IsRunning() {
		// 忽略错误，因为进程可能在检查和发送信号之间已经退出
		process.Signal(syscall.SIGKILL)
		time.Sleep(500 * time.Millisecond)
	}

	os.Remove(pidFile)
	os.Remove(stopMarker)

	return nil
}
