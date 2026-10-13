package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/https-cert/deploy/internal/config"
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
			runtime, err := config.Load(ConfigFile)
			if err != nil {
				return fmt.Errorf("初始化配置失败: %w", err)
			}
			releaseLock, err := acquireDaemonStartLock()
			if err != nil {
				return err
			}
			defer releaseLock()

			// 检查是否已经在运行，如果是则先停止
			if IsRunning() {
				fmt.Println("守护进程已在运行，正在重启...")
				if err := StopDaemon(); err != nil {
					return fmt.Errorf("停止守护进程失败: %w", err)
				}
				time.Sleep(2 * time.Second)
			}

			if err := startDaemon(runtime); err != nil {
				return err
			}

			fmt.Println("守护进程已启动")

			// 异步检查更新
			go func() {
				time.Sleep(1 * time.Second)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				service := updater.NewService(runtime, nil)
				info, err := service.CheckUpdate(ctx)
				if err == nil && info.HasUpdate {
					fmt.Printf("\n发现新版本: %s -> %s\n", info.CurrentVersion, info.LatestVersion)
					fmt.Println("执行 'anssl update' 进行更新")
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSupervisor()
		},
	}
}

// runSupervisor 运行守护进程监控器
func runSupervisor() error {
	runtime, err := config.Load(ConfigFile)
	if err != nil {
		return fmt.Errorf("初始化配置失败: %w", err)
	}

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	logWriter, err := newRotatingLogWriter(GetLogFile(), logRotationOptionsFromRuntime(runtime))
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}
	defer logWriter.Close()

	logSupervisor := func(format string, args ...interface{}) {
		msg := fmt.Sprintf("[Supervisor %s] ", time.Now().Format("15:04:05"))
		msg += fmt.Sprintf(format, args...)
		msg += "\n"
		logWriter.Write([]byte(msg))
		logWriter.Sync()
	}

	pidFile := GetPIDFile()

	// 信号处理：收到 SIGTERM/SIGINT 时杀掉子进程并退出
	child := &supervisorChild{}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)
	go func() {
		sig := <-sigCh
		logSupervisor("收到信号 %v，正在停止...", sig)
		child.stop(5 * time.Second)
		os.Remove(pidFile)
		os.Remove(filepath.Join(getHomeDir(), ".anssl-stop"))
		os.Exit(0)
	}()

	// 日志和停止信号处理准备完成后再发布 PID，供父命令确认本次 supervisor 已启动。
	if err := writePIDRecord(pidFile, pidFileRecord{PID: os.Getpid(), Executable: execPath, StartedAt: time.Now()}); err != nil {
		return fmt.Errorf("写入PID文件失败: %w", err)
	}
	defer removeSupervisorPID(pidFile, os.Getpid())
	logSupervisor("已启动 (PID: %d)", os.Getpid())

	restartDelay := 1 * time.Second
	maxRestartDelay := 30 * time.Second
	consecutiveFailures := 0

	for {
		if shouldStopSupervisor() {
			logSupervisor("停止")
			os.Remove(pidFile)
			return nil
		}

		cmd := exec.Command(execPath, "start", "-c", runtime.ConfigFile)

		cmd.Stdout = logWriter
		cmd.Stderr = logWriter

		startTime := time.Now()
		started, err := child.start(cmd)
		if err != nil {
			consecutiveFailures++
			logSupervisor("启动 worker 失败: %v", err)
			time.Sleep(restartDelay)
			continue
		}
		if !started {
			return nil
		}
		err = child.wait()

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
				return nil
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
	if err := os.WriteFile(stopMarker, []byte("stop"), 0600); err != nil {
		return fmt.Errorf("写入停止标记失败: %w", err)
	}

	pidFile := GetPIDFile()
	record, err := readPIDRecord(pidFile)
	if err != nil {
		_ = os.Remove(stopMarker)
		return fmt.Errorf("读取PID文件失败: %w", err)
	}
	if !supervisorProcessMatches(record) {
		if removeErr := os.Remove(pidFile); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("PID 文件不是当前 supervisor 且清理失败: %w", removeErr)
		}
		_ = os.Remove(stopMarker)
		return fmt.Errorf("PID 文件不是当前 anssl supervisor，未发送停止信号")
	}

	process, err := os.FindProcess(record.PID)
	if err != nil {
		_ = os.Remove(stopMarker)
		return fmt.Errorf("查找进程失败: %w", err)
	}

	// 发送 SIGTERM，supervisor 的信号处理会级联杀掉 worker
	if err := process.Signal(syscall.SIGTERM); err != nil {
		// 进程可能已经退出
		if removeErr := os.Remove(pidFile); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("清理 PID 文件失败: %w", removeErr)
		}
		_ = os.Remove(stopMarker)
		return nil
	}

	// 等待 supervisor 退出
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		if err := process.Signal(syscall.Signal(0)); err != nil {
			// 进程已退出
			_ = os.Remove(pidFile)
			_ = os.Remove(stopMarker)
			return nil
		}
	}

	// 超时，强制杀死
	if err := process.Signal(syscall.SIGKILL); err != nil {
		_ = os.Remove(stopMarker)
		return fmt.Errorf("强制停止守护进程失败: %w", err)
	}
	time.Sleep(500 * time.Millisecond)

	_ = os.Remove(pidFile)
	_ = os.Remove(stopMarker)

	return nil
}
