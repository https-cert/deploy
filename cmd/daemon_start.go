package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/https-cert/deploy/internal/config"
)

const (
	daemonStartTimeout = 10 * time.Second
	startupLogMaxBytes = 8 << 10
)

// startDaemon 使用已校验的绝对配置路径启动 supervisor，避免子进程重新选择默认配置。
func startDaemon(runtime *config.Runtime) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	// 停止标记只针对上一个 supervisor，不能让新进程在启动后立即退出。
	if err := os.Remove(filepath.Join(getHomeDir(), ".anssl-stop")); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清理停止标记失败: %w", err)
	}
	command := exec.Command(execPath, "_supervisor", "-c", runtime.ConfigFile)
	logFile := filepath.Join(filepath.Dir(runtime.ConfigFile), "anssl.log")
	return startSupervisor(command, GetPIDFile(), logFile, daemonStartTimeout)
}

// startSupervisor 保留早期标准输出并等待本次进程的 PID，慢启动不再被固定的 500ms 误判。
func startSupervisor(command *exec.Cmd, pidFile, logFile string, timeout time.Duration) error {
	// 使用真实文件句柄让后台进程在父命令退出后仍可输出早期错误；不能使用父进程的输出管道。
	output, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("打开启动日志失败: %w", err)
	}
	defer output.Close()
	info, err := output.Stat()
	if err != nil {
		return fmt.Errorf("读取启动日志状态失败: %w", err)
	}
	logOffset := info.Size()
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		return fmt.Errorf("启动守护进程失败: %w", err)
	}

	// 及时回收启动失败的进程，并将退出事件与 PID 就绪、启动超时一起等待。
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case err := <-exited:
			removeSupervisorPID(pidFile, command.Process.Pid)
			if err == nil {
				err = fmt.Errorf("supervisor 在启动完成前退出")
			}
			return supervisorStartError(err, logFile, logOffset)
		case <-deadline.C:
			// 超时后停止本次进程，避免报错后又留下一个迟到的后台 supervisor。
			_ = command.Process.Signal(syscall.SIGTERM)
			select {
			case <-exited:
			case <-time.After(6 * time.Second):
				_ = command.Process.Kill()
				<-exited
			}
			removeSupervisorPID(pidFile, command.Process.Pid)
			return supervisorStartError(fmt.Errorf("启动超时（等待 %s）", timeout), logFile, logOffset)
		case <-poll.C:
			record, err := readPIDRecord(pidFile)
			// 只接受刚启动的进程，旧 PID 或并发进程不能充当本次启动成功的依据。
			if err == nil && record.PID == command.Process.Pid && supervisorProcessMatches(record) {
				return nil
			}
		}
	}
}

// removeSupervisorPID 只清理本次已退出的 supervisor 的记录，保留其他进程的 PID 文件。
func removeSupervisorPID(pidFile string, pid int) {
	if record, err := readPIDRecord(pidFile); err == nil && record.PID == pid {
		_ = os.Remove(pidFile)
	}
}

// supervisorStartError 返回退出原因与本次启动追加的日志，避免把旧日志当成新错误。
func supervisorStartError(cause error, logFile string, offset int64) error {
	detail := readStartupLog(logFile, offset)
	if detail == "" {
		return fmt.Errorf("守护进程启动失败: %w；请查看日志 %s", cause, logFile)
	}
	return fmt.Errorf("守护进程启动失败: %w\n%s", cause, detail)
}

// readStartupLog 读取本次启动日志的有限尾部，避免终端输出历史日志或过大的内容。
func readStartupLog(path string, offset int64) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= offset {
		return ""
	}
	if info.Size()-offset > startupLogMaxBytes {
		offset = info.Size() - startupLogMaxBytes
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return ""
	}
	data, _ := io.ReadAll(io.LimitReader(file, startupLogMaxBytes))
	return strings.TrimSpace(string(data))
}
