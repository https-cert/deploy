package cmd

import (
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// supervisorChild 串行化 worker 创建与停止，防止停止信号漏掉刚启动的 worker。
type supervisorChild struct {
	// mu 保护 stopping、command 和 done，并覆盖 cmd.Start 到登记完成的窗口。
	mu sync.Mutex
	// stopping 表示停止已开始，此后不能再创建 worker。
	stopping bool
	// command 是当前正在运行的 worker 命令。
	command *exec.Cmd
	// done 在当前 worker 的 Wait 和输出收集完成后关闭。
	done chan struct{}
}

// start 在同一临界区创建并登记 worker；返回 false 表示 supervisor 已在停止。
func (child *supervisorChild) start(command *exec.Cmd) (bool, error) {
	child.mu.Lock()
	defer child.mu.Unlock()
	if child.stopping {
		return false, nil
	}
	if err := command.Start(); err != nil {
		return false, err
	}
	child.command = command
	child.done = make(chan struct{})
	return true, nil
}

// wait 回收 worker 并通知停止方，避免通过 signal(0) 将僵尸进程误当成仍在运行。
func (child *supervisorChild) wait() error {
	child.mu.Lock()
	command, done := child.command, child.done
	child.mu.Unlock()
	err := command.Wait()
	child.mu.Lock()
	child.command = nil
	close(done)
	child.mu.Unlock()
	return err
}

// stop 禁止新 worker 并等待当前 worker 退出，超时后强杀且等待进程回收。
func (child *supervisorChild) stop(timeout time.Duration) {
	child.mu.Lock()
	child.stopping = true
	command, done := child.command, child.done
	if command != nil {
		// 持锁发送信号，保证 wait 不会清理进程后才发送到过期的 PID。
		_ = command.Process.Signal(syscall.SIGTERM)
	}
	child.mu.Unlock()
	if command == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		_ = command.Process.Kill()
		<-done
	}
}
