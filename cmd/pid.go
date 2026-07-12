package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// pidFileRecord identifies the supervisor process that owns the daemon PID file.
type pidFileRecord struct {
	PID        int       `json:"pid"`        // PID 是 supervisor 进程号。
	Executable string    `json:"executable"` // Executable 是启动 supervisor 的可执行文件路径。
	StartedAt  time.Time `json:"startedAt"`  // StartedAt 是 supervisor 启动时间。
}

// writePIDRecord atomically writes a structured daemon PID record.
func writePIDRecord(path string, record pidFileRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".anssl-pid-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}()
	if err := temp.Chmod(0600); err != nil {
		return err
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

// readPIDRecord reads structured PID files and accepts legacy numeric files during upgrade.
func readPIDRecord(path string) (pidFileRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pidFileRecord{}, err
	}
	var record pidFileRecord
	if json.Unmarshal(data, &record) == nil && record.PID > 0 {
		return record, nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return pidFileRecord{}, fmt.Errorf("无效的 PID 文件")
	}
	return pidFileRecord{PID: pid}, nil
}

// supervisorProcessMatches verifies that a PID belongs to an anssl supervisor process.
func supervisorProcessMatches(record pidFileRecord) bool {
	if record.PID <= 0 {
		return false
	}
	commandLine, err := processCommandLine(record.PID)
	if err != nil || !strings.Contains(commandLine, "_supervisor") {
		return false
	}
	if record.Executable == "" {
		return true
	}
	return strings.Contains(commandLine, filepath.Base(record.Executable))
}

// processCommandLine returns a process command line using the native inspection tool.
func processCommandLine(pid int) (string, error) {
	if runtime.GOOS == "windows" {
		filter := fmt.Sprintf("(Get-CimInstance Win32_Process -Filter \"ProcessId = %d\").CommandLine", pid)
		output, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", filter).CombinedOutput()
		return strings.TrimSpace(string(output)), err
	}
	psPath := "/bin/ps"
	if _, err := os.Stat(psPath); err != nil {
		psPath = "/usr/bin/ps"
	}
	output, err := exec.Command(psPath, "-p", strconv.Itoa(pid), "-o", "command=").CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// acquireDaemonStartLock prevents concurrent daemon and restart commands from spawning supervisors.
func acquireDaemonStartLock() (func(), error) {
	path := GetPIDFile() + ".lock"
	for attempt := 0; attempt < 2; attempt++ {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return nil, fmt.Errorf("写入守护进程启动锁失败: %w", err)
			}
			if err := file.Close(); err != nil {
				_ = os.Remove(path)
				return nil, fmt.Errorf("关闭守护进程启动锁失败: %w", err)
			}
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("创建守护进程启动锁失败: %w", err)
		}
		data, readErr := os.ReadFile(path)
		ownerPID, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if readErr == nil && parseErr == nil {
			if commandLine, inspectErr := processCommandLine(ownerPID); inspectErr == nil && commandLine != "" {
				return nil, fmt.Errorf("已有另一个启动或重启操作正在进行")
			}
		}
		if removeErr := os.Remove(path); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, fmt.Errorf("清理失效启动锁失败: %w", removeErr)
		}
	}
	return nil, fmt.Errorf("创建守护进程启动锁失败")
}
