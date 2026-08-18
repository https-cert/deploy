package updater

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/https-cert/deploy/pkg/logger"
)

const (
	githubRepo       = "https-cert/deploy"
	githubAPIURL     = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	downloadTimeout  = 10 * time.Minute
	downloadRetries  = 3
	smokeTestTimeout = 15 * time.Second
	maxUpdateSize    = int64(200 << 20) // 更新包最大 200 MiB
	updateLockMaxAge = 2 * time.Hour    // 崩溃遗留更新锁的最长保留时间
)

var updateMu sync.Mutex

// 常见的 GitHub 镜像加速服务
const (
	mirrorGitHub  = "github"
	mirrorGHProxy = "ghproxy"
	mirrorCustom  = "custom"
)

var mirrorMap = map[string]string{
	mirrorGitHub:  "https://github.com",
	mirrorGHProxy: "https://gh-proxy.com/https://github.com",
}

// GitHubRelease GitHub Release API 响应结构
type (
	Assets struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	}
	GitHubRelease struct {
		TagName string    `json:"tag_name"`
		Name    string    `json:"name"`
		Body    string    `json:"body"`
		Assets  []*Assets `json:"assets"`
	}
)

// UpdateInfo 更新信息
type UpdateInfo struct {
	CurrentVersion string
	LatestVersion  string
	HasUpdate      bool
	DownloadURL    string
	ChecksumURL    string
	ReleaseNotes   string
	BinaryName     string
}

// CheckUpdate 检查是否有新版本
func CheckUpdate(ctx context.Context) (*UpdateInfo, error) {
	return NewService(nil, nil).CheckUpdate(ctx)
}

// PerformUpdate 执行更新
func PerformUpdate(ctx context.Context, info *UpdateInfo) error {
	return performUpdate(ctx, info, newHTTPClientForRuntime(nil))
}

// performUpdate 使用显式 HTTP 客户端执行原子更新。
func performUpdate(ctx context.Context, info *UpdateInfo, httpClient *http.Client) error {
	if info == nil || !info.HasUpdate || info.DownloadURL == "" || info.ChecksumURL == "" {
		return fmt.Errorf("更新信息不完整，必须包含更新包和 checksum URL")
	}
	updateMu.Lock()
	defer updateMu.Unlock()

	logger.Info("下载更新中...", "version", info.LatestVersion)

	// 获取当前可执行文件路径
	execPath, err := currentExecutablePath()
	if err != nil {
		return err
	}
	if err := checkExecutableWritable(execPath); err != nil {
		return err
	}
	releaseUpdateLock, err := acquireUpdateLock(execPath)
	if err != nil {
		return err
	}
	defer releaseUpdateLock()

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "anssl-update-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 下载新版本（可能是压缩包）
	downloadPath := filepath.Join(tempDir, info.BinaryName)
	if err := downloadFile(ctx, httpClient, info.DownloadURL, downloadPath); err != nil {
		return fmt.Errorf("下载新版本失败: %w", err)
	}

	// 先校验下载包，再解压或执行其中的二进制文件。
	checksumPath := filepath.Join(tempDir, "checksums.txt")
	if err := downloadFile(ctx, httpClient, info.ChecksumURL, checksumPath); err != nil {
		return fmt.Errorf("下载校验文件失败: %w", err)
	}
	if err := verifyChecksum(downloadPath, checksumPath, info.BinaryName); err != nil {
		return fmt.Errorf("文件校验失败: %w", err)
	}

	// 解包获取可执行文件路径
	newBinaryPath, err := extractBinary(downloadPath, tempDir)
	if err != nil {
		return fmt.Errorf("解压新版本失败: %w", err)
	}

	// 设置可执行权限（Unix 系统）
	if runtime.GOOS != "windows" {
		if err := os.Chmod(newBinaryPath, 0755); err != nil {
			return fmt.Errorf("设置可执行权限失败: %w", err)
		}
	}
	if err := smokeTestBinary(ctx, newBinaryPath); err != nil {
		return err
	}

	// 备份当前版本
	backupPath, err := backupExecutable(execPath)
	if err != nil {
		return err
	}

	// 替换可执行文件
	if err := replaceExecutable(newBinaryPath, execPath); err != nil {
		if restoreErr := restoreBackup(backupPath, execPath); restoreErr != nil {
			return fmt.Errorf("替换失败且恢复备份失败: %w, 恢复错误: %v", err, restoreErr)
		}
		return fmt.Errorf("替换可执行文件失败: %w", err)
	}

	logger.Info("更新成功，已保留上一版本备份", "backup", backupPath)

	return nil
}

// Rollback 回滚到上一次更新保留的备份版本。
func Rollback() error {
	updateMu.Lock()
	defer updateMu.Unlock()

	execPath, err := currentExecutablePath()
	if err != nil {
		return err
	}
	if err := checkExecutableWritable(execPath); err != nil {
		return err
	}
	releaseUpdateLock, err := acquireUpdateLock(execPath)
	if err != nil {
		return err
	}
	defer releaseUpdateLock()

	backupPath := backupPathFor(execPath)
	if _, err := os.Stat(backupPath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("未找到可回滚备份: %s", backupPath)
		}
		return fmt.Errorf("检查回滚备份失败: %w", err)
	}

	if err := restoreBackup(backupPath, execPath); err != nil {
		return fmt.Errorf("回滚失败: %w", err)
	}
	logger.Info("回滚成功", "backup", backupPath)
	return nil
}

// acquireUpdateLock prevents separate processes from updating or rolling back the same executable concurrently.
func acquireUpdateLock(execPath string) (func(), error) {
	lockPath := execPath + ".update.lock"
	for attempt := 0; attempt < 2; attempt++ {
		file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
				_ = file.Close()
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("写入更新锁失败: %w", err)
			}
			if err := file.Close(); err != nil {
				_ = os.Remove(lockPath)
				return nil, fmt.Errorf("关闭更新锁失败: %w", err)
			}
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("创建更新锁失败: %w", err)
		}
		info, statErr := os.Stat(lockPath)
		if statErr == nil && time.Since(info.ModTime()) <= updateLockMaxAge {
			return nil, fmt.Errorf("另一个更新或回滚操作正在执行")
		}
		if removeErr := os.Remove(lockPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, fmt.Errorf("清理失效更新锁失败: %w", removeErr)
		}
	}
	return nil, fmt.Errorf("创建更新锁失败")
}

// currentExecutablePath 返回当前可执行文件的真实路径。
func currentExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("解析可执行文件路径失败: %w", err)
	}
	return execPath, nil
}

// checkExecutableWritable 检查当前二进制和所在目录是否可写。
func checkExecutableWritable(execPath string) error {
	if strings.TrimSpace(execPath) == "" {
		return fmt.Errorf("可执行文件路径不能为空")
	}

	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("检查当前二进制失败: %w", err)
	}
	if info.IsDir() {
		return fmt.Errorf("当前二进制路径不是文件: %s", execPath)
	}

	file, err := os.Open(execPath)
	if err != nil {
		return fmt.Errorf("当前二进制不可读: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("关闭当前二进制失败: %w", err)
	}

	parentDir := filepath.Dir(execPath)
	probe, err := os.CreateTemp(parentDir, ".anssl-update-write-*")
	if err != nil {
		return fmt.Errorf("当前二进制所在目录不可写: %w", err)
	}
	probePath := probe.Name()
	if err := probe.Close(); err != nil {
		os.Remove(probePath)
		return fmt.Errorf("关闭写权限探测文件失败: %w", err)
	}
	if err := os.Remove(probePath); err != nil {
		return fmt.Errorf("删除写权限探测文件失败: %w", err)
	}
	return nil
}

// smokeTestBinary 通过 version 命令验证新二进制可执行。
func smokeTestBinary(ctx context.Context, binaryPath string) error {
	smokeCtx, cancel := context.WithTimeout(ctx, smokeTestTimeout)
	defer cancel()

	cmd := exec.CommandContext(smokeCtx, binaryPath, "version")
	output, err := cmd.CombinedOutput()
	if smokeCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("新二进制 smoke test 超时")
	}
	if err != nil {
		return fmt.Errorf("新二进制 smoke test 失败: %w\n%s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// backupPathFor 返回当前二进制的备份路径。
func backupPathFor(execPath string) string {
	return execPath + ".backup"
}

// backupExecutable 备份当前二进制，成功更新后仍保留该备份供 rollback 使用。
func backupExecutable(execPath string) (string, error) {
	backupPath := backupPathFor(execPath)
	if err := copyFile(execPath, backupPath); err != nil {
		return "", fmt.Errorf("备份当前版本失败: %w", err)
	}
	return backupPath, nil
}

// restoreBackup 使用备份恢复当前二进制，同时保留备份文件。
func restoreBackup(backupPath, execPath string) error {
	restorePath := execPath + ".restore"
	os.Remove(restorePath)
	if err := copyFile(backupPath, restorePath); err != nil {
		return fmt.Errorf("准备恢复文件失败: %w", err)
	}
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		if err := copyFile(restorePath, execPath); err != nil {
			os.Remove(restorePath)
			return err
		}
		return os.Remove(restorePath)
	} else if err != nil {
		os.Remove(restorePath)
		return err
	}
	if err := replaceExecutable(restorePath, execPath); err != nil {
		os.Remove(restorePath)
		return err
	}
	return nil
}
