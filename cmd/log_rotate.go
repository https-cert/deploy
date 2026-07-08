package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/https-cert/deploy/internal/config"
)

type logRotationOptions struct {
	// maxSizeBytes 是单个日志文件最大体积，0 表示不按大小轮转。
	maxSizeBytes int64
	// maxBackups 是最多保留的轮转文件数量，0 表示不按数量清理。
	maxBackups int
	// maxAge 是轮转文件最长保留时间，0 表示不按时间清理。
	maxAge time.Duration
}

type rotatingLogWriter struct {
	// mu 保护文件句柄和轮转流程。
	mu sync.Mutex
	// path 是当前日志文件路径。
	path string
	// options 是日志轮转参数。
	options logRotationOptions
	// file 是当前打开的日志文件。
	file *os.File
}

type rotatedLogFile struct {
	// path 是轮转日志文件路径。
	path string
	// modTime 是轮转日志文件修改时间。
	modTime time.Time
}

// newRotatingLogWriter 创建带轮转能力的日志 writer。
func newRotatingLogWriter(path string, options logRotationOptions) (*rotatingLogWriter, error) {
	writer := &rotatingLogWriter{
		path:    path,
		options: options,
	}
	if err := writer.openLocked(); err != nil {
		return nil, err
	}
	return writer, nil
}

// logRotationOptionsFromConfig 从当前配置读取日志轮转参数。
func logRotationOptionsFromConfig() logRotationOptions {
	cfg := config.GetConfig()
	if cfg == nil || cfg.Log == nil {
		return logRotationOptions{
			maxSizeBytes: 20 * 1024 * 1024,
			maxBackups:   5,
			maxAge:       30 * 24 * time.Hour,
		}
	}

	return logRotationOptions{
		maxSizeBytes: int64(cfg.Log.MaxSizeMB) * 1024 * 1024,
		maxBackups:   cfg.Log.MaxBackups,
		maxAge:       time.Duration(cfg.Log.MaxAgeDays) * 24 * time.Hour,
	}
}

// Write 写入日志，并在超过大小限制时轮转。
func (w *rotatingLogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotateIfNeededLocked(int64(len(data))); err != nil {
		return 0, err
	}
	return w.file.Write(data)
}

// Close 关闭当前日志文件。
func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

// Sync 将当前日志文件刷盘。
func (w *rotatingLogWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	return w.file.Sync()
}

// openLocked 打开当前日志文件。
func (w *rotatingLogWriter) openLocked() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}
	w.file = file
	return nil
}

// rotateIfNeededLocked 在需要时轮转日志文件。
func (w *rotatingLogWriter) rotateIfNeededLocked(incomingSize int64) error {
	if w.options.maxSizeBytes <= 0 || w.file == nil {
		return nil
	}

	info, err := w.file.Stat()
	if err != nil {
		return fmt.Errorf("读取日志文件状态失败: %w", err)
	}
	if info.Size()+incomingSize <= w.options.maxSizeBytes {
		return nil
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("关闭日志文件失败: %w", err)
	}
	w.file = nil

	rotatedPath := fmt.Sprintf("%s.%s", w.path, time.Now().Format("20060102150405.000000000"))
	if err := os.Rename(w.path, rotatedPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("轮转日志文件失败: %w", err)
	}
	if err := cleanupRotatedLogs(w.path, w.options); err != nil {
		return err
	}
	return w.openLocked()
}

// cleanupRotatedLogs 清理超出保留策略的轮转日志。
func cleanupRotatedLogs(basePath string, options logRotationOptions) error {
	files, err := listRotatedLogFiles(basePath)
	if err != nil {
		return err
	}

	now := time.Now()
	for _, file := range files {
		if options.maxAge > 0 && now.Sub(file.modTime) > options.maxAge {
			if err := os.Remove(file.path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("删除过期日志失败: %w", err)
			}
		}
	}

	files, err = listRotatedLogFiles(basePath)
	if err != nil {
		return err
	}
	if options.maxBackups <= 0 || len(files) <= options.maxBackups {
		return nil
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})
	for _, file := range files[:len(files)-options.maxBackups] {
		if err := os.Remove(file.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("删除多余日志失败: %w", err)
		}
	}
	return nil
}

// listRotatedLogFiles 返回指定日志文件的轮转文件列表。
func listRotatedLogFiles(basePath string) ([]rotatedLogFile, error) {
	dir := filepath.Dir(basePath)
	prefix := filepath.Base(basePath) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取日志目录失败: %w", err)
	}

	files := make([]rotatedLogFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("读取轮转日志状态失败: %w", err)
		}
		files = append(files, rotatedLogFile{
			path:    filepath.Join(dir, entry.Name()),
			modTime: info.ModTime(),
		})
	}
	return files, nil
}
