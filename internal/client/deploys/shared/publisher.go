package shared

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/https-cert/deploy/pkg/logger"
)

type publishTargetLock struct {
	mu   sync.Mutex // mu serializes publication for one target path.
	refs int        // refs tracks active users of the lock.
}

var (
	publishLocksMu sync.Mutex
	publishLocks   = make(map[string]*publishTargetLock)
	// renameDirectory 允许测试模拟跨设备移动，生产路径始终使用 os.Rename。
	renameDirectory = os.Rename
)

// CopyDirectory 复制整个目录
func CopyDirectory(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(dst, relPath)

		info, err := d.Info()
		if err != nil {
			return err
		}

		if d.IsDir() {
			return os.MkdirAll(targetPath, info.Mode())
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}

		return CopyFileWithMode(path, targetPath, info.Mode())
	})
}

// PublishDirectoryWithRollback 将新目录发布到目标路径，并在失败时尽量恢复旧目录。
func PublishDirectoryWithRollback(sourceDir, targetDir string) error {
	return publishDirectoryWithRollback(sourceDir, targetDir, nil)
}

// PublishDirectoryWithValidation 发布新目录，并在发布后校验失败时恢复旧目录。
func PublishDirectoryWithValidation(sourceDir, targetDir string, validate func() error) error {
	return publishDirectoryWithRollback(sourceDir, targetDir, validate)
}

// publishDirectoryWithRollback 将新目录发布到目标路径，并支持在发布后的校验失败时回滚。
func publishDirectoryWithRollback(sourceDir, targetDir string, afterPublish func() error) error {
	if sourceDir == "" || targetDir == "" {
		return fmt.Errorf("源目录和目标目录不能为空")
	}
	releaseTarget := lockPublishTarget(targetDir)
	defer releaseTarget()

	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		return fmt.Errorf("创建目标父目录失败: %w", err)
	}

	stagingDir := targetDir + ".new"
	backupDir := targetDir + ".bak"

	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("清理临时目录失败: %w", err)
	}
	if err := os.RemoveAll(backupDir); err != nil {
		return fmt.Errorf("清理备份目录失败: %w", err)
	}

	if err := moveDirectory(sourceDir, stagingDir); err != nil {
		return fmt.Errorf("准备新证书目录失败: %w", err)
	}

	hasOld := false
	if _, err := os.Stat(targetDir); err == nil {
		hasOld = true
		if err := os.Rename(targetDir, backupDir); err != nil {
			if cleanupErr := os.RemoveAll(stagingDir); cleanupErr != nil {
				logger.Warn("清理临时目录失败", "path", stagingDir, "error", cleanupErr)
			}
			return fmt.Errorf("备份现有目录失败: %w", err)
		}
	} else if !os.IsNotExist(err) {
		if cleanupErr := os.RemoveAll(stagingDir); cleanupErr != nil {
			logger.Warn("清理临时目录失败", "path", stagingDir, "error", cleanupErr)
		}
		return fmt.Errorf("检查目标目录失败: %w", err)
	}

	if err := os.Rename(stagingDir, targetDir); err != nil {
		if rollbackErr := rollbackPublishedDirectory(targetDir, backupDir, hasOld); rollbackErr != nil {
			return fmt.Errorf("发布新目录失败: %w，回滚失败: %v", err, rollbackErr)
		}
		return fmt.Errorf("发布新目录失败: %w", err)
	}

	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			if rollbackErr := rollbackPublishedDirectory(targetDir, backupDir, hasOld); rollbackErr != nil {
				return fmt.Errorf("发布后校验失败: %w，回滚失败: %v", err, rollbackErr)
			}
			return fmt.Errorf("发布后校验失败: %w", err)
		}
	}

	if hasOld {
		if err := os.RemoveAll(backupDir); err != nil {
			logger.Warn("删除旧证书备份目录失败", "path", backupDir, "error", err)
		}
	}

	logger.Info("证书目录已发布", "path", targetDir)
	return nil
}

// lockPublishTarget acquires a reference-counted lock for one final deployment target.
func lockPublishTarget(targetDir string) func() {
	publishLocksMu.Lock()
	entry := publishLocks[targetDir]
	if entry == nil {
		entry = &publishTargetLock{}
		publishLocks[targetDir] = entry
	}
	entry.refs++
	publishLocksMu.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		publishLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(publishLocks, targetDir)
		}
		publishLocksMu.Unlock()
	}
}

// moveDirectory 移动目录，跨设备时回退为复制后删除源目录。
func moveDirectory(sourceDir, targetDir string) error {
	if err := renameDirectory(sourceDir, targetDir); err != nil {
		if !IsCrossDeviceError(err) {
			return err
		}
		if err := CopyDirectory(sourceDir, targetDir); err != nil {
			return err
		}
		if err := os.RemoveAll(sourceDir); err != nil {
			return fmt.Errorf("清理源目录失败: %w", err)
		}
	}
	return nil
}

// rollbackPublishedDirectory 恢复备份目录，保证发布失败时尽量保留旧证书。
func rollbackPublishedDirectory(targetDir, backupDir string, hasOld bool) error {
	if !hasOld {
		if err := os.RemoveAll(targetDir); err != nil {
			return err
		}
		return nil
	}

	if err := os.RemoveAll(targetDir); err != nil {
		return err
	}
	if err := os.Rename(backupDir, targetDir); err != nil {
		return err
	}
	logger.Warn("证书目录发布失败，已恢复旧目录", "path", targetDir)
	return nil
}

// CopyFileWithMode 复制文件并保持权限
func CopyFileWithMode(src, dst string, mode fs.FileMode) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	dest, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dest.Close()

	if _, err := io.Copy(dest, source); err != nil {
		return err
	}

	return dest.Sync()
}

// IsCrossDeviceError 检测是否为跨设备移动错误
func IsCrossDeviceError(err error) bool {
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return errors.Is(linkErr.Err, syscall.EXDEV)
	}
	return false
}
