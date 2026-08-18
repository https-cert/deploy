package shared

import (
	"context"
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
	mu   chan struct{} // mu serializes publication for one target path.
	refs int           // refs tracks active users of the lock.
}

var (
	publishLocksMu sync.Mutex
	publishLocks   = make(map[string]*publishTargetLock)
	// renameDirectory 允许测试模拟跨设备移动，生产路径始终使用 os.Rename。
	renameDirectory = os.Rename
)

// CopyDirectory 复制整个目录，兼容入口不绑定调用方生命周期。
func CopyDirectory(src, dst string) error {
	return CopyDirectoryWithContext(context.Background(), src, dst)
}

// CopyDirectoryWithContext 复制整个目录，并在遍历和文件复制前响应取消。
func CopyDirectoryWithContext(ctx context.Context, src, dst string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
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

		return CopyFileWithModeContext(ctx, path, targetPath, info.Mode())
	})
}

// PublishDirectoryWithRollback 将新目录发布到目标路径，并在失败时尽量恢复旧目录。
func PublishDirectoryWithRollback(sourceDir, targetDir string) error {
	return PublishDirectoryWithRollbackContext(context.Background(), sourceDir, targetDir)
}

// PublishDirectoryWithRollbackContext 原子发布目录，并在取消或失败时恢复旧目录。
func PublishDirectoryWithRollbackContext(ctx context.Context, sourceDir, targetDir string) error {
	return publishDirectoryWithRollbackContext(ctx, sourceDir, targetDir, nil)
}

// PublishDirectoryWithValidation 发布新目录，并在发布后校验失败时恢复旧目录。
func PublishDirectoryWithValidation(sourceDir, targetDir string, validate func() error) error {
	return PublishDirectoryWithValidationContext(context.Background(), sourceDir, targetDir, validate)
}

// PublishDirectoryWithValidationContext 原子发布目录，并在发布校验或调用方取消时回滚。
func PublishDirectoryWithValidationContext(ctx context.Context, sourceDir, targetDir string, validate func() error) error {
	return publishDirectoryWithRollbackContext(ctx, sourceDir, targetDir, validate)
}

// publishDirectoryWithRollback 保留旧测试和兼容调用的无 context 入口。
func publishDirectoryWithRollback(sourceDir, targetDir string, afterPublish func() error) error {
	return publishDirectoryWithRollbackContext(context.Background(), sourceDir, targetDir, afterPublish)
}

// publishDirectoryWithRollbackContext 将新目录发布到目标路径，并支持在发布后的校验失败时回滚。
func publishDirectoryWithRollbackContext(ctx context.Context, sourceDir, targetDir string, afterPublish func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if sourceDir == "" || targetDir == "" {
		return fmt.Errorf("源目录和目标目录不能为空")
	}
	releaseTarget, err := acquirePublishTarget(ctx, targetDir)
	if err != nil {
		return err
	}
	defer releaseTarget()
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		return fmt.Errorf("创建目标父目录失败: %w", err)
	}

	stagingDir := targetDir + ".new"
	backupDir := targetDir + ".bak"
	defer func() {
		// 取消路径可能发生在跨设备复制或目录切换之间，临时目录必须始终清理。
		if ctx.Err() != nil {
			if err := os.RemoveAll(stagingDir); err != nil {
				logger.Warn("清理取消发布的临时目录失败", "path", stagingDir, "error", err)
			}
		}
	}()

	if err := os.RemoveAll(stagingDir); err != nil {
		return fmt.Errorf("清理临时目录失败: %w", err)
	}
	if err := os.RemoveAll(backupDir); err != nil {
		return fmt.Errorf("清理备份目录失败: %w", err)
	}

	if err := ctx.Err(); err != nil {
		_ = os.RemoveAll(stagingDir)
		return err
	}
	if err := moveDirectoryWithContext(ctx, sourceDir, stagingDir); err != nil {
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
	if err := ctx.Err(); err != nil {
		rollbackErr := rollbackPublishedDirectory(targetDir, backupDir, hasOld)
		if rollbackErr != nil {
			return fmt.Errorf("发布被取消: %w，回滚失败: %v", err, rollbackErr)
		}
		return err
	}

	if afterPublish != nil {
		if err := afterPublish(); err != nil {
			if rollbackErr := rollbackPublishedDirectory(targetDir, backupDir, hasOld); rollbackErr != nil {
				return fmt.Errorf("发布后校验失败: %w，回滚失败: %v", err, rollbackErr)
			}
			return fmt.Errorf("发布后校验失败: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		rollbackErr := rollbackPublishedDirectory(targetDir, backupDir, hasOld)
		if rollbackErr != nil {
			return fmt.Errorf("发布被取消: %w，回滚失败: %v", err, rollbackErr)
		}
		return err
	}

	if hasOld {
		if err := os.RemoveAll(backupDir); err != nil {
			logger.Warn("删除旧证书备份目录失败", "path", backupDir, "error", err)
		}
	}

	logger.Info("证书目录已发布", "path", targetDir)
	return nil
}

// acquirePublishTarget 获取可取消的目标目录锁。
func acquirePublishTarget(ctx context.Context, targetDir string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	publishLocksMu.Lock()
	entry := publishLocks[targetDir]
	if entry == nil {
		entry = &publishTargetLock{mu: make(chan struct{}, 1)}
		publishLocks[targetDir] = entry
	}
	entry.refs++
	publishLocksMu.Unlock()

	select {
	case entry.mu <- struct{}{}:
		return func() {
			<-entry.mu
			publishLocksMu.Lock()
			entry.refs--
			if entry.refs == 0 {
				delete(publishLocks, targetDir)
			}
			publishLocksMu.Unlock()
		}, nil
	case <-ctx.Done():
		publishLocksMu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(publishLocks, targetDir)
		}
		publishLocksMu.Unlock()
		return nil, ctx.Err()
	}
}

// lockPublishTarget 保留旧测试和兼容调用使用的不可取消入口。
func lockPublishTarget(targetDir string) func() {
	release, _ := acquirePublishTarget(context.Background(), targetDir)
	return func() {
		if release != nil {
			release()
		}
	}
}

// moveDirectory 移动目录，跨设备时回退为复制后删除源目录。
func moveDirectory(sourceDir, targetDir string) error {
	return moveDirectoryWithContext(context.Background(), sourceDir, targetDir)
}

// moveDirectoryWithContext 移动目录，并在跨设备复制期间响应取消。
func moveDirectoryWithContext(ctx context.Context, sourceDir, targetDir string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := renameDirectory(sourceDir, targetDir); err != nil {
		if !IsCrossDeviceError(err) {
			return err
		}
		if err := CopyDirectoryWithContext(ctx, sourceDir, targetDir); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
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

// CopyFileWithMode 复制文件并保持权限。
func CopyFileWithMode(src, dst string, mode fs.FileMode) error {
	return CopyFileWithModeContext(context.Background(), src, dst, mode)
}

// CopyFileWithModeContext 复制文件并在复制前后响应取消。
func CopyFileWithModeContext(ctx context.Context, src, dst string, mode fs.FileMode) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
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
	if err := ctx.Err(); err != nil {
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
