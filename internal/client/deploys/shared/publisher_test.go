package shared

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestPublishDirectoryWithRollbackPublishesNewContent 验证成功发布会替换旧目录并清理备份。
func TestPublishDirectoryWithRollbackPublishesNewContent(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := writePublisherFixture(t, tempDir, "source", "new")
	targetDir := writePublisherFixture(t, tempDir, "target", "old")

	if err := PublishDirectoryWithRollback(sourceDir, targetDir); err != nil {
		t.Fatalf("PublishDirectoryWithRollback() error = %v", err)
	}
	assertPublisherContent(t, targetDir, "new")
	if _, err := os.Stat(targetDir + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup directory still exists: %v", err)
	}
}

// TestPublishDirectoryWithRollbackRestoresOldContent 验证发布后校验失败会恢复旧目录。
func TestPublishDirectoryWithRollbackRestoresOldContent(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := writePublisherFixture(t, tempDir, "source", "new")
	targetDir := writePublisherFixture(t, tempDir, "target", "old")
	wantErr := errors.New("validation failed")

	err := publishDirectoryWithRollback(sourceDir, targetDir, func() error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("publishDirectoryWithRollback() error = %v, want %v", err, wantErr)
	}
	assertPublisherContent(t, targetDir, "old")
}

// TestLockPublishTargetSerializesSameTarget 验证同一个目标路径的发布锁不会并发进入。
func TestLockPublishTargetSerializesSameTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	releaseFirst := lockPublishTarget(target)
	acquired := make(chan func(), 1)
	go func() {
		acquired <- lockPublishTarget(target)
	}()

	select {
	case release := <-acquired:
		release()
		t.Fatal("second target lock acquired before first release")
	case <-time.After(20 * time.Millisecond):
	}
	releaseFirst()
	select {
	case release := <-acquired:
		release()
	case <-time.After(time.Second):
		t.Fatal("second target lock did not acquire after release")
	}
}

// TestIsCrossDeviceError 验证 EXDEV 链接错误会触发复制回退。
func TestIsCrossDeviceError(t *testing.T) {
	err := &os.LinkError{Op: "rename", Old: "source", New: "target", Err: syscall.EXDEV}
	if !IsCrossDeviceError(err) {
		t.Fatal("IsCrossDeviceError() = false, want true")
	}
}

// TestMoveDirectoryFallsBackToCopyOnCrossDevice 验证 EXDEV 会实际复制目录并删除源目录。
func TestMoveDirectoryFallsBackToCopyOnCrossDevice(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := writePublisherFixture(t, tempDir, "source-exdev", "copied")
	targetDir := filepath.Join(tempDir, "target-exdev")
	originalRename := renameDirectory
	renameDirectory = func(oldPath, newPath string) error {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { renameDirectory = originalRename })
	if err := moveDirectory(sourceDir, targetDir); err != nil {
		t.Fatalf("moveDirectory() cross-device fallback error = %v", err)
	}
	assertPublisherContent(t, targetDir, "copied")
	if _, err := os.Stat(sourceDir); !os.IsNotExist(err) {
		t.Fatalf("source directory should be removed after copy: %v", err)
	}
}

// writePublisherFixture 创建包含固定内容的发布测试目录。
func writePublisherFixture(t *testing.T, parent, name, content string) string {
	t.Helper()
	directory := filepath.Join(parent, name)
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "cert.pem"), []byte(content), 0644); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
	return directory
}

// assertPublisherContent 断言发布目录中的测试内容。
func assertPublisherContent(t *testing.T, directory, want string) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(directory, "cert.pem"))
	if err != nil {
		t.Fatalf("read published file: %v", err)
	}
	if string(content) != want {
		t.Fatalf("published content = %q, want %q", content, want)
	}
}
