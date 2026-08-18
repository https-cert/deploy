//go:build !windows

package updater

import (
	"os"
	"path/filepath"
)

// replaceExecutable 在同一目录准备临时文件并原子替换 Unix 可执行文件。
func replaceExecutable(newPath, oldPath string) error {
	oldInfo, err := os.Stat(oldPath)
	if err != nil {
		return err
	}
	stagedFile, err := os.CreateTemp(filepath.Dir(oldPath), ".anssl-replace-*")
	if err != nil {
		return err
	}
	stagedPath := stagedFile.Name()
	if err := stagedFile.Close(); err != nil {
		_ = os.Remove(stagedPath)
		return err
	}
	if err := copyFile(newPath, stagedPath); err != nil {
		_ = os.Remove(stagedPath)
		return err
	}
	if err := os.Chmod(stagedPath, oldInfo.Mode().Perm()); err != nil {
		_ = os.Remove(stagedPath)
		return err
	}
	if err := os.Rename(stagedPath, oldPath); err != nil {
		_ = os.Remove(stagedPath)
		return err
	}
	return nil
}
