//go:build windows

package updater

import "os"

// replaceExecutable 通过旧文件临时重命名替换 Windows 可执行文件。
func replaceExecutable(newPath, oldPath string) error {
	oldBackup := oldPath + ".old"
	if err := os.Rename(oldPath, oldBackup); err != nil {
		return err
	}
	if err := copyFile(newPath, oldPath); err != nil {
		_ = os.Rename(oldBackup, oldPath)
		return err
	}
	_ = os.Remove(oldBackup)
	return nil
}
