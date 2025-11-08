package client

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/updater"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
)

// handleUpdate 处理版本更新
func (c *Client) handleUpdate() {
	logger.Info("收到版本更新通知")

	updateInfo, err := updater.CheckUpdate(c.ctx)
	if err != nil {
		logger.Error("检查更新失败", err)
		return
	}

	if !updateInfo.HasUpdate {
		return
	}

	logger.Info("发现新版本", "current", updateInfo.CurrentVersion, "latest", updateInfo.LatestVersion)

	if err := updater.PerformUpdate(c.ctx, updateInfo); err != nil {
		logger.Error("更新失败", err)
		return
	}

	logger.Info("更新完成，重启中...")

	// 创建更新标记文件
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	markerFile := filepath.Join(execDir, ".cert-deploy-updated")
	content := fmt.Sprintf("%s\n%s\n", updateInfo.LatestVersion, time.Now().Format(time.RFC3339))
	os.WriteFile(markerFile, []byte(content), 0644)

	time.Sleep(1 * time.Second)
	os.Exit(0)
}
