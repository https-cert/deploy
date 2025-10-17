package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
)

const (
	githubRepo      = "https-cert/deploy"
	githubAPIURL    = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	downloadTimeout = 10 * time.Minute
	checksumTimeout = 30 * time.Second
)

// 常见的 GitHub 镜像加速服务
const (
	mirrorGitHub   = "github"
	mirrorGHProxy  = "ghproxy"
	mirrorGHProxy2 = "ghproxy2"
	mirrorCustom   = "custom"
)

var mirrorMap = map[string]string{
	mirrorGitHub:   "https://github.com",
	mirrorGHProxy:  "https://ghproxy.net/https://github.com",
	mirrorGHProxy2: "https://gh-proxy.com/https://github.com",
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
	currentVersion := config.Version
	if currentVersion == "" {
		currentVersion = "v0.0.1"
	}

	release, err := fetchLatestRelease(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取最新版本失败: %w", err)
	}

	latestVersion := release.TagName

	// 比较版本
	hasUpdate := compareVersions(currentVersion, latestVersion)

	if !hasUpdate {
		return &UpdateInfo{
			CurrentVersion: currentVersion,
			LatestVersion:  latestVersion,
			HasUpdate:      false,
		}, nil
	}

	// 确定要下载的二进制文件名
	binaryName := getBinaryName()
	checksumName := "checksums.txt"

	// 查找下载链接
	var downloadURL, checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			downloadURL = asset.BrowserDownloadURL
		}
		if asset.Name == checksumName {
			checksumURL = asset.BrowserDownloadURL
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("未找到适合当前系统的二进制文件: %s", binaryName)
	}

	// 转换下载链接（应用镜像加速）
	downloadURL = transformDownloadURL(downloadURL)
	if checksumURL != "" {
		checksumURL = transformDownloadURL(checksumURL)
	}

	return &UpdateInfo{
		CurrentVersion: currentVersion,
		LatestVersion:  latestVersion,
		HasUpdate:      true,
		DownloadURL:    downloadURL,
		ChecksumURL:    checksumURL,
		ReleaseNotes:   release.Body,
		BinaryName:     binaryName,
	}, nil
}

// PerformUpdate 执行更新
func PerformUpdate(ctx context.Context, info *UpdateInfo) error {
	logger.Info("下载更新中...", "version", info.LatestVersion)

	// 获取当前可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取可执行文件路径失败: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("解析可执行文件路径失败: %w", err)
	}

	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "cert-deploy-update-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 下载新版本
	newBinaryPath := filepath.Join(tempDir, info.BinaryName)
	if err := downloadFile(ctx, info.DownloadURL, newBinaryPath); err != nil {
		return fmt.Errorf("下载新版本失败: %w", err)
	}

	// 下载并验证 checksum
	if info.ChecksumURL != "" {
		checksumPath := filepath.Join(tempDir, "checksums.txt")
		if err := downloadFile(ctx, info.ChecksumURL, checksumPath); err != nil {
			return fmt.Errorf("下载校验文件失败: %w", err)
		} else {
			if err := verifyChecksum(newBinaryPath, checksumPath, info.BinaryName); err != nil {
				return fmt.Errorf("文件校验失败: %w", err)
			}
		}
	}

	// 设置可执行权限（Unix 系统）
	if runtime.GOOS != "windows" {
		if err := os.Chmod(newBinaryPath, 0755); err != nil {
			return fmt.Errorf("设置可执行权限失败: %w", err)
		}
	}

	// 备份当前版本
	backupPath := execPath + ".backup"
	if err := copyFile(execPath, backupPath); err != nil {
		return fmt.Errorf("备份当前版本失败: %w", err)
	}

	// 替换可执行文件
	if err := replaceExecutable(newBinaryPath, execPath); err != nil {
		// 恢复备份
		if restoreErr := os.Rename(backupPath, execPath); restoreErr != nil {
			return fmt.Errorf("替换失败且恢复备份失败: %w, 恢复错误: %v", err, restoreErr)
		}
		return fmt.Errorf("替换可执行文件失败: %w", err)
	}

	// 删除备份
	os.Remove(backupPath)

	return nil
}

// fetchLatestRelease 获取最新的 Release 信息
func fetchLatestRelease(ctx context.Context) (*GitHubRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", githubAPIURL, nil)
	if err != nil {
		return nil, err
	}

	// 设置 User-Agent，GitHub API 要求
	req.Header.Set("User-Agent", "cert-deploy-updater")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API 返回错误状态码: %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, err
	}

	return &release, nil
}

// getHTTPClient 获取配置了代理的 HTTP 客户端
func getHTTPClient() *http.Client {
	transport := &http.Transport{}

	// 检查配置文件中的代理设置
	cfg := config.GetConfig()
	if cfg != nil && cfg.Update.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Update.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	} else {
		// 使用系统环境变量的代理设置
		transport.Proxy = http.ProxyFromEnvironment
	}

	return &http.Client{
		Transport: transport,
		Timeout:   downloadTimeout,
	}
}

// transformDownloadURL 根据配置转换下载 URL（使用镜像加速）
func transformDownloadURL(originalURL string) string {
	cfg := config.GetConfig()

	// 如果配置为空或未配置镜像，使用默认镜像 ghproxy
	if cfg == nil {
		mirrorURL := mirrorMap[mirrorGHProxy]
		return strings.Replace(originalURL, "https://github.com", mirrorURL, 1)
	}

	// 如果未配置镜像或镜像为空，使用默认镜像 ghproxy
	if cfg.Update.Mirror == "" {
		mirrorURL := mirrorMap[mirrorGHProxy]
		return strings.Replace(originalURL, "https://github.com", mirrorURL, 1)
	}

	// 如果明确配置使用 GitHub 原始地址，直接返回
	if cfg.Update.Mirror == mirrorGitHub {
		return originalURL
	}

	// 使用自定义镜像
	if cfg.Update.Mirror == mirrorCustom && cfg.Update.CustomURL != "" {
		// 替换 github.com 为自定义地址
		newURL := strings.Replace(originalURL, "https://github.com", cfg.Update.CustomURL, 1)
		return newURL
	}

	// 使用预定义的镜像服务
	if mirrorURL, ok := mirrorMap[cfg.Update.Mirror]; ok {
		newURL := strings.Replace(originalURL, "https://github.com", mirrorURL, 1)
		return newURL
	}

	return originalURL
}

// compareVersions 比较版本号，如果 latest > current 返回 true
func compareVersions(current, latest string) bool {
	// 简单的字符串比较，适用于 v1.2.3 格式
	// 去掉 'v' 前缀
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	return latest != current
}

// getBinaryName 根据当前系统获取二进制文件名
func getBinaryName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var name string
	switch goos {
	case "darwin":
		if goarch == "arm64" {
			name = "cert-deploy-mac-arm64"
		} else {
			name = "cert-deploy-mac"
		}
	case "linux":
		if goarch == "arm64" {
			name = "cert-deploy-linux-arm64"
		} else {
			name = "cert-deploy-linux"
		}
	case "windows":
		if goarch == "arm64" {
			name = "cert-deploy-windows-arm64.exe"
		} else {
			name = "cert-deploy-windows.exe"
		}
	default:
		name = fmt.Sprintf("cert-deploy-%s-%s", goos, goarch)
	}

	return name
}

// downloadFile 下载文件
func downloadFile(ctx context.Context, downloadURL, filepath string) error {
	ctx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return err
	}

	client := getHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

// verifyChecksum 验证文件的 SHA256 校验和
func verifyChecksum(binaryPath, checksumPath, binaryName string) error {
	// 读取 checksums.txt
	content, err := os.ReadFile(checksumPath)
	if err != nil {
		return err
	}

	// 解析 checksums.txt，找到对应文件的 checksum
	lines := strings.Split(string(content), "\n")
	var expectedChecksum string
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 && parts[1] == binaryName {
			expectedChecksum = parts[0]
			break
		}
	}

	if expectedChecksum == "" {
		return fmt.Errorf("在校验文件中未找到 %s 的校验和", binaryName)
	}

	// 计算下载文件的 SHA256
	file, err := os.Open(binaryPath)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// 比较
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("校验和不匹配\n期望: %s\n实际: %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// replaceExecutable 替换可执行文件
func replaceExecutable(newPath, oldPath string) error {
	// Windows 系统下不能直接替换正在运行的文件，需要特殊处理
	if runtime.GOOS == "windows" {
		// 将旧文件重命名
		oldBackup := oldPath + ".old"
		if err := os.Rename(oldPath, oldBackup); err != nil {
			return err
		}
		// 复制新文件
		if err := copyFile(newPath, oldPath); err != nil {
			// 恢复
			os.Rename(oldBackup, oldPath)
			return err
		}
		// 标记旧文件在重启后删除
		os.Remove(oldBackup)
		return nil
	}

	// Unix 系统：先删除旧文件，再移动新文件
	// 注意：即使进程正在运行，删除文件也不会影响当前进程（inode 仍然存在）
	// 但是需要保留权限，所以先获取权限
	oldInfo, err := os.Stat(oldPath)
	if err != nil {
		return err
	}
	oldMode := oldInfo.Mode()

	// 删除旧文件（进程仍在运行，inode 保留）
	if err := os.Remove(oldPath); err != nil {
		return err
	}

	// 移动新文件到目标位置（原子操作）
	if err := os.Rename(newPath, oldPath); err != nil {
		return err
	}

	// 设置正确的权限
	return os.Chmod(oldPath, oldMode)
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}

	// 复制权限
	sourceInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	return os.Chmod(dst, sourceInfo.Mode())
}
