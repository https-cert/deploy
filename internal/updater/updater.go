package updater

import (
	"archive/zip"
	"compress/gzip"
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
	"strconv"
	"strings"
	"time"

	"archive/tar"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	githubRepo      = "https-cert/deploy"
	githubAPIURL    = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
	downloadTimeout = 10 * time.Minute
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
		currentVersion = "v0.4.0"
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
	tempDir, err := os.MkdirTemp("", "anssl-update-*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 下载新版本（可能是压缩包）
	downloadPath := filepath.Join(tempDir, info.BinaryName)
	if err := downloadFile(ctx, info.DownloadURL, downloadPath); err != nil {
		return fmt.Errorf("下载新版本失败: %w", err)
	}

	// 解包获取可执行文件路径
	newBinaryPath, err := extractBinary(downloadPath, tempDir)
	if err != nil {
		return fmt.Errorf("解压新版本失败: %w", err)
	}

	// 下载并验证 checksum（针对下载的压缩包/文件本身进行校验）
	if info.ChecksumURL != "" {
		checksumPath := filepath.Join(tempDir, "checksums.txt")
		if err := downloadFile(ctx, info.ChecksumURL, checksumPath); err != nil {
			return fmt.Errorf("下载校验文件失败: %w", err)
		} else {
			if err := verifyChecksum(downloadPath, checksumPath, info.BinaryName); err != nil {
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
	req.Header.Set("User-Agent", "anssl-updater")
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
	currentVer, errCurr := parseSemanticVersion(current)
	latestVer, errLatest := parseSemanticVersion(latest)
	if errCurr == nil && errLatest == nil {
		return latestVer.compare(currentVer) > 0
	}

	// 解析失败时降级为简单比较
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")
	return latest != current
}

type semanticVersion struct {
	major      int
	minor      int
	patch      int
	prerelease string
}

func parseSemanticVersion(raw string) (semanticVersion, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	if raw == "" {
		return semanticVersion{}, fmt.Errorf("empty version")
	}

	var prerelease string
	if idx := strings.Index(raw, "-"); idx >= 0 {
		prerelease = raw[idx+1:]
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, "+"); idx >= 0 {
		raw = raw[:idx]
	}

	parts := strings.Split(raw, ".")
	if len(parts) == 0 {
		return semanticVersion{}, fmt.Errorf("invalid version: %s", raw)
	}

	parsePart := func(idx int) (int, error) {
		if idx >= len(parts) || parts[idx] == "" {
			return 0, nil
		}
		return strconv.Atoi(parts[idx])
	}

	major, err := parsePart(0)
	if err != nil {
		return semanticVersion{}, err
	}
	minor, err := parsePart(1)
	if err != nil {
		return semanticVersion{}, err
	}
	patch, err := parsePart(2)
	if err != nil {
		return semanticVersion{}, err
	}

	return semanticVersion{
		major:      major,
		minor:      minor,
		patch:      patch,
		prerelease: prerelease,
	}, nil
}

func (v semanticVersion) compare(other semanticVersion) int {
	if v.major != other.major {
		if v.major > other.major {
			return 1
		}
		return -1
	}

	if v.minor != other.minor {
		if v.minor > other.minor {
			return 1
		}
		return -1
	}

	if v.patch != other.patch {
		if v.patch > other.patch {
			return 1
		}
		return -1
	}

	if v.prerelease == other.prerelease {
		return 0
	}

	if v.prerelease == "" {
		return 1
	}
	if other.prerelease == "" {
		return -1
	}

	return strings.Compare(v.prerelease, other.prerelease)
}

// getBinaryName 根据当前系统获取二进制文件名
func getBinaryName() string {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	var name string
	switch goos {
	case "darwin":
		if goarch == "arm64" {
			name = "anssl-darwin-arm64.tar.gz"
		} else {
			name = "anssl-darwin-amd64.tar.gz"
		}
	case "linux":
		if goarch == "arm64" {
			name = "anssl-linux-arm64.tar.gz"
		} else {
			name = "anssl-linux-amd64.tar.gz"
		}
	case "windows":
		if goarch == "arm64" {
			name = "anssl-windows-arm64.zip"
		} else {
			name = "anssl-windows-amd64.zip"
		}
	default:
		name = fmt.Sprintf("anssl-%s-%s.tar.gz", goos, goarch)
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

// extractBinary 从下载的文件中提取可执行文件。
// 支持 .tar.gz、.zip，如果是普通文件则直接返回原路径。
func extractBinary(downloadPath, tempDir string) (string, error) {
	name := filepath.Base(downloadPath)

	// tar.gz 压缩包
	if strings.HasSuffix(name, ".tar.gz") {
		f, err := os.Open(downloadPath)
		if err != nil {
			return "", err
		}
		defer f.Close()

		gzr, err := gzip.NewReader(f)
		if err != nil {
			return "", err
		}
		defer gzr.Close()

		tr := tar.NewReader(gzr)

		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", err
			}

			if hdr.Typeflag != tar.TypeReg {
				continue
			}

			dstPath := filepath.Join(tempDir, filepath.Base(hdr.Name))
			out, err := os.Create(dstPath)
			if err != nil {
				return "", err
			}

			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return "", err
			}
			out.Close()
			return dstPath, nil
		}

		return "", fmt.Errorf("压缩包中未找到可执行文件")
	}

	// zip 压缩包
	if strings.HasSuffix(name, ".zip") {
		r, err := zip.OpenReader(downloadPath)
		if err != nil {
			return "", err
		}
		defer r.Close()

		for _, f := range r.File {
			if f.FileInfo().IsDir() {
				continue
			}

			rc, err := f.Open()
			if err != nil {
				return "", err
			}

			dstPath := filepath.Join(tempDir, filepath.Base(f.Name))
			out, err := os.Create(dstPath)
			if err != nil {
				rc.Close()
				return "", err
			}

			if _, err := io.Copy(out, rc); err != nil {
				rc.Close()
				out.Close()
				return "", err
			}

			rc.Close()
			out.Close()
			return dstPath, nil
		}

		return "", fmt.Errorf("压缩包中未找到可执行文件")
	}

	// 普通文件，直接返回
	return downloadPath, nil
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
