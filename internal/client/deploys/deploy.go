package deploys

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	CertsDir        = "certs"                           // 证书临时存储目录
	FeiNiuFixedPath = "/usr/trim/var/trim_connect/ssls" // 飞牛固定部署路径
)

// Deployer 证书部署器接口（为未来扩展预留）
type Deployer interface {
	Deploy(sourceDir, domain string) error
}

// CertDeployer 证书部署器
type CertDeployer struct {
	downloadFunc func(url, filePath string) error // 证书下载函数
}

// NewCertDeployer 创建证书部署器
func NewCertDeployer(downloadFunc func(url, filePath string) error) *CertDeployer {
	return &CertDeployer{
		downloadFunc: downloadFunc,
	}
}

// SanitizeDomain 处理泛域名，将 * 转换为 _
func SanitizeDomain(domain string) string {
	return strings.ReplaceAll(domain, "*", "_")
}

// DeployCertificate 部署证书（同时部署到所有配置的目标）
func (cd *CertDeployer) DeployCertificate(domain, url string) error {
	// 创建certs目录
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 处理泛域名，将 * 转换为 _
	safeDomain := SanitizeDomain(domain)

	// 文件名格式为 {domain}_certificates.zip
	fileName := fmt.Sprintf("%s_certificates.zip", safeDomain)
	zipFile := filepath.Join(CertsDir, fileName)

	// 下载zip文件
	if err := cd.downloadFunc(url, zipFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", zipFile)

	// 确保下载失败时清理
	defer func() {
		if _, err := os.Stat(zipFile); err == nil {
			// 部署成功后删除zip文件
			os.Remove(zipFile)
		}
	}()

	// 检查是否配置了SSL目录
	sslConfig := config.GetConfig().SSL
	nginxPath := sslConfig.NginxPath
	apachePath := sslConfig.ApachePath
	rustFSPath := sslConfig.RustFSPath
	feiNiuEnabled := sslConfig.FeiNiuEnabled
	onePanelEnabled := sslConfig.OnePanel != nil && sslConfig.OnePanel.URL != ""

	if nginxPath == "" && apachePath == "" && rustFSPath == "" && !feiNiuEnabled && !onePanelEnabled {
		logger.Info("未配置SSL目录，证书已下载", "file", zipFile)
		return nil
	}

	// 证书文件夹名（使用处理后的安全域名）
	folderName := safeDomain
	extractDir := filepath.Join(CertsDir, folderName)

	// 1. 解压zip文件
	if err := ExtractZip(zipFile, extractDir); err != nil {
		// 清理失败的解压文件
		os.RemoveAll(extractDir)
		return fmt.Errorf("解压证书失败: %w", err)
	}

	// 确保解压目录在部署完成后被清理
	defer os.RemoveAll(extractDir)

	// 2. 部署到 Nginx 目录
	if nginxPath != "" {
		if err := cd.DeployToNginx(extractDir, nginxPath, folderName, safeDomain); err != nil {
			return fmt.Errorf("部署到Nginx失败: %w", err)
		}
	}

	// 3. 部署到 Apache 目录
	if apachePath != "" {
		if err := cd.DeployToApache(extractDir, apachePath, folderName, safeDomain); err != nil {
			return fmt.Errorf("部署到Apache失败: %w", err)
		}
	}

	// 4. 部署到 RustFS 目录
	if rustFSPath != "" {
		if err := cd.DeployToRustFS(extractDir, rustFSPath, safeDomain); err != nil {
			return fmt.Errorf("部署到RustFS失败: %w", err)
		}
	}

	// 5. 部署到飞牛目录
	if feiNiuEnabled {
		if err := cd.DeployToFeiNiu(extractDir, FeiNiuFixedPath, domain); err != nil {
			return fmt.Errorf("部署到飞牛失败: %w", err)
		}
	}

	// 6. 部署到 1Panel 目录
	if onePanelEnabled {
		if err := cd.DeployTo1Panel(extractDir, domain); err != nil {
			return fmt.Errorf("部署到1Panel失败: %w", err)
		}
	}

	// 6. 检查nginx是否存在，如果存在则测试配置和重新加载
	if nginxPath != "" && IsNginxAvailable() {
		// 测试nginx配置
		if err := TestNginxConfig(); err != nil {
			logger.Warn("nginx配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := ReloadNginx(); err != nil {
				logger.Warn("nginx重新加载失败，请手动重启nginx", "error", err)
			}
		}
	} else if nginxPath != "" {
		logger.Info("nginx未安装或不在PATH中，跳过nginx相关操作")
	}

	// 7. 检查apache是否存在，如果存在则测试配置和重新加载
	if apachePath != "" && IsApacheAvailable() {
		// 测试apache配置
		if err := TestApacheConfig(); err != nil {
			logger.Warn("apache配置测试失败", "error", err)
		} else {
			// 配置测试通过才尝试重新加载
			if err := ReloadApache(); err != nil {
				logger.Warn("apache重新加载失败，请手动重启apache", "error", err)
			}
		}
	} else if apachePath != "" {
		logger.Info("apache未安装或不在PATH中，跳过apache相关操作")
	}

	logger.Info("自动部署流程完成", "domain", domain)
	return nil
}

// ExtractZip 解压zip文件
func ExtractZip(zipFile, extractDir string) error {
	// 创建解压目录
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("创建解压目录失败: %w", err)
	}

	// 打开zip文件
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("打开zip文件失败: %w", err)
	}
	defer reader.Close()

	// 解压所有文件
	for _, file := range reader.File {
		if err := extractZipFile(file, extractDir); err != nil {
			return err
		}
	}

	return nil
}

// extractZipFile 解压单个zip文件条目
func extractZipFile(file *zip.File, extractDir string) error {
	// 使用 filepath.Rel 安全地检查路径
	targetPath := filepath.Join(extractDir, file.Name)

	// 清理路径并检查符号链接
	cleanTarget := filepath.Clean(targetPath)
	rel, err := filepath.Rel(extractDir, cleanTarget)
	if err != nil || strings.HasPrefix(rel, "..") || strings.Contains(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("不安全的文件路径: %s", file.Name)
	}

	// 使用清理后的路径
	targetPath = cleanTarget

	// 创建目录
	if file.FileInfo().IsDir() {
		return os.MkdirAll(targetPath, file.FileInfo().Mode())
	}

	// 创建文件目录
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("创建文件目录失败: %w", err)
	}

	// 打开zip文件中的文件
	rc, err := file.Open()
	if err != nil {
		return fmt.Errorf("打开zip中的文件失败: %w", err)
	}
	defer rc.Close()

	// 创建目标文件
	outFile, err := os.Create(targetPath)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer outFile.Close()

	// 复制文件内容
	if _, err := io.Copy(outFile, rc); err != nil {
		return fmt.Errorf("复制文件内容失败: %w", err)
	}

	// 设置文件权限
	if err := os.Chmod(targetPath, file.FileInfo().Mode()); err != nil {
		return fmt.Errorf("设置文件权限失败: %w", err)
	}

	return nil
}

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
