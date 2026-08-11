package deploys

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pkg/logger"
)

const (
	CertsDir            = "certs"                           // 证书临时存储目录
	FeiNiuFixedPath     = "/usr/trim/var/trim_connect/ssls" // 飞牛固定部署路径
	maxArchiveFileSize  = int64(16 << 20)                   // 单个证书归档条目最大 16 MiB
	maxArchiveTotalSize = int64(64 << 20)                   // 证书归档解压后最大 64 MiB
	maxArchiveEntries   = 256                               // 证书归档最多允许 256 个条目
)

// Deployer 证书部署器接口（为未来扩展预留）
type Deployer interface {
	Deploy(sourceDir, domain string) error
}

// CertDeployer 证书部署器
type CertDeployer struct {
	downloadFunc func(url, filePath string) error // 证书下载函数
}

type publishTargetLock struct {
	mu   sync.Mutex // mu serializes publication for one target path.
	refs int        // refs tracks active users of the lock.
}

var (
	publishLocksMu sync.Mutex
	publishLocks   = make(map[string]*publishTargetLock)
)

// NewCertDeployer 创建证书部署器
func NewCertDeployer(downloadFunc func(url, filePath string) error) *CertDeployer {
	return &CertDeployer{
		downloadFunc: downloadFunc,
	}
}

// prepareCertificateArchive validates a domain, downloads its archive and returns a temporary extraction directory.
func (cd *CertDeployer) prepareCertificateArchive(domain, downloadURL string) (canonicalDomain, safeDomain, extractDir string, cleanup func(), err error) {
	canonicalDomain, safeDomain, err = NormalizeDeploymentDomain(domain)
	if err != nil {
		return "", "", "", nil, err
	}
	if cd == nil || cd.downloadFunc == nil {
		return "", "", "", nil, fmt.Errorf("证书下载函数未初始化")
	}
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return "", "", "", nil, fmt.Errorf("创建证书目录失败: %w", err)
	}

	archivePath, err := newTemporaryArchivePath(safeDomain)
	if err != nil {
		return "", "", "", nil, err
	}
	extractDir, err = os.MkdirTemp(CertsDir, "."+safeDomain+"-extract-*")
	if err != nil {
		_ = os.Remove(archivePath)
		return "", "", "", nil, fmt.Errorf("创建临时解压目录失败: %w", err)
	}

	cleanup = func() {
		_ = os.Remove(archivePath)
		_ = os.RemoveAll(extractDir)
	}
	if err := cd.downloadFunc(downloadURL, archivePath); err != nil {
		cleanup()
		return "", "", "", nil, fmt.Errorf("下载证书失败: %w", err)
	}
	logger.Info("证书下载完成", "file", archivePath)
	if err := ExtractTar(archivePath, extractDir); err != nil {
		cleanup()
		return "", "", "", nil, fmt.Errorf("解压证书失败: %w", err)
	}
	return canonicalDomain, safeDomain, extractDir, cleanup, nil
}

// newTemporaryArchivePath creates a unique archive path below the certificate directory.
func newTemporaryArchivePath(safeDomain string) (string, error) {
	tempFile, err := os.CreateTemp(CertsDir, "."+safeDomain+"-archive-*")
	if err != nil {
		return "", fmt.Errorf("创建临时归档文件失败: %w", err)
	}
	path := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("关闭临时归档文件失败: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("清理临时归档文件失败: %w", err)
	}
	return path, nil
}

// SanitizeDomain returns the filesystem-safe representation of a valid deployment domain.
func SanitizeDomain(domain string) string {
	_, safeName, err := NormalizeDeploymentDomain(domain)
	if err != nil {
		return ""
	}
	return safeName
}

// DeployCertificate 部署证书（同时部署到所有配置的目标）
func (cd *CertDeployer) DeployCertificate(domain, url string) error {
	if cd == nil || cd.downloadFunc == nil {
		return fmt.Errorf("证书下载函数未初始化")
	}
	canonicalDomain, safeDomain, err := NormalizeDeploymentDomain(domain)
	if err != nil {
		return err
	}
	domain = canonicalDomain

	// 创建certs目录
	if err := os.MkdirAll(CertsDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %w", err)
	}

	// 文件名格式为 {domain}_certificates.tar
	tarFile, err := newTemporaryArchivePath(safeDomain)
	if err != nil {
		return err
	}

	// 下载tar文件
	if err := cd.downloadFunc(url, tarFile); err != nil {
		return fmt.Errorf("下载证书失败: %w", err)
	}

	logger.Info("证书下载完成", "file", tarFile)

	// 确保下载失败时清理
	defer func() {
		if _, err := os.Stat(tarFile); err == nil {
			// 部署成功后删除tar文件
			os.Remove(tarFile)
		}
	}()

	// 检查是否配置了SSL目录
	sslConfig := config.GetConfig().SSL
	nginxPath := sslConfig.NginxPath
	apachePath := sslConfig.ApachePath
	rustFS := sslConfig.RustFS
	onePanelEnabled := sslConfig.OnePanel != nil && sslConfig.OnePanel.URL != ""
	safeLineEnabled := sslConfig.SafeLine != nil && sslConfig.SafeLine.URL != "" && sslConfig.SafeLine.APIToken != ""
	rustFSEnabled := rustFS != nil && rustFS.Path != ""

	if nginxPath == "" && apachePath == "" && !rustFSEnabled && !onePanelEnabled && !safeLineEnabled {
		logger.Info("未配置SSL目录，证书已下载", "file", tarFile)
		return nil
	}

	// 证书文件夹名（使用处理后的安全域名）
	folderName := safeDomain
	extractDir, err := os.MkdirTemp(CertsDir, "."+folderName+"-extract-*")
	if err != nil {
		return err
	}

	// 1. 解压tar文件
	if err := ExtractTar(tarFile, extractDir); err != nil {
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
	if rustFSEnabled {
		var rustFSErr error
		if config.IsSSHConfigured(&rustFS.SSHConfig) {
			rustFSErr = cd.DeployToRemoteRustFS(extractDir, safeDomain, rustFS)
		} else {
			rustFSErr = cd.DeployToRustFS(extractDir, rustFS.Path, safeDomain)
		}
		if rustFSErr != nil {
			return fmt.Errorf("部署到RustFS失败: %w", rustFSErr)
		}
	}

	// 5. 部署到 1Panel 目录
	if onePanelEnabled {
		if err := cd.DeployTo1Panel(extractDir, domain); err != nil {
			return fmt.Errorf("部署到1Panel失败: %w", err)
		}
	}

	// 6. 部署到雷池 WAF
	if safeLineEnabled {
		if err := cd.DeployToSafeLine(extractDir, domain); err != nil {
			return fmt.Errorf("部署到雷池失败: %w", err)
		}
	}

	// 7. 检查nginx是否存在，如果存在则测试配置和重新加载
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

	// 8. 检查apache是否存在，如果存在则测试配置和重新加载
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

const (
	archiveFormatTar     = "tar"
	archiveFormatTarGzip = "tar.gz"
	archiveFormatZip     = "zip"
)

// ExtractTar 解压证书压缩包。
// 当前证书包标准格式为 tar；这里兼容 tar.gz 和旧版 zip，避免前后端版本短暂不一致时部署失败。
func ExtractTar(tarFile, extractDir string) error {
	cleanExtractDir := filepath.Clean(extractDir)
	if strings.TrimSpace(extractDir) == "" || cleanExtractDir == "." || cleanExtractDir == string(filepath.Separator) || filepath.VolumeName(cleanExtractDir) != "" && filepath.Dir(cleanExtractDir) == cleanExtractDir {
		return fmt.Errorf("解压目录不安全")
	}
	// 解压目录只保存本次归档内容，避免遗留符号链接影响文件创建。
	if err := os.RemoveAll(extractDir); err != nil {
		return fmt.Errorf("清理解压目录失败: %w", err)
	}
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("创建解压目录失败: %w", err)
	}
	completed := false
	defer func() {
		if !completed {
			_ = os.RemoveAll(extractDir)
		}
	}()

	// 打开tar文件
	reader, err := os.Open(tarFile)
	if err != nil {
		return fmt.Errorf("打开tar文件失败: %w", err)
	}
	defer reader.Close()

	bufferedReader := bufio.NewReader(reader)
	header, err := bufferedReader.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return fmt.Errorf("读取压缩包文件头失败: %w", err)
	}

	var extractErr error
	switch detectArchiveFormat(header) {
	case archiveFormatTarGzip:
		gzipReader, err := gzip.NewReader(bufferedReader)
		if err != nil {
			return fmt.Errorf("打开gzip压缩tar失败: %w", err)
		}
		defer gzipReader.Close()
		extractErr = extractTarReader(tar.NewReader(gzipReader), extractDir, archiveHeaderSummary(header))
	case archiveFormatZip:
		extractErr = extractZipArchive(tarFile, extractDir)
	default:
		extractErr = extractTarReader(tar.NewReader(bufferedReader), extractDir, archiveHeaderSummary(header))
	}
	if extractErr != nil {
		return extractErr
	}
	completed = true
	return nil
}

func detectArchiveFormat(header []byte) string {
	if len(header) >= 2 && header[0] == 0x1f && header[1] == 0x8b {
		return archiveFormatTarGzip
	}
	if len(header) >= 4 {
		switch string(header[:4]) {
		case "PK\x03\x04", "PK\x05\x06", "PK\x07\x08":
			return archiveFormatZip
		}
	}
	return archiveFormatTar
}

func archiveHeaderSummary(header []byte) string {
	if len(header) == 0 {
		return "<empty>"
	}

	const maxHeaderSummaryBytes = 64
	if len(header) > maxHeaderSummaryBytes {
		header = header[:maxHeaderSummaryBytes]
	}

	printable := make([]byte, 0, len(header))
	for _, b := range header {
		if b >= 32 && b <= 126 {
			printable = append(printable, b)
		} else {
			printable = append(printable, '.')
		}
	}

	return fmt.Sprintf("ascii=%q hex=%s", string(printable), hex.EncodeToString(header))
}

func extractTarReader(tarReader *tar.Reader, extractDir, headerSummary string) error {
	// 解压所有文件
	firstEntry := true
	var totalSize int64
	entryCount := 0
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if firstEntry {
				return fmt.Errorf("读取tar文件失败: %w, 文件头: %s", err, headerSummary)
			}
			return fmt.Errorf("读取tar文件失败: %w", err)
		}
		firstEntry = false
		entryCount++
		if entryCount > maxArchiveEntries {
			return fmt.Errorf("证书归档条目数量超过限制: %d", maxArchiveEntries)
		}
		if header.Size < 0 || header.Size > maxArchiveFileSize || totalSize > maxArchiveTotalSize-header.Size {
			return fmt.Errorf("证书归档解压大小超过限制")
		}
		totalSize += header.Size

		if err := extractTarFile(header, tarReader, extractDir); err != nil {
			return err
		}
	}
}

// extractTarFile 解压单个tar文件条目
func extractTarFile(header *tar.Header, reader io.Reader, extractDir string) error {
	if header == nil || header.Name == "" {
		return nil
	}

	targetPath, err := safeArchiveTarget(extractDir, header.Name)
	if err != nil {
		return err
	}

	mode := archiveFileMode(header.Name, os.FileMode(header.Mode))
	switch header.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(targetPath, 0755)
	case tar.TypeReg, tar.TypeRegA:
		// 继续处理普通文件
	default:
		// 跳过符号链接、硬链接和设备文件等特殊条目
		return nil
	}

	// 创建文件目录
	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("创建文件目录失败: %w", err)
	}

	// 创建目标文件
	outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer outFile.Close()

	// 复制文件内容
	if _, err := io.CopyN(outFile, reader, header.Size); err != nil {
		return fmt.Errorf("复制文件内容失败: %w", err)
	}

	// 设置文件权限
	if err := os.Chmod(targetPath, mode); err != nil {
		return fmt.Errorf("设置文件权限失败: %w", err)
	}

	return nil
}

func safeArchiveTarget(extractDir, entryName string) (string, error) {
	if filepath.IsAbs(entryName) || filepath.VolumeName(entryName) != "" || strings.Contains(entryName, "\\") || (len(entryName) >= 3 && entryName[1] == ':' && (entryName[2] == '/' || entryName[2] == '\\')) {
		return "", fmt.Errorf("不安全的文件路径: %s", entryName)
	}
	cleanEntry := filepath.Clean(entryName)
	if cleanEntry == "." || cleanEntry == ".." || strings.HasPrefix(cleanEntry, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("不安全的文件路径: %s", entryName)
	}

	targetPath := filepath.Join(extractDir, entryName)

	// 清理路径并检查符号链接
	cleanTarget := filepath.Clean(targetPath)
	rel, err := filepath.Rel(extractDir, cleanTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("不安全的文件路径: %s", entryName)
	}

	return cleanTarget, nil
}

func extractZipArchive(zipFile, extractDir string) error {
	reader, err := zip.OpenReader(zipFile)
	if err != nil {
		return fmt.Errorf("打开zip文件失败: %w", err)
	}
	defer reader.Close()

	if len(reader.File) > maxArchiveEntries {
		return fmt.Errorf("证书归档条目数量超过限制: %d", maxArchiveEntries)
	}
	var totalSize int64
	for _, file := range reader.File {
		entrySize := int64(file.UncompressedSize64)
		if entrySize < 0 || entrySize > maxArchiveFileSize || totalSize > maxArchiveTotalSize-entrySize {
			return fmt.Errorf("证书归档解压大小超过限制")
		}
		totalSize += entrySize
		if err := extractZipFile(file, extractDir); err != nil {
			return err
		}
	}

	return nil
}

func extractZipFile(file *zip.File, extractDir string) error {
	if file == nil || file.Name == "" {
		return nil
	}

	targetPath, err := safeArchiveTarget(extractDir, file.Name)
	if err != nil {
		return err
	}

	info := file.FileInfo()
	if info.IsDir() {
		mode := info.Mode().Perm()
		if mode == 0 {
			mode = 0755
		}
		return os.MkdirAll(targetPath, mode)
	}
	if !info.Mode().IsRegular() {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("创建文件目录失败: %w", err)
	}

	reader, err := file.Open()
	if err != nil {
		return fmt.Errorf("打开zip文件条目失败: %w", err)
	}
	defer reader.Close()

	mode := archiveFileMode(file.Name, info.Mode())
	outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer outFile.Close()

	if _, err := io.CopyN(outFile, reader, int64(file.UncompressedSize64)); err != nil {
		return fmt.Errorf("复制文件内容失败: %w", err)
	}

	if err := os.Chmod(targetPath, mode); err != nil {
		return fmt.Errorf("设置文件权限失败: %w", err)
	}

	return nil
}

// archiveFileMode returns a conservative permission mode for extracted certificate files.
func archiveFileMode(name string, _ os.FileMode) os.FileMode {
	if strings.EqualFold(filepath.Base(name), "privateKey.key") || strings.HasSuffix(strings.ToLower(name), ".key") {
		return 0600
	}
	return 0644
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

// PublishDirectoryWithRollback 将新目录发布到目标路径，并在失败时尽量恢复旧目录。
func PublishDirectoryWithRollback(sourceDir, targetDir string) error {
	return publishDirectoryWithRollback(sourceDir, targetDir, nil)
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
	if err := os.Rename(sourceDir, targetDir); err != nil {
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
