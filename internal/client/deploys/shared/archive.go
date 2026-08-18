package shared

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// OperationContextError 返回部署操作当前的取消或超时状态。
func OperationContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

const (
	CertsDir             = "certs" // CertsDir 是证书临时存储目录。
	archiveFormatTar     = "tar"
	archiveFormatTarGzip = "tar.gz"
	archiveFormatZip     = "zip"
	maxArchiveFileSize   = int64(16 << 20) // 单个证书归档条目最大 16 MiB。
	maxArchiveTotalSize  = int64(64 << 20) // 证书归档解压后最大 64 MiB。
	maxArchiveEntries    = 256             // 证书归档最多允许 256 个条目。
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
	case tar.TypeReg, 0: // 0 是旧版 tar 普通文件标记，需继续兼容已有证书归档。
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
