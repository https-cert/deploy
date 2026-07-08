package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestExtractBinaryTarGzFindsExecutableByName 验证 tar.gz 包中可以按名称提取可执行文件。
func TestExtractBinaryTarGzFindsExecutableByName(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "anssl-linux-amd64.tar.gz")

	writeTarGzArchive(t, archivePath, []archiveEntry{
		{name: "config.example.yaml", content: "server:\n  accessKey: template\n"},
		{name: "anssl", content: "binary-content"},
	})

	extractedPath, err := extractBinaryNamed(archivePath, tempDir, "anssl")
	if err != nil {
		t.Fatalf("extractBinaryNamed() error = %v", err)
	}

	assertFileContent(t, extractedPath, "binary-content")
}

// TestExtractBinaryZipFindsExecutableByName 验证 zip 包中可以按名称提取可执行文件。
func TestExtractBinaryZipFindsExecutableByName(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "anssl-windows-amd64.zip")

	writeZipArchive(t, archivePath, []archiveEntry{
		{name: "config.example.yaml", content: "server:\n  accessKey: template\n"},
		{name: "anssl.exe", content: "windows-binary-content"},
	})

	extractedPath, err := extractBinaryNamed(archivePath, tempDir, "anssl.exe")
	if err != nil {
		t.Fatalf("extractBinaryNamed() error = %v", err)
	}

	assertFileContent(t, extractedPath, "windows-binary-content")
}

// TestExtractBinaryTarGzMissingExecutable 验证压缩包缺少可执行文件时返回错误。
func TestExtractBinaryTarGzMissingExecutable(t *testing.T) {
	tempDir := t.TempDir()
	archivePath := filepath.Join(tempDir, "anssl-linux-amd64.tar.gz")

	writeTarGzArchive(t, archivePath, []archiveEntry{
		{name: "config.example.yaml", content: "server:\n  accessKey: template\n"},
	})

	if _, err := extractBinaryNamed(archivePath, tempDir, "anssl"); err == nil {
		t.Fatal("extractBinaryNamed() error = nil, want error")
	}
}

// TestSmokeTestBinaryRunsVersion 验证 smoke test 会执行新二进制的 version 命令。
func TestSmokeTestBinaryRunsVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script smoke test is Unix-only")
	}

	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "anssl")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo v-test; exit 0; fi\nexit 1\n"), 0755); err != nil {
		t.Fatalf("write smoke binary: %v", err)
	}

	if err := smokeTestBinary(context.Background(), binaryPath); err != nil {
		t.Fatalf("smokeTestBinary() error = %v", err)
	}
}

// TestSmokeTestBinaryFails 验证 smoke test 会拒绝执行失败的新二进制。
func TestSmokeTestBinaryFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script smoke test is Unix-only")
	}

	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "anssl")
	if err := os.WriteFile(binaryPath, []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatalf("write smoke binary: %v", err)
	}

	if err := smokeTestBinary(context.Background(), binaryPath); err == nil {
		t.Fatal("smokeTestBinary() error = nil, want error")
	}
}

// TestRestoreBackupRestoresMissingExecutable 验证目标文件缺失时可以从备份恢复。
func TestRestoreBackupRestoresMissingExecutable(t *testing.T) {
	tempDir := t.TempDir()
	execPath := filepath.Join(tempDir, "anssl")
	backupPath := backupPathFor(execPath)
	if err := os.WriteFile(backupPath, []byte("backup-binary"), 0755); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	if err := restoreBackup(backupPath, execPath); err != nil {
		t.Fatalf("restoreBackup() error = %v", err)
	}

	assertFileContent(t, execPath, "backup-binary")
	assertFileContent(t, backupPath, "backup-binary")
}

// TestRestoreBackupReplacesExistingExecutable 验证目标文件存在时可以从备份替换恢复。
func TestRestoreBackupReplacesExistingExecutable(t *testing.T) {
	tempDir := t.TempDir()
	execPath := filepath.Join(tempDir, "anssl")
	backupPath := backupPathFor(execPath)
	if err := os.WriteFile(execPath, []byte("current-binary"), 0755); err != nil {
		t.Fatalf("write current binary: %v", err)
	}
	if err := os.WriteFile(backupPath, []byte("backup-binary"), 0755); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	if err := restoreBackup(backupPath, execPath); err != nil {
		t.Fatalf("restoreBackup() error = %v", err)
	}

	assertFileContent(t, execPath, "backup-binary")
	assertFileContent(t, backupPath, "backup-binary")
}

type archiveEntry struct {
	// name 是压缩包内文件名。
	name string
	// content 是压缩包内文件内容。
	content string
}

// writeTarGzArchive 写入测试用 tar.gz 压缩包。
func writeTarGzArchive(t *testing.T, archivePath string, entries []archiveEntry) {
	t.Helper()

	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	for _, entry := range entries {
		content := []byte(entry.content)
		if err := tw.WriteHeader(&tar.Header{
			Name: entry.name,
			Mode: 0755,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("write tar header: %v", err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatalf("write tar content: %v", err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
}

// writeZipArchive 写入测试用 zip 压缩包。
func writeZipArchive(t *testing.T, archivePath string, entries []archiveEntry) {
	t.Helper()

	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("create zip archive: %v", err)
	}
	defer file.Close()

	zw := zip.NewWriter(file)
	for _, entry := range entries {
		writer, err := zw.Create(entry.name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := writer.Write([]byte(entry.content)); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
}

// assertFileContent 断言文件内容等于预期字符串。
func assertFileContent(t *testing.T, filePath, want string) {
	t.Helper()

	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(got) != want {
		t.Fatalf("extracted content = %q, want %q", got, want)
	}
}
