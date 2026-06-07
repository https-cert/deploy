package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

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

type archiveEntry struct {
	name    string
	content string
}

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
