package deploys

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testTarEntry struct {
	name     string
	body     string
	mode     int64
	typeflag byte
}

func TestExtractTarExtractsRegularFiles(t *testing.T) {
	tempDir := t.TempDir()
	tarPath := filepath.Join(tempDir, "certificates.tar")
	extractDir := filepath.Join(tempDir, "extract")

	writeTestTar(t, tarPath, []testTarEntry{
		{name: "nested", mode: 0o755, typeflag: tar.TypeDir},
		{name: "cert.pem", body: "cert", mode: 0o644, typeflag: tar.TypeReg},
		{name: "nested/privateKey.key", body: "key", mode: 0o600, typeflag: tar.TypeReg},
		{name: "ignored-link", mode: 0o777, typeflag: tar.TypeSymlink},
	})

	if err := ExtractTar(tarPath, extractDir); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	assertFileContent(t, filepath.Join(extractDir, "cert.pem"), "cert")
	assertFileContent(t, filepath.Join(extractDir, "nested", "privateKey.key"), "key")

	if _, err := os.Stat(filepath.Join(extractDir, "ignored-link")); !os.IsNotExist(err) {
		t.Fatalf("expected symlink entry to be skipped, got err=%v", err)
	}
}

func TestExtractTarRejectsUnsafePath(t *testing.T) {
	tempDir := t.TempDir()
	tarPath := filepath.Join(tempDir, "certificates.tar")
	extractDir := filepath.Join(tempDir, "extract")

	writeTestTar(t, tarPath, []testTarEntry{
		{name: "../escape.pem", body: "bad", mode: 0o644, typeflag: tar.TypeReg},
	})

	err := ExtractTar(tarPath, extractDir)
	if err == nil {
		t.Fatal("ExtractTar() expected unsafe path error")
	}
	if !strings.Contains(err.Error(), "不安全的文件路径") {
		t.Fatalf("expected unsafe path error, got %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(tempDir, "escape.pem")); !os.IsNotExist(statErr) {
		t.Fatalf("unsafe file should not be written, stat err=%v", statErr)
	}
}

func TestExtractTarExtractsGzipCompressedTar(t *testing.T) {
	tempDir := t.TempDir()
	tarPath := filepath.Join(tempDir, "certificates.tar")
	extractDir := filepath.Join(tempDir, "extract")

	writeTestTarGzip(t, tarPath, []testTarEntry{
		{name: "cert.pem", body: "cert-from-gzip", mode: 0o644, typeflag: tar.TypeReg},
	})

	if err := ExtractTar(tarPath, extractDir); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	assertFileContent(t, filepath.Join(extractDir, "cert.pem"), "cert-from-gzip")
}

func TestExtractTarExtractsLegacyZip(t *testing.T) {
	tempDir := t.TempDir()
	tarPath := filepath.Join(tempDir, "certificates.tar")
	extractDir := filepath.Join(tempDir, "extract")

	writeTestZip(t, tarPath, map[string]string{
		"cert.pem":        "cert-from-zip",
		"privateKey.key":  "key-from-zip",
		"nested/full.pem": "fullchain-from-zip",
	})

	if err := ExtractTar(tarPath, extractDir); err != nil {
		t.Fatalf("ExtractTar() error = %v", err)
	}

	assertFileContent(t, filepath.Join(extractDir, "cert.pem"), "cert-from-zip")
	assertFileContent(t, filepath.Join(extractDir, "privateKey.key"), "key-from-zip")
	assertFileContent(t, filepath.Join(extractDir, "nested", "full.pem"), "fullchain-from-zip")
}

func TestExtractTarReportsInvalidArchiveHeader(t *testing.T) {
	tempDir := t.TempDir()
	tarPath := filepath.Join(tempDir, "certificates.tar")
	extractDir := filepath.Join(tempDir, "extract")

	if err := os.WriteFile(tarPath, []byte("证书不存在\n"), 0o644); err != nil {
		t.Fatalf("write invalid archive: %v", err)
	}

	err := ExtractTar(tarPath, extractDir)
	if err == nil {
		t.Fatal("ExtractTar() expected invalid archive error")
	}
	if !strings.Contains(err.Error(), "文件头") {
		t.Fatalf("expected header summary in error, got %v", err)
	}
}

func writeTestTar(t *testing.T, tarPath string, entries []testTarEntry) {
	t.Helper()

	file, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("create tar: %v", err)
	}
	defer file.Close()

	writer := tar.NewWriter(file)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
			Typeflag: entry.typeflag,
		}
		if entry.typeflag == tar.TypeDir {
			header.Size = 0
		}

		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write tar header %q: %v", entry.name, err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write tar body %q: %v", entry.name, err)
			}
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
}

func writeTestTarGzip(t *testing.T, tarPath string, entries []testTarEntry) {
	t.Helper()

	file, err := os.Create(tarPath)
	if err != nil {
		t.Fatalf("create gzip tar: %v", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	writer := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name:     entry.name,
			Mode:     entry.mode,
			Size:     int64(len(entry.body)),
			Typeflag: entry.typeflag,
		}
		if entry.typeflag == tar.TypeDir {
			header.Size = 0
		}

		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write gzip tar header %q: %v", entry.name, err)
		}
		if header.Size > 0 {
			if _, err := writer.Write([]byte(entry.body)); err != nil {
				t.Fatalf("write gzip tar body %q: %v", entry.name, err)
			}
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip tar writer: %v", err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
}

func writeTestZip(t *testing.T, zipPath string, entries map[string]string) {
	t.Helper()

	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer file.Close()

	writer := zip.NewWriter(file)
	for name, body := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %q: %v", name, err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("expected %s to contain %q, got %q", path, want, string(got))
	}
}
