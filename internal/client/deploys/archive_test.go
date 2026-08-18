package deploys

import (
	"context"
	"os"
	"testing"
)

// TestPrepareCertificateArchiveCleansTemporaryFiles 验证解压失败会清理下载归档和临时目录。
func TestPrepareCertificateArchiveCleansTemporaryFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	deployer := NewCertDeployer(Options{DownloadFunc: func(_ context.Context, _ string, target string) error {
		return os.WriteFile(target, []byte("invalid archive"), 0600)
	}})
	if _, _, _, _, err := deployer.prepareCertificateArchive(context.Background(), "example.com", "https://example.com/archive"); err == nil {
		t.Fatal("invalid archive should fail")
	}
	entries, err := os.ReadDir(CertsDir)
	if err != nil {
		t.Fatalf("read certificate temp directory: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary archive files were not cleaned: %+v", entries)
	}
}
