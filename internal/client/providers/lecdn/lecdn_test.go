package lecdn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// leCDNHTTPClientFunc 将函数适配为 LeCDN 离线测试客户端。
type leCDNHTTPClientFunc func(*http.Request) (*http.Response, error)

// Do 执行测试定义的 HTTP 请求逻辑。
func (function leCDNHTTPClientFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

// TestDiscoverResourcesAndResolveExactTarget 验证证书引用聚合与精确 targetRef 解析。
func TestDiscoverResourcesAndResolveExactTarget(t *testing.T) {
	var siteRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/site":
			siteRequests.Add(1)
			writeLeCDNData(writer, `{"items":[{"id":1,"domain_name":"site","domain_status":"active"}],"total":1,"current_page":1,"page_size":100}`)
		case "/site/1/domain_name":
			writeLeCDNData(writer, `[{"id":11,"site_id":1,"domain_name":"cdn.example.com","certificate_enable":true,"certificate_id":7}]`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newLeCDNTestProvider(server)
	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != 1 {
		t.Fatalf("unexpected catalog: %#v", catalog)
	}
	if siteRequests.Load() != 1 {
		t.Fatalf("site pagination requests = %d, want 1", siteRequests.Load())
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil {
		t.Fatalf("ResolveResource() error = %v", err)
	}
	if resolved.ResourceID != "7" || resolved.Domain != "cdn.example.com" {
		t.Fatalf("resolved resource = %#v", resolved)
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "lecdn:missing"); err == nil {
		t.Fatal("ResolveResource() unexpectedly accepted stale targetRef")
	}
}

// TestDiscoverResourcesEmptyPartialAndPermissionDenied 验证 LeCDN 目录状态分类。
func TestDiscoverResourcesEmptyPartialAndPermissionDenied(t *testing.T) {
	tests := []struct {
		name          string
		permission    bool
		empty         bool
		domainFailure bool
		wantStatus    deployPB.DeploymentResourceStatus
		wantResources int
	}{
		{name: "empty", empty: true, wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY},
		{name: "partial", domainFailure: true, wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL, wantResources: 1},
		{name: "permission", permission: true, wantStatus: deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/site" {
					if test.permission {
						http.Error(writer, "forbidden", http.StatusForbidden)
						return
					}
					if test.empty {
						writeLeCDNData(writer, `{"items":[],"total":0}`)
						return
					}
					writeLeCDNData(writer, `{"items":[{"id":1},{"id":2}],"total":2}`)
					return
				}
				if test.domainFailure && request.URL.Path == "/site/2/domain_name" {
					http.Error(writer, "temporary", http.StatusServiceUnavailable)
					return
				}
				writeLeCDNData(writer, `[{"id":11,"site_id":1,"domain_name":"cdn.example.com","certificate_enable":true,"certificate_id":7}]`)
			}))
			defer server.Close()
			catalog := newLeCDNTestProvider(server).DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
			if catalog.Status != test.wantStatus || len(catalog.Resources) != test.wantResources {
				t.Fatalf("catalog status=%s resources=%d error=%v", catalog.Status, len(catalog.Resources), catalog.Error)
			}
		})
	}
}

// TestDiscoverResourcesHonorsCancellation 验证 LeCDN 请求继承调用方取消状态。
func TestDiscoverResourcesHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	provider := NewWithOptions("https://lecdn.invalid", "token", &Options{HTTPClient: leCDNHTTPClientFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})})
	catalog := provider.DiscoverResources(ctx, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE || !errors.Is(catalog.Error, context.Canceled) {
		t.Fatalf("canceled catalog = %#v", catalog)
	}
}

// TestDeployCertificateUpdatesReadsBackAndSyncs 验证 fake 部署完成原地更新、回读和站点同步。
func TestDeployCertificateUpdatesReadsBackAndSyncs(t *testing.T) {
	certificatePEM, privateKeyPEM := generateLeCDNCertificate(t, "cdn.example.com")
	encodedCertificate := base64.StdEncoding.EncodeToString([]byte(certificatePEM))
	var updated atomic.Bool
	var synced atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Request-ID", "lecdn-request")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/certificate/7":
			writeLeCDNData(writer, fmt.Sprintf(`{"name":"certificate","ssl_pem":%q,"status":"active","not_after":"2026-12-01"}`, encodedCertificate))
		case request.Method == http.MethodPut && request.URL.Path == "/certificate/7":
			updated.Store(true)
			writeLeCDNData(writer, `{}`)
		case request.Method == http.MethodPost && request.URL.Path == "/site/1/force_sync":
			synced.Store(true)
			writeLeCDNData(writer, `{}`)
		case request.Method == http.MethodGet && request.URL.Path == "/site/1/sync_status":
			writeLeCDNData(writer, `{"status":"success","task_id":9}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	provider := newLeCDNTestProvider(server)
	result, err := provider.DeployCertificate(context.Background(), providers.CertificateMaterial{
		Name:           "certificate",
		Domain:         "cdn.example.com",
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  privateKeyPEM,
	}, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, providers.DeploymentResource{
		TargetRef:  "lecdn-target",
		ResourceID: "7",
		Domain:     "cdn.example.com",
		Domains:    []string{"cdn.example.com"},
		SiteIDs:    []string{"1"},
	})
	if err != nil {
		t.Fatalf("DeployCertificate() error = %v", err)
	}
	if !updated.Load() || !synced.Load() || result.RequestID != "lecdn-request" {
		t.Fatalf("result=%#v updated=%v synced=%v", result, updated.Load(), synced.Load())
	}
}

// newLeCDNTestProvider 创建连接 httptest 服务的 LeCDN provider。
func newLeCDNTestProvider(server *httptest.Server) *Provider {
	return NewWithOptions(server.URL, "token", &Options{HTTPClient: server.Client(), PollInterval: time.Millisecond, SyncTimeout: time.Second})
}

// writeLeCDNData 写入 LeCDN 成功响应包络。
func writeLeCDNData(writer http.ResponseWriter, data string) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write([]byte(`{"code":0,"message":"ok","data":` + data + `}`))
}

// generateLeCDNCertificate 生成离线部署测试使用的自签名证书和匹配私钥。
func generateLeCDNCertificate(t *testing.T, domain string) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	return strings.TrimSpace(string(certificatePEM)) + "\n", strings.TrimSpace(string(privateKeyPEM)) + "\n"
}
