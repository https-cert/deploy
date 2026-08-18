package dogecloud

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// TestDogeCloudOfflineOrchestration 验证多吉云资源发现、精确解析、上传、绑定和回读闭环。
func TestDogeCloudOfflineOrchestration(t *testing.T) {
	certificate := generateDogeCloudCertificate(t, "www.example.com")
	var stateMu sync.Mutex
	certificateID := ""
	certificateNote := ""
	boundCertificateID := ""
	domainEnabled := true
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.Header.Get("Authorization"), "TOKEN access-key:") {
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("X-Request-Id", "request-dogecloud")
		stateMu.Lock()
		defer stateMu.Unlock()
		switch request.URL.Path {
		case "/cdn/domain/list.json":
			domains := []map[string]any{}
			if domainEnabled {
				domains = append(domains, map[string]any{"id": "domain-1", "name": "www.example.com", "certId": boundCertificateID, "status": "online"})
			}
			writeDogeCloudResponse(t, response, map[string]any{"domains": domains})
		case "/cdn/cert/list.json":
			certificates := []map[string]any{}
			if certificateID != "" {
				certificates = append(certificates, map[string]any{"id": certificateID, "note": certificateNote})
			}
			writeDogeCloudResponse(t, response, map[string]any{"certs": certificates})
		case "/cdn/cert/upload.json":
			payload := map[string]any{}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("解析上传请求失败: %v", err)
			}
			certificateID = "certificate-1"
			certificateNote, _ = payload["note"].(string)
			writeDogeCloudResponse(t, response, map[string]any{"id": certificateID})
		case "/cdn/cert/bind.json":
			payload := map[string]any{}
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Errorf("解析绑定请求失败: %v", err)
			}
			if payload["domain"] != "www.example.com" || payload["id"] != "certificate-1" {
				t.Errorf("绑定目标不匹配: %+v", payload)
			}
			boundCertificateID, _ = payload["id"].(string)
			writeDogeCloudResponse(t, response, map[string]any{})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	provider := NewWithOptions("access-key", "access-secret", &Options{HTTPClient: server.Client(), APIBaseURL: server.URL})
	if ok, err := provider.TestConnection(context.Background()); !ok || err != nil {
		t.Fatalf("连接测试失败: ok=%v err=%v", ok, err)
	}
	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != 1 {
		t.Fatalf("资源发现失败: %+v", catalog)
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil || resolved.Domain != "www.example.com" {
		t.Fatalf("精确资源解析失败: resource=%+v err=%v", resolved, err)
	}
	if err := provider.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err != nil {
		t.Fatalf("资源测试失败: %v", err)
	}
	result, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil || result.RequestID != "request-dogecloud" || boundCertificateID != "certificate-1" {
		t.Fatalf("证书部署失败: result=%+v bound=%q err=%v", result, boundCertificateID, err)
	}
	if err := provider.UploadCertificate(context.Background(), certificate); err != nil {
		t.Fatalf("已有证书复用失败: %v", err)
	}

	stateMu.Lock()
	domainEnabled = false
	stateMu.Unlock()
	if catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatalf("空目录状态不匹配: %+v", catalog)
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err == nil {
		t.Fatal("失效 targetRef 应返回错误")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if catalog := provider.DiscoverResources(canceled, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Error == nil {
		t.Fatalf("取消发现应返回错误: %+v", catalog)
	}
	if catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_DCDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_UNAVAILABLE {
		t.Fatalf("不支持业务状态不匹配: %+v", catalog)
	}
}

// TestDogeCloudPermissionAndConfiguration 验证权限不足、缺少凭据和停止资源分类。
func TestDogeCloudPermissionAndConfiguration(t *testing.T) {
	permissionServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("X-Request-Id", "request-denied")
		http.Error(response, "denied", http.StatusForbidden)
	}))
	defer permissionServer.Close()
	provider := NewWithOptions("access-key", "access-secret", &Options{HTTPClient: permissionServer.Client(), APIBaseURL: permissionServer.URL})
	if catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限不足状态不匹配: %+v", catalog)
	}
	if catalog := New("", "").DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置状态不匹配: %+v", catalog)
	}
}

// writeDogeCloudResponse 写入统一的多吉云 fake API 成功响应。
func writeDogeCloudResponse(t *testing.T, response http.ResponseWriter, data map[string]any) {
	t.Helper()
	if err := json.NewEncoder(response).Encode(map[string]any{"code": http.StatusOK, "msg": "ok", "data": data}); err != nil {
		t.Errorf("写入 fake API 响应失败: %v", err)
	}
}

// generateDogeCloudCertificate 生成覆盖指定域名的离线 RSA 证书材料。
func generateDogeCloudCertificate(t *testing.T, domain string) providers.CertificateMaterial {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	return providers.CertificateMaterial{
		Name:           "dogecloud-test",
		Domain:         domain,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})),
	}
}
