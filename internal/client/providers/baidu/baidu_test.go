package baidu

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/baidubce/bce-sdk-go/bce"
	cdnapi "github.com/baidubce/bce-sdk-go/services/cdn/api"
	certservice "github.com/baidubce/bce-sdk-go/services/cert"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// fakeBaiduCDNClient 实现百度云 CDN 单元测试所需的最小控制面。
type fakeBaiduCDNClient struct {
	domains       map[string][]string             // domains 按 marker 保存分页域名。
	nextMarkers   map[string]string               // nextMarkers 保存下一页 marker。
	configs       map[string]*cdnapi.DomainConfig // configs 保存域名详情。
	configErrors  map[string]error                // configErrors 保存详情读取错误。
	httpsConfigs  map[string]*cdnapi.HTTPSConfig  // httpsConfigs 保存 HTTPS 配置。
	listError     error                           // listError 是分页读取错误。
	listCalls     int                             // listCalls 记录分页调用次数。
	updatedDomain string                          // updatedDomain 是最近更新的域名。
}

// ListDomains 返回 marker 对应的 fake 域名页。
func (f *fakeBaiduCDNClient) ListDomains(marker string) ([]string, string, error) {
	f.listCalls++
	if f.listError != nil {
		return nil, "", f.listError
	}
	return append([]string(nil), f.domains[marker]...), f.nextMarkers[marker], nil
}

// GetDomainConfig 返回 fake 域名详情。
func (f *fakeBaiduCDNClient) GetDomainConfig(domain string) (*cdnapi.DomainConfig, error) {
	if err := f.configErrors[domain]; err != nil {
		return nil, err
	}
	return f.configs[domain], nil
}

// GetDomainHttps 返回 fake HTTPS 配置副本。
func (f *fakeBaiduCDNClient) GetDomainHttps(domain string) (*cdnapi.HTTPSConfig, error) {
	configuration := f.httpsConfigs[domain]
	if configuration == nil {
		return nil, nil
	}
	copy := *configuration
	return &copy, nil
}

// SetDomainHttps 保存 fake HTTPS 配置。
func (f *fakeBaiduCDNClient) SetDomainHttps(domain string, configuration *cdnapi.HTTPSConfig) error {
	f.updatedDomain = domain
	copy := *configuration
	f.httpsConfigs[domain] = &copy
	return nil
}

// fakeBaiduCertificateClient 实现百度云证书托管测试控制面。
type fakeBaiduCertificateClient struct {
	certificates []certservice.CertificateDetailMeta // certificates 是证书目录。
	fingerprint  string                              // fingerprint 是上传后回读指纹。
	created      int                                 // created 记录上传次数。
}

// CreateCert 保存上传证书元数据并返回稳定 ID。
func (f *fakeBaiduCertificateClient) CreateCert(args *certservice.CreateCertArgs) (*certservice.CreateCertResult, error) {
	f.created++
	certificate := certservice.CertificateDetailMeta{CertId: "certificate-1", CertName: args.CertName, CertFingerprint: f.fingerprint}
	f.certificates = append(f.certificates, certificate)
	return &certservice.CreateCertResult{CertId: certificate.CertId, CertName: certificate.CertName}, nil
}

// ListCertDetail 返回 fake 证书目录。
func (f *fakeBaiduCertificateClient) ListCertDetail() (*certservice.ListCertDetailResult, error) {
	return &certservice.ListCertDetailResult{Certs: append([]certservice.CertificateDetailMeta(nil), f.certificates...)}, nil
}

// GetCertDetail 按 ID 返回 fake 证书详情。
func (f *fakeBaiduCertificateClient) GetCertDetail(id string) (*certservice.CertificateDetailMeta, error) {
	for index := range f.certificates {
		if f.certificates[index].CertId == id {
			copy := f.certificates[index]
			return &copy, nil
		}
	}
	return nil, errors.New("certificate not found")
}

// TestBaiduOfflineOrchestration 验证百度云分页发现、部分成功、精确解析和部署闭环。
func TestBaiduOfflineOrchestration(t *testing.T) {
	certificate := generateBaiduCertificate(t, "www.example.com")
	fingerprint, err := providers.LeafCertificateSHA256(certificate.CertificatePEM)
	if err != nil {
		t.Fatalf("计算测试证书指纹失败: %v", err)
	}
	cdn := &fakeBaiduCDNClient{
		domains:      map[string][]string{"": {"www.example.com", "broken.example.com"}, "page-2": {"api.example.com"}},
		nextMarkers:  map[string]string{"": "page-2"},
		configs:      map[string]*cdnapi.DomainConfig{},
		configErrors: map[string]error{"broken.example.com": errors.New("detail failed")},
		httpsConfigs: map[string]*cdnapi.HTTPSConfig{"www.example.com": {Http2Enabled: true}},
	}
	cdn.configs["www.example.com"] = &cdnapi.DomainConfig{Domain: "www.example.com", CreateTime: "2026-01-01T00:00:00Z", Status: "RUNNING"}
	cdn.configs["api.example.com"] = &cdnapi.DomainConfig{Domain: "api.example.com", CreateTime: "2026-01-02T00:00:00Z", Status: "STOPPED"}
	certificates := &fakeBaiduCertificateClient{fingerprint: fingerprint}
	provider := newWithClients("access-key", "secret-key", cdn, certificates)

	if ok, err := provider.TestConnection(context.Background()); !ok || err != nil {
		t.Fatalf("连接测试失败: ok=%v err=%v", ok, err)
	}
	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(catalog.Resources) != 2 || cdn.listCalls < 2 {
		t.Fatalf("分页部分发现不匹配: catalog=%+v calls=%d", catalog, cdn.listCalls)
	}
	resource := catalog.Resources[1]
	if resource.Domain != "www.example.com" {
		t.Fatalf("资源排序不匹配: %+v", catalog.Resources)
	}
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil || resolved.Domain != resource.Domain {
		t.Fatalf("精确 targetRef 解析失败: resource=%+v err=%v", resolved, err)
	}
	if err := provider.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err != nil {
		t.Fatalf("资源测试失败: %v", err)
	}
	result, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil || result.Message == "" || cdn.updatedDomain != "www.example.com" || certificates.created != 1 {
		t.Fatalf("证书部署失败: result=%+v domain=%q created=%d err=%v", result, cdn.updatedDomain, certificates.created, err)
	}
	if configuration := cdn.httpsConfigs["www.example.com"]; configuration == nil || !configuration.Enabled || configuration.CertId != "certificate-1" || !configuration.Http2Enabled {
		t.Fatalf("HTTPS 配置未正确保留和更新: %+v", configuration)
	}
	if err := provider.UploadCertificate(context.Background(), certificate); err != nil || certificates.created != 1 {
		t.Fatalf("已有证书复用失败: created=%d err=%v", certificates.created, err)
	}

	cdn.configs["www.example.com"] = &cdnapi.DomainConfig{Domain: "www.example.com", CreateTime: "changed", Status: "RUNNING"}
	if _, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource); err == nil {
		t.Fatal("删除重建后的资源应被拒绝")
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "stale-target"); err == nil {
		t.Fatal("失效 targetRef 应返回错误")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if catalog := provider.DiscoverResources(canceled, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Error == nil {
		t.Fatalf("取消发现应返回错误: %+v", catalog)
	}
}

// TestBaiduEmptyPermissionAndConfiguration 验证空目录、权限不足和未配置状态。
func TestBaiduEmptyPermissionAndConfiguration(t *testing.T) {
	empty := newWithClients("access-key", "secret-key", &fakeBaiduCDNClient{domains: map[string][]string{}, nextMarkers: map[string]string{}, configs: map[string]*cdnapi.DomainConfig{}, configErrors: map[string]error{}, httpsConfigs: map[string]*cdnapi.HTTPSConfig{}}, &fakeBaiduCertificateClient{})
	if catalog := empty.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatalf("空目录状态不匹配: %+v", catalog)
	}
	denied := bce.NewBceServiceError(bce.EACCESS_DENIED, "denied", "request-denied", http.StatusForbidden)
	permission := newWithClients("access-key", "secret-key", &fakeBaiduCDNClient{listError: denied}, &fakeBaiduCertificateClient{})
	if catalog := permission.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限不足状态不匹配: %+v", catalog)
	}
	unconfigured := newWithClients("", "", nil, nil)
	if catalog := unconfigured.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置状态不匹配: %+v", catalog)
	}
}

// generateBaiduCertificate 生成覆盖指定域名的离线 RSA 证书材料。
func generateBaiduCertificate(t *testing.T, domain string) providers.CertificateMaterial {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	return providers.CertificateMaterial{
		Name:           "baidu-test",
		Domain:         domain,
		CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})),
		PrivateKeyPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})),
	}
}
