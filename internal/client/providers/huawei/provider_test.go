package huawei

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/sdkerr"
	cdnmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/cdn/v2/model"
	scmmodel "github.com/huaweicloud/huaweicloud-sdk-go-v3/services/scm/v3/model"
)

// fakeHuaweiSCMClient 实现华为云 SCM 测试控制面。
type fakeHuaweiSCMClient struct {
	certificateID   string // certificateID 是已导入证书 ID。
	certificateName string // certificateName 是指纹派生名称。
	fingerprint     string // fingerprint 是证书 SHA-1 指纹。
	importCalls     int    // importCalls 记录真实导入次数。
}

// ListCertificates 返回可供幂等复用的 SCM 证书目录。
func (f *fakeHuaweiSCMClient) ListCertificates(*scmmodel.ListCertificatesRequest) (*scmmodel.ListCertificatesResponse, error) {
	items := []scmmodel.CertificateDetail{}
	if f.certificateID != "" {
		items = append(items, scmmodel.CertificateDetail{Id: f.certificateID, Name: f.certificateName, Status: "UPLOAD"})
	}
	total := int32(len(items))
	return &scmmodel.ListCertificatesResponse{Certificates: &items, TotalCount: &total}, nil
}

// ImportCertificate 保存导入证书名称并返回稳定 ID。
func (f *fakeHuaweiSCMClient) ImportCertificate(request *scmmodel.ImportCertificateRequest) (*scmmodel.ImportCertificateResponse, error) {
	f.importCalls++
	f.certificateID = "certificate-1"
	f.certificateName = request.Body.Name
	return &scmmodel.ImportCertificateResponse{CertificateId: huaweiStringPointer(f.certificateID)}, nil
}

// ShowCertificate 返回导入后的 SCM 状态与指纹。
func (f *fakeHuaweiSCMClient) ShowCertificate(*scmmodel.ShowCertificateRequest) (*scmmodel.ShowCertificateResponse, error) {
	return &scmmodel.ShowCertificateResponse{Id: huaweiStringPointer(f.certificateID), Name: huaweiStringPointer(f.certificateName), Status: huaweiStringPointer("UPLOAD"), Fingerprint: huaweiStringPointer(f.fingerprint)}, nil
}

// fakeHuaweiCDNClient 实现华为云 CDN 测试控制面。
type fakeHuaweiCDNClient struct {
	domains        []cdnmodel.Domains      // domains 是 fake 域名目录。
	listError      error                   // listError 是目录读取错误。
	detail         *cdnmodel.DomainsDetail // detail 是部署前域名详情。
	certificateID  string                  // certificateID 是更新后的 SCM 证书 ID。
	certificatePEM string                  // certificatePEM 是更新后的证书内容。
	updateCalls    int                     // updateCalls 记录更新次数。
}

// ListDomains 返回 fake CDN 域名目录。
func (f *fakeHuaweiCDNClient) ListDomains(*cdnmodel.ListDomainsRequest) (*cdnmodel.ListDomainsResponse, error) {
	if f.listError != nil {
		return nil, f.listError
	}
	total := int32(len(f.domains))
	items := append([]cdnmodel.Domains(nil), f.domains...)
	return &cdnmodel.ListDomainsResponse{Total: &total, Domains: &items, XRequestId: huaweiStringPointer("request-list")}, nil
}

// ShowDomainDetailByName 返回部署目标当前身份。
func (f *fakeHuaweiCDNClient) ShowDomainDetailByName(*cdnmodel.ShowDomainDetailByNameRequest) (*cdnmodel.ShowDomainDetailByNameResponse, error) {
	return &cdnmodel.ShowDomainDetailByNameResponse{Domain: f.detail, XRequestId: huaweiStringPointer("request-detail")}, nil
}

// ShowDomainFullConfig 返回部署前或更新后的 HTTPS 配置。
func (f *fakeHuaweiCDNClient) ShowDomainFullConfig(*cdnmodel.ShowDomainFullConfigRequest) (*cdnmodel.ShowDomainFullConfigResponse, error) {
	httpsStatus := "off"
	certificateSource := int32(0)
	certificateID := ""
	if f.certificateID != "" {
		httpsStatus = "on"
		certificateSource = 2
		certificateID = f.certificateID
	}
	config := &cdnmodel.ConfigsGetBody{OriginProtocol: huaweiStringPointer("follow"), Https: &cdnmodel.HttpGetBody{HttpsStatus: &httpsStatus, CertificateSource: &certificateSource, ScmCertificateId: &certificateID, CertificateValue: &f.certificatePEM, Http2Status: huaweiStringPointer("on")}}
	return &cdnmodel.ShowDomainFullConfigResponse{Configs: config, XRequestId: huaweiStringPointer("request-config")}, nil
}

// UpdateDomainMultiCertificates 保存精确域名绑定的 SCM 证书 ID。
func (f *fakeHuaweiCDNClient) UpdateDomainMultiCertificates(request *cdnmodel.UpdateDomainMultiCertificatesRequest) (*cdnmodel.UpdateDomainMultiCertificatesResponse, error) {
	f.updateCalls++
	f.certificateID = stringPointerValue(request.Body.Https.ScmCertificateId)
	result := []cdnmodel.UpdateDomainMultiCertificatesResponseBodyResult{{DomainName: huaweiStringPointer(request.Body.Https.DomainName), Status: huaweiStringPointer("success")}}
	return &cdnmodel.UpdateDomainMultiCertificatesResponse{Status: huaweiStringPointer("success"), Result: &result, XRequestId: huaweiStringPointer("request-update")}, nil
}

// TestHuaweiOfflineOrchestration 验证华为云 CDN 部分发现、精确解析、SCM 导入和配置回读。
func TestHuaweiOfflineOrchestration(t *testing.T) {
	certificate := generateHuaweiCertificate(t, "www.example.com")
	fingerprint, err := leafCertificateSHA1(certificate.CertificatePEM)
	if err != nil {
		t.Fatalf("计算测试证书指纹失败: %v", err)
	}
	valid := huaweiDomain("domain-1", "www.example.com", "web", "online", 100)
	invalid := cdnmodel.Domains{DomainName: huaweiStringPointer("invalid.example.com")}
	detail := huaweiDomainDetail("domain-1", "www.example.com", "web", "online", 100)
	scm := &fakeHuaweiSCMClient{fingerprint: fingerprint}
	cdn := &fakeHuaweiCDNClient{domains: []cdnmodel.Domains{valid, invalid}, detail: &detail, certificatePEM: certificate.CertificatePEM}
	provider := newWithClients("access-key", "secret-key", "cn-north-4", "cn-north-4", []string{"cn-north-4"}, scm, cdn, nil, nil)

	if ok, err := provider.TestConnection(context.Background()); !ok || err != nil {
		t.Fatalf("连接测试失败: ok=%v err=%v", ok, err)
	}
	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(catalog.Resources) != 1 {
		t.Fatalf("部分资源发现不匹配: %+v", catalog)
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil || resolved.Domain != "www.example.com" {
		t.Fatalf("精确 targetRef 解析失败: resource=%+v err=%v", resolved, err)
	}
	if err := provider.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err != nil {
		t.Fatalf("资源测试失败: %v", err)
	}
	result, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil || result.RequestID != "request-config" || scm.importCalls != 1 || cdn.updateCalls != 1 {
		t.Fatalf("证书部署失败: result=%+v imports=%d updates=%d err=%v", result, scm.importCalls, cdn.updateCalls, err)
	}
	if err := provider.UploadCertificate(context.Background(), certificate); err != nil || scm.importCalls != 1 {
		t.Fatalf("SCM 证书复用失败: imports=%d err=%v", scm.importCalls, err)
	}

	changed := huaweiDomainDetail("domain-1", "www.example.com", "web", "online", 200)
	cdn.detail = &changed
	if _, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource); err == nil {
		t.Fatal("生命周期变化后的资源应被拒绝")
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

// TestHuaweiEmptyPermissionAndConfiguration 验证空目录、权限不足和未配置状态。
func TestHuaweiEmptyPermissionAndConfiguration(t *testing.T) {
	empty := newWithClients("access-key", "secret-key", "cn-north-4", "cn-north-4", nil, &fakeHuaweiSCMClient{}, &fakeHuaweiCDNClient{}, nil, nil)
	if catalog := empty.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatalf("空目录状态不匹配: %+v", catalog)
	}
	denied := sdkerr.ServiceResponseError{StatusCode: http.StatusForbidden, RequestId: "request-denied", ErrorCode: "CDN.0002", ErrorMessage: "forbidden"}
	permission := newWithClients("access-key", "secret-key", "cn-north-4", "cn-north-4", nil, &fakeHuaweiSCMClient{}, &fakeHuaweiCDNClient{listError: &denied}, nil, nil)
	if catalog := permission.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限不足状态不匹配: %+v", catalog)
	}
	unconfigured := newWithClients("", "", "cn-north-4", "cn-north-4", nil, nil, nil, nil, nil)
	if catalog := unconfigured.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置状态不匹配: %+v", catalog)
	}
}

// huaweiDomain 构造一条华为云 CDN 域名列表记录。
func huaweiDomain(id, domain, businessType, status string, createdAt int64) cdnmodel.Domains {
	zero := int32(0)
	return cdnmodel.Domains{Id: &id, DomainName: &domain, BusinessType: &businessType, DomainStatus: &status, CreateTime: &createdAt, Disabled: &zero, Locked: &zero}
}

// huaweiDomainDetail 构造一条华为云 CDN 域名详情记录。
func huaweiDomainDetail(id, domain, businessType, status string, createdAt int64) cdnmodel.DomainsDetail {
	zero := int32(0)
	return cdnmodel.DomainsDetail{Id: &id, DomainName: &domain, BusinessType: &businessType, DomainStatus: &status, CreateTime: &createdAt, Disabled: &zero, Locked: &zero}
}

// huaweiStringPointer 返回字符串副本的地址。
func huaweiStringPointer(value string) *string {
	return &value
}

// generateHuaweiCertificate 生成覆盖指定域名的离线 RSA 证书材料。
func generateHuaweiCertificate(t *testing.T, domain string) providers.CertificateMaterial {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	return providers.CertificateMaterial{Name: "huawei-test", Domain: domain, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))}
}
