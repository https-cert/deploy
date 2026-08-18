package aliyun

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/pb/deployPB"
)

// fakeAliyunDeploymentAPI 实现阿里云 OpenAPI adapter 测试控制面。
type fakeAliyunDeploymentAPI struct {
	domains       []map[string]any // domains 是完整 fake CDN 域名目录。
	pageError     int              // pageError 指定返回错误的页码。
	listError     error            // listError 是第一页目录错误。
	writtenName   string           // writtenName 是最近提交的证书名称。
	writtenDomain string           // writtenDomain 是最近更新的域名。
	listCalls     int              // listCalls 记录目录分页次数。
	writeCalls    int              // writeCalls 记录证书更新次数。
}

// Call 根据 action 返回 fake OpenAPI 响应并校验 context。
func (f *fakeAliyunDeploymentAPI) Call(ctx context.Context, request cloudAPIRequest) (cloudAPIResponse, error) {
	if err := ctx.Err(); err != nil {
		return cloudAPIResponse{}, err
	}
	switch request.Action {
	case "DescribeUserDomains":
		f.listCalls++
		page, _ := strconv.Atoi(request.Query["PageNumber"])
		if page <= 0 {
			page = 1
		}
		if f.listError != nil || f.pageError == page {
			if f.listError != nil {
				return cloudAPIResponse{}, f.listError
			}
			return cloudAPIResponse{}, errors.New("page failed")
		}
		start := (page - 1) * aliyunCatalogPageSize
		if start > len(f.domains) {
			start = len(f.domains)
		}
		end := start + aliyunCatalogPageSize
		if end > len(f.domains) {
			end = len(f.domains)
		}
		pageRecords := append([]map[string]any(nil), f.domains[start:end]...)
		return cloudAPIResponse{RequestID: fmt.Sprintf("request-page-%d", page), Body: map[string]any{"PageData": pageRecords, "TotalCount": len(f.domains)}}, nil
	case "DescribeCdnDomainDetail":
		return cloudAPIResponse{RequestID: "request-detail", Body: map[string]any{"GetDomainDetailModel": map[string]any{"DomainName": request.Query["DomainName"], "ServerCertificateStatus": "on"}}}, nil
	case "SetCdnDomainSSLCertificate":
		f.writeCalls++
		f.writtenName = request.Query["CertName"]
		f.writtenDomain = request.Query["DomainName"]
		if request.Query["SSLPri"] == "" || request.Query["SSLPub"] == "" {
			return cloudAPIResponse{}, errors.New("missing certificate material")
		}
		return cloudAPIResponse{RequestID: "request-write", Body: map[string]any{}}, nil
	case "DescribeDomainCertificateInfo":
		return cloudAPIResponse{RequestID: "request-readback", Body: map[string]any{"CertInfos": map[string]any{"CertInfo": []map[string]any{{"CertName": f.writtenName, "Status": "success"}}}}}, nil
	default:
		return cloudAPIResponse{}, fmt.Errorf("unexpected action: %s", request.Action)
	}
}

// TestAliyunOfflineOrchestration 验证阿里云 CDN 分页、精确解析、部署和回读闭环。
func TestAliyunOfflineOrchestration(t *testing.T) {
	domains := make([]map[string]any, 0, aliyunCatalogPageSize+1)
	for index := 0; index <= aliyunCatalogPageSize; index++ {
		domains = append(domains, map[string]any{"DomainName": fmt.Sprintf("d%03d.example.com", index), "DomainStatus": "online", "HttpsSwitch": "on", "GmtCreated": fmt.Sprintf("created-%03d", index)})
	}
	api := &fakeAliyunDeploymentAPI{domains: domains}
	provider := &Provider{AccessKeyId: "access-key", AccessKeySecret: "secret-key", deploymentAPI: api}
	certificate := generateAliyunCertificate(t, "d000.example.com")

	catalog := provider.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN)
	if catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY || len(catalog.Resources) != aliyunCatalogPageSize+1 || api.listCalls != 2 {
		t.Fatalf("分页资源发现失败: catalog=%+v calls=%d", catalog, api.listCalls)
	}
	resource := catalog.Resources[0]
	resolved, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef)
	if err != nil || resolved.Domain != "d000.example.com" {
		t.Fatalf("精确 targetRef 解析失败: resource=%+v err=%v", resolved, err)
	}
	if err := provider.TestResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource.TargetRef); err != nil {
		t.Fatalf("资源测试失败: %v", err)
	}
	result, err := provider.DeployCertificate(context.Background(), certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource)
	if err != nil || result.RequestID != "request-write" || api.writeCalls != 1 || api.writtenDomain != "d000.example.com" || api.writtenName == "" {
		t.Fatalf("证书部署失败: result=%+v writes=%d domain=%q name=%q err=%v", result, api.writeCalls, api.writtenDomain, api.writtenName, err)
	}
	if _, err := provider.ResolveResource(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "stale-target"); err == nil {
		t.Fatal("失效 targetRef 应返回错误")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if catalog := provider.DiscoverResources(canceled, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Error == nil {
		t.Fatalf("取消发现应返回错误: %+v", catalog)
	}
	if _, err := provider.DeployCertificate(canceled, certificate, deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, resource); err == nil {
		t.Fatal("取消部署应返回错误")
	}
}

// TestAliyunPartialEmptyPermissionAndConfiguration 验证部分成功、空目录、权限和配置状态。
func TestAliyunPartialEmptyPermissionAndConfiguration(t *testing.T) {
	domains := make([]map[string]any, aliyunCatalogPageSize+1)
	for index := range domains {
		domains[index] = map[string]any{"DomainName": fmt.Sprintf("p%03d.example.com", index), "DomainStatus": "online", "HttpsSwitch": "on", "GmtCreated": fmt.Sprintf("created-%03d", index)}
	}
	partialAPI := &fakeAliyunDeploymentAPI{domains: domains, pageError: 2}
	partial := &Provider{AccessKeyId: "access-key", AccessKeySecret: "secret-key", deploymentAPI: partialAPI}
	if catalog := partial.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PARTIAL || len(catalog.Resources) != aliyunCatalogPageSize {
		t.Fatalf("部分成功状态不匹配: %+v", catalog)
	}
	empty := &Provider{AccessKeyId: "access-key", AccessKeySecret: "secret-key", deploymentAPI: &fakeAliyunDeploymentAPI{}}
	if catalog := empty.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatalf("空目录状态不匹配: %+v", catalog)
	}
	denied := &cloudAPIError{StatusCode: 403, Code: "Forbidden", RequestID: "request-denied"}
	permission := &Provider{AccessKeyId: "access-key", AccessKeySecret: "secret-key", deploymentAPI: &fakeAliyunDeploymentAPI{listError: denied}}
	if catalog := permission.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_PERMISSION_DENIED {
		t.Fatalf("权限不足状态不匹配: %+v", catalog)
	}
	unconfigured := &Provider{deploymentAPI: &fakeAliyunDeploymentAPI{}}
	if catalog := unconfigured.DiscoverResources(context.Background(), deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN); catalog.Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatalf("未配置状态不匹配: %+v", catalog)
	}
}

// generateAliyunCertificate 生成覆盖指定域名的离线 RSA 证书材料。
func generateAliyunCertificate(t *testing.T, domain string) providers.CertificateMaterial {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(6), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	return providers.CertificateMaterial{Name: "aliyun-test", Domain: domain, CertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})), PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))}
}
