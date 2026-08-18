package providers

import (
	"strings"
	"testing"

	"github.com/https-cert/deploy/pb/deployPB"
)

// TestBuildTargetRefAndStableIdentity 验证资源引用稳定性和资源生命周期身份回退。
func TestBuildTargetRefAndStableIdentity(t *testing.T) {
	first := BuildTargetRef(" Aliyun ", deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, " Resource-1 ")
	second := BuildTargetRef("aliyun", deployPB.DeploymentType_DEPLOYMENT_TYPE_CDN, "resource-1")
	if first != second || !strings.HasPrefix(first, "aliyun-cdn-") {
		t.Fatalf("targetRef 不稳定: first=%q second=%q", first, second)
	}
	if identity, ok := StableDomainIdentity(" stable-id ", "", ""); !ok || identity != "stable-id" {
		t.Fatalf("稳定 ID 未优先使用: identity=%q ok=%v", identity, ok)
	}
	if identity, ok := StableDomainIdentity("", "example.com", "2026-01-01"); !ok || identity != "example.com\x002026-01-01" {
		t.Fatalf("域名生命周期身份不匹配: identity=%q ok=%v", identity, ok)
	}
	if _, ok := StableDomainIdentity("", "example.com", ""); ok {
		t.Fatal("缺少创建时间时不应生成回退身份")
	}
}

// TestDeploymentTypeRefName 验证部署类型稳定转换成 targetRef 片段。
func TestDeploymentTypeRefName(t *testing.T) {
	if got := DeploymentTypeRefName(deployPB.DeploymentType_DEPLOYMENT_TYPE_OSS_CUSTOM_DOMAIN); got != "oss-custom-domain" {
		t.Fatalf("部署类型引用名称不匹配: %q", got)
	}
}

// TestNormalizeDomainAndDomains 验证域名规范化、通配符、端口、去重和非法输入处理。
func TestNormalizeDomainAndDomains(t *testing.T) {
	tests := []struct {
		name    string // name 是子测试名称。
		input   string // input 是待规范化域名。
		want    string // want 是期望规范化结果。
		wantErr bool   // wantErr 表示是否期望失败。
	}{
		{name: "普通域名", input: " Example.COM. ", want: "example.com"},
		{name: "通配符", input: "*.Example.COM", want: "*.example.com"},
		{name: "带端口", input: "example.com:443", want: "example.com"},
		{name: "国际化域名", input: "例子.测试", want: "xn--fsqu00a.xn--0zwm56d"},
		{name: "空值", input: "", wantErr: true},
		{name: "包含路径", input: "example.com/path", wantErr: true},
		{name: "多重通配符", input: "*.*.example.com", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeDomain(test.input)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("NormalizeDomain(%q) = %q, %v; want %q, wantErr=%v", test.input, got, err, test.want, test.wantErr)
			}
		})
	}

	domains := NormalizeDomains("B.example.com", "a.example.com", "b.EXAMPLE.com", "bad/path")
	if len(domains) != 2 || domains[0] != "a.example.com" || domains[1] != "b.example.com" {
		t.Fatalf("域名集合规范化不匹配: %v", domains)
	}
}

// TestFindResourceByTargetRef 验证精确匹配、空引用、失效引用和重复引用。
func TestFindResourceByTargetRef(t *testing.T) {
	ready := DeploymentResource{TargetRef: "target-1", Domain: "example.com", Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY}
	resource, err := FindResourceByTargetRef([]DeploymentResource{ready}, " target-1 ")
	if err != nil || resource.Domain != ready.Domain {
		t.Fatalf("精确资源匹配失败: resource=%+v err=%v", resource, err)
	}
	for name, resources := range map[string][]DeploymentResource{
		"空引用":  nil,
		"失效引用": {{TargetRef: "other"}},
		"重复引用": {ready, ready},
	} {
		t.Run(name, func(t *testing.T) {
			targetRef := "target-1"
			if name == "空引用" {
				targetRef = ""
			}
			if _, err := FindResourceByTargetRef(resources, targetRef); err == nil {
				t.Fatal("异常 targetRef 应返回错误")
			}
		})
	}
}

// TestEnsureResourceReady 验证只允许 READY 资源执行部署。
func TestEnsureResourceReady(t *testing.T) {
	if err := EnsureResourceReady(DeploymentResource{Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_READY}); err != nil {
		t.Fatalf("READY 资源被拒绝: %v", err)
	}
	if err := EnsureResourceReady(DeploymentResource{Availability: deployPB.DeploymentResourceAvailability_DEPLOYMENT_RESOURCE_AVAILABILITY_DISABLED}); err == nil {
		t.Fatal("不可用资源应被拒绝")
	}
}
