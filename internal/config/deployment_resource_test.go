package config

import "testing"

// TestValidateCloudflareProviderCredentials 要求 Cloudflare DNS 配置提供本地 API Token。
func TestValidateCloudflareProviderCredentials(t *testing.T) {
	if err := validateProviderCredentials(&Provider{
		Name: ProviderCloudflare,
		Auth: &ProviderAuth{APIToken: "  token  "},
	}, ""); err != nil {
		t.Fatalf("有效 Cloudflare API Token 被拒绝：%v", err)
	}
	if err := validateProviderCredentials(&Provider{
		Name: ProviderCloudflare,
		Auth: &ProviderAuth{},
	}, ""); err == nil {
		t.Fatal("缺少 Cloudflare API Token 时仍通过校验")
	}
}
