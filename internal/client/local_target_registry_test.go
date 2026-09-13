package client

import (
	"context"
	"errors"
	"testing"

	"github.com/https-cert/deploy/internal/client/deploys"
	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/https-cert/deploy/internal/config"
	"github.com/https-cert/deploy/pb/deployPB"
)

// connectionOnlyProvider 只实现连接测试与动态资源，模拟 LeCDN（无证书中心上传）。
type connectionOnlyProvider struct {
	tested bool
}

func (p *connectionOnlyProvider) TestConnection(context.Context) (bool, error) {
	p.tested = true
	return true, nil
}

func (p *connectionOnlyProvider) DiscoverResources(context.Context, deployPB.DeploymentType) providers.ResourceCatalogResult {
	return providers.EmptyCatalog()
}

func (p *connectionOnlyProvider) ResolveResource(context.Context, deployPB.DeploymentType, string) (providers.DeploymentResource, error) {
	return providers.DeploymentResource{}, errors.New("not implemented")
}

func (p *connectionOnlyProvider) TestResource(context.Context, deployPB.DeploymentType, string) error {
	return nil
}

func (p *connectionOnlyProvider) DeployCertificate(context.Context, providers.CertificateMaterial, deployPB.DeploymentType, providers.DeploymentResource) (providers.DeploymentResult, error) {
	return providers.DeploymentResult{}, errors.New("not implemented")
}

func TestProviderClientExposesConnectionWithoutUploader(t *testing.T) {
	fake := &connectionOnlyProvider{}
	runtime := &config.Runtime{Config: &config.Configuration{
		Server:   &config.ServerConfig{AccessKey: "access-key"},
		Provider: []*config.Provider{{Name: config.ProviderLeCDN, Auth: &config.ProviderAuth{APIBaseURL: "https://lecdn.example", APIToken: "token"}}},
	}}
	installFakeProviderFactory(t, deployPB.Provider_PROVIDER_LECDN, func(*config.Provider) (any, error) { return fake, nil })

	client, err := newProviderClient(runtime, deployPB.Provider_PROVIDER_LECDN)
	if err != nil {
		t.Fatalf("newProviderClient() error = %v", err)
	}
	if client.Uploader != nil {
		t.Fatal("LeCDN should not expose certificate uploader")
	}
	if client.Connection == nil || client.Resources == nil {
		t.Fatalf("LeCDN should expose connection and resources: connection=%v resources=%v", client.Connection, client.Resources)
	}
	ok, err := testDeploymentConnection(context.Background(), deployPB.Provider_PROVIDER_LECDN, deployPB.DeploymentType_DEPLOYMENT_TYPE_UNSPECIFIED, "", runtime)
	if err != nil || !ok || !fake.tested {
		t.Fatalf("connection-only provider test failed: ok=%v tested=%v err=%v", ok, fake.tested, err)
	}
}

func TestRunLocalTargetDeployURLKeepsLocalPublishFailureKind(t *testing.T) {
	err := runLocalTargetDeployURL(context.Background(), deploys.NewCertDeployer(deploys.Options{
		DownloadFunc: func(context.Context, string, string) error {
			return errors.New("download boom")
		},
		SSL: &config.DeployConfig{},
	}), deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT, "example.com", "https://example.com/archive")
	if err == nil {
		t.Fatal("expected local deploy failure")
	}
	if kind := providers.FailureKind(err); kind != deployPB.FailureKind_FAILURE_KIND_LOCAL_PUBLISH {
		t.Fatalf("FailureKind() = %v, want LOCAL_PUBLISH", kind)
	}
	if _, retryable := providers.DeploymentErrorInfo(err); retryable {
		t.Fatal("local publish failure should not be retryable")
	}
}

func TestFindLocalTargetCoversAllV2LocalTypes(t *testing.T) {
	expected := []deployPB.DeploymentType{
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_NGINX_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_CADDY_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_APACHE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_RUSTFS_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_FEINIU_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_OPENVPN_AS_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_UPLOAD_ONLY_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_SAFELINE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_1PANEL_WEBSITE_CERT,
		deployPB.DeploymentType_DEPLOYMENT_TYPE_ANSSL_CLI_BT_PANEL_WEBSITE_CERT,
	}
	for _, deploymentType := range expected {
		target, ok := findLocalTarget(deploymentType)
		if !ok {
			t.Fatalf("missing local target for %s", deploymentType)
		}
		if target.DeploymentType != deploymentType {
			t.Fatalf("target type mismatch: got %s want %s", target.DeploymentType, deploymentType)
		}
		required := target.TargetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED
		if required && (target.DeployMaterial == nil || target.Discover == nil) {
			t.Fatalf("resource target %s must provide DeployMaterial and Discover", deploymentType)
		}
		if !required && target.DeployURL == nil {
			t.Fatalf("non-resource target %s must provide DeployURL", deploymentType)
		}
		if target.Test == nil {
			t.Fatalf("target %s must provide Test", deploymentType)
		}
	}
}

func TestLocalTargetSpecsMatchRegistrySize(t *testing.T) {
	specs := localTargetSpecs()
	if len(specs) != len(localTargets) {
		t.Fatalf("specs size %d != registry size %d", len(specs), len(localTargets))
	}
	for _, spec := range specs {
		if spec.key.Provider != deployPB.Provider_PROVIDER_ANSSL_CLI {
			t.Fatalf("unexpected provider in local spec: %s", spec.key.Provider)
		}
		if _, ok := findLocalTarget(spec.key.DeploymentType); !ok {
			t.Fatalf("spec references missing local target %s", spec.key.DeploymentType)
		}
	}
}
