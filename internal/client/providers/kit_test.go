package providers

import (
	"errors"
	"testing"

	"github.com/https-cert/deploy/pb/deployPB"
)

func TestCatalogHelpers(t *testing.T) {
	if CatalogFromResources(nil).Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_EMPTY {
		t.Fatal("nil resources should be EMPTY")
	}
	if CatalogFromResources([]DeploymentResource{{TargetRef: "x"}}).Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_READY {
		t.Fatal("non-empty resources should be READY")
	}
	if UnavailableCatalog(errors.New("boom")).Error == nil {
		t.Fatal("UnavailableCatalog must keep error")
	}
	if NotConfiguredCatalog().Status != deployPB.DeploymentResourceStatus_DEPLOYMENT_RESOURCE_STATUS_NOT_CONFIGURED {
		t.Fatal("NotConfigured status mismatch")
	}
}

func TestTargetRefCodec(t *testing.T) {
	ref, err := EncodeTargetRef("lb-1", "https", "443")
	if err != nil || ref != "lb-1|https|443" {
		t.Fatalf("encode failed: ref=%q err=%v", ref, err)
	}
	parts, err := DecodeTargetRef(ref, 3)
	if err != nil || len(parts) != 3 || parts[0] != "lb-1" {
		t.Fatalf("decode failed: parts=%v err=%v", parts, err)
	}
	if _, err := EncodeTargetRef("has space"); err == nil {
		t.Fatal("space in part should fail")
	}
	if _, err := DecodeTargetRef("a|b", 3); err == nil {
		t.Fatal("wrong part count should fail")
	}
	if _, err := DecodeTargetRef(" leading", 1); err == nil {
		t.Fatal("whitespace targetRef should fail")
	}
}
