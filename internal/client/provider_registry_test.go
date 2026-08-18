package client

import (
	"testing"

	"github.com/https-cert/deploy/pb/deployPB"
)

// TestProviderRegistryIsUniqueAndComplete verifies each cloud provider and resource type is registered once.
func TestProviderRegistryIsUniqueAndComplete(t *testing.T) {
	seenProviders := make(map[deployPB.Provider]struct{}, len(providerDefinitions))
	seenResources := make(map[DeploymentHandlerKey]struct{})
	for _, definition := range providerDefinitions {
		if definition.Provider == deployPB.Provider_PROVIDER_UNSPECIFIED || definition.ConfigName == "" || definition.New == nil {
			t.Fatalf("invalid provider definition: %#v", definition)
		}
		if _, exists := seenProviders[definition.Provider]; exists {
			t.Fatalf("duplicate provider %s", definition.Provider)
		}
		seenProviders[definition.Provider] = struct{}{}
		for _, deploymentType := range definition.ResourceTypes {
			key := DeploymentHandlerKey{Provider: definition.Provider, DeploymentType: deploymentType}
			if _, exists := seenResources[key]; exists {
				t.Fatalf("duplicate resource type: %#v", key)
			}
			seenResources[key] = struct{}{}
			if !providerSupportsResource(definition.Provider, deploymentType) {
				t.Fatalf("resource type is not reported as supported: %#v", key)
			}
		}
	}
	if len(seenProviders) != 9 {
		t.Fatalf("registered cloud provider count = %d, want 9", len(seenProviders))
	}
}

// TestDeploymentHandlerSpecsPreserveCloudOrder verifies capability order remains stable after registry generation.
func TestDeploymentHandlerSpecsPreserveCloudOrder(t *testing.T) {
	specs := deploymentHandlerSpecs()
	if len(specs) == 0 {
		t.Fatal("deploymentHandlerSpecs() returned no capabilities")
	}
	cloudIndex := -1
	for index, spec := range specs {
		if spec.key.Provider != deployPB.Provider_PROVIDER_ANSSL_CLI {
			cloudIndex = index
			break
		}
	}
	if cloudIndex < 0 || specs[cloudIndex].key.Provider != deployPB.Provider_PROVIDER_ALIYUN || specs[cloudIndex].key.DeploymentType != deployPB.DeploymentType_DEPLOYMENT_TYPE_UPLOAD_CERT {
		t.Fatalf("first cloud capability changed: %#v", specs[cloudIndex])
	}
	for index := cloudIndex; index < len(specs); index++ {
		if specs[index].key.Provider == deployPB.Provider_PROVIDER_ANSSL_CLI {
			t.Fatalf("local capability appeared after cloud capability at index %d", index)
		}
	}
}

// TestDeploymentHandlerExecutionKinds verifies every capability has an explicit route consistent with its target mode.
func TestDeploymentHandlerExecutionKinds(t *testing.T) {
	for _, spec := range deploymentHandlerSpecs() {
		if spec.executionKind == 0 {
			t.Fatalf("provider=%s deploymentType=%s has no execution kind", spec.key.Provider, spec.key.DeploymentType)
		}
		dynamic := spec.executionKind == deploymentExecutionLocalResource || spec.executionKind == deploymentExecutionCloudResource
		requiresTarget := spec.targetMode == deployPB.DeploymentTargetMode_DEPLOYMENT_TARGET_MODE_REQUIRED
		if dynamic != requiresTarget {
			t.Fatalf("provider=%s deploymentType=%s dynamic=%v targetMode=%s", spec.key.Provider, spec.key.DeploymentType, dynamic, spec.targetMode)
		}
		if spec.key.Provider == deployPB.Provider_PROVIDER_ANSSL_CLI && (spec.executionKind == deploymentExecutionCloudUpload || spec.executionKind == deploymentExecutionCloudResource) {
			t.Fatalf("local capability uses cloud execution kind: %s", spec.key.DeploymentType)
		}
	}
}
