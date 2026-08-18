/*
Package qiniu implements certificate upload and exact-domain certificate
deployment for Qiniu CDN products.

The certificate API and domain API use different hosts and authentication
schemes. Keeping the request construction here makes it possible to sign the
same bytes that are ultimately sent to the domain API.
*/
package qiniu

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/https-cert/deploy/internal/client/providers"
	"github.com/qiniu/go-sdk/v7/auth"
)

const (
	defaultAPIBaseURL    = "https://api.qiniu.com"
	defaultFusionBaseURL = "https://fusion.qiniuapi.com"
	maxResponseBodySize  = 1024 * 1024
	resourcePageSize     = 1000
	resourceMaxPages     = 20
	resourceMaxCount     = 10000
	resourceConcurrency  = 4
)

var (
	_ providers.ProviderHandler            = (*Provider)(nil)
	_ providers.DeploymentResourceDeployer = (*Provider)(nil)
	_ providers.ResourceDiscoverer         = (*Provider)(nil)
)

// Product identifies the Qiniu domain product that owns a custom domain.
type Product string

const (
	// ProductCDN identifies a Qiniu CDN custom domain.
	ProductCDN Product = "cdn"
	// ProductDCDN identifies a Qiniu DCDN custom domain.
	ProductDCDN Product = "dcdn"
)

// HTTPClient is the subset of http.Client used by Provider.
// It allows unit tests to inject an httptest client without global state.
type HTTPClient interface {
	// Do sends one HTTP request and returns its response.
	Do(*http.Request) (*http.Response, error)
}

// Options configures a Provider instance.
type Options struct {
	// HTTPClient sends signed API requests. A timeout-enabled default is used when nil.
	HTTPClient HTTPClient
	// APIBaseURL overrides the Qiniu domain API host. It is intended for tests.
	APIBaseURL string
	// FusionBaseURL overrides the Qiniu certificate API host. It is intended for tests.
	FusionBaseURL string
}

// Provider owns the Qiniu credentials and HTTP transport used for certificate operations.
type Provider struct {
	// AccessKey is retained for compatibility with existing callers. Do not log it.
	AccessKey string
	// AccessSecret is retained for compatibility with existing callers. Do not log it.
	AccessSecret string
	// credentials signs QBox and Qiniu V2 requests.
	credentials *auth.Credentials
	// httpClient sends requests after they have been signed.
	httpClient HTTPClient
	// apiBaseURL is the Qiniu domain API base URL.
	apiBaseURL string
	// fusionBaseURL is the Qiniu certificate API base URL.
	fusionBaseURL string
}

// CertificateUploadResult contains the certificate identity returned by Qiniu.
type CertificateUploadResult struct {
	// CertificateID is Qiniu's certID and is required by the domain binding API.
	CertificateID string
	// ProviderRequestID is Qiniu's request identifier for the upload operation.
	ProviderRequestID string
}

// TargetDeploymentResult describes one exact-domain certificate deployment at the Qiniu API layer.
type TargetDeploymentResult struct {
	// CertificateID is the Qiniu certID bound to the custom domain.
	CertificateID string
	// Domain is the exact custom domain that was verified and updated.
	Domain string
	// Product is the Qiniu product validated before the update.
	Product Product
	// UploadRequestID identifies the certificate upload request when this method uploaded a certificate.
	UploadRequestID string
	// ProviderRequestID identifies the domain update request.
	ProviderRequestID string
}

// APIError carries enough provider context for a later caller to decide whether to retry.
type APIError struct {
	// Operation identifies the failed Qiniu API operation.
	Operation string
	// StatusCode is the provider HTTP status code, or zero before a response exists.
	StatusCode int
	// ProviderRequestID is Qiniu's request identifier when the response included one.
	ProviderRequestID string
	// Retryable reports whether retrying the operation may succeed without configuration changes.
	Retryable bool
	// Message is a sanitized provider or local failure description.
	Message string
	// Cause retains the underlying transport or parsing error.
	Cause error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("七牛 %s 失败: HTTP %d: %s", e.Operation, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("七牛 %s 失败: %s", e.Operation, e.Message)
}

// Unwrap exposes the underlying cause for errors.Is and errors.As.
func (e *APIError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// New creates a Provider using Qiniu production API endpoints.
func New(accessKey, accessSecret string) *Provider {
	return NewWithOptions(accessKey, accessSecret, nil)
}

// NewWithOptions creates a Provider with an injectable HTTP transport and API endpoints.
func NewWithOptions(accessKey, accessSecret string, options *Options) *Provider {
	providerOptions := Options{}
	if options != nil {
		providerOptions = *options
	}

	if providerOptions.HTTPClient == nil {
		providerOptions.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if strings.TrimSpace(providerOptions.APIBaseURL) == "" {
		providerOptions.APIBaseURL = defaultAPIBaseURL
	}
	if strings.TrimSpace(providerOptions.FusionBaseURL) == "" {
		providerOptions.FusionBaseURL = defaultFusionBaseURL
	}

	return &Provider{
		AccessKey:     accessKey,
		AccessSecret:  accessSecret,
		credentials:   auth.New(accessKey, accessSecret),
		httpClient:    providerOptions.HTTPClient,
		apiBaseURL:    strings.TrimRight(providerOptions.APIBaseURL, "/"),
		fusionBaseURL: strings.TrimRight(providerOptions.FusionBaseURL, "/"),
	}
}

// TestConnection tests QBox credentials against the Qiniu certificate API.
func (p *Provider) TestConnection(ctx context.Context) (bool, error) {
	return p.TestConnectionWithContext(ctx)
}

// TestConnectionWithContext tests QBox credentials while respecting caller cancellation.
func (p *Provider) TestConnectionWithContext(ctx context.Context) (bool, error) {
	if err := p.validateCredentials("测试连接"); err != nil {
		return false, err
	}

	_, err := p.execute(ctx, "获取证书列表", http.MethodGet, p.fusionBaseURL, "/sslcert", authorizationQBox, nil)
	if err != nil {
		return false, err
	}
	return true, nil
}
