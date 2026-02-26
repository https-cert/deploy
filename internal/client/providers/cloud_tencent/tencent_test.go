package cloud_tencent

import (
	"errors"
	"strings"
	"testing"

	tencentcommon "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	tencenterrors "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// mockSSLClient 模拟腾讯云 SSL SDK 客户端调用行为。
type mockSSLClient struct {
	describeFn func(request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error)
	uploadFn   func(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error)
}

// DescribeCertificates 模拟查询证书列表接口。
func (m *mockSSLClient) DescribeCertificates(request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
	if m.describeFn == nil {
		return &ssl.DescribeCertificatesResponse{}, nil
	}
	return m.describeFn(request)
}

// UploadCertificate 模拟上传证书接口。
func (m *mockSSLClient) UploadCertificate(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
	if m.uploadFn == nil {
		return &ssl.UploadCertificateResponse{}, nil
	}
	return m.uploadFn(request)
}

// newTestProvider 创建可注入 mock 客户端的 Provider。
func newTestProvider(client sslClient) *Provider {
	provider := New("sid-test", "skey-test")
	provider.newClient = func(secretID, secretKey string) (sslClient, error) {
		return client, nil
	}
	return provider
}

func TestTestConnectionSuccess(t *testing.T) {
	provider := newTestProvider(&mockSSLClient{
		describeFn: func(request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
			if request == nil || request.Limit == nil || *request.Limit != 1 {
				t.Fatalf("unexpected request: %+v", request)
			}
			return &ssl.DescribeCertificatesResponse{
				Response: &ssl.DescribeCertificatesResponseParams{
					RequestId: tencentcommon.StringPtr("req-1"),
				},
			}, nil
		},
	})

	success, err := provider.TestConnection()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Fatal("expected success to be true")
	}
}

func TestTestConnectionWrapsSDKError(t *testing.T) {
	provider := newTestProvider(&mockSSLClient{
		describeFn: func(request *ssl.DescribeCertificatesRequest) (*ssl.DescribeCertificatesResponse, error) {
			return nil, tencenterrors.NewTencentCloudSDKError("AuthFailure", "unauthorized", "req-401")
		},
	})

	success, err := provider.TestConnection()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if success {
		t.Fatal("expected success to be false")
	}
	if !strings.Contains(err.Error(), "AuthFailure") {
		t.Fatalf("expected wrapped code in error, got: %v", err)
	}
}

func TestUploadCertificateSuccess(t *testing.T) {
	var capturedRequest *ssl.UploadCertificateRequest
	provider := newTestProvider(&mockSSLClient{
		uploadFn: func(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			capturedRequest = request
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{
					CertificateId: tencentcommon.StringPtr("cert-1"),
					RequestId:     tencentcommon.StringPtr("req-upload"),
				},
			}, nil
		},
	})

	err := provider.UploadCertificate("my-cert", "example.com", "CERT", "KEY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedRequest == nil {
		t.Fatal("expected upload request to be captured")
	}
	if capturedRequest.Alias == nil || *capturedRequest.Alias != "my-cert" {
		t.Fatalf("unexpected alias: %+v", capturedRequest.Alias)
	}
	if capturedRequest.Repeatable == nil || !*capturedRequest.Repeatable {
		t.Fatalf("expected repeatable=true, got: %+v", capturedRequest.Repeatable)
	}
	if capturedRequest.CertificateType == nil || *capturedRequest.CertificateType != "SVR" {
		t.Fatalf("unexpected certificate type: %+v", capturedRequest.CertificateType)
	}
}

func TestUploadCertificateAcceptsRepeatCertID(t *testing.T) {
	provider := newTestProvider(&mockSSLClient{
		uploadFn: func(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{
					RepeatCertId: tencentcommon.StringPtr("repeat-1"),
					RequestId:    tencentcommon.StringPtr("req-repeat"),
				},
			}, nil
		},
	})

	if err := provider.UploadCertificate("my-cert", "example.com", "CERT", "KEY"); err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
}

func TestUploadCertificateMissingCertificateID(t *testing.T) {
	provider := newTestProvider(&mockSSLClient{
		uploadFn: func(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return &ssl.UploadCertificateResponse{
				Response: &ssl.UploadCertificateResponseParams{
					RequestId: tencentcommon.StringPtr("req-missing-id"),
				},
			}, nil
		},
	})

	err := provider.UploadCertificate("my-cert", "example.com", "CERT", "KEY")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "缺少证书ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUploadCertificateWrapsSDKError(t *testing.T) {
	provider := newTestProvider(&mockSSLClient{
		uploadFn: func(request *ssl.UploadCertificateRequest) (*ssl.UploadCertificateResponse, error) {
			return nil, tencenterrors.NewTencentCloudSDKError("InvalidParameter", "invalid", "req-invalid")
		},
	})

	err := provider.UploadCertificate("my-cert", "example.com", "CERT", "KEY")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "InvalidParameter") {
		t.Fatalf("expected wrapped code in error, got: %v", err)
	}
}

func TestGetClientFactoryError(t *testing.T) {
	provider := New("sid-test", "skey-test")
	provider.newClient = func(secretID, secretKey string) (sslClient, error) {
		return nil, errors.New("init failed")
	}

	_, err := provider.TestConnection()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "初始化腾讯云 SSL SDK 客户端失败") {
		t.Fatalf("unexpected error: %v", err)
	}
}
