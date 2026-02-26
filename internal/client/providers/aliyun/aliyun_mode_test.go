//go:build !windows

package aliyun

import (
	"strings"
	"testing"
	"time"
)

func TestNormalizeOptions_Defaults(t *testing.T) {
	opts, err := normalizeOptions(nil)
	if err != nil {
		t.Fatalf("normalizeOptions(nil) unexpected error: %v", err)
	}
	if opts.Service != ServiceCAS {
		t.Fatalf("expected default service %s, got %s", ServiceCAS, opts.Service)
	}
}

func TestNormalizeOptions_ESARequiresSiteID(t *testing.T) {
	_, err := normalizeOptions(&Options{
		Service: ServiceESA,
	})
	if err == nil {
		t.Fatal("expected error when ESA service without site id")
	}
}

func TestNormalizeOptions_ESAWithSiteID(t *testing.T) {
	opts, err := normalizeOptions(&Options{
		Service:   ServiceESA,
		ESASiteID: " 12345 ",
	})
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if opts.Service != ServiceESA {
		t.Fatalf("expected service %s, got %s", ServiceESA, opts.Service)
	}
	if opts.ESASiteID != "12345" {
		t.Fatalf("expected trimmed site id, got %q", opts.ESASiteID)
	}
}

func TestNormalizeOptions_InvalidService(t *testing.T) {
	_, err := normalizeOptions(&Options{
		Service: "invalid",
	})
	if err == nil {
		t.Fatal("expected invalid service error")
	}
}

func TestBuildUniqueESACertificateName(t *testing.T) {
	now := time.Date(2026, 2, 26, 20, 30, 45, 0, time.UTC)
	timestamp := "20260226203045-000000"

	t.Run("prefer provided name", func(t *testing.T) {
		got := buildUniqueESACertificateName("my-cert", "domain.example.com", now)
		if got != "my-cert-"+timestamp {
			t.Fatalf("unexpected name: %s", got)
		}
	})

	t.Run("fallback to domain", func(t *testing.T) {
		got := buildUniqueESACertificateName("   ", "domain.example.com", now)
		if got != "domain.examp-"+timestamp {
			t.Fatalf("unexpected name: %s", got)
		}
	})

	t.Run("sanitize invalid chars", func(t *testing.T) {
		got := buildUniqueESACertificateName("1000.xiyun.vip_2026-02-26 20:21:22", "domain.example.com", now)
		if got != "1000.xiyun.v-"+timestamp {
			t.Fatalf("unexpected sanitized name: %s", got)
		}
	})

	t.Run("fallback to default", func(t *testing.T) {
		got := buildUniqueESACertificateName("   ", "   ", now)
		if got != "anssl-"+timestamp {
			t.Fatalf("unexpected name: %s", got)
		}
	})

	t.Run("truncate long base name", func(t *testing.T) {
		longName := strings.Repeat("a", 70)
		got := buildUniqueESACertificateName(longName, "domain.example.com", now)
		expected := strings.Repeat("a", 12) + "-" + timestamp
		if got != expected {
			t.Fatalf("unexpected truncated name: %s", got)
		}
	})
}

func TestSelectESACertificateIDByName(t *testing.T) {
	tests := []struct {
		name      string
		result    []any
		target    string
		wantID    string
		wantError bool
	}{
		{
			name: "match unique upload certificate",
			result: []any{
				map[string]any{"Id": "1001", "Name": "example-cert", "Type": "upload"},
			},
			target: "example-cert",
			wantID: "1001",
		},
		{
			name: "match with lowercase keys",
			result: []any{
				map[string]any{"id": "10011", "name": "example-cert", "type": "upload"},
			},
			target: "example-cert",
			wantID: "10011",
		},
		{
			name: "match with cert aliases",
			result: []any{
				map[string]any{"CertId": "10012", "CertName": "example-cert", "CertType": "upload"},
			},
			target: "example-cert",
			wantID: "10012",
		},
		{
			name: "missing exact match",
			result: []any{
				map[string]any{"Id": "1002", "Name": "example-cert-1", "Type": "upload"},
			},
			target:    "example-cert",
			wantError: true,
		},
		{
			name: "multiple exact matches",
			result: []any{
				map[string]any{"Id": "1003", "Name": "example-cert", "Type": "upload"},
				map[string]any{"Id": "1004", "Name": "example-cert", "Type": "cas"},
			},
			target:    "example-cert",
			wantError: true,
		},
		{
			name: "free certificate should fail",
			result: []any{
				map[string]any{"Id": "1005", "Name": "example-cert", "Type": "free"},
			},
			target:    "example-cert",
			wantError: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			gotID, err := selectESACertificateIDByName(testCase.result, testCase.target)
			if testCase.wantError {
				if err == nil {
					t.Fatalf("expected error, got id=%s", gotID)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotID != testCase.wantID {
				t.Fatalf("expected id=%s, got id=%s", testCase.wantID, gotID)
			}
		})
	}
}

func TestIsESAErrorCode(t *testing.T) {
	err1 := testError("SDKError: Code: Certificate.Duplicated")
	if !isESAErrorCode(err1, "Certificate.Duplicated") {
		t.Fatal("expected true for plain Code format")
	}

	err2 := testError(`SDKError: Data: {"Code":"Certificate.Duplicated"}`)
	if !isESAErrorCode(err2, "Certificate.Duplicated") {
		t.Fatal("expected true for json Code format")
	}

	err3 := testError("SDKError: Code: InvalidParameter")
	if isESAErrorCode(err3, "Certificate.Duplicated") {
		t.Fatal("expected false for mismatched code")
	}
}

func TestParseESAListCertificatesResult(t *testing.T) {
	tests := []struct {
		name      string
		resp      map[string]any
		wantLen   int
		wantError bool
	}{
		{
			name: "top-level Result",
			resp: map[string]any{
				"Result": []any{
					map[string]any{"Id": "1", "Name": "cert-1"},
				},
			},
			wantLen: 1,
		},
		{
			name: "body Result map",
			resp: map[string]any{
				"body": map[string]any{
					"RequestId": "abc",
					"Result": []any{
						map[string]any{"Id": "2", "Name": "cert-2"},
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "body nested certificates map",
			resp: map[string]any{
				"body": map[string]any{
					"Data": map[string]any{
						"CertList": []any{
							map[string]any{"Id": "22", "Name": "cert-22"},
						},
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "Body Result json string",
			resp: map[string]any{
				"Body": `{"RequestId":"abc","Result":[{"Id":"3","Name":"cert-3"}]}`,
			},
			wantLen: 1,
		},
		{
			name: "body json bytes",
			resp: map[string]any{
				"body": []byte(`{"Data":{"Certificates":[{"Id":"33","Name":"cert-33"}]}}`),
			},
			wantLen: 1,
		},
		{
			name: "body cert aliases",
			resp: map[string]any{
				"body": map[string]any{
					"Data": map[string]any{
						"CertificateList": []any{
							map[string]any{"CertId": "44", "CertName": "cert-44"},
						},
					},
				},
			},
			wantLen: 1,
		},
		{
			name: "missing Result",
			resp: map[string]any{
				"statusCode": 200,
			},
			wantError: true,
		},
		{
			name: "total count zero without list",
			resp: map[string]any{
				"body": map[string]any{
					"TotalCount": "0",
					"PageNumber": "1",
					"PageSize":   "100",
				},
			},
			wantLen: 0,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := parseESAListCertificatesResult(testCase.resp)
			if testCase.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != testCase.wantLen {
				t.Fatalf("expected len=%d, got len=%d", testCase.wantLen, len(result))
			}
		})
	}
}

func TestSelectESACertificateIDByFingerprintOrSerial(t *testing.T) {
	tests := []struct {
		name              string
		result            []any
		targetFingerprint string
		targetSerial      string
		wantID            string
		wantError         bool
	}{
		{
			name: "match by fingerprint",
			result: []any{
				map[string]any{
					"Id":                "2001",
					"FingerprintSha256": "AA:BB:CC:11",
					"SerialNumber":      "1234",
				},
			},
			targetFingerprint: "aabbcc11",
			wantID:            "2001",
		},
		{
			name: "match by serial",
			result: []any{
				map[string]any{
					"CertId":       "2002",
					"SerialNumber": "00ABCD",
				},
			},
			targetSerial: "abcd",
			wantID:       "2002",
		},
		{
			name: "not found",
			result: []any{
				map[string]any{
					"Id":                "2003",
					"FingerprintSha256": "ffee",
				},
			},
			targetFingerprint: "aabb",
			wantError:         true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			gotID, err := selectESACertificateIDByFingerprintOrSerial(testCase.result, testCase.targetFingerprint, testCase.targetSerial)
			if testCase.wantError {
				if err == nil {
					t.Fatalf("expected error, got id=%s", gotID)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotID != testCase.wantID {
				t.Fatalf("expected id=%s, got id=%s", testCase.wantID, gotID)
			}
		})
	}
}

type testError string

func (e testError) Error() string {
	return string(e)
}
