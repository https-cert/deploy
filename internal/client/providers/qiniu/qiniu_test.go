package qiniu_test

import (
	"testing"

	"github.com/orange-juzipi/cert-deploy/internal/client/providers/qiniu"
	"github.com/orange-juzipi/cert-deploy/internal/config"
	"github.com/orange-juzipi/cert-deploy/pkg/logger"
)

var provider *qiniu.Provider

func TestMain(m *testing.M) {
	config.Init("../../../../config.yaml")
	logger.Init()

	cfg := config.GetConfig()

	for _, p := range cfg.Provider {
		if p.Name == "qiniu" {
			logger.Info("测试提供商上传证书", "provider", p.Name, "accessKey", p.AccessKey, "accessSecret", p.AccessSecret)
			// 创建实例
			provider = qiniu.New(p.AccessKey, p.AccessSecret)
		}
	}

	if provider == nil {
		logger.Warn("未找到提供商配置")
		return
	}
	m.Run()
}

// TestProvider 测试提供商连接
func TestConnect(t *testing.T) {
	// 执行连接测试
	success, err := provider.TestConnection()
	if err != nil {
		logger.Error("连接测试执行失败", "error", err)
		return
	}

	if success {
		logger.Info("连接测试成功")
	} else {
		logger.Warn("连接测试失败")
	}
}

func TestUploadCert(t *testing.T) {

	cert := `-----BEGIN CERTIFICATE-----
MIIDhzCCAw6gAwIBAgISBYTLHz8CUP3LECUuiw5XcWjkMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
ODAeFw0yNTA5MjIwNDE5MTVaFw0yNTEyMjEwNDE5MTRaMBcxFTATBgNVBAMTDGUu
MDA1MDkwLnh5ejBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGmM/2K9NuFUZOEM
WXI0KBRwQXRu84KF0fEU6OHgSjy8jePRvBjufii+D1KxEmHRgbnc7E9Ljq0kJyHp
P+kEGTqjggIdMIICGTAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUH
AwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPxcjCFC4UWh9BC5
zYOMarmUCFVIMB8GA1UdIwQYMBaAFI8NE6L2Ln7RUGwzGDhdWY4jcpHKMDIGCCsG
AQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL2U4LmkubGVuY3Iub3JnLzAX
BgNVHREEEDAOggxlLjAwNTA5MC54eXowEwYDVR0gBAwwCjAIBgZngQwBAgEwLgYD
VR0fBCcwJTAjoCGgH4YdaHR0cDovL2U4LmMubGVuY3Iub3JnLzEwMS5jcmwwggEG
BgorBgEEAdZ5AgQCBIH3BIH0APIAdwDtPEvW6AbCpKIAV9vLJOI4Ad9RL+3EhsVw
DyDdtz4/4AAAAZlv20cHAAAEAwBIMEYCIQDlQtOT/i/yEgjwb7uxCLYU2Y7xjsRM
s4w/LXezsXV6rgIhAKKJ2Pr5lDDc9T2KUuB0YnCgxzCH+8dbnd7+nBhkzaAnAHcA
DeHyMCvTDcFAYhIJ6lUu/Ed0fLHX6TDvDkIetH5OqjQAAAGZb9tH1gAABAMASDBG
AiEAv3kxxeL52ZZBkIrFJjeILoeMJku3bMlDquc+pDFVPAwCIQC30oQrGl9kCrIr
zAcKAhXQBR+Wbk1zRy64QMQcTxoN+jAKBggqhkjOPQQDAwNnADBkAjAhZYZZ7l1G
6o4x/s7GtHBPFi4swy+Vh54qZkcNTPFJp4tuf+iS3QNmCtBWtuT+nB8CMCWS1ax0
nc07sQBjGZEKWd7TXFgfleuATJr04obhC2ZU5qQh1FxMrsJdwmBN1vORpA==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIEVjCCAj6gAwIBAgIQY5WTY8JOcIJxWRi/w9ftVjANBgkqhkiG9w0BAQsFADBP
MQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFy
Y2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNDAzMTMwMDAwMDBa
Fw0yNzAzMTIyMzU5NTlaMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBF
bmNyeXB0MQswCQYDVQQDEwJFODB2MBAGByqGSM49AgEGBSuBBAAiA2IABNFl8l7c
S7QMApzSsvru6WyrOq44ofTUOTIzxULUzDMMNMchIJBwXOhiLxxxs0LXeb5GDcHb
R6EToMffgSZjO9SNHfY9gjMy9vQr5/WWOrQTZxh7az6NSNnq3u2ubT6HTKOB+DCB
9TAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMB
MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFI8NE6L2Ln7RUGwzGDhdWY4j
cpHKMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEB
BCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzATBgNVHSAE
DDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5j
ci5vcmcvMA0GCSqGSIb3DQEBCwUAA4ICAQBnE0hGINKsCYWi0Xx1ygxD5qihEjZ0
RI3tTZz1wuATH3ZwYPIp97kWEayanD1j0cDhIYzy4CkDo2jB8D5t0a6zZWzlr98d
AQFNh8uKJkIHdLShy+nUyeZxc5bNeMp1Lu0gSzE4McqfmNMvIpeiwWSYO9w82Ob8
otvXcO2JUYi3svHIWRm3+707DUbL51XMcY2iZdlCq4Wa9nbuk3WTU4gr6LY8MzVA
aDQG2+4U3eJ6qUF10bBnR1uuVyDYs9RhrwucRVnfuDj29CMLTsplM5f5wSV5hUpm
Uwp/vV7M4w4aGunt74koX71n4EdagCsL/Yk5+mAQU0+tue0JOfAV/R6t1k+Xk9s2
HMQFeoxppfzAVC04FdG9M+AC2JWxmFSt6BCuh3CEey3fE52Qrj9YM75rtvIjsm/1
Hl+u//Wqxnu1ZQ4jpa+VpuZiGOlWrqSP9eogdOhCGisnyewWJwRQOqK16wiGyZeR
xs/Bekw65vwSIaVkBruPiTfMOo0Zh4gVa8/qJgMbJbyrwwG97z/PRgmLKCDl8z3d
tA0Z7qq7fta0Gl24uyuB05dqI5J1LvAzKuWdIjT1tP8qCoxSE/xpix8hX2dt3h+/
jujUgFPFZ0EVZ0xSyBNRF3MboGZnYXFUxpNjTWPKpagDHJQmqrAcDmWJnMsFY3jS
u1igv3OefnWjSQ==
-----END CERTIFICATE-----
`
	key := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIA/o5oDJOufhnM0blUNgPEp6ZpyJfmRjF0CIJVCUI4SVoAoGCCqGSM49
AwEHoUQDQgAEaYz/Yr024VRk4QxZcjQoFHBBdG7zgoXR8RTo4eBKPLyN49G8GO5+
KL4PUrESYdGBudzsT0uOrSQnIek/6QQZOg==
-----END EC PRIVATE KEY-----
`

	// 执行上传证书
	err := provider.UploadCertificate("test-cert2", cert, key)
	if err != nil {
		logger.Error("上传证书执行失败", "error", err)
		return
	}

	logger.Info("上传证书成功")
}
