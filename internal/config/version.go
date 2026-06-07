package config

// Version is injected by release builds with:
//
//	go build -ldflags="-X github.com/https-cert/deploy/internal/config.Version=vX.Y.Z"
//
// Development builds keep "dev" to avoid shipping stale hard-coded versions.
var Version = "dev"
