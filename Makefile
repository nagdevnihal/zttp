GO := $(shell which go 2>/dev/null || echo /snap/go/current/bin/go)
VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

LDFLAGS := -ldflags="-s -w \
	-X main.Version=$(VERSION) \
	-X main.BuildTime=$(BUILD_TIME) \
	-X main.GitCommit=$(GIT_COMMIT) \
	-X main.DefaultProxyAddr=$(PROXY_ADDR)"

.PHONY: all build build-proxy build-cli release tidy test clean docker-up docker-down migrate seed

## ── Development ─────────────────────────────────────────────────────────────

all: build

## Download and tidy Go dependencies
tidy:
	$(GO) mod tidy

## Build all binaries (proxy + CLI)
build: build-proxy build-cli

PROXY_ADDR ?= 127.0.0.1:2224

## Cross-compile CLI binaries for all platforms
release:
	@mkdir -p dist/release
	@echo "Building releases with proxy address: $(PROXY_ADDR)"
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 $(GO) build -buildvcs=false $(LDFLAGS) -o dist/release/zttp-linux-amd64   ./cmd/zttp/
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 $(GO) build -buildvcs=false $(LDFLAGS) -o dist/release/zttp-linux-arm64   ./cmd/zttp/
	GOOS=darwin  GOARCH=amd64 CGO_ENABLED=0 $(GO) build -buildvcs=false $(LDFLAGS) -o dist/release/zttp-darwin-amd64  ./cmd/zttp/
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 $(GO) build -buildvcs=false $(LDFLAGS) -o dist/release/zttp-darwin-arm64  ./cmd/zttp/
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -buildvcs=false $(LDFLAGS) -o dist/release/zttp-windows-amd64.exe ./cmd/zttp/
	cd dist/release && sha256sum * > SHA256SUMS.txt
	@echo "✓ All binaries built in dist/release/"

## Run the release build inside a Docker container (bypasses snap/wsl issues)
release-docker:
	@mkdir -p dist/release
	docker run --rm -v $(PWD):/usr/src/zttp -w /usr/src/zttp golang:latest \
		make release PROXY_ADDR=$(PROXY_ADDR)

## Build the ZTTP proxy server
build-proxy:
	@mkdir -p dist
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o dist/zttp-proxy ./cmd/proxy/
	@echo "✓ Built: dist/zttp-proxy"

## Build the zttp CLI client
build-cli:
	@mkdir -p dist
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o dist/zttp ./cmd/zttp/
	@echo "✓ Built: dist/zttp"

## Run all tests
test:
	$(GO) test -v -race ./...

## Run proxy locally (requires Postgres + Vault running)
run-proxy:
	$(GO) run ./cmd/proxy/

## ── Database ────────────────────────────────────────────────────────────────

## Apply database migrations
migrate:
	$(GO) run ./db/migrate/

## Apply seed data (dev only)
seed:
	PGPASSWORD=zttpsecret psql -h localhost -U zttp -d zttp -f db/seed.sql

## Generate a bcrypt hash for a password (usage: make hashpw PW=mypassword)
hashpw:
	$(GO) run ./tools/hashpw/ $(PW)

## ── Docker ──────────────────────────────────────────────────────────────────

## Start all Docker Compose services
docker-up:
	docker compose -f deploy/docker-compose.yml up -d --build
	@echo ""
	@echo "Services started. Check health:"
	@echo "  curl http://localhost:8080/healthz"
	@echo "  curl http://localhost:8200/v1/sys/health"

## Follow proxy logs
docker-logs:
	docker compose -f deploy/docker-compose.yml logs -f proxy

## Stop all services and remove volumes
docker-down:
	docker compose -f deploy/docker-compose.yml down -v

## Show running container status
docker-ps:
	docker compose -f deploy/docker-compose.yml ps

## ── Cleanup ─────────────────────────────────────────────────────────────────

clean:
	rm -rf dist/
	$(GO) clean -cache
