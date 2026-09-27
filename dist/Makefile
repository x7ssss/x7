# x7 cross-platform compilation Makefile
# Static stripped binaries under 12MB limit

MODULE := github.com/x7ssss/x7
VERSION := v1.0.0
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "release")
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X $(MODULE)/cmd.Version=$(VERSION) -X $(MODULE)/cmd.GitCommit=$(COMMIT) -X $(MODULE)/cmd.BuildDate=$(BUILD_DATE)

DIST_DIR := $(CURDIR)/dist
ifeq ($(notdir $(CURDIR)),dist)
	DIST_DIR := $(CURDIR)
	ROOT_DIR := $(CURDIR)/..
else
	ROOT_DIR := $(CURDIR)
endif

.PHONY: all clean build-all linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 test

all: build-all

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

linux-amd64: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/x7-linux-amd64 $(ROOT_DIR)/cmd/x7

linux-arm64: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/x7-linux-arm64 $(ROOT_DIR)/cmd/x7

darwin-amd64: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/x7-darwin-amd64 $(ROOT_DIR)/cmd/x7

darwin-arm64: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/x7-darwin-arm64 $(ROOT_DIR)/cmd/x7

windows-amd64: $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST_DIR)/x7-windows-amd64.exe $(ROOT_DIR)/cmd/x7
	cp $(DIST_DIR)/x7-windows-amd64.exe $(DIST_DIR)/x7.exe 2>/dev/null || true
	cp $(DIST_DIR)/x7-windows-amd64.exe $(DIST_DIR)/x7 2>/dev/null || true

build-all: linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64
	@echo "All targets compiled successfully into $(DIST_DIR)"

test:
	go test -v ./...

clean:
	rm -rf $(DIST_DIR)/*
