# Root Makefile forwarding to dist build targets
.PHONY: all clean build-all linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 test

all: build-all

linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 build-all clean:
	$(MAKE) -f dist/Makefile $@

test:
	go test -v ./...
