SHELL := /bin/sh

BINARY := dist/vless-wan

.PHONY: all build clean fmt test vet verify xray

all: verify

build: xray
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) .

xray:
	./scripts/fetch-xray.sh

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -d .; exit 1; }

test:
	go test -race -cover ./...

vet:
	go vet ./...

verify: fmt test vet

clean:
	rm -rf dist core/xray coverage.out
