BINARY      := blackbox
CMD         := ./cmd/blackbox
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS     := -s -w -X main.version=$(VERSION)
GOFLAGS     ?=
BIN_DIR     ?= /usr/local/bin

.PHONY: all build test vet lint fmt clean install

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(CMD)

test:
	go test -race -count=1 -coverprofile=coverage.out ./...

vet:
	go vet ./...

lint:
	golangci-lint run

fmt:
	gofmt -w .

clean:
	rm -rf bin coverage.out

install: build
	install -Dm0755 bin/$(BINARY) $(BIN_DIR)/$(BINARY)
