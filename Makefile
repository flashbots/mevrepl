.PHONY: build lint fmt

build:
	go build -o mevrepl ./cmd/mevrepl

lint:
	go vet ./...
	staticcheck ./...

fmt:
	gofmt -s -w .
