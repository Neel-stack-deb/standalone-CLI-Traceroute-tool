.PHONY: build test install run

build:
	go build -o bin/traceroute-tool ./cmd/traceroute-tool

test:
	go test ./...

install:
	bash .cursor/install.sh

run: build
	./bin/traceroute-tool -m 5 8.8.8.8
