.PHONY: build test install run run-cap

BINARY := bin/traceroute-tool

build:
	go build -o $(BINARY) ./cmd/traceroute-tool

test:
	go test ./...

install:
	bash .cursor/install.sh

run: build
	sudo $(BINARY) -m 10 -w 3 -q 3 8.8.8.8

run-cap: build
	@echo "Granting cap_net_raw to $(BINARY) (requires sudo once)"
	sudo setcap cap_net_raw+ep $(BINARY)
	$(BINARY) -m 10 -w 3 -q 3 8.8.8.8
