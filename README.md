# standalone-CLI-Traceroute-tool

Standalone Go CLI that traces network routes using Linux `tracepath`.

## Requirements

- Go 1.22+
- `iputils-tracepath` (installed automatically by `.cursor/install.sh`)

## Commands

```bash
make install   # download deps and build bin/traceroute-tool
make test      # run unit tests
make build     # build the binary
./bin/traceroute-tool -m 10 example.com
```

