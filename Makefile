BIN     = wgvpn
LDFLAGS = -s -w

.PHONY: build clean

# Cross-compile for Ubuntu/Linux amd64 (run from Windows)
build:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/wgvpn/

clean:
	rm -f $(BIN)
