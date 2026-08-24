.PHONY: build release release-all clean

BINARY_NAME=plenarai
MODULE=github.com/plenarai/cli

# Detect OS
ifeq ($(OS),Windows_NT)
	GOOS=windows
	EXT=.exe
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		GOOS=darwin
	else
		GOOS=linux
	endif
	EXT=
endif

# Detect arch
GOARCH=$(shell go env GOARCH)

# Development build (sin ofuscacion, sin firmar)
build:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BINARY_NAME)$(EXT) ./cmd/plenarai

# Production build (ofuscado + firmado + optimizado)
# Requiere: go install mvdan.cc/garble@latest
release:
	@echo "Building obfuscated binary for $(GOOS)/$(GOARCH)..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) garble -tiny -literals -seed=random build -trimpath -ldflags "-s -w" -o $(BINARY_NAME)$(EXT) ./cmd/plenarai
	@echo "Computing integrity hash..."
	$(eval HASH := $(shell sha256sum $(BINARY_NAME)$(EXT) | cut -d' ' -f1))
	@echo "Hash: $(HASH)"
	@echo "Rebuilding with embedded hash..."
	GOOS=$(GOOS) GOARCH=$(GOARCH) garble -tiny -literals -seed=random build -trimpath -ldflags "-s -w -X $(MODULE)/internal/security.ExpectedHash=$(HASH)" -o $(BINARY_NAME)$(EXT) ./cmd/plenarai
	@echo "Production build complete: $(BINARY_NAME)$(EXT)"

# Production cross-platform (ofuscado + optimizado)
# GOOS/GOARCH explícitos en cada variante; sin ellos go build produce el
# binario de la plataforma anfitriona aunque el nombre del fichero diga otra cosa.
SERVER_URL_LDFLAGS := -X $(MODULE)/internal/config.ServerURL=https://plenarai.com

release-all:
	GOOS=linux GOARCH=amd64 garble -tiny -literals -seed=random build -trimpath -ldflags "-s -w $(SERVER_URL_LDFLAGS)" -o $(BINARY_NAME)-linux-amd64 ./cmd/plenarai
	GOOS=darwin GOARCH=amd64 garble -tiny -literals -seed=random build -trimpath -ldflags "-s -w $(SERVER_URL_LDFLAGS)" -o $(BINARY_NAME)-darwin-amd64 ./cmd/plenarai
	GOOS=darwin GOARCH=arm64 garble -tiny -literals -seed=random build -trimpath -ldflags "-s -w $(SERVER_URL_LDFLAGS)" -o $(BINARY_NAME)-darwin-arm64 ./cmd/plenarai
	GOOS=windows GOARCH=amd64 garble -tiny -literals -seed=random build -trimpath -ldflags "-s -w $(SERVER_URL_LDFLAGS)" -o $(BINARY_NAME)-windows-amd64.exe ./cmd/plenarai

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe $(BINARY_NAME)-*
