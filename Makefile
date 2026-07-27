GOTOOLCHAIN ?= auto
export GOTOOLCHAIN

COMPONENT := honeycombauthextension
TOOLS_BIN := $(abspath .tools)

.PHONY: test
test:
	cd $(COMPONENT) && go test ./...

.PHONY: vet
vet:
	cd $(COMPONENT) && go vet ./...

.PHONY: lint
lint: vet
	command -v golangci-lint >/dev/null 2>&1 && cd $(COMPONENT) && golangci-lint run ./... || echo "golangci-lint not installed; ran go vet only"

.PHONY: tidy
tidy:
	cd $(COMPONENT) && go mod tidy

# Tool versions are pinned in internal/tools/go.mod (the contrib pattern);
# mdatagen can't be `go run pkg@version` because its go.mod has replace directives.
.PHONY: install-tools
install-tools:
	cd internal/tools && GOWORK=off GOBIN=$(TOOLS_BIN) go install go.opentelemetry.io/collector/cmd/mdatagen

.PHONY: generate
generate: install-tools
	cd $(COMPONENT) && $(TOOLS_BIN)/mdatagen metadata.yaml

# Build and run the example distro (OTLP receiver + honeycombauth + debug exporter).
.PHONY: example
example:
	cd example && ./run.sh
