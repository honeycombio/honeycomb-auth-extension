GOTOOLCHAIN ?= auto
export GOTOOLCHAIN

COMPONENT := honeycombauthextension

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

.PHONY: generate
generate:
	cd $(COMPONENT) && go run go.opentelemetry.io/collector/cmd/mdatagen metadata.yaml

# Build and run the example distro (OTLP receiver + honeycombauth + debug exporter).
.PHONY: example
example:
	cd example && ./run.sh
