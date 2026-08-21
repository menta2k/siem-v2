# SIEM v2 — multi-provider WAF log correlation & request flow analysis
.DEFAULT_GOAL := help
SHELL := /bin/bash
BACKEND := backend
BIN := bin
GO ?= go
GOFLAGS ?= -trimpath
LDFLAGS ?= -s -w
SERVICES := logproc apiserver retentiond profilerd
COMPOSE := docker compose -f deploy/compose/docker-compose.yml

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n",$$1,$$2}'

## ---------- build ----------
.PHONY: build
build: $(addprefix build-,$(SERVICES)) ## Build all Go services as static binaries

.PHONY: build-%
build-%:
	@mkdir -p $(BIN)
	cd $(BACKEND) && CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o ../$(BIN)/$* ./cmd/$*

.PHONY: build-wirefilter
build-wirefilter: ## Build the Rust wirefilter sidecar
	cd wirefilter-svc && cargo build --release

.PHONY: build-frontend
build-frontend: ## Build the Nuxt frontend
	cd frontend && npm ci && npm run build

## ---------- api ----------
.PHONY: api
api: ## Regenerate the OpenAPI spec from the protobuf definitions
	# One invocation over ALL protos, not one per package: protoc-gen-openapi
	# emits a single openapi.yaml, and per-package invocation makes the outputs
	# collide so only the last service survives.
	cd $(BACKEND) && buf build -o /tmp/siem-api-image.binpb && \
		protoc --openapi_out=api \
			--openapi_opt="title=SIEM v2 — Request Flow Analysis API,version=1.0.0,default_response=false" \
			--descriptor_set_in=/tmp/siem-api-image.binpb \
			flow/v1/flow.proto alert/v1/alert.proto evaluation/v1/evaluation.proto admin/v1/admin.proto

.PHONY: api-lint
api-lint: ## Lint the protobuf definitions
	cd $(BACKEND) && buf lint

.PHONY: api-check
api-check: api ## Fail if the committed OpenAPI spec is stale
	@git diff --exit-code -- $(BACKEND)/api/openapi.yaml \
		|| (echo "ERROR: openapi.yaml is stale. Run 'make api' and commit." && exit 1)

.PHONY: api-breaking
api-breaking: ## Fail on a breaking API change against main
	cd $(BACKEND) && buf breaking --against '.git#branch=main,subdir=backend'


## ---------- test ----------
.PHONY: test
test: ## Unit + fixture tests
	cd $(BACKEND) && $(GO) test ./... -race -count=1

.PHONY: test-cover
test-cover: ## Coverage report; constitution requires >=80% on parse/correlate/authz
	cd $(BACKEND) && $(GO) test ./... -race -coverprofile=coverage.out -covermode=atomic
	cd $(BACKEND) && $(GO) tool cover -func=coverage.out | tail -1

.PHONY: test-integration
test-integration: ## Integration tests against real dependencies
	cd $(BACKEND) && $(GO) test ./test/integration/... -tags=integration -count=1 -timeout=15m

.PHONY: test-scenarios
test-scenarios: ## Recorded end-to-end replay scenarios
	cd $(BACKEND) && $(GO) test ./test/scenarios/... -tags=scenario -count=1 -timeout=20m

.PHONY: test-detections
test-detections: ## Constitution III gate: every detection must pass a positive AND a near-miss fixture
	cd $(BACKEND) && $(GO) test ./internal/alerting/... -run TestDetectionFixtures -count=1

.PHONY: test-objectlock
test-objectlock: ## V9 gate: prove Object Lock is ENFORCED, not merely API-accepted
	cd $(BACKEND) && $(GO) test ./test/integration/... -tags=integration -run TestObjectLockConformance -v -count=1

.PHONY: load-test
load-test: ## Sustained + burst load harness (RATE, PROVIDERS, DURATION)
	cd $(BACKEND) && $(GO) test ./test/load/... -tags=load -count=1 -timeout=25h \
		-args -rate=$(or $(RATE),2000) -providers=$(or $(PROVIDERS),4) -duration=$(or $(DURATION),5m)

## ---------- quality ----------
.PHONY: lint
lint: ## Lint Go, Rust and frontend
	cd $(BACKEND) && golangci-lint run ./... || true
	cd wirefilter-svc && cargo clippy -- -D warnings || true
	cd frontend && npm run lint || true

.PHONY: fmt
fmt: ## Format all code
	cd $(BACKEND) && $(GO) fmt ./...
	cd wirefilter-svc && cargo fmt || true

## ---------- run ----------
.PHONY: dev-up
dev-up: ## Start the local dependency stack
	$(COMPOSE) up -d

.PHONY: dev-down
dev-down: ## Stop the local dependency stack
	$(COMPOSE) down

.PHONY: migrate
migrate: ## Apply PostgreSQL migrations
	cd $(BACKEND) && $(GO) run ./cmd/retentiond --migrate-only --conf ../configs/retentiond.yaml

.PHONY: run-%
run-%: ## Run a service (run-logproc, run-apiserver, run-retentiond)
	cd $(BACKEND) && $(GO) run ./cmd/$* --conf ../backend/configs/$*.yaml

.PHONY: run-frontend
run-frontend: ## Run the Nuxt dev server
	cd frontend && npm run dev

## ---------- docker ----------
.PHONY: docker
docker: ## Build container images for every service
	@for s in $(SERVICES); do \
		docker build -f deploy/docker/Dockerfile.backend --build-arg SERVICE=$$s -t siem-v2/$$s:dev . || exit 1; \
	done
	docker build -f deploy/docker/Dockerfile.wirefilter -t siem-v2/wirefilter-svc:dev wirefilter-svc

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN) $(BACKEND)/coverage.out
