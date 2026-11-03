# GeDefense Retail - Build- und Betriebsziele
# Go stdlib only; kein CGO; kein Netzwerk-Download noetig.

GO ?= go
BIN := bin
MOD := src/retail

.PHONY: all build build-gate test vet race fmt fmt-check check run sim-demo e2e e2e-gate visual-qa gate-e2e clean

all: build

build:
	cd $(MOD) && $(GO) build -trimpath -o ../../$(BIN)/ ./cmd/retaild
	cd $(MOD) && $(GO) build -trimpath -o ../../$(BIN)/ ./cmd/retail-sim

build-gate:
	cd $(MOD) && $(GO) build -trimpath -o ../../$(BIN)/ ./cmd/retailgate

gate-e2e: build-gate
	python tests/gate_e2e.py

test:
	cd $(MOD) && $(GO) test ./...

vet:
	cd $(MOD) && $(GO) vet ./...

race:
	cd $(MOD) && $(GO) test -race ./...

fmt:
	cd $(MOD) && gofmt -w .

fmt-check:
	cd $(MOD) && test -z "$$(gofmt -l .)"

check: fmt-check vet build test

run:
	cd $(MOD) && $(GO) run ./cmd/retaild serve --config ../../config/retail.json

sim-demo:
	cd $(MOD) && $(GO) run ./cmd/retail-sim feed --url http://127.0.0.1:8080 --scenario normal --rate 5

e2e:
	python tests/e2e.py

visual-qa:
	python tests/visual_qa.py

clean:
	rm -rf $(BIN)