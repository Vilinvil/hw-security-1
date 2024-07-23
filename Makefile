.PHONY: all
all: build up

.PHONY: gen-cert
gen-cert:
	./scripts/gen-cert.sh

.PHONY: build
build:
	docker compose build

.PHONY: up
up:
	docker compose up -d