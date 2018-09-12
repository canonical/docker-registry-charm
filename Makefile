.PHONY: build
build:
	charm build --no-local-layers

.PHONY: lint
lint:
	flake8 reactive/docker-registry.py

.PHONY: check
check: lint
