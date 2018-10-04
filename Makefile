.PHONY: build
build:
	charm build --no-local-layers --report

.PHONY: lint
lint:
	flake8 reactive/docker-registry.py
