.PHONY: build
build:
	charm build -o dist ./layer/docker-registry

.PHONY: lint
lint:
	flake8 layer/docker-registry/reactive/docker-registry.py

.PHONY: clean
clean:
	-rm -rf dist

.PHONY: check
check: lint
