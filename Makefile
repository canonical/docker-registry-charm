.PHONY: build
build: hooks/charmhelpers

hooks/charmhelpers: charm-helpers.yaml
	./charm_helpers_sync.py -c charm-helpers.yaml

.PHONY: lint
lint:
	flake8 hooks/config-changed

.PHONY: clean
clean:
	-rm -rf hooks/charmhelpers

.PHONY: check
check: lint
