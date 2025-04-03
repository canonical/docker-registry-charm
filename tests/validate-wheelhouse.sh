#!/bin/bash
set -eux

build_dir="$(mktemp -d --tmpdir=${TOX_ENV_DIR}/tmp)"
charm="$(egrep '^name\S*:' ./metadata.yaml | awk '{ print $2 }')"
function cleanup { rm -rf "$build_dir"; }
trap cleanup EXIT

charm-build src --build-dir "$build_dir" --debug
pip install -f "$build_dir/$charm/wheelhouse" --no-index --no-cache-dir "$build_dir"/$charm/wheelhouse/*
