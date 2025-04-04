#!/usr/bin/env bash
# This script is used to prepare the layers for the charm build process.
# It will pull the layers from the charm store and place them in the tmp directory.
set -eu

# ensure we have environment variables set
: "${RELEASE_BRANCH:?Environment variable RELEASE_BRANCH is not set.}"
: "${CHARM_LAYERS_DIR:?Environment variable CHARM_LAYERS_DIR is not set.}"
: "${CHARM_INTERFACES_DIR:?Environment variable CHARM_INTERFACES_DIR is not set.}"
: "${CRAFT_ARCH_BUILD_ON:=$(dpkg --print-architecture)}"
: "${LAYER_INDEX:='https://raw.githubusercontent.com/charmed-kubernetes/layer-index/main/'}"

# Ensure the temporary directory was created successfully
TMP_DIR=$(mktemp -d)
if [ ! -d "$TMP_DIR" ]; then
    echo "Failed to create a temporary directory."
    exit 1
fi
trap 'rm -rf "$TMP_DIR"' EXIT

# ensure we have the right prerequisites
for cmd in charm wget yq; do
    if ! command -v $cmd &> /dev/null; then
        echo "$cmd command not found. Please install $cmd."
        exit 1
    fi
done

mkdir -p $CHARM_INTERFACES_DIR
mkdir -p $CHARM_LAYERS_DIR
wget "https://raw.githubusercontent.com/charmed-kubernetes/jenkins/refs/heads/main/jobs/includes/charm-layer-list.inc" -O ${TMP_DIR}/layers.yaml
for layer in $(cat ${TMP_DIR}/layers.yaml | yq '.[] | keys | .[]' - ); do
    if [[ ! "$layer" =~ ^(interface:|layer:) ]]; then continue; fi
    echo "Pulling layer: ${layer}"
    charm pull-source \
        --layer-index ${LAYER_INDEX} \
        --branch ${RELEASE_BRANCH} \
        ${layer} &
done
wait
