#!/bin/bash
set -euo pipefail

images="$(mktemp)"

echo '🕵️ Images to be analyzed:'
kustomize build "$1" | \
    yq '.spec.template.spec.containers[].image as $img ireduce([]; . + {"containerImage": $img}) | {"components": .}' |
    tee "${images}"

echo
echo '🕵️ Validation report:'
ec validate image --images $images --policy policies/prod.yaml --output yaml
