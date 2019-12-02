#!/bin/bash

if ! command -v yq >/dev/null 2>&1; then
  echo "please install the \"yq\" binary (YAML wrapper for jq)"
fi

commands=$(yq -r '.script | join(" && ")' .travis.yml)
echo "$commands"
eval $commands
