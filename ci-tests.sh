#!/usr/bin/env bash
set -e
TARGET="$([ -n "$1" ] && echo "--target $1" || echo "")"

COMMON_FEATURES="xchachapoly vector-tests"
COMMON_ARGS="--color=always"

FEATURE_SETS=(
    "" # common features only
    "ring-resolver"
    "ring-accelerated"
    "libsodium-resolver"
    "libsodium-accelerated"
)
if ! rustc -vV | grep 'host: .*windows' &> /dev/null; then
    FEATURE_SETS+=("hfs pqclean_kyber1024")
    FEATURE_SETS+=("ring-resolver hfs pqclean_kyber1024")
fi

cmd() {
    echo -e "\033[34m=>\033[m "$@""
    output="$("$@" 2>&1)" || (echo "$output" && exit 1)
}

cmd cargo check --benches

cmd cargo test $COMMON_ARGS $TARGET --no-default-features
cmd cargo clippy $COMMON_ARGS --no-default-features

for feature_set in ${FEATURE_SETS[@]}; do
    features="$COMMON_FEATURES $feature_set"
    cmd cargo test $COMMON_ARGS $TARGET --features "$features"
    cmd cargo clippy $COMMON_ARGS --features "$features" -- -D warnings
done
