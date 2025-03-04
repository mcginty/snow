#!/usr/bin/env bash
set -e
TARGET="$([ -n "$1" ] && echo "--target $1" || echo "")"
MSRV="$(cargo metadata --no-deps | jq -r .packages[0].rust_version)"
RUSTC_VERSION="$(rustc --version | cut -w -f2)"

COMMON_FEATURES="use-p256 use-xchacha20poly1305 vector-tests"
if ! rustc -vV | grep 'host: .*windows' &> /dev/null; then
    COMMON_FEATURES="hfs use-pqcrypto-kyber1024 $COMMON_FEATURES"
fi

set -x
cargo check --benches --tests --examples
if [[ "$CI" != "true" || "$RUSTC_VERSION" == "$MSRV" ]]; then
    cargo clippy --features "$COMMON_FEATURES" --tests --benches --examples -- -Dwarnings
else
    echo "skipping cargo clippy on non-MSRV CI run. MSRV: $MSRV, rustc: $RUSTC_VERSION"
fi
cargo test $TARGET --no-default-features
# Custom set of crypto without std
cargo test $TARGET --no-default-features --features "default-resolver use-curve25519 use-blake2 use-chacha20poly1305"
# Custom set of crypto with std
cargo test $TARGET --no-default-features --features "default-resolver use-curve25519 use-sha2 use-chacha20poly1305"
cargo test $TARGET --features "ring-resolver $COMMON_FEATURES"
cargo test $TARGET --features "ring-accelerated $COMMON_FEATURES"
