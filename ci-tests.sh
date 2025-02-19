#!/usr/bin/env bash
set -e
TARGET="$([ -n "$1" ] && echo "--target $1" || echo "")"

COMMON_FEATURES="use-p256 use-xchacha20poly1305 vector-tests"
if ! rustc -vV | grep 'host: .*windows' &> /dev/null; then
    COMMON_FEATURES="hfs use-pqcrypto-kyber1024 $COMMON_FEATURES"
fi

set -x
cargo check --benches --tests --examples
cargo clippy --features "$COMMON_FEATURES" --tests --benches --examples -- -Dwarnings
cargo test $TARGET --no-default-features
# Custom set of crypto without std
cargo test $TARGET --no-default-features --features "default-resolver use-curve25519 use-blake2 use-chacha20poly1305"
# Custom set of crypto with std
cargo test $TARGET --no-default-features --features "default-resolver use-curve25519 use-sha2 use-chacha20poly1305"
cargo test $TARGET --features "ring-resolver $COMMON_FEATURES"
cargo test $TARGET --features "ring-accelerated $COMMON_FEATURES"
