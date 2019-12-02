#!/usr/bin/env bash
set -e
TARGET="$([ -n "$1" ] && echo "--target $1" || echo "")"

set -x
cargo check --benches
cargo test $TARGET --no-default-features
cargo test $TARGET --features "vector-tests"
cargo test $TARGET --features "ring-resolver vector-tests"
cargo test $TARGET --features "ring-accelerated vector-tests"

if [[ "$OSTYPE" != "darwin"* && "$OSTYPE" != "msys" ]]; then
  cargo test $TARGET --features "hfs pqclean_kyber1024 vector-tests"
  cargo test $TARGET --features "ring-resolver hfs pqclean_kyber1024 vector-tests"
else
  echo "skipping HFS/PQClean tests, pending fix of https://github.com/rustpq/pqcrypto/issues/6"
fi

