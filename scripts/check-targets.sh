#!/bin/sh
# Lint every crate for every target it supports. Only Linux builds the full `listen` binary; the
# other backends are checked as libraries until they've been run on real hardware (see
# listen/src/main.rs).
#
# Needs: rustup target add x86_64-unknown-freebsd aarch64-apple-darwin x86_64-pc-windows-gnu \
#        thumbv7em-none-eabihf
set -eu
cd "$(dirname "$0")/.."

echo "== host"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

for target in x86_64-unknown-freebsd aarch64-apple-darwin x86_64-pc-windows-gnu; do
    echo "== $target"
    cargo clippy -p common -p crypto -p listen --lib --target "$target" --locked -- -D warnings
done

# Bare metal: the platform layer and crypto only, until listen has a bare-metal backend.
echo "== thumbv7em-none-eabihf"
cargo clippy -p common -p crypto --target thumbv7em-none-eabihf --locked -- -D warnings
