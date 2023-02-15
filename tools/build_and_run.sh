#!/bin/bash
set -e
cd /src/fuzzer
cargo make build
RUST_BACKTRACE=full ./fuzzer
