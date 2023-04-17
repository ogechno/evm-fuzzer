#!/bin/bash
set -e
cd /src/fuzzer
# cargo make build
# RUST_BACKTRACE=full ./fuzzer -r ./crashes/e38b0a49881beb1d
cargo make silkworm-routine
./fuzzer
