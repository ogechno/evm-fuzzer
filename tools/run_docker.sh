#!/bin/bash
set -e
# docker build -t evmfuzzing_image .
# echo "Image build done"
docker run -ti --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v $(realpath ../evm-fuzzer):/src evmfuzzing_image 
# --user $(id -u):$(id -g) evmfuzzing_image 
