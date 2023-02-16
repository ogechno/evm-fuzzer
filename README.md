# evm-fuzzer
## Getting started
1. Clone the evm-fuzzer repository and download the submodules
```bash
git clone https://github.com/ogechno/evm-fuzzer
cd evm-fuzzer
git submodule update --recursive
```
2. Build the docker image using
```bash
./tools/run_docker.sh
```
3. Build evm-fuzzer inside the running docker image
```bash
./tools/build_and_run.sh
```

## Useful commands
Add new testcase to corpus:
```bash
./tools/convert.sh <bytecode in hex> ../fuzzer/coprus/<filename> 
```
Remove duplicates from the corpus:
```
cd fuzzer/corpus
find . -name '*-[0-9]*' -delete
```
Make vim not append \n at the end of the file do:
```bash
:set noendofline and :set nofixendofline 
```

## TODO
- Repeat single testcases 
- Update evmone and geth to latest version
- Branch for thesis
- Branch for bsides
- don't add dup testcases to corpus
- split up harness
- add nethermind and besu support
- Setup LibAFL with new Components
    - Define custom objective
    - DiffExecutor, DiffObserver
- multi transaction
- go-fuzz-build support
- Geth harness clean up with Config and NewEnv (runtime)
- tmin corpus minimizer
- Grammar Mutator
