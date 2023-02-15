# evm-fuzzer
## Getting started
1. Clone the evm-fuzzer repository with
```bash
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
Move duplicates out of corpus:
```
find . -name '*-[0-9]*' -delete
```
For corpus testdata to make vim not append \n at the end of the file do:
```bash
:set noendofline and :set nofixendofline 
```

## TODO
- Clean up repo
- Repeat single testcases 
- Branch for thesis
- don't add dup testcases to corpus
- Setup LibAFL with new Components
    - Define custom objective
    - DiffExecutor, DiffObserver
- multi transaction
- go-fuzz-build support
- Geth harness clean up with Config and NewEnv (runtime)
- tmin corpus minimizer
- Grammar Mutator
