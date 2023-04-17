# mkdir build
cd build
# rm CMakeCache.txt
cmake -DSILKWORM_CORE_ONLY=ON -DCMAKE_C_COMPILER=/src/fuzzer/target/debug/libafl_cc -DCMAKE_CXX_COMPILER=/src/fuzzer/target/debug/libafl_cxx ..
cmake --build . --target all
mv fuzzer ../fuzzer
