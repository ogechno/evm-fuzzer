# cd ..
# mkdir build
cd build
# rm CMakeCache.txt
cmake -DSILKWORM_CORE_ONLY=ON ..
cmake --build . --target all
mv fuzzer ../fuzzer/.
