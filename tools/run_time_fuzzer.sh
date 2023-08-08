OUTPUT_FILE="time.txt"
cd fuzzer
echo "Started fuzzing at: [$(date)]" >> "$OUTPUT_FILE"
timeout --signal=SIGTERM 10s ./fuzzer
