#!/bin/bash
cd /src/fuzzer/crashes
for file in *; do 
    if [ -f "$file" ]; then 
        string=$(../fuzzer -r $file)
        if [[ $string == *"NOT CRASHED"* ]]; then
            echo "$file NOT CRASHED"
            rm $file
        fi
    fi
done
