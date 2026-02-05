#!/bin/bash

# Ensure directory exists
mkdir -p data/benign

echo "[*] Generating Benign Windows Binaries..."

for i in {1..500}; do
    # 1. Generate a random alphanumeric string (50 chars) to change entropy/hash
    RAND_STR=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 50)

    # 2. Create the C source file DIRECTLY (No temp.c, no sed)
    #    We write the C code straight into a new file for this iteration
    cat <<EOF > "benign_source_$i.c"
#include <stdio.h>
int main() {
    // Random noise: $RAND_STR
    printf("I am safe file number $i\n");
    return 0;
}
EOF

    # 3. Compile it
    #    Input: benign_source_$i.c (in current folder)
    #    Output: data/benign/safe_$i.exe
    x86_64-w64-mingw32-gcc "benign_source_$i.c" -o "data/benign/safe_$i.exe" -s 2>/dev/null

    # 4. Cleanup: Remove the C file immediately
    if [ -f "benign_source_$i.c" ]; then
        rm "benign_source_$i.c"
    fi
done

# Check if it worked
COUNT=$(ls data/benign/*.exe 2>/dev/null | wc -l)
echo "[+] Done! Generated $COUNT benign .exe files in data/benign/"