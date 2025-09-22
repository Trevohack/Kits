#!/bin/bash

echo "=== Enumerating .ko files ==="
find /lib/modules/$(uname -r) -type f -name "*.ko" | head -n 20

echo -e "\n=== Checking tracing functions ==="
for f in /sys/kernel/tracing/* /sys/debug/kernel/tracing/*; do
    [[ -f $f || -d $f ]] && echo "$f exists"
done 

echo -e "\n=== Kernel Modules ==="
cat /proc/modules

echo -e "\n=== Kernel Logs Sample ==="
dmesg | tail -n 10
journalctl -k -n 10


