#!/bin/bash
num_gen=$1

for ((i=1; i<=num_gen; i=i+1))
do
    sync
    echo 3 > /proc/sys/vm/drop_caches

    echo "test string data" $i | netcat -q1 -u 192.168.21.1 40960 -p 40960
    echo "test string data" $i
done
