#!/bin/bash
n="$1"
j=(1 1 1 1)
n=$((n/4))
for i in $(seq 1 $n);
do
    iptables -t nat   -A INPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
    # iptables -t filter -A INPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
    # iptables -t raw  -A INPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
    # iptables -t mangle  -A INPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT

    j[0]=$(( ${j[0]} + 1))

    for k in {1..4};
    do
        if [ ${j[k-1]} = 256 ]
        then
            j[k]=$(( ${j[k]} + 1))
            j[k-1]=1
            k=4
        fi
    done

done
