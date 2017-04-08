#!/bin/bash
n="$1"
j=(1 1 1 1)
# iptables -t nat -F
# iptables -t filter -F
# iptables -t raw -F
# iptables -t mangle -F
# iptables -t nat -A PREROUTING -p tcp -s "158.130.52.22" --sport 53000:53100 -j DNAT --to-destination "158.130.166.173"
n=$((n/4))
echo "configuring rules inside rule generator\n"
for i in $(seq 1 $n);
do
    iptables  -t nat   -A OUTPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
    iptables  -t filter -A OUTPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
    iptables  -t raw  -A OUTPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
    iptables  -t mangle  -A OUTPUT -p udp -s "${j[3]}.${j[2]}.${j[1]}.${j[0]}" -j ACCEPT
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

echo "configured the rules. Inside rule generator...\n"