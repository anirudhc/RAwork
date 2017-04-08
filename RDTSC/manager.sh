#!/bin/bash
Num_rule=0
iptables -t nat -F
iptables -t filter -F
iptables -t mangle -F
iptables -t raw -F

for ((i=1000; i<=200000; i=i+1000))
do
    ./rule_generator.sh 1000
    Num_rule=$((Num_rule+1000))
    echo $Num_rule > "rule.txt"

    dmesg -C

    sleep 1
    ./nc_packet_generator.sh 40
    sleep 1

    dmesg > demsg_output.txt

    ./calculator
	echo $Num_rule

done
