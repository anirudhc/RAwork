#!/bin/bash

def_host=localhost
def_port=63007

HOST=${2:-$def_host}
SPORT=${3:-$def_port}
DPORT=53000
for ((i =0; i< 30; i= i+1))
do
	echo $HOST
	echo $PORT
	echo $SPORT
	echo -n "$1" | netcat -p $DPORT -q1 -u $HOST $SPORT
	echo "Sent a packet to " $DPORT
	((DPORT++))
	sleep 1
done
