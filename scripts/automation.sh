#!/bin/bash
#automation.sh

echo "Spawnign packet generator shell"

gnome-terminal -e  ./nc_packet_generator.sh

if [ -z "$1"]; then
	echo "Nothing to do!\n"
else
	echo "Spawning the rule configure "
	gnome-terminal -e ./rule_generator.sh
fi

echo "Spawning the sniffer shell"
gnome-terminal -e './pcap lo'

echo "Done... Exiting\n"