import subprocess
import sys
import time
import os

if len(sys.argv) < 3:
	print "error. Not enough arguments."
	exit(0)
ipOfRemoteHost = str(sys.argv[1])
portOfRemoteHost = str(sys.argv[2])
numRules = 2000;

# flush all rules in IPtable before starting the experiment.
os.system('iptables -t nat -F')
os.system('iptables -t filter -F')
os.system('iptables -t raw -F')
os.system('iptables -t mangle -F')

#configurig IPtables to perform DNAT
os.system('iptables -t nat -A PREROUTING -p udp --dport 53000 -j DNAT --to 158.130.167.255:53000')
os.system('iptables -A FORWARD -d 158.130.167.255 -p tcp --dport 53000 -j ACCEPT')
os.system('iptables -t nat -A POSTROUTING -j MASQUERADE')
os.system('sysctl net.ipv4.ip_forward=1')

subprocess.call(["./rule_generator.sh", "2000"])

print "Done with flushing... Send the packets now."

for i in range(75):
	fileName = "out"
	fileName += str(numRules)
	fileName += ".txt"
	output = open(fileName, "a")
	subprocess.call(["./sniffer", "eth0"], stdout=output)
	print "Finished capture... " + str(i + 1)
	time.sleep(10)
	#Calling rule generator to configure numRules number of additional rules.
	subprocess.call(["./rule_generator.sh", "2000"])
	time.sleep(5)
	print "configured additional 2000 rules in IPtable. Total rules are " + str(numRules)
	for i in range(5):
		subprocess.call(["nc", "-w1", ipOfRemoteHost, portOfRemoteHost])
		time.sleep(0.1)
	numRules += 2000
	print "sent response packets"
