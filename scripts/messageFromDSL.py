import sys
import subprocess
import time

# os.system('inotifywait -e modify ./t1.txt')
# os.system('sudo tcpdump -i lo src port 53000')

if len(sys.argv) < 3:
	print "missing arguments. Usage <host> <port>"
	exit(0);

HOST = str(sys.argv[1])

PORT = str(sys.argv[2])

raw_input ("Press enter when ready...")

for i in range(5):
	subprocess.call(["./nc_packet_generator.sh", "hello",HOST, PORT]);
	subprocess.call(["nc", "-l", PORT])
	print "Finshed round " + str(i+1)
	time.sleep(10)