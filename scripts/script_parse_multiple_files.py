"""
This is a python script to parse the text file that contains the sniffer capture of TCP packets.
"""

import sys

# #Reading the commandline arguments
# inputFile = str(sys.argv[1])

baseString = "out"


fileNum = 2000;

for i in range(62):
   fileNum = (i+1)*2000

   inputFile = baseString + str(fileNum) + ".txt"
   print ""
   print str(fileNum) + ",",
   f = open(inputFile, "r")
   lineNum = 1 # line number to keep track of start and end time.
   start = 0 #Start time - time of entry into the system
   end = 0 # End time - time of leaving the system into the network.
   totalTime = 0
   avgTime = 0
   # iterating through the file line by line.
   for line in f:
      # if the line contains the following string then enter the condition.
      # The unparsed text looks like this : "The time stamp of the packet is [55528]".
      # we only need the numerical value in the above string.
      if line.find("The time stamp of the packet is ") != -1:
         line = line.strip("The time stamp of the packet is ").strip("[")
         # unable to remove "]" for some reason using split(). This is a workaround. FIXME 
         line = line[:-2]
         # Comparing the line number and using it as start and end time, to calculate the total time spent before exiting the interface.
         if lineNum % 2 != 0:
            start = int(line) 
            lineNum +=1
         else:
            end = int (line)
            # print str(end - start) + ",",
            totalTime += (end - start)
            lineNum +=1;
   avgTime = (totalTime*2) / lineNum
   # print "the line num is " + str(lineNum)
   # print " the total time is " + str(totalTime)
   print str(avgTime)
