#!/usr/bin/python

import subprocess
from time import sleep

# manager
def engine():
	print "Main engine controller"

proc = []

for x in range (0,5):
	proc.append(x)
	proc[x] = subprocess.Popen(["./sauron.py", "-n "+str(x)], shell=False)
	sleep(1)
	if str(proc[x].poll() == "None"):
		print "Service " + str(x) + " on Node 1 is checking "
	else:
		print "Service " + str(x) + " on Node 1 is not checking "


sleep(60)

for x in range (0,5):
	subprocess.call(["kill", "-9", "%d" % proc[x].pid])
	proc[x].wait()

#print 'poll =', proc[0].poll()
#print 'poll =', proc[1].poll()

