#!/usr/bin/python

import subprocess
from time import sleep

# manager
def engine():
	print "Main engine controller"



proc = []

config_file =open('node_config_file')
if config_file:
	lines = config_file.readlines()
else:
	sys.exit("No config file")


print "Got " + str(len(lines)) + " lines"
line_nr = len(lines)

for x in range (0,line_nr):
	proc.append(x)
	proc[x] = subprocess.Popen(["./sauron.py", "-n "+str(x)], shell=False)
	sleep(1)
	if str(proc[x].poll() == "None"):
		print "Service " + str(x) + " is checking "
	else:
		print "Service " + str(x) + " is not checking "


sleep(20)

for x in range (0,line_nr):
	if str(proc[x].poll()) == "None":
		print 'Service checker for node ' + str(x) + " monitoring"
	else:
		print "Node " + str(x) + "not monitoring"


#sleep(60)

for x in range (0,line_nr):
	subprocess.call(["kill", "-9", "%d" % proc[x].pid])
	proc[x].wait()

#print 'poll =', proc[1].poll()

