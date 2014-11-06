#!/usr/bin/python

import subprocess
import time

# manager

def engine():
	print "Main engine controller"

proc = []

proc.append(0) 
proc.append(1) 
proc[0] = subprocess.Popen(["./sauron.py", "-n 1"], shell=False)
proc[1] = subprocess.Popen(["./sauron.py", "-n 2"], shell=False)

print 'poll =', proc[0].poll(), '("None" osht ndez dmth )'
print 'poll =', proc[1].poll(), '("None" osht ndez dmth )'

time.sleep(30)
subprocess.call(["kill", "-9", "%d" % proc[0].pid])
subprocess.call(["kill", "-9", "%d" % proc[1].pid])

proc[0].wait()
proc[1].wait()

print 'poll =', proc[0].poll()
print 'poll =', proc[1].poll()

