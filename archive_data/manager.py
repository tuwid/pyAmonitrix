#!/usr/bin/python

from socket import socket, htons, AF_INET, SOCK_DGRAM, SOCK_RAW, getprotobyname, gethostbyname, error, gaierror
import sys
import signal
import subprocess
from time import sleep

proc = []
# manager
def signal_handler(signal, frame):
        print('Ctrl+C!')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def get_lines():
	config_file =open('node_config_file')
	if config_file:
		lines = config_file.readlines()
	else:
		sys.exit("No config file")
	return lines

sock = socket(AF_INET, SOCK_DGRAM)
server_address = ('localhost', 10010)

print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
while True:
    data, address = sock.recvfrom(1024)
    print >>sys.stderr,str(address[0]) +" " + str(data)

    if data:
		if data == "help":
			sock.sendto(" \n engine start \n engines status \n engine stop \n kill node nr X", address)
		elif data == "engine start":
			raport = "\n"
			#print "u futem tek starti"
			line_nr = len(get_lines())
			raport += "Got " + str(line_nr) + " lines \n"
			sock.sendto("Starting services... Please wait \n", address)
			for x in range (0,line_nr):
				proc.append(x)
				proc[x] = subprocess.Popen(["./sauron.py", "-n "+str(x)], shell=False)
				sleep(2)
				if str(proc[x].poll() == "None"):
					print "Service " + str(x) + " is checking "
					#raport += "Service " + str(x) + " is checking \n"
				else:
					#raport += "Service " + str(x) + " is not checking \n"
					print "Service " + str(x) + " is not checking "	
			        #print >>sys.stderr, 'sent %s bytes back to %s' % (sent, address)
		elif data == "engine status":
			raport = "\n"
			line_nr = len(get_lines())
			raport = "Jane " + str(line_nr) + " sherbime tek file i config \n"
			if len(proc) > 0:
				for x in range (0,line_nr):
					#print str(x) + " is " + str(proc[x].poll())
					if str(proc[x].poll()) == "None":
						raport += 'Service checker for node ' + str(x) + " monitoring \n"
					else:
						raport += "Node " + str(x) + " not monitoring \n"
			sock.sendto(raport , address)
		elif data == "engine stop":
			raport = "\n"
			line_nr = len(get_lines())
			if len(proc) > 0:
				print proc
				for x in range (0,line_nr):
					try:
						if str(proc[x].poll()) == "None":
							subprocess.call(["kill", "-9", "%d" % proc[x].pid])
							proc[x].wait()
							raport += "Send sigkill to node with pid " + str(proc[x].pid) + "\n"
						else:
							raport += "Node " + str(x) + " doesnt appear to be running \n"
					except:
						print "meh?"
			else:
				raport = "No services are currently runnig"
			sock.sendto(raport, address)
		else:
			sent = sock.sendto("Comand not found, press help for help", address)
