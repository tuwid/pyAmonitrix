#!/usr/bin/python

import socket   #for sockets
import sys  #for exit
import signal


def signal_handler(signal, frame):
        print('Ctrl+C!')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# create dgram udp socket
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.settimeout(30)
except socket.error:
	print 'Failed to create socket'
	sys.exit()

host = 'localhost';
port = 10010;

while(1) :
	msg = raw_input('> #  ')

	if len(msg) > 0:
		try :
			#Set the whole string
			s.sendto(msg, (host, port))

			# receive data from client (data, addr)
			d = s.recvfrom(1024)
			reply = d[0]
			addr = d[1]

			print '> ' + reply

		except socket.error, msg:
			print ' Timeout or something'
			sys.exit()
