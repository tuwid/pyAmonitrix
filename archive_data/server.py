#!/usr/bin/python
#import socket
from socket import socket, htons, AF_INET, SOCK_DGRAM, SOCK_RAW, getprotobyname, gethostbyname, error, gaierror
import re
import sys
import signal

def signal_handler(signal, frame):
        print('Ctrl+C!')
        sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)


class service:
	#"""service instance (similar to node)""" 
	# sherbimet kane 
	#	id
	#	current_status OK, ERROR, (FLAPPING?)
	#	last_5
	#	last_event
	#	notific_staus

	def __init__(self,id):
		self.id = id
		self.last_status = ""
		self.data = ""
	def add_status(self,status):
		self.last_status = status
	def add_data(self,node_data):
		self.data = node_data
	def print_node(self):
		try:
			print "Node id - ",self.id
			print "Node last status - ",self.last_status
			print "Node latest_data - ",self.data
		except:
			sys.exit("fuck it")


class mon_instance:
	#"""instance that will help us process data""" 
	def __init__(self,ip):
		self.ip = ip
		self.latest_data = ""
		self.nodes = []

		#self.nodes = service[]
	def get_ip(self):
		return self.ip
	def set_lates_data(self,ldata):
		self.latest_data = ldata
	def get_data(self):
		return self.data
	def process(self,data):
		print ""
	def add_nodes(self,node):
		self.nodes.append(node)
	def status(self):
		try:
			print "Instance ip: ",self.ip
			#print self.latest_data
			print "Nr of nodes: ",len(self.nodes)
		except:
			sys.exit("Error")


instances = []
#instances.append(mon_instance("127.0.0.1"))

def process(data):
	pattern = re.compile(r'(\S+) Node (\d+) (\S+) (.*)', flags=re.DOTALL)
	results = pattern.findall(data)
	instance_ip = str(results[0][0])
	node_id = str(results[0][1])
	service_status = str(results[0][2])
	service_data = str(results[0][3])
	#print "\tParsed data:"
	#print "Instance ip \t: ",instance_ip
	#print "Node id \t: ",node_id
	#print "Service status \t: ",service_status
	#print "Service data \t: ",service_data

	temp_service = service(node_id)
	temp_service.add_status(service_status)
	temp_service.add_data(service_data)
	#temp_service.print_node()

	found = -1
	for x in range(0,len(instances)): 
		#print "id ",x," ",instances[x].get_ip()
		if instances[x].get_ip() == instance_ip:
			#print "\tFound instance with IP " + instances[x].get_ip()
			found = x
			#if instances[0]['']

	if found == -1:
		#print "\tWe dont have that, adding " + str(instance_ip)
		instances.append(mon_instance(instance_ip))
		instances[-1].add_nodes(temp_service)
	else:
		instances[found].add_nodes(temp_service)



process("127.0.0.1 Node 6 OK banner: +OK Dovecot ready.   16:44:09.553908")
process("127.0.0.1 Node 6 OK banner: +OK Dovecot ready.   16:44:09.553908")
process("127.0.0.2 Node 1 OK 105.588 16:44:10.329358")
process("127.0.0.3 Node 1 OK 51.041 16:44:11.382219")
process("127.0.0.2 Node 1 OK 51.041 16:44:11.382219")
process("127.0.0.1 Node 2 ERROR Error Unable to connect to <class 'socket.timeout'> 16:44:11.440851")

instances[0].status()
instances[1].status()
instances[2].status()
#instances[3].status()
#instances[4].status()



sys.exit(1)


# Create a TCP/IP socket
sock = socket(AF_INET, SOCK_DGRAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)
while True:
    data, address = sock.recvfrom(4096)
    print >>sys.stderr,str(address[0]) +" " + str(data)
	
	# vjen e dhena si me poshte:
	# 127.0.0.1 Node 6 OK, banner: +OK Dovecot ready.   16:44:09.553908
	# 127.0.0.1 Node 1 OK 105.588 16:44:10.329358
	# 127.0.0.1 Node 1 OK 51.041 16:44:11.382219
	# 127.0.0.1 Node 2 ERROR Error Unable to connect to <class 'socket.timeout'> 16:44:11.440851
	#
	# krijohet instanca 1 me IP 127.0.0.1
	# 	i shtohet instances 1 nyjet 1,2,6
	#	nyjes 6 i vihet statusi OK
	#	
	# 1 instance (nje IP) ka disa sherbime
	# pervec sherbimeve instanca ka:
	#	node_list
	#	node_status(??)
	#	
	# sherbimet kane 
	#	status (mesatarja e 5 statuseve te fundit)	OK, ERROR, FLAPPING
	# 	last_status 
	#	last_5
	#	notific_staus

    #sent = sock.sendto("!", address)
    #print >>sys.stderr, 'sent %s bytes back to %s' % (sent, address)
