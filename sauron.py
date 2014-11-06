#!/usr/bin/python

from socket import socket, htons, AF_INET, SOCK_RAW, getprotobyname, gethostbyname, error, gaierror
from struct import pack, unpack
from random import random  # Possibly switch to os.urandom()
from select import select
from time import time, sleep
from sys import version_info as py_version

import os
import re
import sys
import httplib
import syslog
import datetime
import threading
import argparse

# NYJE
# do marri nji file config nga diku ( aktualisht thjesht do lexoje nje file )
# do parsoje sherbimet qe do monitoroje nga ai file
# do startoje sherbimet e monitorimit dhe rezultatet do i postoje ne nje API


def check_if_root():
	if not os.geteuid() == 0:
		#sys.exit('Script must be run as root')
		sys.exit('Y U NO ROOT ??')
	else:
		print "Root check OK"

check_if_root()

# Remove this line to make all functions public, or selectively add needed functions to make them public.
#__all__ = ["create_packet", "echo", "recursive"]

# Python 3 doesn't have the xrange function anymore, this line makes it compliant with both v2 and v3.
xrange = range if py_version[0] >= 3 else xrange

ICMP_ECHO_REQUEST = 8
ICMP_CODE = getprotobyname("icmp")
ERROR_DESCR = {1: "ICMP messages can only be sent from processes running as root.",
				10013: "ICMP messages can only be sent by users or processes with administrator rights."}


def write_log(node_event):
	node_event += " " +str(datetime.datetime.now().time())
	syslog.syslog(syslog.LOG_ERR, node_event)


def checksum(source_string):
    checksum = 0
    count_to = len(source_string) & -2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        checksum += this_val
        checksum &= 0xffffffff  # Necessary?
        count += 2
    if count_to < len(source_string):
        checksum += ord(source_string[len(source_string) - 1])
        checksum &= 0xffffffff  # Necessary?
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    answer = ~checksum
    answer &= 0xffff
    return answer >> 8 | (answer << 8 & 0xff00)


def create_packet(id):
    """Creates a new echo request packet based on the given "id"."""
    # Builds Dummy Header
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = 192 * "Q"

    # Builds Real Header
    header = pack("bbHHh", ICMP_ECHO_REQUEST, 0, htons(checksum(header + data)), id, 1)
    return header + data


def response_handler(sock, packet_id, time_sent, timeout):
    """Handles packet response, returning either the delay or timing out (returns "None")."""
    while True:
        ready = select([sock], [], [], timeout)
        if ready[0] == []:  # Timeout
            return

        time_received = time()
        rec_packet, addr = sock.recvfrom(1024)
        icmp_header = rec_packet[20:28]
        type, code, checksum, rec_id, sequence = unpack("bbHHh", icmp_header)

        if rec_id == packet_id:
            return time_received - time_sent

        timeout -= time_received - time_sent
        if timeout <= 0:
            return


def echo(dest_addr, timeout=1):
    """
    Sends one ICMP echo request to a given host.

    "timeout" can be any integer or float except for negatives and zero.

    Returns either the delay (in seconds), or "None" on timeout or an
    invalid address, respectively.
    """
    try:
        sock = socket(AF_INET, SOCK_RAW, ICMP_CODE)
    except error as err:
        err_num, err_msg = err.args
        if err_num in ERROR_DESCR:
            raise error(ERROR_DESCR[err_num])  # Operation not permitted
        else:
            raise error(err_msg)

    try:
        gethostbyname(dest_addr)
    except gaierror:
        return

    packet_id = int((id(timeout) * random()) % 65535)
    packet = create_packet(packet_id)
    while packet:
        # The ICMP protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = sock.sendto(packet, (dest_addr, 1))
        packet = packet[sent:]

    delay = response_handler(sock, packet_id, time(), timeout)
    sock.close()
    return delay


def recursive(dest_addr, count=8, timeout=1, floodlock=1, generator=False):
    """
    Pings "dest_addr" "count" times and returns a list of replies or yields
    values as they come up if "generator" is True.

    "count" is an integer that defines the ammount of requsts to perform.
    "timeout" is the number of seconds to wait before dropping request.
    "floodlock" regulates the interval between calls to prevent flood
    and is set in seconds.

    If replied, returns echo delay in seconds. If no response is recorded
    "None" is set.
    """
    if generator:
        for i in xrange(count):
            yield echo(dest_addr, timeout)
            sleep(floodlock)
    else:
        log = []
        for i in xrange(count):
            log.append(echo(dest_addr, timeout))
            sleep(floodlock)
        yield tuple(log)
	return
	#return tuple(log)

def verbose(dest_addr, count=8, timeout=1, floodlock=1, infinite=False):
    """Recursive ping with live feedback. Mind the infinity."""
    try:
    	host = gethostbyname(dest_addr)
    except:
		sys.exit("Unable to resolve host")

    print("PING {} ({}): Ammount {}; Timeout {}s".format(dest_addr, gethostbyname(dest_addr), count, timeout))

    if infinite:
        while True:
            reply = echo(dest_addr, timeout)
            if reply is None:
                print("echo timeout... icmp_seq={}".format(seqn))
            else:
                print("echo from {}:   icmp_seq={}  delay={} ms").format(host, seqn, round(reply*1000, 3))
            sleep(floodlock)
    else:
		log = []
		fail = 0
		for seqn in xrange(count):
			log.append(echo(dest_addr, timeout))
			if log[-1] is None:
				print("echo timeout... icmp_seq={}".format(seqn))
				fail += 1
			else:
				print("echo from {}:   icmp_seq={}  delay={} ms").format(host, seqn, round(log[-1]*1000, 3))
			sleep(floodlock)
		print("sent={} received={} ratio={}%".format(count, count-fail, (float(count-fail) * 100)/count))
		print("{} / {} / {}    (min/avg/max in ms)".format(round(min(log)*1000, 3),
			round(sum([x*1000 for x in log if x is not None])/len(log), 3), round(max(log)*1000, 3)))


class node:
    """the node thing""" 

    def __init__(self,node_id,node_type,node_host,node_timeout,node_interval):
        self.node_id = int(node_id)
        self.node_type = str(node_type)
        self.node_status = "1"
        self.node_host = node_host
        self.node_timeout = int(node_timeout)
        self.node_interval = int(node_interval)
        self.node_url = "-1"

	def getID(self):
		return self.node_id
	def getStatus(self):
		return self.node_status
    def setStatus(self,new_status):
    	self.node_status = new_status
    def setUrl(self,node_url):
    	self.node_url = node_url

    def serviceCheck(self):

    	if self.node_type == "http_status":
    		#if str(self.node_url).startswith("http"):
    		#	print ""
    		#else:
			#	self.node_url = "http://"+ str(self.node_url)
			#
			while (int(self.node_status) == 1):
				full_url = self.node_url.split("/")
				base_url = full_url[2]
				if ":" in base_url:
					service_port = base_url.split(":")[1] 
					base_url = base_url.split(":")[0]
				else:
					service_port = 80

				part_nr = 0
				part_url = ""
				#print "Splitting Url "
				for piece in full_url:
					#print piece
					part_nr+=1
					#print part_nr
					if(part_nr > 3):
						part_url += "/" + piece 
						#print part_url
				r = httplib.HTTPConnection(base_url, service_port, timeout=self.node_timeout)
				#print base_url + " port " + service_port + " me path " + part_url
				r.request("GET",part_url)
				response = r.getresponse()
				print response.status, response.reason
				write_log("Node "+ str(self.node_id) + " " + str(response.status) + " " +  response.reason)
				sleep(self.node_interval)

    	if self.node_type == "ping":
    		#print "doing ping stuff"
			#verbose(self.node_host,4,2)
			#verbose("lulz.eua",4,2)
			host = gethostbyname(self.node_host)
			count = 10
			floodlock = 1
			timeout = self.node_timeout
			log = []
			fail = 0
			interval = self.node_interval
			while (int(self.node_status) == 1):
				for seqn in xrange(count):
					log.append(echo(self.node_host, timeout))
					if log[-1] is None:
						print("echo timeout... ")
						fail += 1
						write_log("Node "+ str(self.node_id) + " " + "request timeout")
					else:
						write_log("Node "+ str(self.node_id) + " " + str(round(log[-1]*1000, 3)))
						print("echo from {}:  delay={} ms").format(host, round(log[-1]*1000, 3))
					sleep(floodlock)
				sleep(interval)
			#print("sent={} received={} ratio={}%".format(count, count-fail, (float(count-fail) * 100)/count))
			#print("{} / {} / {}    (min/avg/max in ms)".format(round(min(log)*1000, 3), round(sum([x*1000 for x in log if x is not None])/len(log), 3), round(max(log)*1000, 3)))
		#if self.node_type == "smtp_check":
		#if self.node_type == "pop_check":

    def printConfig(self):
		print "Node \nID: " + str(self.node_id)
		print "Type: " + self.node_type
		print "Host " + self.node_host
		print "Timeout " + self.node_timeout
		print "interval " + self.node_interval
		if self.node_url:
			print "Url: " + str(self.node_url)

def get_file():
	print "Get file procedure"

def post_data():
	print "Update API/server procedure"

def parse_file():
	#print "Parse file procedure"
	try:
		node_config_file = open("node_config_file", "r")
	except:
		sys.exit("Unable to find config file!")
	#print "Name of the file: ", node_config_file.name
	config_lines = node_config_file.readlines()
	#print config_lines
	node_config_file.close()

	return config_lines

def parse_config(cfg_param):
	nodeList = []

	for cfg_line in cfg_param:
		parse1 = cfg_line.split(";")

		for line in parse1:
			parse2 = line.split(":")
			#print parse2[0]
			if(parse2[0] == "id"):
				conf_id = parse2[1]
				#print "Setting ID"
			elif(parse2[0] == "type"):
				conf_type = parse2[1]
				#print "Setting type"
			elif(parse2[0] == "host"):
				conf_host = parse2[1]
				#print "Setting host"
			elif(parse2[0] == "timeout"):
				conf_timeout = parse2[1]
				#print "Setting timeout"
			elif(parse2[0] == "interval"):
				conf_interval = parse2[1]
				#print "Setting interval"
			elif(parse2[0] == "url"):
				conf_url = parse2[1]
		nodeList.append(node(conf_id,conf_type,conf_host,conf_timeout,conf_interval))
		#if conf_url:
		#	nodeList[conf_id].setUrl(conf_url)
	return nodeList



node_list = parse_config(parse_file())

#node_list[0].printConfig()
#node_list[1].printConfig()


# kujdes! URL na vjen ne base64---> 
# test2.setUrl("http://pbx.webservice01.com:8081/zabbix/dashboard.php")

parser = argparse.ArgumentParser(description=''' node id ''')
parser.add_argument("-n", metavar="node_id", help='node_id')
args = parser.parse_args()


if (args.n == None):
	parser.print_help()

if(args.n):
	if(int(args.n) > len(node_list)-1 ): # since the numbering starts from 0
		sys.exit("Specified node id is outside range")
	node_list[int(args.n)].serviceCheck()
