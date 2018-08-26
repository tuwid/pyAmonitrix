#!/usr/bin/python

from socket import socket, htons, AF_INET, SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, getprotobyname, gethostbyname, setdefaulttimeout, error, gaierror
from struct import pack, unpack
from random import random  # Possibly switch to os.urandom()
from select import select
from time import time, sleep
from sys import version_info as py_version
# from pyvirtualdisplay import Display
# from selenium import webdriver


import os
import re
import sys
import signal
import string
import syslog
import base64
import httplib
import requests
import datetime
import threading
import argparse
import Queue, threading

def signal_handler(signal, frame):
		print('Ctrl+C!')
		sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def check_if_root():
	if not os.geteuid() == 0:
		#sys.exit('Script must be run as root')
		sys.exit('Y U NO ROOT ??')

check_if_root()

# Remove this line to make all functions public, or selectively add needed functions to make them public.
#__all__ = ["create_packet", "echo", "recursive"]

# Python 3 doesn't have the xrange function anymore, this line makes it compliant with both v2 and v3.
xrange = range if py_version[0] >= 3 else xrange

ICMP_ECHO_REQUEST = 8
ICMP_CODE = getprotobyname("icmp")
ERROR_DESCR = {1: "ICMP messages can only be sent from processes running as root.", 10013: "ICMP messages can only be sent by users or processes with administrator rights."}


def write_log(_sensor_event):
	_sensor_event = _sensor_event.replace("\n"," ")
	_sensor_event = _sensor_event.replace("\r"," ")
	_sensor_event += " " +str(datetime.datetime.now().time())
	syslog.syslog(syslog.LOG_ERR, _sensor_event)

def blacklist_check(hst):

    serverlist = [
    ',access.redhawk.org',
    'b.barracudacentral.org',
    'bl.shlink.org',
    'bl.spamcannibal.org',
    'bl.spamcop.net',
    'bl.tiopan.com',
    'blackholes.wirehub.net',
    'blacklist.sci.kun.nl',
    'block.dnsbl.sorbs.net',
    'blocked.hilli.dk',
    'bogons.cymru.com',
    'cart00ney.surriel.com',
    'cbl.abuseat.org',
    'cblless.anti-spam.org.cn',
    'dev.null.dk',
    'dialup.blacklist.jippg.org',
    'dialups.mail-abuse.org',
    'dialups.visi.com',
    'dnsbl.abuse.ch',
    'dnsbl.anticaptcha.net',
    'dnsbl.antispam.or.id',
    'dnsbl.dronebl.org',
    'dnsbl.justspam.org',
    'dnsbl.kempt.net',
    'dnsbl.sorbs.net',
    'dnsbl.tornevall.org',
    'dnsbl-1.uceprotect.net',
    'duinv.aupads.org',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'dul.dnsbl.sorbs.net',
    'dul.ru',
    'escalations.dnsbl.sorbs.net',
    'hil.habeas.com',
    'black.junkemailfilter.com',
    'http.dnsbl.sorbs.net',
    'intruders.docs.uu.se',
    'ips.backscatterer.org',
    'korea.services.net',
    'l2.apews.org',
    'mail-abuse.blacklist.jippg.org',
    'misc.dnsbl.sorbs.net',
    'msgid.bl.gweep.ca',
    'new.dnsbl.sorbs.net',
    'no-more-funn.moensted.dk',
    'old.dnsbl.sorbs.net',
    'opm.tornevall.org',
    'pbl.spamhaus.org',
    'proxy.bl.gweep.ca',
    'dyna.spamrats.com',
    'spam.spamrats.com',
    'psbl.surriel.com',
    'pss.spambusters.org.ar',
    'rbl.schulte.org',
    'rbl.snark.net',
    'recent.dnsbl.sorbs.net',
    'relays.bl.gweep.ca',
    'relays.bl.kundenserver.de',
    'relays.mail-abuse.org',
    'relays.nether.net',
    'rsbl.aupads.org',
    'sbl.spamhaus.org',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'spam.olsentech.net',
    'spamguard.leadmon.net',
    'spamsources.fabel.dk',
    'tor.ahbl.org',
    'tor.dnsbl.sectoor.de',
    'ubl.unsubscore.com',
    'web.dnsbl.sorbs.net',
    'xbl.spamhaus.org',
    'zen.spamhaus.org',
    'zombie.dnsbl.sorbs.net',
    'dnsbl.inps.de',
    'dyn.shlink.org',
    'rbl.megarbl.net',
    'bl.mailspike.net'
    ]

    queue = Queue.Queue()
    global on_blacklist
    on_blacklist = []

    class ThreadRBL(threading.Thread):
        def __init__(self, queue):
            threading.Thread.__init__(self)
            self.queue = queue

        def run(self):
            while True:
                #grabs host from queue
                hostname,root_name = self.queue.get()

                check_host = "%s.%s" % (hostname, root_name)
                try:
                    setdefaulttimeout(5)
                    check_addr = gethostbyname(check_host)
                except error:
                    check_addr = None
                if check_addr != None and "127.0.0." in check_addr:
                    on_blacklist.append(root_name)

                #signals to queue job is done
                self.queue.task_done()

    host = None
    addr = hst

    if host:
        try:
            addr = socket.gethostbyname(host)
        except:
            return "ERROR: Host '%s' not found - maybe try a FQDN?" % host 
    
    addr_parts = string.split(addr, '.')
    addr_parts.reverse()
    check_name = string.join(addr_parts, '.')

    host = addr

    for i in range(5):
        t = ThreadRBL(queue)
        t.setDaemon(True)
        t.start() 
   
    #populate queue with data
    for blhost in serverlist:
        queue.put((check_name,blhost))

    queue.join()
    #sleep(5)
    
    if len(on_blacklist) >= 0:
		return 'ERROR',' %s on %s spam blacklists|%s' % (host,len(on_blacklist),on_blacklist)
    else:
		return 'OK', '%s not on known spam blacklists' % host

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
		print("{} / {} / {}	(min/avg/max in ms)".format(round(min(log)*1000, 3),
			round(sum([x*1000 for x in log if x is not None])/len(log), 3), round(max(log)*1000, 3)))


def write_log2(_sensor_id,_sensor_status,_sensor_message):
	_sensor_message = _sensor_message.replace("\n"," ")
	_sensor_message = _sensor_message.replace("\r"," ")
	_sensor_message += " " +str(datetime.datetime.now().time())
	payload = { 'service_id' : _sensor_id, 'status' : _sensor_status, 'message': _sensor_message}
	r = requests.post("http://monx.zero1.al:31416/api/service_data",data=payload)



class _sensor:
	#"""the _sensor thing""" 
	def __init__(self,_sensor_id,_sensor_type,_sensor_host,_sensor_timeout,_sensor_interval):
		self._sensor_id = int(_sensor_id)
		self._sensor_type = str(_sensor_type)
		self._sensor_status = "1"
		self._sensor_host = _sensor_host
		self._sensor_timeout = int(_sensor_timeout)
		self._sensor_interval = int(_sensor_interval)
		self._sensor_url = "-1"
		self._sensor_text_match = "-1"

	def getID(self):
		return self._sensor_id
	def getStatus(self):
		return self._sensor_status
	def setStatus(self,new_status):
		self._sensor_status = new_status
	def setTextmatch(self,text_match):
		try:
			self._sensor_text_match = base64.b64decode(str(text_match))
		except:
			write_log("invalid text_match")
			sys.exit("invalid text_match")
	def setUrl(self,_sensor_url):
		# the url comes in a base64 format 
		try:
			self._sensor_url = base64.b64decode(str(_sensor_url))
		except:
			write_log("invalid url")
			sys.exit("invalid url")
	def serviceCheck(self):

		# if self._sensor_type == "http_load":
		# 	display = Display(visible=0, size=(800, 600))
		# 	display.start()
		# 	while (int(self._sensor_status) == 1):
		# 		browser = webdriver.Firefox()
		# 		browser.get(self._sensor_url)
		# 		#print browser.title
		# 		navigationStart = browser.execute_script("return window.performance.timing.navigationStart")
		# 		responseStart = browser.execute_script("return window.performance.timing.responseStart")
		# 		domComplete = browser.execute_script("return window.performance.timing.domComplete")

		# 		backendPerformance = responseStart - navigationStart
		# 		frontendPerformance = domComplete - responseStart
				
		# 		#print ("_sensor " + str(self._sensor_id) + "  Back End: %s" % backendPerformance + "ms" +  " Front End: %s" % frontendPerformance + "ms " + " Total: " + str(backendPerformance + frontendPerformance) + "ms ")
		# 		#write_log2("_sensor " + str(self._sensor_id) , " OK " ,"Back End: %s" % backendPerformance + "ms" +  " Front End: %s" % frontendPerformance + "ms " + " Total: " + str(backendPerformance + frontendPerformance) + "ms ")
		# 		write_log2("_sensor " + str(self._sensor_id) + " OK " + "Back End: %s" % backendPerformance + "ms" +  " Front End: %s" % frontendPerformance + "ms " + " Total: " + str(backendPerformance + frontendPerformance) + "ms ")
		# 		browser.save_screenshot('screenshot_pra.png')
		# 		browser.quit()

		# 		sleep(self._sensor_interval)
		# 	display.stop()

		if self._sensor_type == "http_title":
			while (int(self._sensor_status) == 1):
				try:
					r = requests.get(self._sensor_url)
					#print r.status_code
					#print r.headers
					#print r.content
					source = r.content
					pattern = re.compile(r'<title[^>]*>([^<]+)</title>', flags=re.DOTALL)
					results = pattern.findall(source)
					#write_log("_sensor "+ str(self._sensor_id) + " OK " + str(results))
					write_log2(str(self._sensor_id) , " OK " , str(results))
				except:
					#write_log("_sensor "+ str(self._sensor_id) + " ERROR, unable to get http title ")
					write_log2(str(self._sensor_id) , "ERROR" , " Unable to get http title ")
					#sys.exit("not hmm")
				sleep(self._sensor_interval)

		if self._sensor_type == "http_status":
			#if str(self._sensor_url).startswith("http"):
			#	print ""
			#else:
			#	self._sensor_url = "http://"+ str(self._sensor_url)
			#
			#print self.printConfig()

			while (int(self._sensor_status) == 1):
				web_error = ""
				full_url = self._sensor_url.split("/")
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
					part_nr+=1
					if(part_nr > 3):
						part_url += "/" + piece 
						#print part_url
				r = httplib.HTTPConnection(base_url, service_port, timeout=self._sensor_timeout)
				try:
					r.request("GET",part_url)
				except:
					e = sys.exc_info()[0]
					#print e
					web_error = "Error Unable to connect to " + str(e)
					#print web_error
					#write_log("_sensor "+ str(self._sensor_id) + " ERROR " + str(web_error))
					write_log2(str(self._sensor_id) , "ERROR" , str(web_error))
				if not web_error:
					response = r.getresponse()
					#print response.status, response.reason
					#write_log("_sensor "+ str(self._sensor_id) + " OK " + str(response.status) + " " +  response.reason)
					write_log2(str(self._sensor_id) , "OK" , str(response.status) + " " +  response.reason)
				sleep(self._sensor_interval)

		if self._sensor_type == "ping":
			#print self.printConfig()
			ping_error = ""
			#print "doing ping stuff"
			#verbose(self._sensor_host,4,2)
			#verbose("lulz.eua",4,2)
			while (int(self._sensor_status) == 1):
				interval = self._sensor_interval
				try:
					host = gethostbyname(self._sensor_host)
				except:
					ping_error = "Unable to resolve host " + str(self._sensor_host) + " " + str(sys.exc_info()[0])
					#write_log("_sensor "+ str(self._sensor_id) + " ERROR " + str(ping_error))
					write_log2(str(self._sensor_id) , "ERROR" , str(ping_error))
					#print ping_error
					#sys.exit("")
				if ping_error == "":
					count = 10
					floodlock = 1
					timeout = self._sensor_timeout
					log = []
					fail = 0
					for seqn in xrange(count):
						log.append(echo(str(self._sensor_host), timeout))
						if log[-1] is None:
						 	#print("echo timeout... ")
							fail += 1
							write_log2(str(self._sensor_id) , "ERROR" , "request timeout")
						else:
							write_log2(str(self._sensor_id) , "OK" , str(round(log[-1]*1000, 3)))
							#print("echo from {}:  delay={} ms").format(host, round(log[-1]*1000, 3))
						sleep(floodlock)
				sleep(self._sensor_interval)
			#print("sent={} received={} ratio={}%".format(count, count-fail, (float(count-fail) * 100)/count))
			#print("{} / {} / {}	(min/avg/max in ms)".format(round(min(log)*1000, 3), round(sum([x*1000 for x in log if x is not None])/len(log), 3), round(max(log)*1000, 3)))

		if self._sensor_type == "http_content":
			while (int(self._sensor_status) == 1):
				web_error = ""
				full_url = self._sensor_url.split("/")
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
					part_nr+=1
					if(part_nr > 3):
						part_url += "/" + piece 
				try:
					r = requests.get(self._sensor_url)
				except:
					e = sys.exc_info()[0]
					#print e
					web_error = "Error Unable to connect to " + str(e)
					#sys.exit('problem pra')
					#print web_error
					write_log2(str(self._sensor_id) , "ERROR" , str(web_error))
				if not web_error:
					pattern = re.compile(self._sensor_text_match, flags=re.DOTALL)
					results = pattern.findall(str(r.content))
					#print results
					if(results):
						write_log2(str(self._sensor_id) , "OK" , "text matched " + str(results))
					else:
						write_log2(str(self._sensor_id) , "ERROR", " text not-matched " + str(results))
				sleep(self._sensor_interval)

		if self._sensor_type == "dns_check":
			print "dns check and stuff"
		if self._sensor_type == "blacklist":
			while (int(self._sensor_status) == 1):
				stat,msg = blacklist_check(self._sensor_host)
				write_log2(str(self._sensor_id) , stat, msg)
				sleep(self._sensor_interval)
		if self._sensor_type == "smtp_check":
			while (int(self._sensor_status) == 1):
				#print self.printConfig()
				try:
					ip = gethostbyname(self._sensor_host)
				except:
					ip = None
				if ip == None:
					write_log2(str(self._sensor_id) , "ERROR" ,"DNS Error Unable to resolve host " + str(self._sensor_host))
				if ip:
					try:
						pop_sock = socket(AF_INET, SOCK_STREAM) # TCP Socket
						pop_sock.settimeout(int(self._sensor_timeout))
						#sock.connect((self._sensor_host, self._sensor_port))
						pop_sock.connect((self._sensor_host, 25))
					except:
						#pop_sock.close()
						pop_sock = None
						write_log2(str(self._sensor_id) , "ERROR" ," Socket errror Unable to create socket ")

					if pop_sock:
						#print("[+] Connected to %s:%d"%(self._sensor_host, 110))
						try:
							pop_sock.send("Check\r\n\r\n")
							banner = str(pop_sock.recv(2048))
						except:
							banner = None

						if banner:
							#banner = banner.replace("\n", "")
							write_log2(str(self._sensor_id) , "OK" ," port OK, banner: " + str(banner))
						else:
							write_log2(str(self._sensor_id) , "ERROR" ," port OK, sbanner ERROR ")
						pop_sock.close() # Done
					else:
						write_log2(str(self._sensor_id) , "ERROR" ," port ERROR, banner ERROR")
				sleep(self._sensor_interval)

		if self._sensor_type == "pop_check":
			while (int(self._sensor_status) == 1):
				#print self.printConfig()
				try:
					ip = gethostbyname(self._sensor_host)
				except:
					ip = None

				if ip == None:
					write_log2( str(self._sensor_id) , "ERROR" ," DNS error, Unable to resolve host " + str(self._sensor_host))

				if ip:
					try:
						pop_sock = socket(AF_INET, SOCK_STREAM) # TCP Socket
						pop_sock.settimeout(int(self._sensor_timeout))
						#sock.connect((self._sensor_host, self._sensor_port))
						pop_sock.connect((self._sensor_host, 110))
					except:
						#pop_sock.close()
						pop_sock = None
						write_log2(str(self._sensor_id) , "ERROR" ," Socket error, Unable to create socket/connect to host ")

					if pop_sock:
						#print("[+] Connected to %s:%d"%(self._sensor_host, 110))
						try:
							pop_sock.send("Check\r\n\r\n")
							banner = str(pop_sock.recv(2048))
						except:
							banner = None

						if banner:
							#banner = banner.replace("\n", "")
							write_log2(str(self._sensor_id) , "OK" ," banner: " + str(banner))
						else:
							write_log2(str(self._sensor_id) , " ERROR, banner ERROR ")
						pop_sock.close() # Done
					else:
						write_log2(str(self._sensor_id) , "ERROR", "port ERROR ,banner ERROR")
				sleep(self._sensor_interval)

	def printConfig(self):
		print "_sensor \nID: " + str(self._sensor_id)
		print "Type: " + str(self._sensor_type)
		print "Host: " + str(self._sensor_host)
		print "Timeout: " + str(self._sensor_timeout)
		print "interval: " + str(self._sensor_interval)
		if self._sensor_url != "-1":
			print "Url: " + str(self._sensor_url)

def get_file():
	print "Get file procedure"

def post_data():
	print "Update API/server procedure"

def parse_file():
	#print "Parse file procedure"
	try:
		_sensor_config_file = open("service_config_file", "r")
	except:
		sys.exit("Unable to find config file!")
	#print "Name of the file: ", _sensor_config_file.name
	config_lines = _sensor_config_file.readlines()
	#print config_lines
	_sensor_config_file.close()

	return config_lines

def parse_config(cfg_param):
	_sensorList = []

	for cfg_line in cfg_param:
		parse1 = cfg_line.split(";")
		conf_id,conf_type,conf_host,conf_timeout,conf_timeout,conf_interval,conf_url,conf_match = (True,)*8
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
			elif(parse2[0] == "match"):
				conf_match = parse2[1]
		_sensorList.append(_sensor(conf_id,conf_type,conf_host,conf_timeout,conf_interval))
		if conf_url:
			_sensorList[-1].setUrl(str(conf_url))
		if conf_match:
			_sensorList[-1].setTextmatch(str(conf_match))

	return _sensorList

_sensor_list = parse_config(parse_file())

#_sensor_list[0].printConfig()
#_sensor_list[1].printConfig()


# kujdes! URL na vjen ne base64---> 
# test2.setUrl("http://pbx.webservice01.com:8081/zabbix/dashboard.php")

parser = argparse.ArgumentParser(description=''' _sensor id ''')
parser.add_argument("-n", metavar="_sensor_id", help='_sensor_id')
args = parser.parse_args()


if (args.n == None):
	parser.print_help()

if(args.n):
	if(int(args.n) > len(_sensor_list)-1 ): # since the numbering starts from 0
		sys.exit("Specified _sensor id is outside range")
	_sensor_list[int(args.n)].serviceCheck()
