#!/usr/bin/python

from socket import *

def scan(host, port):
	try:
		ip = gethostbyname(host)
	except:
		ip = None

	if ip == None:
		sys.exit("Cant resolve host pra")

	try:
		sock = socket(AF_INET, SOCK_STREAM) # TCP Socket
		sock.settimeout(10)
		sock.connect((host, port))
	except:
		sock.close()
		sock = None

	#setdefaulttimeout(5) # set default timeout to 5 sec
	if sock:
		print("[+] Connected to %s:%d"%(host, port))
		try:
			sock.send("1\r\n")
			banner = str(sock.recv(1024))
		except:
			banner = None

		if banner:
			print("[+] Banner: %s"%banner)
		else:
			print("[!] Can't grab the target banner")
		sock.close() # Done
	else:
		print("[!] Can't connect to %s:%d"%(host, port))

scan("69.89.27.216",110)