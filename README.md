


Ammonitrix is a monitoring system we're building in python to monitor services remotely ( its agentless)
At the moment we have the following sensons
	icmp check
	http load time (frontend + backend)
	http status
	http title
The project is not finished yet as we're currently working on it.

At the moment we're working on:
	adding new sensors
	implement a realtime frontend
	setting up the server
	mail support
	sms support
	raporting

At the moment the results are transmited via syslog (for diagnostics)

examle of a node working (checking on service with ID 3 ):

root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 3

Node 3 Back End: 288ms Front End: 219ms  Total: 507ms 
Node 3 Back End: 229ms Front End: 234ms  Total: 463ms 
Node 3 Back End: 238ms Front End: 210ms  Total: 448ms 
Node 3 Back End: 237ms Front End: 229ms  Total: 466ms 

And these results are logged on the syslog server as:

tuwid@valhalla:~$ tail -f /var/log/syslog | grep sauron
Nov 15 17:00:42 valhalla sauron.py: Node 3 Back End: 214ms Front End: 237ms  Total: 451ms  17:00:42.063517
Nov 15 17:25:52 valhalla sauron.py: Node 3 Back End: 288ms Front End: 219ms  Total: 507ms  17:25:52.595306
Nov 15 17:26:07 valhalla sauron.py: Node 3 Back End: 229ms Front End: 234ms  Total: 463ms  17:26:07.922704
Nov 15 17:26:23 valhalla sauron.py: Node 3 Back End: 238ms Front End: 210ms  Total: 448ms  17:26:23.187763

Other sensors working:
root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 2

200 
200 
200 

On the syslog end:
tuwid@valhalla:~$ tail -f /var/log/syslog | grep sauron

Nov 15 17:28:01 valhalla sauron.py: Node 2 200  17:28:01.598997
Nov 15 17:28:28 valhalla sauron.py: Node 2 200  17:28:28.373709
Nov 15 17:28:38 valhalla sauron.py: Node 2 200  17:28:38.655486
Nov 15 17:28:48 valhalla sauron.py: Node 2 200  17:28:48.942433

