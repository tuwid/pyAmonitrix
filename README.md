


Ammonitrix is a monitoring system we're building in python to monitor services remotely ( its agentless) <br>
At the moment we have the following sensons <br>
	icmp check <br>
	http load time (frontend + backend) <br>
	http status <br>
	http title <br>
The project is not finished yet as we're currently working on it. <br>

At the moment we're working on: <br>
	adding new sensors <br>
	implement a realtime frontend <br>
	setting up the server <br>
	mail support <br>
	sms support <br>
	raporting <br>

At the moment the results are transmited via syslog (for diagnostics) <br>

examle of a node working (checking on service with ID 3 ): <br>

root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 3 <br>

Node 3 Back End: 288ms Front End: 219ms  Total: 507ms  <br>
Node 3 Back End: 229ms Front End: 234ms  Total: 463ms  <br>
Node 3 Back End: 238ms Front End: 210ms  Total: 448ms  <br>
Node 3 Back End: 237ms Front End: 229ms  Total: 466ms  <br>

And these results are logged on the syslog server as: <br>

tuwid@valhalla:~$ tail -f /var/log/syslog | grep sauron <br>
Nov 15 17:00:42 valhalla sauron.py: Node 3 Back End: 214ms Front End: 237ms  Total: 451ms  17:00:42.063517  <br>
Nov 15 17:25:52 valhalla sauron.py: Node 3 Back End: 288ms Front End: 219ms  Total: 507ms  17:25:52.595306 <br>
Nov 15 17:26:07 valhalla sauron.py: Node 3 Back End: 229ms Front End: 234ms  Total: 463ms  17:26:07.922704 <br>
Nov 15 17:26:23 valhalla sauron.py: Node 3 Back End: 238ms Front End: 210ms  Total: 448ms  17:26:23.187763 <br>

Other sensors working: <br>
root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 2 <br>
 <br>
200  <br>
200  <br>
200  <br>

On the syslog end: <br>
tuwid@valhalla:~$ tail -f /var/log/syslog | grep sauron <br>

Nov 15 17:28:01 valhalla sauron.py: Node 2 200  17:28:01.598997 <br>
Nov 15 17:28:28 valhalla sauron.py: Node 2 200  17:28:28.373709 <br>
Nov 15 17:28:38 valhalla sauron.py: Node 2 200  17:28:38.655486 <br>
Nov 15 17:28:48 valhalla sauron.py: Node 2 200  17:28:48.942433 <br>

