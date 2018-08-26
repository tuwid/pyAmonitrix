


Ammonitrix is a monitoring system we're building in python to monitor services remotely ( its agentless) <br>
At the moment we have the following sensons <br>
    -icmp check <br>
    -http load time (frontend + backend) <br>
    -http status <br>
    -http title <br>
    -POP check <br>
    -smtp check <br>
    -blacklist check <br>
    -http text content matching <br>
    -web screenshot

The project is not finished yet as we're currently working on it. <br>

At the moment we're working on: <br>
	* broken links ?
    * domain expire
	* SLA Management
	* SLA Monitoring
	* email round trip 
    * dns check (dns match)
    * ssh check
    * rdp status
    * certificate expire check
    * mysql status
    * MSSQL status
    * ssh/telnet banner ?
    * vpn/openvpn/ipsec status
	* api ?
    * memcache ?
    * VOIP
    * notific via twitter
    * twitter keyword monitor ? xD 
    - adding new sensors <br>
    - implement a realtime frontend <br>
    - setting up the server <br>
    - mail notification mail support <br>
    - sms notification support <br>
    - raporting <br>

* In a not so distant future:
	- agent monitoring (linux internals monitoring , memory, disk, routes, interfaces, io-load )
	- mysql performance stats

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

root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 6  <br>

Node 6 port OK, banner: +OK Dovecot ready.   11:22:36.363076  <br>
Node 6 port OK, banner: +OK Dovecot ready.   11:22:43.784474  <br>
Node 6 port OK, banner: +OK Dovecot ready.   11:22:51.204418  <br>
  <br>
root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 5  <br>

Node 5 ['404 Not Found'] 11:23:36.954337  <br>
Node 5 ['404 Not Found'] 11:23:47.054163  <br>
Node 5 ['404 Not Found'] 11:23:57.411693  <br>
Node 5 ['404 Not Found'] 11:24:08.504208  <br>
Node 5 ['404 Not Found'] 11:24:18.596090  <br>
  <br>

root@valhalla:/home/tuwid/Dropbox/pamon# ./sauron.py -n 4  <br>

Node 4 matched ['Te dhena mbi situaten e blacklisting'] 11:24:36.522339  <br>
Node 4 matched ['Te dhena mbi situaten e blacklisting'] 11:24:46.641266  <br>
Node 4 matched ['Te dhena mbi situaten e blacklisting'] 11:24:56.743526  <br>
Node 4 matched ['Te dhena mbi situaten e blacklisting'] 11:25:06.838635  <br>
Node 4 matched ['Te dhena mbi situaten e blacklisting'] 11:25:16.969715  <br>
Node 4 matched ['Te dhena mbi situaten e blacklisting'] 11:25:27.107149  <br>
  <br>

On the syslog end: <br>
tuwid@valhalla:~$ tail -f /var/log/syslog | grep sauron <br>

Nov 15 17:28:01 valhalla sauron.py: Node 2 200  17:28:01.598997 <br>
Nov 15 17:28:28 valhalla sauron.py: Node 2 200  17:28:28.373709 <br>
Nov 15 17:28:38 valhalla sauron.py: Node 2 200  17:28:38.655486 <br>
Nov 15 17:28:48 valhalla sauron.py: Node 2 200  17:28:48.942433 <br>

