#!/usr/bin/python
import pika
import os,sys
import string
import logging,syslog
import httplib,requests,json
import datetime,time
import threading,signal
import argparse
import Queue,threading
from socket import getprotobyname, gethostbyname, setdefaulttimeout, gaierror, error as SocketError
from urllib2 import Request, urlopen, URLError, HTTPError
import socket
import errno

debug_level = os.environ.get('DEBUG', 'INFO')
logging.basicConfig(level=debug_level)

def blacklist_check(hst):

    serverlist = [
        'access.redhawk.org',
        'b.barracudacentral.org',
        'bl.shlink.org',
        'bl.spamcannibal.org',
        'bl.spamcop.net',
        # 'bl.tiopan.com',
        # 'blackholes.wirehub.net',
        # 'blacklist.sci.kun.nl',
        # 'block.dnsbl.sorbs.net',
        # 'blocked.hilli.dk',
        # 'bogons.cymru.com',
        # 'cart00ney.surriel.com',
        'cbl.abuseat.org',
        # 'cblless.anti-spam.org.cn',
        # 'dev.null.dk',
        # 'dialup.blacklist.jippg.org',
        # 'dialups.mail-abuse.org',
        # 'dialups.visi.com',
        # 'dnsbl.abuse.ch',
        # 'dnsbl.anticaptcha.net',
        # 'dnsbl.antispam.or.id',
        # 'dnsbl.dronebl.org',
        # 'dnsbl.justspam.org',
        # 'dnsbl.kempt.net',
        'dnsbl.sorbs.net',
        # 'dnsbl.tornevall.org',
        'dnsbl-1.uceprotect.net',
        # 'duinv.aupads.org',
        'dnsbl-2.uceprotect.net',
        'dnsbl-3.uceprotect.net',
        # 'dul.dnsbl.sorbs.net',
        # 'dul.ru',
        # 'escalations.dnsbl.sorbs.net',
        # 'hil.habeas.com',
        # 'black.junkemailfilter.com',
        # 'http.dnsbl.sorbs.net',
        # 'intruders.docs.uu.se',
        # 'ips.backscatterer.org',
        # 'korea.services.net',
        # 'l2.apews.org',
        # 'mail-abuse.blacklist.jippg.org',
        # 'misc.dnsbl.sorbs.net',
        # 'msgid.bl.gweep.ca',
        # 'new.dnsbl.sorbs.net',
        # 'no-more-funn.moensted.dk',
        # 'old.dnsbl.sorbs.net',
        # 'opm.tornevall.org',
        'pbl.spamhaus.org',
        # 'proxy.bl.gweep.ca',
        # 'dyna.spamrats.com',
        'spam.spamrats.com',
        # 'psbl.surriel.com',
        # 'pss.spambusters.org.ar',
        # 'rbl.schulte.org',
        # 'rbl.snark.net',
        # 'recent.dnsbl.sorbs.net',
        # 'relays.bl.gweep.ca',
        # 'relays.bl.kundenserver.de',
        # 'relays.mail-abuse.org',
        # 'relays.nether.net',
        # 'rsbl.aupads.org',
        'sbl.spamhaus.org',
        # 'smtp.dnsbl.sorbs.net',
        # 'socks.dnsbl.sorbs.net',
        # 'spam.dnsbl.sorbs.net',
        # 'spam.olsentech.net',
        # 'spamguard.leadmon.net',
        # 'spamsources.fabel.dk',
        # 'tor.ahbl.org',
        # 'tor.dnsbl.sectoor.de',
        # 'ubl.unsubscore.com',
        # 'web.dnsbl.sorbs.net',
        'xbl.spamhaus.org',
        'zen.spamhaus.org',
        'zombie.dnsbl.sorbs.net',
        # 'dnsbl.inps.de',
        # 'dyn.shlink.org',
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
                hostname, root_name = self.queue.get()

                check_host = "%s.%s" % (hostname, root_name)
                try:
                    setdefaulttimeout(5)
                    check_addr = gethostbyname(check_host)
                except SocketError:
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
        queue.put((check_name, blhost))

    queue.join()
    #sleep(5)

    if len(on_blacklist) >= 0:
        return 'error', ' %s on %s spam blacklists|%s' % (host, len(on_blacklist), on_blacklist), len(on_blacklist), on_blacklist
    else:
        return 'ok', '%s not on known spam blacklists' % host, 0, []

def httpCheck(url, timeout, depth):
    logging.debug("Got parameters " + str(url) + " -- " + str(timeout) + " -- " + str(depth))
    if(depth > 3):
        logging.debug("Depth more than 3, too many redirect ")
        return "error", "Too many redirects", 0, "301"
    service_port = 80
    ssl_enabled = False
    web_error = ""
    part_nr = 0
    part_url = ""

    if (str(url).startswith("https")):
        logging.debug("Url starts with https, ssl_enabled true")
        service_port = 443
        ssl_enabled = True

    full_url = url.split("/")
    base_url = full_url[2]
    if ":" in base_url:
        service_port = int(base_url.split(":")[1])
        base_url = base_url.split(":")[0]

    logging.debug("Splitting Url ")
    for piece in full_url:
        part_nr += 1
        if(part_nr > 3):
            part_url += "/" + piece
    logging.info((base_url + " " + str(service_port)))
    timestart = datetime.datetime.now()

    if ssl_enabled:
        r = httplib.HTTPSConnection(
            base_url, service_port, timeout=timeout)
    else:
        r = httplib.HTTPConnection(
            base_url, service_port, timeout=timeout)

    try:
        r.request("GET", part_url)
    except HTTPError as e:
        web_error = "HTTP Issue: " + str(e)
        ecode = e.errno
    except URLError as e:
        web_error = "L4 Issue : " + str(e)
        ecode = e.errno
    except SocketError as e:
        web_error = "Socket Issue: " + str(e)
        ecode = e.errno

    timestop = datetime.datetime.now()
    if not web_error:
        response = r.getresponse()
        if(response.status == 200 or response.status == 201):
            logging.debug("Got into OK status with 200 code")
            delta = int((timestop - timestart).total_seconds() * 1000)
            ert = delta
            status = "ok"
            sline = str(response.status) + " " + response.reason + ", " + str(delta) + "ms"
            logging.info(sline)
            ecode = response.status
            logging.debug("Got out of OK status with 200 code")
        elif(response.status == 301 or response.status == 302):
            logging.debug("Got into REDIRECT status ")
            headers = dict(response.getheaders())
            if headers.has_key('location'):
                if headers['location'].startswith("/"):
                    if(ssl_enabled):
                        url = "https://" + base_url +":"+ str(service_port) + headers['location']
                        logging.debug("New Redirect URL: " + url)
                    else:
                        url = "http://" + base_url + ":" + str(service_port) + headers['location']
                        logging.debug("New Redirect URL: " + url)
                else:
                    url = headers['location']
                depth+=1
            status, sline, ert, ecode = httpCheck(url, timeout, depth)
            logging.debug("Got out of REDIRECT status ")
            logging.debug(status + " " + sline + " " + str(ert) +" " + str(ecode))
        else:
            logging.debug("Got into fallback")
            status = "error"
            delta = int((timestop - timestart).total_seconds() * 1000)
            web_error = "L7 error - " + \
                str(response.status) + " " + \
                response.reason + " " + str(delta) + "ms"
            sline = web_error
            ert = delta
            logging.debug("LAST ELSE " + sline)
            ecode = response.status
    else:
        delta = int((timestop - timestart).total_seconds() * 1000)
        ert = delta
        status = "error"
        sline = web_error
        logging.info(web_error)
    return status, sline, ert, ecode
class _sensor:
    def __init__(self, raw_json):
        logging.debug("Composing object sensor")
        tmp_obj = json.loads(raw_json)
        self._sensor_id = tmp_obj['service_id']
        self._sensor_type = tmp_obj['service_type']
        self._sensor_status = "UNDEF"
        self._sensor_sline = "---"
        if(self._sensor_type == 'http'):
            logging.debug("we got a http type object")
            self._sensor_url = tmp_obj['service_params']['endpoint']
            self._sensor_timeout = int(tmp_obj['service_params']['timeout'])
            self._sensor_ecode = 0
            self._sensor_ert = 0
        if(tmp_obj['service_type'] == 'blacklist'):
            self._sensor_ip = tmp_obj['service_params']['ip']
            self._sensor_bllist = []
            self._sensor_blnr = 0

    def getStatus(self):
        return self._sensor_status,

    def serviceCheck(self):
        if self._sensor_type == "http":
            self._sensor_status, self._sensor_sline, self._sensor_ert, self._sensor_ecode = httpCheck( self._sensor_url, self._sensor_timeout, 0)
            if self._sensor_status == 'error':
                self._sensor_status, self._sensor_sline, self._sensor_ert, self._sensor_ecode = httpCheck( self._sensor_url, self._sensor_timeout, 0)
            if self._sensor_status == 'error':
                self._sensor_status, self._sensor_sline, self._sensor_ert, self._sensor_ecode = httpCheck( self._sensor_url, self._sensor_timeout, 0)

        if self._sensor_type == "blacklist":
            self._sensor_status, self._sensor_sline, self._sensor_blnr,  self._sensor_bllist  = blacklist_check(self._sensor_ip)

    def postBack(self):
        post_data = {
            'apikey': 'awbnm_jdk123skaj+dkasjd0zxc',
            'service_id':     str(self._sensor_id),
            'service_data': {
                'endpoint_code': str(self._sensor_ecode),
                'endpoint_rt':   str(self._sensor_ert),
                'status_line':   str(self._sensor_sline),
            },
            'service_status': str(self._sensor_status)
        }

        req = Request(api_url)
        req.add_header('Content-Type', 'application/json')
        req.add_header('apikey', 'awbnm_jdk123skaj+dkasjd0zxc')
        logging.debug(json.dumps(post_data))
        try:
            response = urlopen(req, json.dumps(post_data))
            logging.info(response.read())
        except HTTPError as e:
            logging.error('HTTP Issue while posting to API ' + str(e))
        except URLError as e:
            logging.error('L4 Issue while posting to API ' + str(e))
        except SocketError as e:
            logging.error('Socket Issue while posting to API ' + str(e))
        # logging.info(response.code)

    def printConfig(self):
        logging.info("_sensor ID: " + str(self._sensor_id))
        logging.info("Type: " + str(self._sensor_type))
        logging.info("STATUS: " + str(self._sensor_status))
        logging.info("Status Line: " + self._sensor_sline)
        if self._sensor_type == "http":
            logging.info("Timeout: " + str(self._sensor_timeout))
            logging.info("Url: " + str(self._sensor_url))
            logging.info("Code: " + str(self._sensor_ecode))
            logging.info("Return Time: " + str(self._sensor_ert))
        if self._sensor_type == "blacklist":
            logging.info("BL Nr: " + str(self._sensor_blnr))
            logging.info("RBL List: " + str(self._sensor_bllist))

def signal_handler(signal, frame):
        logging.info('Ctrl+C!')
        sys.exit(0)

def message_process(msg):
  logging.info("Processing")
  worker = _sensor(msg)
  worker.serviceCheck()
  worker.printConfig()
  worker.postBack()
  logging.info("Processing finished")
  return

def callback(ch, method, properties, body):
  message_process(body)

def amqp_init():
    url = 'amqp://guest:guest@' + rabbit_host +":5672/"
    params = pika.URLParameters(url)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()  # start a channel
    channel.queue_declare(queue=feed_queue, durable=True)  # Declare a queue

    # set up subscription on the queue
    channel.basic_consume(callback, queue=feed_queue, no_ack=True)
    channel.start_consuming()
    connection.close()

master_api_key = os.environ.get('MASTER_APIKEY', 'awbnm_jdk123skaj+dkasjd0zxc')
rabbit_host = os.environ.get('RABBITMQ','localhost')
api_url = os.environ.get('BACKEND_ENDPOINT','https://api.monx.me/api/services/result')
feed_queue = os.environ.get('FEED_QUEUE', 'test')

signal.signal(signal.SIGINT, signal_handler)
amqp_init()
