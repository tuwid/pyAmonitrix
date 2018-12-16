#!/usr/bin/python
import os
import sys
import json
import pika
import string
import logging
import signal
import httplib
import datetime
from socket import getprotobyname, gethostbyname, setdefaulttimeout, gaierror, error as SocketError
from urllib2 import Request, urlopen, URLError, HTTPError
import errno

debug_level = os.environ.get('DEBUG', 'INFO')
logging.basicConfig(level=debug_level)

def signal_handler(signal, frame):
    logging.info('Ctrl+C!')
    sys.exit(0)

def amqp_init(rabbit_host, feed_queue):
    url = 'amqp://guest:guest@' + rabbit_host + ":5672/"
    params = pika.URLParameters(url)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()  # start a channel
    channel.queue_declare(queue=feed_queue, durable=True)  # Declare a queue

    # set up subscription on the queue
    channel.basic_consume(callback, queue=feed_queue)
    channel.start_consuming()
    connection.close()

def message_process(msg):
  logging.info("Processing")
  worker = _message(msg)
  worker.process()
  logging.debug("Processing finished")
  return

def callback(ch, method, properties, body):
  message_process(body)

class _message:
	def __init__(self, raw_json):
		tmp_obj = json.loads(raw_json)
		self._notific_type = tmp_obj['notific_type']
		self._id = tmp_obj['data']['id']
		self._message = tmp_obj['data']['message']

	def process(self):
		logging.debug("Entering in selection")
		if self._notific_type == 'telegram':
    			logging.debug("Entering in telegram section")
			telegram_api = "https://api.telegram.org/" + str(telegram_api_key) + "/sendmessage"
			logging.debug("Sending data to "+telegram_api)
			payload = { 'chat_id': str(self._id), 'text': str(self._message) }
			
			req = Request(telegram_api)
			req.add_header('Content-Type', 'application/json')
			logging.debug(json.dumps(payload))
			try:
				response = urlopen(req, json.dumps(payload))
				logging.info(response.read())
			except HTTPError as e:
				logging.error('HTTP Issue while posting to API ' + str(e))
			except URLError as e:
				logging.error('L4 Issue while posting to API ' + str(e))
			except SocketError as e:
				logging.error('Socket Issue while posting to API ' + str(e))
			logging.info(response.code)
		logging.debug("Exiting the selection")


master_api_key = os.environ.get('MASTER_APIKEY', 'awbnm_jdk123skaj+dkasjd0zxc')
telegram_api_key = os.environ.get('TELEGRAM_API_KEY', 'bot257231296:AAGm1f2gDQegbV-rTu8wMxeXWAseH403xjo')
rabbit_host = os.environ.get('RABBITMQ','rabbitmq')
api_url = os.environ.get('BACKEND_ENDPOINT','https://api.monx.me/api/services/result')
feed_queue = os.environ.get('FEED_QUEUE', 'notifications_telegram')

signal.signal(signal.SIGINT, signal_handler)
amqp_init(rabbit_host, feed_queue)

# hermes = _message('{"notific_type":"telegram","data":{"id":"95155092","message":"Server: DuapuneHetzner Recovered from high load"}}')
# hermes.process()
