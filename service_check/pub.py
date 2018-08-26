#!/usr/bin/python
import pika, os, logging
logging.basicConfig()

# Parse CLODUAMQP_URL (fallback to localhost)
url = os.environ.get('CLOUDAMQP_URL', 'amqp://guest:guest@localhost/%2f')
params = pika.URLParameters(url)
params.socket_timeout = 5

connection = pika.BlockingConnection(params) # Connect to CloudAMQP
channel = connection.channel() # start a channel
channel.queue_declare(queue='test', durable=True)  # Declare a queue
# send a message

httpcheck = """ 
{
    "service_id": "5aaee13f4ba0ac002cf184d7",
    "service_type": "http",
    "service_params":
        {
            "endpoint": "https://mailer.webservice01.com/webmail/",
            "timeout": "10",
            "auth": "null"
        }
}

"""

blacklist = """
{
    "service_id": "5aaee13f4ba0ac002cf184d7",
    "service_type": "blacklist",
    "service_params":
        {
            "ip": "79.109.1.100",
        }
}

"""


channel.basic_publish(exchange='', routing_key='test', body="""
{
    "service_id": "5aaee13f4ba0ac002cf184d7",
    "service_type": "blacklist",
    "service_params":
        {
            "ip": "79.109.1.100"
        }
}

""")
print ("[x] Message sent to consumer")
connection.close()
