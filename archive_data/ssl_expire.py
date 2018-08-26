#!/usr/bin/python

import getopt,sys
import __main__
from OpenSSL import SSL
import socket
import datetime
import requests

try:
    r = requests.get("https://162.159.249.200/")
except Exception, ex:
    print 'error trying to wrap in ssl %s' % ex
sys.exit(1)

# On debian Based systems requires python-openssl

host = "162.159.249.200"
port = "443"
method = "SSLv23"


def main():
  options = get_options()

  # Initialize context
  if method=='SSLv3':
    ctx = SSL.Context(SSL.SSLv3_METHOD)
  elif method=='SSLv2':
    ctx = SSL.Context(SSL.SSLv2_METHOD)
  elif method=='SSLv23':
    ctx = SSL.Context(SSL.SSLv23_METHOD)
  else:
    ctx = SSL.Context(SSL.TLSv1_METHOD)

  # Set up client
  sock = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
  sock.connect((host, int(port)))
  # Send an EOF
  try:
    sock.send("\x04")
    sock.shutdown()
    peer_cert=sock.get_peer_certificate()
    sock.close()
  
  except SSL.Error,e:
    print e

  exit_status=0
  exit_message=[]

  cur_date = datetime.datetime.utcnow()
  cert_nbefore = datetime.datetime.strptime(peer_cert.get_notBefore(),'%Y%m%d%H%M%SZ')
  cert_nafter = datetime.datetime.strptime(peer_cert.get_notAfter(),'%Y%m%d%H%M%SZ')

  expire_days = int((cert_nafter - cur_date).days)

  if cert_nbefore > cur_date:
    if exit_status < 2: 
      exit_status = 2
    exit_message.append('C: cert is not valid')
  elif expire_days < 0:
    if exit_status < 2: 
      exit_status = 2
    exit_message.append('Expire critical (expired)')
  elif options['critical'] > expire_days:
    if exit_status < 2: 
      exit_status = 2
    exit_message.append('Expire critical')
  elif options['warning'] > expire_days:
    if exit_status < 1: 
      exit_status = 1
    exit_message.append('Expire warning')
  else:
    exit_message.append('Expire OK')

  exit_message.append('['+str(expire_days)+'d]')

  for part in peer_cert.get_subject().get_components():
    if part[0]=='CN':
      cert_cn=part[1]

  if options['cn']!='' and options['cn'].lower()!=cert_cn.lower():
    if exit_status < 2:
      exit_status = 2
    exit_message.append(' - CN mismatch')
  else:
    exit_message.append(' - CN OK')

  exit_message.append(' - cn:'+cert_cn)

  print ''.join(exit_message)
  sys.exit(exit_status)

if __name__ == "__main__":
  main()