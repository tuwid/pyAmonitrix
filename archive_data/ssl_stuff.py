import socket
from OpenSSL import SSL

HOST = "www.google.com"
PORT = 443

# replace HOST name with IP, this should fail connection attempt,
# but it doesn't by default
HOST = socket.getaddrinfo(HOST, PORT)[0][4][0]
print(HOST)

# uses HOST
def verify_cb(conn, x509, errno, errdepth, retcode):
  """
  callback for certificate validation
  should return true if verification passes and false otherwise
  """
  if errno == 0:
    if errdepth != 0:
      # don't validate names of root certificates
      return True
    else:
      if x509.get_subject().commonName != HOST:
        return False
  else:
    return False

context = SSL.Context(SSL.SSLv23_METHOD)
context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
context.load_verify_locations("cacerts.txt")

# create socket and connect to server
sock = socket.socket()
sock = SSL.Connection(context, sock)
sock.connect((HOST, PORT))
sock.do_handshake()