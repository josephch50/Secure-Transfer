from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
import pickle
from socket import AF_INET, socket, SOCK_STREAM, SHUT_WR
import logging, sys

# ----------------------------------------------------------- #
# NAME : Joseph Chen                                          #
# DUE DATE : 2/18/2019                                        #
# EE 4723 Network Security Final Project                      #
# FILE NAME : scp_client.py                                   #
# ----------------------------------------------------------- #

logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
HOST = 'localhost'
PORT = 33000
BUFSIZE = 2048
DEBUG = 1


class AES_EAX:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw):
        # Encrypt the data with the session key
        c = AES.new(self.key, AES.MODE_EAX)
        text, tag = c.encrypt_and_digest(raw)
        n = c.nonce
        return n, tag, text

    def decrypt(self, n, tag, enc):
        # Decrypt the data with the AES session key
        c = AES.new(self.key, AES.MODE_EAX, n)
        d = c.decrypt_and_verify(enc, tag)
        return d


def debug(*argv):
    if DEBUG:
        for arg in argv:
            if type(arg) == bytes:
                sys.stderr.write(arg.hex())
            else:
                sys.stderr.write(arg)
            sys.stderr.write(" ")
        sys.stderr.write("\n")


def form_packet(payload):
    return bytes(str(len(payload)).zfill(4), "utf8") + payload + bytes("".zfill(BUFSIZE - len(payload) - 4), "utf8")


def receive(skt, *argv):
    pkt = skt.recv(BUFSIZE)
    debug(">> [PACKET]", *argv, pkt)
    pktlen = int(pkt[:4].decode("utf8"))
    return pkt[4:pktlen+4]


def send(skt, msg):
    try:
        skt.send(msg)
    except BrokenPipeError:
        sys.exit("Error: Server terminated the connection.")


debug("***************Secure File Transfer***************")
if len(sys.argv) != 4:
    sys.exit("Error: Parameters incorrect. python scp_client username password filename")
# Open File and check if valid.
try:
    f = open(sys.argv[3], "rb")
except FileNotFoundError:
    sys.exit("Error. File not found.")

# Generate RSA Public and Private Keys
debug("Generate RSA...")
KEY = RSA.generate(BUFSIZE)
PRIVATE_KEY = KEY.export_key()
private_key = RSA.import_key(PRIVATE_KEY)
PUBLIC_KEY = KEY.publickey().export_key()
debug("RSA Generated.")

# Create Socket
CLIENT = socket(AF_INET, SOCK_STREAM)
CLIENT.connect((HOST, PORT))
debug("Sending Public Key...")
# Send Public Key
send(CLIENT, PUBLIC_KEY)
debug("Receiving Session Key...")
# Receive Encrypted Session Key
enc_session_key = receive(CLIENT, "SESSION KEY")
# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)
cipher = AES_EAX(session_key)

username = sys.argv[1]
password = sys.argv[2]
h = SHA512.new(password.encode("utf8"))

debug("Username:\n", username, "\nPassword: ", h.hexdigest())
cipherText = cipher.encrypt(username.encode("utf8"))  # Send Username
serializedData = pickle.dumps(cipherText)
msg = form_packet(serializedData)
send(CLIENT, msg)  # Send Nonce, Tag, and Cipher Text

cipherText = cipher.encrypt(h.hexdigest().encode("utf8"))
serializedData = pickle.dumps(cipherText)
msg = form_packet(serializedData)
send(CLIENT, msg)  # Send Nonce, Tag, and Cipher Text

serializedData = receive(CLIENT, "AUTHENTICATION")  # Receive Authentication Message
if serializedData == -1:
    CLIENT.shutdown(SHUT_WR)
    sys.exit("Error. Unable to connect.")
nonce, tag, cipherText = pickle.loads(serializedData)
data = cipher.decrypt(nonce, tag, cipherText)
debug(data.decode("utf8"))
if data.decode("utf8").rfind("Error.", 0, 6) == 0:  # Error Message
    CLIENT.shutdown(SHUT_WR)
    sys.exit("Cannot transfer file.")

data = sys.argv[3].encode("utf-8")  # Send Filename
serializedData = pickle.dumps(cipher.encrypt(data))
msg = form_packet(serializedData)
send(CLIENT, msg)  # Send Nonce, Tag, and Cipher Text
debug("Sending File...")
allData = b''
while 1:
    contents = f.read(BUFSIZE-32-4-21)  # 2048: 32 bit Nonce & Tag, 4 bit overhead, pickle overhead
    allData = allData + contents
    if len(contents) == 0:
        break
    cipherText = cipher.encrypt(contents)
    serializedData = pickle.dumps(cipherText)
    msg = form_packet(serializedData)
    send(CLIENT, msg)  # Send Nonce, Tag, and Cipher Text

h = SHA256.new(allData)
debug("Checksum:", h.hexdigest())
data = str(h.hexdigest()).encode("utf-8")
serializedData = pickle.dumps(cipher.encrypt(data))
msg = form_packet(serializedData)
send(CLIENT, msg)  # Send Nonce, Tag, and Cipher Text
debug("Sending Complete.")

CLIENT.shutdown(SHUT_WR)

