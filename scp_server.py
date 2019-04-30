from Crypto.Cipher import AES, Blowfish, DES3, PKCS1_OAEP
from Crypto.Hash import HMAC
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
from Crypto import Random
import pickle
from socket import AF_INET, socket, SOCK_STREAM, SHUT_WR
import logging, sys

# ----------------------------------------------------------- #
# NAME : Joseph Chen                                          #
# DUE DATE : 2/18/2019                                        #
# EE 4723 Network Security Final Project                      #
# FILE NAME : scp_server.py                                   #
# ----------------------------------------------------------- #

HOST = 'localhost'
PORT = 33000
BUFSIZE = 2048
DEBUG = 1
users = [
    ["user", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"],      # "password"
    ["kit", "a4b143a7cb6635c8045e800b930284e3705d2ba2bc233c405de71eb8559df0f4c43a36d3a101413062a79821869bd278b910e7df89f897dc7186496de77ef2cb"],       # "cischke"
    ["test", "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"]       # "test"
]


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
    if len(pkt) == 0:
        return -1
    pktlen = int(pkt[:4].decode("utf8"))
    return pkt[4:pktlen+4]


debug("Generate RSA...")
KEY = RSA.generate(2048)
PRIVATE_KEY = KEY.export_key()
PUBLIC_KEY = KEY.publickey().export_key()
debug("RSA Generated.")

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind((HOST, PORT))
SERVER.listen(1)

while True:
    debug("Waiting for connection...")
    # file = 0
    client, client_address = SERVER.accept()
    debug("%s:%s has connected." % client_address)

    debug(" Receiving Client RSA...")
    msg = client.recv(BUFSIZE)
    debug(" Importing Client RSA...")
    recipient_key = RSA.import_key(msg)

    session_key = get_random_bytes(16)  # Generate Session Key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)  # Encrypt session key w/ client pub key
    msg = form_packet(enc_session_key)  # Form Packet
    client.send(msg)                    # Send Session Key
    cipher = AES_EAX(session_key)       # Create Cipher Text

    serializedData = receive(client, "USERNAME")    # Username
    nonce, tag, cipherText = pickle.loads(serializedData)
    data = cipher.decrypt(nonce, tag, cipherText)
    username = data.decode("utf-8")

    serializedData = receive(client, "PASSWORD")    # Password
    nonce, tag, cipherText = pickle.loads(serializedData)
    data = cipher.decrypt(nonce, tag, cipherText)
    password = data.decode("utf-8")
    authFlag = 0
    for user in users:
        if user[0] == username:
            if user[1] == password:
                authFlag = 1
    if authFlag == 0:
        cipherText = cipher.encrypt("Error. Not Authenticated".encode("utf8"))
        serializedData = pickle.dumps(cipherText)
        msg = form_packet(serializedData)
        client.send(msg)
        debug("Error. User Not Authenticated.")
        debug("Receive \n Username:", username, "\n Password: ", password)
        client.close()
    else:
        cipherText = cipher.encrypt(str("Authenticated. Welcome: " + username).encode("utf8"))
        serializedData = pickle.dumps(cipherText)
        msg = form_packet(serializedData)
        client.send(msg)
        debug("User Authenticated. Username:", username)
        # Receive Nonce, Tag, and Cipher Text
        serializedData = receive(client, "DATA")  # File name
        nonce, tag, cipherText = pickle.loads(serializedData)
        data = cipher.decrypt(nonce, tag, cipherText)

        file = open("txd" + data.decode("utf8"), "wb")             # Decrypted File
        badFile = open("encryptedTX" + data.decode('utf8'), "wb")  # Encrypted File

        prevData = b''
        currData = b''
        allData = b''
        while True:
            prevData = currData
            # Receive Nonce, Tag, and Cipher Text
            serializedData = receive(client, "DATA")
            if serializedData == -1:        # If the next data packet is empty,
                break                       # don't write prevData. It's the checksum.

            nonce, tag, cipherText = pickle.loads(serializedData)
            currData = cipher.decrypt(nonce, tag, cipherText)
            allData = allData + prevData
            file.write(prevData)            # Write previous data
            badFile.write(serializedData)

        h = SHA256.new(allData)
        debug("Received Checksum:", prevData.decode("utf8"))
        debug("Calculated Checksum:", h.hexdigest())

        if h.hexdigest() == prevData.decode("utf8"):
            data = "Checksum matches. File Transfer: SUCCESS".encode("utf-8")
            debug("Checksum matches. File Transfer: SUCCESS")
        else:
            data = "Checksum does not match. File Transfer: FAIL".encode("utf-8")
            debug("Checksum does not match. File Transfer: FAIL")

        serializedData = pickle.dumps(cipher.encrypt(data))
        msg = form_packet(serializedData)
        client.send(msg)  # Send File Transfer Success/Fail Message

        file.close()
        client.shutdown(SHUT_WR)

