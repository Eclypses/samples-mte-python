#!/usr/bin/env python3

from telnetlib import EC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
import base64,hashlib,socket,struct,sys

from EclypsesECDH import EclypsesECDH

# Cross test server and port.
HOST = "127.0.0.1"
PORT = 27015

ecdh = EclypsesECDH()

# Create socket.
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Handle incoming bytes from server.
def recv_all(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

#-------------------------------------------------------------------------
# This simple program demonstrates Diffie-Hellman key exchange with server.
# -------------------------------------------------------------------------
# The purpose of the handshake is to create unique entropy for MTE
# in a secure manner for the encoder and decoder.
# The "client" creates the personalization string or ConversationIdentifier.
# the "server" creates the nonce in the form of a timestamp.
# -------------------------------------------------------------------------
def main():
    try:
        # Connect to the socket.
        sock.connect((HOST,PORT))
        print(f'Socket connected to {sock.getpeername()}')

        # Get the public key.
        key_to_pass = "pk~"
        key_to_pass += ecdh.get_device_public_key().decode()
        key_to_pass = bytearray(key_to_pass,'utf-8')

        # Send the public key to the other side,
        # by first sending the length,
        # and then sending the actual key.
        packet_len = len(key_to_pass)
        packet_len = struct.pack('>I', packet_len)
        sock.sendall(packet_len)
        sock.sendall(key_to_pass)

        # Receive the partner public key from the other side,
        # by first receiving the length,
        # and then receiving the actual key.
        response_len = recv_all(sock, 4)
        msg_len = struct.unpack('>I', response_len)[0]
        response = recv_all(sock,msg_len)
        socket_key = response.decode()
        key = socket_key.split("pk~")
        partner_public_key = bytes(key[1],'utf-8')
          
        # Create shared secret.
        shared_secret = ecdh.create_shared_secret(partner_public_key)  
        share_to_pass = "ss~"
        share_to_pass += shared_secret.decode()
        share_to_pass = bytearray(share_to_pass,'utf-8')

        # Send the shared secret to the other side.    
        packet_len = len(share_to_pass)
        packet_len = struct.pack('>I', packet_len)
        sock.sendall(packet_len)
        sock.sendall(share_to_pass)

        # Receive the shared secret from the other side.
        response_len = recv_all(sock, 4)
        msg_len = struct.unpack('>I', response_len)[0]
        response = recv_all(sock,msg_len)
        socket_shared = response.decode()
        key = socket_shared.split("ss~")
        partner_shared_key = key[1]

        # Display the keys and shared secrets.
        # Python Public Key
        print(f'Python Public Key: \n{key_to_pass}')
        # Socket Public Key
        print(f'Socket Public Key: \n{partner_public_key}')
        # Python Shared Secret
        print(f'Python Shared Secret: \n{share_to_pass.decode()}')
        # Socket Shared Secret
        print(f'Socket Shared Secret: \n{partner_shared_key}')

    finally:
        # Close down the connection.
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

if __name__ == "__main__":
    sys.exit(main())
