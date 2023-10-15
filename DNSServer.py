import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import socket
import threading
import signal
import os
import sys
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

# Define the generate_aes_key function to create an AES key from a password and salt
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

# Define the encrypt_with_aes function to encrypt data using the AES key
def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data

# Define the decrypt_with_aes function to decrypt data using the AES key
def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

# Define the salt, password, and input_string for encryption
salt = b'Tandon'  
password = 'sb9166@nyu.edu'
input_string = 'AlwaysWatching'

# Encrypt the input_string
encrypted_value = encrypt_with_aes(input_string, password, salt)

# Decrypt the encrypted value (for testing)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)

# Create a dictionary of DNS records
dns_records = {
    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },
    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },
    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },
    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },
    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: encrypted_value,
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}

# Create a UDP socket and bind it to a specific address and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('localhost', 53))  # Bind to the DNS port (53)

# Function to handle incoming DNS requests and send responses
def handle_dns_request(data, addr):
    try:
        # Parse the request using the dns.message.from_wire method
        request = dns.message.from_wire(data)

        # Create a response message using the dns.message.make_response method
        response = dns.message.make_response(request)

        # Get the question from the request
        question = request.question[0]
        qname = question.name.to_text()
        qtype = question.rdtype

        # Check if there is a record in the dns_records dictionary that matches the question
        if qname in dns_records and qtype in dns_records[qname]:
            # Retrieve the data for the record and create an appropriate rdata object for it
            answer_data = dns_records[qname][qtype]

            rdata_list = []

            if qtype == dns.rdatatype.MX:
                for pref, server in answer_data:
                    rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
            elif qtype == dns.rdatatype.SOA:
                mname, rname, serial, refresh, retry, expire, minimum = answer_data
                rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                rdata_list.append(rdata)
            else:
                if isinstance(answer_data, str):
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                else:
                    rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]

            for rdata in rdata_list:
                response.answer.append(dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype))
                response.answer[-1].add(rdata)

        # Set the response flags
        response.flags |= 1 << 10

        # Send the response back to the client using the server_socket.sendto method
        server_socket.sendto(response.to_wire(), addr)
        print("Responding to request:", qname)
    except KeyboardInterrupt:
        print('\nExiting...')
        server_socket.close()
        sys.exit(0)

# Function to run the DNS server and handle user input
def run_dns_server():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()

    while True:
        data, addr = server_socket.recvfrom(1024)
        handle_dns_request(data, addr)

if __name__ == '__main__':
    run_dns_server()
