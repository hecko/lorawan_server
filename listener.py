#!/usr/bin/python

import sys
import base64
import json
import socket
import struct
from pprint import pprint 
 
UDP_IP = ""
UDP_PORT = 1700 

packet_types = ( 'PKT_PUSH_DATA', 'PKT_PUSH_ACK', 'PKT_PULL_DATA', 'PKT_PULL_RESP', 'PKT_PULL_ACK' )

info = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(4000)
    info['hex'] = " ".join("{:02x}".format(ord(c)) for c in data)
    info['protocol_version'] = ord(data[0])
    info['random_token'] = " ".join("{:02x}".format(ord(c)) for c in data[1:3]) 
    info['packet_type'] = struct.unpack("B", data[3])[0] 
    info['packet_type_human'] = packet_types[struct.unpack("B", data[3])[0]]
    info['gateway_mac_ident'] = " ".join("{:02x}".format(ord(c)) for c in data[4:12]) 
    if info['packet_type'] == 0:
        info['raw_payload'] = "".join("{:02x}".format(ord(c)) for c in data[12:]).decode('hex')
        info['i'] = json.loads(info['raw_payload'])

    try:
        '''The data payload is actually a PHYPayload from LoRaWAN spec.

        ''' 
        d = info['i']['rxpk'][0]['data']
        print("Will try to decode the data payload " + d) 
        d = base64.b64encode(d)
        print("base64 encoded: " + d) 
        pprint(info)
        sys.exit(1)
    except Exception as e:
        pass
    print
    print
