#!/usr/bin/python

import sys
import base64
import json
import socket
import struct
from pprint import pprint 
from lora.crypto import loramac_decrypt
 
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

    if info['packet_type_human'] == 'PKT_PUSH_DATA':
        info['raw_payload'] = "".join("{:02x}".format(ord(c)) for c in data[12:]).decode('hex')
        info['i'] = json.loads(info['raw_payload'])

    if 'i' in info and info['packet_type_human'] == 'PKT_PUSH_DATA':
        if not 'rxpk' in info['i']:
            continue
        '''The data payload is actually a PHYPayload from LoRaWAN spec.

        ''' 
        d = info['i']['rxpk'][0]['data']

        PHYPayload = []
        for c in base64.decodestring(d):
            PHYPayload.append(ord(c))

        MACPayload = PHYPayload[1:]
        MACPayload = MACPayload[:-4]
        info['FPort'] = MACPayload[7]
        info['FRMPayload'] = MACPayload[8:]
        info['FHDR'] = MACPayload[:7]

        info['DevAddr'] = "".join("{:02x}".format(info['FHDR'][c]) for c in range(3,-1,-1))
        info['FCnt'] = struct.unpack("<H", "".join(chr(c) for c in info['FHDR'][5:7]))[0] 
        info['FCtrl'] = info['FHDR'][4]
        info['FCtrl_bin'] = bin(info['FCtrl'])

        payload = ''.join("{:02x}".format(c) for c in info['FRMPayload'])

        print("Will try to decode the FRMPayload payload " + payload) 
        key = '820EB5127B0B98C8CC0B7EE43253E0D1'

        out = loramac_decrypt(payload, info['FCnt'], key, info['DevAddr'])
        info['decrypted_payload'] = out
        pprint(info)
