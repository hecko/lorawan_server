#!/usr/bin/python

import sys
import time
import json
import socket
import struct
import base64
import argparse
from pprint import pprint 
from datetime import datetime
from lora.crypto import loramac_decrypt

parser = argparse.ArgumentParser(description='Semtech LoRaWAN packet forwarder listener')
parser.add_argument('-v', '--verbose', action='store_true', help='Be verbose')
args = parser.parse_args()
 
UDP_IP = ""
UDP_PORT = 1700 

packet_types = ( 'PKT_PUSH_DATA', 'PKT_PUSH_ACK', 'PKT_PULL_DATA', 'PKT_PULL_RESP', 'PKT_PULL_ACK' )

info = {}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(4000)
    dt = datetime.now()
    
    info['hex'] = " ".join("{:02x}".format(ord(c)) for c in data)
    info['protocol_version'] = ord(data[0])
    info['random_token'] = " ".join("{:02x}".format(ord(c)) for c in data[1:3]) 
    info['packet_type'] = struct.unpack("B", data[3])[0] 
    info['packet_type_human'] = packet_types[struct.unpack("B", data[3])[0]]
    info['gateway_mac_ident'] = " ".join("{:02x}".format(ord(c)) for c in data[4:12]) 

    info['raw_payload'] = "".join("{:02x}".format(ord(c)) for c in data[12:]).decode('hex')

    print(str(dt.isoformat("T")) + " received packet from forwarder (protocol version " + str(info['protocol_version']) + "). Packet type: " + info['packet_type_human'])

    try:
        info['i'] = json.loads(info['raw_payload'])
    except Exception as e:
        pass

    if 'i' in info and info['packet_type_human'] == 'PKT_PUSH_DATA':

        if not 'rxpk' in info['i']:
            continue
        '''The 'data' payload is actually a PHYPayload from LoRaWAN spec.

        ''' 
        d = info['i']['rxpk'][0]['data']

        pprint(d)

        info['PHYPayload'] = []
        for c in base64.decodestring(d):
            info['PHYPayload'].append(ord(c))

        info['MIC'] = info['PHYPayload'][-4:]
        info['MHDR'] = info['PHYPayload'][0]
        info['MACPayload'] = info['PHYPayload'][1:]
        info['MACPayload'] = info['MACPayload'][:-4]
        info['FPort'] = info['MACPayload'][7]
        info['FRMPayload'] = info['MACPayload'][8:]
        info['FHDR'] = info['MACPayload'][:7]

        info['DevAddr'] = "".join("{:02x}".format(info['FHDR'][c]) for c in range(3,-1,-1))
        info['FCnt'] = struct.unpack("<H", "".join(chr(c) for c in info['FHDR'][5:7]))[0] 
        info['FCtrl'] = info['FHDR'][4]
        info['FCtrl_bin'] = bin(info['FCtrl'])

        payload = ''.join("{:02x}".format(c) for c in info['FRMPayload'])

        if args.verbose:
            print("Will try to decode the FRMPayload payload " + payload) 
        key = '820EB5127B0B98C8CC0B7EE43253E0D1'

        out = loramac_decrypt(payload, info['FCnt'], key, info['DevAddr'])
        info['decrypted_payload'] = out
        if args.verbose:
            pprint(info)
