#!/usr/bin/python

import struct
import base64
from lora.crypto import loramac_decrypt
from pprint import pprint
from binascii import unhexlify


p = "QGyoHrSACgACb3nY9sWjyQG6P/dE"
sequence_counter = 10

PHYPayload = []

for c in base64.decodestring(p):
   PHYPayload.append(ord(c))

pprint(PHYPayload)

MACPayload = PHYPayload[1:]
MACPayload = MACPayload[:-4]
FHDR = MACPayload[:7]
FPort = MACPayload[7]
FRMPayload = MACPayload[8:]
print("Fport: " + str(FPort))

pprint(FRMPayload)

print
print
payload = ''.join("{:02x}".format(c) for c in FRMPayload)

print("Payload: " + payload)
key = '820EB5127B0B98C8CC0B7EE43253E0D1'
dev_addr = 'B41EA86C'

out = loramac_decrypt(payload, sequence_counter, key, dev_addr)
print out
