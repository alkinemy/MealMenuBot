#!/usr/bin/python

import sys
from loco_packet_base import LocoPacketBase

try:
	from bson import BSON
except ImportError, e:
	print ("Import Error %s", e)
	sys.exit()

class LocoPacket(LocoPacketBase):
	def __init__(self):
		LocoPacketBase.__init__(self)

	#Override
	def create(self, command, args):
		packet_id = "\xFF\xFF\xFF\xFF"
		status_code = "\x00\x00"
		method = command + ("\x00" * (11 - len(command)))
		body_type = "\x00"
		body_contents = BSON.encode(args)
		body_length = body_contents[:4]

		return packet_id + status_code + method + body_type + body_lentgh + body_contents
