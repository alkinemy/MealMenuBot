#!/usr/bin/python

from loco_packet_base import LocoPacketBase

class LocoSecureHandshakePacket(LocoPacketBase):
	def __init__(self):
		LocoPacketBase.__init__(self)

	#Override
	def create(self, command, args):
		pass
