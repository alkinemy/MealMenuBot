#!/usr/bin/python

from loco_packet_base import LocoPacketBase
from loco_secure_normal_packet import LocoSecureNormalPacket

class LocoSecureHandshakePacket(LocoPacketBase):
	def __init__(self):
		LocoPacketBase.__init__(self)

	#Override
	def create(self, command, args):
		aes_key = "\x00" * 16 #TODO fix

		handshake = "\x80\x00\x00\x00"
		handshake += "\x01\x00\x00\x00"
		handshake += "\x01\x00\x00\x00"
		handshake += self.encrypt_rsa(aes_key)

		return (handshake + LocoSecureNormalPacket().create(command, args))
