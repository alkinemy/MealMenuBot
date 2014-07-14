#!/usr/bin/python

import struct

from loco_packet_base import LocoPacketBase
from loco_packet import LocoPacket


class LocoSequreNormalPacket(LocoPacketBase):
	def __init__(self):
		LocoPacketBase.__init__(self)

	def create(self, command, args):
		body_contents = LocoPacket().create(command, args)

		aes_encrypted_body_contents = self.__encrypt_data_by_aes(body_contents)
		aes_encrypted_body_length = len(aes_encrypted_body_contents)

		return aes_encrypted_body_length + aes_encrypted_body_contents

	def __encrypt_data_by_aes(self, data):
		#encrypt - need more information
		packet = ""

		data_length = len(data)
		encrypt_target_length = (data_length / 16 + 1) * 16
		while (encrypt_target_length > 2048):
			encrypt_target = data[:2047]
			aes_encrypted_data = self.encrypt_aes(encrypt_target)
			aes_encrypted_data_length = len(aes_encrypted_data)
			
			packet += struct.pack("I", aes_encrypted_data_length) + aes_encrypted_data

			data = data[2048:]
			data_length = len(data)
			encrypt_target_length = (data_length / 16 + 1) * 16

		aes_encrypted_data = self.encrypt_aes(data)
		aes_encrypted_data_length = len(aes_encrypted_data)
		packet += struct.pack("I", aes_encrypted_data_length) + aes_encrypted_data

		return packet
