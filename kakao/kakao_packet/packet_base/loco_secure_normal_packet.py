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
		packet = ""

		encrypt_target_length = (len(data) / 16 + 1) * 16
		while (encrypt_target_length > 0):
			packet += self.__encrypt_data_less_than_2048_bytes_by_aes(data[:2047])

			data = data[2048:]
			encrypt_target_length = (len(data) / 16 + 1) * 16

		return packet

	def __encrypt_data_less_than_2048_bytes_by_aes(self, data):
		#data : less then 2048 bytes
		aes_encrypted_data = self.encrypt_by_aes(data)
		aes_encrypted_data_length = len(aes_encrypted_data)
		
		return struct.pack("I", aes_encrypted_data_length) + aes_encrypted_data
