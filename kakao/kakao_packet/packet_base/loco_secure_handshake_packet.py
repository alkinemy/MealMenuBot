#!/usr/bin/python

from loco_packet_base import LocoPacketBase
from loco_secure_normal_packet import LocoSecureNormalPacket

sys.path.append(os.path.abspath("../packet_config"))
import loco_config

class LocoSecureHandshakePacket(LocoPacketBase):
	def __init__(self):
		LocoPacketBase.__init__(self)

	#Override
	def create(self, command, args):
		return (self.__generate_handshake() + LocoSecureNormalPacket().create(command, args))

	def __generate_handshake(self):
		encrypted_data_block_length = "\x80\x00\x00\x00"
		handshake_type = "\x01\x00\x00\x00"
		encrypt_type = "\x01\x00\x00\x00"
		encrypted_data += self.encrypt_by_rsa(loco_config.AES["key"])

		return encrypted_data_block_length + handshake_type + encrypt_type + encrypted_data
