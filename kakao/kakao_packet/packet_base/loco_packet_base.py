#!/usr/bin/python

import sys
import os
from binascii import unhexlify

try:
	import rsa
	from Crypto.Cipher import AES
except ImportError, e:
	print("Import Error %s" % e)
	sys.exit()

sys.path.append(os.path.abspath("../packet_config"))
import loco_config

class LocoPacketBase:
	def create(self, command, args):
		return

	def encrypt_by_aes(self, data):
		aes = AES.new(key=loco_config.AES["key"], mode=AES.MODE_CBC, IV=loco_config.AES["IV"])
		padded_data = self.encode_by_pkcs7(data)

		return aes.encrypt(padded_data)

	def encrypt_by_rsa(self, data):
		N = 0xaf0dddb4de63c066808f08b441349ac0d34c57c499b89b2640fd357e5f4783bfa7b808af199d48a37c67155d77f063ddc356ebf15157d97f5eb601edc5a104fffcc8895cf9e46a40304ae1c6e44d0bcc2359221d28f757f859feccf07c13377eec2bf6ac2cdd3d13078ab6da289a236342599f07ffc1d3ef377d3181ce24c719
		E = 3

		public_key = rsa.PublicKey(N, E)

		return rsa.encrypt(data, public_key)

	def __encode_by_pkcs7(self, data):
		data_length = len(data)
		amount_to_pad = loco_config.BLOCK_SIZE + (0, - (data_length % loco_config.BLOCK_SIZE)) [amount_to_pad != 0]

		return data + unhexlify("%02x" % amount_to_pad) * amount_to_pad
