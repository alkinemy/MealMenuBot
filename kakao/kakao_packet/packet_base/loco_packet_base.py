#!/usr/bin/python

import rsa

class LocoPacketBase:
	def __init__(self):
		pass

	def create(self, command, args):
		pass

	def encrypt_by_aes(self, data):
		pass

	def encrypt_by_rsa(self, data):
		N = 0xaf0dddb4de63c066808f08b441349ac0d34c57c499b89b2640fd357e5f4783bfa7b808af199d48a37c67155d77f063ddc356ebf15157d97f5eb601edc5a104fffcc8895cf9e46a40304ae1c6e44d0bcc2359221d28f757f859feccf07c13377eec2bf6ac2cdd3d13078ab6da289a236342599f07ffc1d3ef377d3181ce24c719
		E = 3

		public_key = rsa.PublicKey(N, E)

		return rsa.encrypt(data, public_key)
