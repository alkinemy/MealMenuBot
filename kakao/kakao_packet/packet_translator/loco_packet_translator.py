#!/usr/bin/python

from binascii import hexlify

try:
	from Crypto.Cipher import AES
except ImportError, e:
	print("Import Error %s" % e)
	sys.exit()

sys.path.append(os.path.abspath("../kakao_config"))
import loco_config

class LocoPacketTranslator:
	def translate_hexcode(self, hexcode):
		pass

	def __decrypt_by_aes(self, data):
		aes = AES.new(key=loco_config.AES["key"], mode=AES.MODE_CBC, IV=loco_config.AES["IV"])
		padded_data = aes.decrypt(data)

		return self.__decode_by_pkcs7(padded_data)

	def __decode_by_pkcs7(self, data):
		return data[:-int(hexlify(data[-1]))]
