#!/usr/bin/python
#-*- coding: utf-8 -*-

import struct
import sys
import os

from binascii import hexlify
from bson import decode_all

from functools import reduce

try:
	from Crypto.Cipher import AES
except ImportError as e:
	print("Import Error %s" % e)
	sys.exit()

sys.path.append(os.path.abspath("../packet_config"))
import loco_config

#패킷을 직접 콘솔로 입력받아 출력
#개발 중에 패킷 확인을 위한 클래스
class LocoPacketPrinter:
	def print_packet(self):
		self.data = input("input hexcode: ")
		self.data = reduce(lambda x, y : x + y, map(lambda x : struct.pack("B", int(x, 16)), self.data.split(" ")))
		
		print(self.receive_and_translate())

	def receive_and_translate(self):
		head = self.data[:4]
		self.data = self.data[4:]
		
		if (self.__is_loco_packet(head)):
			return self.__receive_and_translate_loco_packet(head)
		else:
			print("secure")
			return self.__receive_and_translate_loco_secure_packet(head)
		
	def __is_loco_packet(self, head):
		return (head == b"\x02\x00\x00\x00") or (head == b"\xFF\xFF\xFF\xFF")

	def __receive_and_translate_loco_packet(self, head):
		result = self.__translate_packet_header(head)
		result["body_contents"] = decode_all(self.data[18:])[0]

		return result

	def __receive_and_translate_loco_secure_packet(self, head):
		entire_body = self.__receive_and_decrypt_by_aes(head)
		entire_body_length = struct.unpack("I", entire_body[18:22])[0]
		recv_entire_body_length = len(entire_body[22:])

		while (recv_entire_body_length < entire_body_length):
			head = self.data[:4]
			self.data = self.data[4:]
			result = self.__receive_and_decrypt_by_aes(head)
			entire_body += body
			recv_entire_body_length += len(body)

		return self.__translate_loco_packet(entire_body)

	def __translate_loco_packet(self, body):
		result = {}
		result["packet_id"] = body[0:4]
		result["status_code"] = body[4:6]
		result["method"] = body[6:17]
		result["body_type"] = body[17:18]
		result["body_length"] = struct.unpack("I", body[18:22])[0]

		return result


	def __receive_and_decrypt_by_aes(self, head):
		aes_encrypted_data = b""
		aes_encrypted_data_length = struct.unpack("I", head)[0]
		received_aes_encrypted_data_length = 0

		while(received_aes_encrypted_data_length < aes_encrypted_data_length):
			length = aes_encrypted_data_length - received_aes_encrypted_data_length
			received = self.data[:length]
			self.data = self.data[length:]
			aes_encrypted_data += received
			received_aes_encrypted_data_length += len(received)
		
		return self.__decrypt_by_aes(aes_encrypted_data)

	def __translate_packet_header(self, head):
		result = {}
		result["packet_id"] = head
		result["status_code"] = self.data[0:2]
		result["method"] = self.data[2:13]
		result["body_type"] = self.data[13:14]
		result["body_length"] = struct.unpack("I", self.data[14:18])[0]

		return result

	def __decrypt_by_aes(self, data):
		aes = AES.new(key=loco_config.AES["key"], mode=AES.MODE_CBC, IV=loco_config.AES["IV"])
		padded_data = aes.decrypt(data)

		return self.__decode_by_pkcs7(padded_data)

	def __decode_by_pkcs7(self, data):
		return data[:-int(format(data[-1], "02x"), 16)]
#return data[:-int(hexlify(data[-1]))]



if (__name__ == "__main__"):
	printer = LocoPacketPrinter()
	while(True):
		printer.print_packet()
