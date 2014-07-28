#!/usr/bin/python
#-*- coding: utf-8 -*-

import struct
import sys
import os

from binascii import hexlify
from functools import reduce

try:
	from Crypto.Cipher import AES
	from bson import decode_all
except ImportError as e:
	print("Import Error %s" % e)
	sys.exit()

sys.path.append(os.path.abspath("../packet_config"))
import loco_config

#패킷을 직접 콘솔로 입력받아 출력
#개발 중에 패킷 확인을 위한 클래스
class LocoPacketPrinter:
	def print_packet(self):
		try:
			self.data = input("input hexcode: ")
			self.data = reduce(lambda x, y : x + y, map(lambda x : struct.pack("B", int(x, 16)), self.data.split(" ")))
			
			self.__print_response(self.receive_and_translate())
		except Exception as e:
			print("Exception occurred : %s" % e)

	def receive_and_translate(self):
		head = self.data[:4]
		self.data = self.data[4:]
		
		if (self.__is_loco_packet(head)):
			print("----Start base packet printing----")
			return self.__receive_and_translate_loco_packet(head)
		else:
			print("----Start secure packet printing----")
			return self.__receive_and_translate_loco_secure_packet(head)
		
	def __is_loco_packet(self, head):
		return (head == b"\x02\x00\x00\x00") or (head == b"\xFF\xFF\xFF\xFF")

	def __receive_and_translate_loco_packet(self, head):
		result = self.__translate_packet_header(head)

		if (self.data[18:]):
			result["body_contents"] = decode_all(self.data[18:])[0]

		return result

	def __receive_and_translate_loco_secure_packet(self, head):
		entire_body = self.__receive_and_decrypt_by_aes(head)
		print(self.__translate_bytes(entire_body))
		entire_body_length = struct.unpack("I", entire_body[18:22])[0]
		recv_entire_body_length = len(entire_body[22:])
		print("1", recv_entire_body_length, entire_body_length)

		while (recv_entire_body_length < entire_body_length):
			inner_head = self.data[:4]
			self.data = self.data[4:]
			result = self.__receive_and_decrypt_by_aes(inner_head)
			entire_body += result
			recv_entire_body_length += len(result)

		return self.__translate_loco_packet(entire_body)

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

	def __translate_loco_packet(self, body):
		result = {}
		result["packet_id"] = body[0:4]
		result["status_code"] = body[4:6]
		result["method"] = body[6:17]
		result["body_type"] = body[17:18]
		result["body_length"] = struct.unpack("I", body[18:22])[0]

		if (body[22:]):
			result["body_contents"] = decode_all(body[22:])[0]

		return result

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

	def __translate_bytes(self, data):
		return reduce(lambda x, y : x + " " + y, map(lambda x : format(int(x), "02x"), data))

	def __print_response(self, data):
		print("    %s : %s" % ("packet_id", data["packet_id"]))
		print("    %s : %s" % ("method", data["method"]))
		print("    %s : %s" % ("status_code", data["status_code"]))
		print("    %s : %s" % ("body_type", data["body_type"]))
		print("    %s : %s" % ("body_length", data["body_length"]))
		
		if (data["body_length"] > 0):
			print("    %s : %s" % ("body_contents", data["body_contents"]))


if (__name__ == "__main__"):
	printer = LocoPacketPrinter()
	while(True):
		printer.print_packet()
