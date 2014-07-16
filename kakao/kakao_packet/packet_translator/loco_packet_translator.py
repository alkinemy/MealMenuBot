#!/usr/bin/python
#-*- coding: utf-8 -*-

import struct
import sys
import os

from binascii import hexlify

try:
	from Crypto.Cipher import AES
	from bson import decode_all
except ImportError as e:
	print("Import Error %s" % e)
	sys.exit()

sys.path.append(os.path.abspath("../packet_config"))
import loco_config

class LocoPacketTranslator:
	#TODO
	#kakao main machine에 translate function을 만들고 안에서 소켓이 null인지 확인해야함
	def receive_and_translate(self, socket, force_reply=False):
		head = socket.recv(4)
		
		if (self.__is_connection_closed(head)):
			print("Error translate response: Connection closed")
			socket.close()
			return None
		elif (self.__is_loco_packet(head)):
			return self.__receive_and_translate_loco_packet(head, socket)
		else:
			#is loco_secure_packet
			return self.__receive_and_translate_loco_secure_packet(head, socket, force_reply)
		
	def __is_connection_closed(self, head):
		return (not head)

	def __is_loco_packet(self, head):
		return (head == "\xFF\xFF\xFF\xFF")

	def __receive_and_translate_loco_packet(self, head, socket):
		result = self.__translate_packet_header(head + socket.recv(18))
		result["body_contents"] = decode_all(socket.recv(result["body_length"]))[0]

		return result

	def __receive_and_translate_loco_secure_packet(self, head, socket, force_reply):
		result = {}

		#receive and decrypt packet
		body = self.__receive_and_decrypt_by_aes(head, socket)
		entire_body_length = struct.unpack("I", entire_body[18:22])[0]
		recv_entire_body_length = len(body[22:])

		#다른 패킷이 넘어오면 그것에 대한 처리?
		while (recv_entire_body_length < entire_body_length):
			body = self.__receive_and_decrypt_by_aes(socket.recv(4), socket)
			entire_body += body
			recv_entire_body_length += len(body)

		result = self.__translate_hexcode(entire_body)

		#만약에 loco_packet이 아니고 force_reply면 다시 receive_translate시작
		if (not self.__is_loco_packet(result["packet_id"]) and force_reply):
			#Handle non-loco-packet
			return self.receive_and_translate(socket, force_reply)
		else:
			return result

	def __receive_and_decrypt_by_aes(self, head, socket):
		aes_encrypted_data = ""
		aes_encrypted_data_length = struct.unpack("I", head)[0]
		received_aes_encrypted_data_length = 0

		while(received_aes_encrypted_data_length < aes_encrypted_data_length):
			received = socket.recv(aes_encrypted_data_length - received_aes_encrypted_data_length)
			aes_encrypted_data += received
			received_aes_encrypted_data_length += len(received)
		
		return self.__decrypt_by_aes(aes_encrypted_data)
	
	def __translate_hexcode(self, hexcode):
		result = self.__translate_packet_header(hexcode)
		result["body_contents"] = decode_all(hexcode[22:])[0]

		return result

	def __translate_packet_header(self, hexcode):
		result = {}
		result["packet_id"] = hexcode[0:4]
		result["status_code"] = hexcode[4:6]
		result["method"] = hexcode[6:17]
		result["body_type"] = hexcode[17:18]
		result["body_length"] = struct.unpack("I", hexcode[18:22])[0]

		return result

	def __decrypt_by_aes(self, data):
		aes = AES.new(key=loco_config.AES["key"], mode=AES.MODE_CBC, IV=loco_config.AES["IV"])
		padded_data = aes.decrypt(data)

		return self.__decode_by_pkcs7(padded_data)

	def __decode_by_pkcs7(self, data):
		return data[:-int(hexlify(data[-1]), 16)]
