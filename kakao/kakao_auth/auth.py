#!/usr/bin/python

import requests
import json
import hashlib
import base64
import sys
import os

sys.path.append(os.path.abspath("../kakao_status"))

from response_status import KakaoResponseStatus
import config

class KakaoAuth:
	def __init__(self):
		self.__initialize_session_key()
		self.__initialize_url()
		self.__initialize_data()
		self.__initialize_header()

	def __initialize_session_key(self):
		self.__session_key = ""

	def __initialize_url(self):
		self.__url = {}
		self.__url["LOGIN_URL"] = "https://sb-talk.kakao.com/api/v1/sub_device/login"

	def __initialize_data(self):
		self.__data = {}
		self.__data["email"] = config.USER["EMAIL"]
		self.__data["password"] = config.USER["PASSWORD"]
		self.__data["name"] = config.USER["NAME"]
		self.__data["auto_login"] = False
		self.__data["device_uuid"] = self.__generate_device_uuid()

	def __initialize_header(self):
		self.__headers = {}
		self.__headers["A"] = "mac/0.9.0/ko"
		self.__headers["Accept"] = "application/json"
		self.__headers["Accept-Language"] = "ko"
		self.__headers["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
		self.__headers["User-Agent"] = "KT/0.9.0 Mc/10.9 ko"
		self.__headers["X-VC"] = self.__generate_x_vc_token()

	def auth(self):
		self.__send_auth_request()
		print (self.get_user_key())
		print ("auth_request success")

	def __send_auth_request(self):
		request = requests.post(self.__url["LOGIN_URL"], data=self.__data, headers=self.__headers)
		response = json.loads(request.text)
		
		if (KakaoResponseStatus().is_registration_required(response["status"])):
			self.__do_auth_request_registration()
			self.__do_auth_accept_registration()
		elif (KakaoResponseStatus().is_request_success(response["status"])):
			self.__set_session_key(response["sessionKey"])
		else:
			print (response)
			print ("error auth_request")
			sys.exit()


	def __do_auth_request_registration(self):
		self.__data["once"] = False
		request = requests.post(self.__url["LOGIN_URL"], data=self.__data, headers=self.__headers)
		response = json.loads(request.text)

		if (not KakaoResponseStatus().is_request_success(response["status"])):
			print (response)
			print ("error auth_request_registration")
			sys.exit()
			
	def __do_auth_accept_registration(self):
		self.__data["forced"] = False
		self.__data["passcode"] = input("input passcode: ")

		request = requests.post(self.__url["LOGIN_URL"], data=self.__data, headers=self.__headers)
		response = json.loads(request.text)

		if (KakaoResponseStatus().is_request_success(response["status"])):
			self.__set_session_key(response["sessionKey"])
			print ("auth_accept_registration success")
		else:
			print (response)
			print ("error auth_accept_registration")
			sys.exit()

	def get_session_key(self):
		return self.__session_key

	def get_user_key(self):
		return self.__session_key + "-" + self.__data["device_uuid"]

	def __set_session_key(self, session_key):
		self.__session_key = session_key

	def __generate_x_vc_token(self):
		#Change "NITSUA" and "HSOJ" if kakao version is updated
		#0.9.0 = JOSH, AUSTIN
		#0.9.1 = NITSUA, HSOJ
		x_vc = "JOSH|" + self.__headers["User-Agent"] + "|AUSTIN|" + self.__data["email"]  + "|" + self.__data["device_uuid"]
		x_vc = x_vc.encode("UTF-8")

		hashed_x_vc = hashlib.sha512(x_vc).hexdigest()

		return hashed_x_vc[:16]

	def __generate_device_uuid(self):
		device_uuid = config.USER["DEVICE_UUID"].encode("UTF-8")
		sha1_hashed_device_uuid = hashlib.sha1(device_uuid).digest()
		sha256_hashed_device_uuid = hashlib.sha256(device_uuid).digest()

		return base64.b64encode(sha1_hashed_device_uuid + sha256_hashed_device_uuid).decode("UTF-8")
