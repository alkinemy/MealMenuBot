#!/usr/bin/python

import requests
import json
import hashlib
import sys
import base64


class KakaoLogin:
	kakao_url = {
		"LOGIN_URL" : "https://sb-talk.kakao.com/api/v1/sub_device/login"
	}

	headers = {
		"A" : "mac/0.9.0/ko",
		"Accept" : "application/json",
		"Accept-Language" : "ko",
		"Content-Type" : "application/x-www-form-urlencoded; charset=utf-8",
		"User-Agent" : "KT/0.9.0 Mc/10.9 ko",
		"X-VC" : ""
	}

	data = {
		"email" : "",
		"password" : "",
		"device_uuid" : "",
		"name" : "",
		"auto_login" : ""
	}

	def __init__(self, email, password):
		self.data["email"] = email
		self.data["password"] = password
		self.data["name"] = "meal.menu.bot"
		self.data["auto_login"] = False
		
		self.data["device_uuid"] = self.generate_device_uuid()
		self.headers["X_VC"] = self.generate_x_vc_token()

	def login(self):
		self.login_request()
		self.login_registration()

	def login_request(self):
		request = requests.post(self.kakao_url["LOGIN_URL"], data=self.data, headers=self.headers)
		response = json.loads(request.text)

		if response["status"] != -100:
			print response
			print "error login_request"
			sys.exit()
		else:
			print "login_request success"

	def login_registration(self):
		return

	def generate_x_vc_token(self):
		#Change "NITSUA" and "HSOJ" if kakao version is updated
		#0.9.0 = JOSH, AUSTIN
		#0.9.1 = NITSUA, HSOJ
		x_vc = "JOSH|" + self.headers["User-Agent"] + "|AUSTIN|" + self.data["email"]  + "|" + self.data["device_uuid"]
		hashed_x_vc = hashlib.sha512(x_vc).hexdigest()

		return x_vc[:16]

	def generate_device_uuid(self):
		device_uuid = "088BE760-07E1-11E4-9191-0800200C9A66"
		sha1_hashed_device_uuid = hashlib.sha1(device_uuid).hexdigest()
		sha256_hashed_device_uuid = hashlib.sha256(device_uuid).hexdigest()

		sha_hashed = sha1_hashed_device_uuid + sha256_hashed_device_uuid
		
		return base64.b64encode(sha_hashed)
