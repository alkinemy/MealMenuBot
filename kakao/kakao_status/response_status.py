#!/usr/bin/python

class KakaoResponseStatus(object):
	_instance = None
	def __new__(cls, *args, **kwargs):
		if not cls._instance:
			cls._instance = super(KakaoResponseStatus, cls).__new__(cls, *args, **kwargs)
		return cls._instance

	def is_request_success(self, status):
		return (status == 0)

	def is_registration_required(self, status):
		return (status == -100)
