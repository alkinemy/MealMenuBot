#!/usr/bin/python

#TODO : import packet class

class LocoPacketFactory(object):
	_instance = None
	def __new__(cls, *args, **kwargs):
		if not cls._instance:
			cls._instance = super(LocoPacketFactory, cls).__new__(cls, *args, **kwargs)
		return cls._instance

	def getPacket(self, packet_name, packet_data):
		if (packet_name == "BUY"):
			return LocoPacketBUY(packet_data)
		elif (packet_name == "PING"):
			return LocoPacketPING(packet_data)
		#TODO : add packet
