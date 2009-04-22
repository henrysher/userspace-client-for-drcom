#!/usr/bin/env python

import thread, Queue
import socket
import sys, time
import random

safeprint = thread.allocate_lock()
dataQueue = Queue.Queue()

BUFFER = 1024
running = 0
num = 5
i = 0
recv_addr = ('localhost', 8080)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('localhost',8080))
s.setblocking(0)

def listen():
	while 1:
		try:
			data = dataQueue.get(block=False)
		except Queue.Empty:
			pass
		else:
			if data == 'login':
				login()
			elif data == 'recv_ack':
				try:
					recv_data = dataQueue.get(block=False)
				except:
					pass
				else:
					packet_process(recv_data)
#			elif data == 'logout':
#				logout()
#			elif data == 'timer1':
#				timer1()
#			elif data == 'timer2':
#				timer2()
			elif data == 'random_send':
				random_sender()
			else:
				pass

def recv_ack():
	global recv_addr
	while 1:
		try:
			recv_data, recv_addr = s.recvfrom(BUFFER)
		except:
			pass
		else:
			dataQueue.put('recv_ack')
			dataQueue.put(recv_data)

def random_sender():
	# FIXME: data sent not random
	send_data = '\x4d\x26\x6b\x25'
	s.sendto(send_data, recv_addr)

def random_timer():
	global running, i, num
	while running:
		i +=1
		time.sleep(0.1)
		if i == num:
			dataQueue.put('random_send')
			num = int(random.random()*100)+50
			i = 0
		
def set_timer():
	global running
	global i
	while running:
		i += 1
		time.sleep(0.1)
		if i/20*20 == i:
			dataQueue.put('timer1')
		if i/50*50 == i:
			dataQueue.put('timer2')
	
def timer1():
	print time.ctime(),'timer1 is ON'

def timer2():
	print time.ctime(),'timer2 is ON'


def login():
	safeprint.acquire()
	print 'login'
	safeprint.release()
	global running
	running = 1
#	thread.start_new_thread(set_timer,())
	thread.start_new_thread(random_timer,())


def logout():
	safeprint.acquire()
	print 'logout'
	safeprint.release()
	global running
	running = 0


def packet_process(recv_data):
	safeprint.acquire()
	show_hex(recv_data)
	safeprint.release()
	# FIXME: stupid way for testing
	if recv_data[0:2] == '\x01\x10':
		send_data = '\x02\x10\x51\x02\xd8\x16\x00\x00\x00\x00\x01\x00\xd0\x03\xe8\xf0\x00\x00\x00\x00\xac\x13\x42\x01\xf0\x00\x00\x84\x00\x00\xa2\xd8\x2c\x20\x00\x00\x00\x00\x1e\x00\x00\x00'
		s.sendto(send_data, recv_addr)
	elif recv_data[0:2] == '\x03\x01':
		send_data = '\04\x00\x00\x05\x17\xc3\x29\x00\x00\xd8\xc6\x40\x00\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x44\x72\x63\x6f\xac\x12\x01\x06\xd8\x01\xac\x13\x42\x01\x01\x7b\xb0\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		print len(send_data)
		s.sendto(send_data, recv_addr)
		login()

	elif recv_data[0:1] == '\xff':
		send_data = '\x07\x01\x10\x00\x06\x00\x00\x00\x4e\x4c\x21\x00\xac\x13\x42\x01\x00\x84\x00\x00\xa2\xd8\x2c\x20\x00\x00\x00\x00\x1e\x00\x00\x00'
		s.sendto(send_data, recv_addr)

	elif recv_data[0:1] == '\x07':
		if recv_data[5] == '\x01':
			send_data = '\x07\x1a\x28\x00\x0b\x02\x1e\x00\x7a\x03\x22\x00\x00\x00\x00\x00\x12\x56\xd3\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		elif recv_data[5] == '\x03':
			send_data = '\x07\x1a\x28\x00\x0b\x04\x1e\x00\x7a\xff\xff\x00\x00\x00\x00\x00\x12\x56\xd3\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		s.sendto(send_data, recv_addr)

	elif recv_data[0:2] == '\x01\x0e':
		send_data = '\x02\x0e\x6b\x03\xb2\x6d\x10\x00\x00\x00\x01\x00\xb9\x03\xe8\xf0\x00\x00\x00\x00\x0a\x20\x64\x8d\xf0\x00'
		s.sendto(send_data, recv_addr)

	elif recv_data[0:2] == '\x06\x01':
		send_data = '\x04\x00\x00\x05\x17\x95\x40\x00\x00\x0e\xe0\xfc\x00\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x44\x72\x63\x6f\xac\x12\x01\x06\xc3	\x00\xac\x13\x42\x2c\x01\xf4\xb0\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		s.sendto(send_data, recv_addr)
		logout()

	else:
		pass

def command():
	s = raw_input()
#	if s == 'login':
#		dataQueue.put(s)
#	elif s == 'logout':
#		dataQueue.put(s)
#	elif s == 'q':
	if s == 'q':
		sys.exit(1)

def show_hex(hex_oper):
	for i in range(0,len(hex_oper)):
		print hex(ord(hex_oper[i])),
	print '\n'

if __name__ == "__main__":
	thread.start_new_thread(listen,())
	thread.start_new_thread(recv_ack,())

	while 1:
		command()

