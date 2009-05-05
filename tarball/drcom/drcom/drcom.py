#!/usr/bin/env python
# -*- coding: utf-8 -*-

## import modules needed
import pygtk
pygtk.require('2.0')
import gtk, gnome.ui, pynotify
import os, sys, time
import threading
import socket, fcntl, struct
import md5, re, binascii
from operator import xor
import locale, gettext
import thread, Queue

safe_send = thread.allocate_lock()
dataQueue = Queue.Queue()
IP_ADDR = 'localhost'
#IP_ADDR = '202.1.1.1'
PORT = 8080
#PORT = 61440

## global variables
conf_name='drcom.conf'
conf_path='/home/'+os.environ['USER']+'/.drcom'
sound_path='/usr/share/drcom/drcom.wav'
icon_path='/usr/share/drcom/drcom.png'
license_path='/usr/share/drcom/COPYING'
lang_path = '/usr/share/drcom/po/'

## I18N
APP = "drcom"
local_path = os.path.realpath(os.path.dirname(lang_path))
langs = []
lc, encoding = locale.getdefaultlocale()
if (lc):
	langs = [lc]

language = os.environ.get('LANG', None)
if (language):
	langs += language.split(":")
result = gettext.bindtextdomain(APP, local_path)
gettext.textdomain(APP)
lang = gettext.translation(APP, local_path, languages=langs, fallback = True)
_ = lang.gettext


## class drcom_client
class drcom_client():

	## build-in test function
	def hex_xor(self,xor_oper1,xor_oper2,oper_len):
		xor_result=''
		for i in range(0,oper_len):
			temp=chr(xor(ord(xor_oper1[i]),ord(xor_oper2[i])))
			xor_result=xor_result+temp
		return xor_result

	def show_hex(self,hex_oper):
		for i in range(0,len(hex_oper)):
			print hex(ord(hex_oper[i])),
		print '\n'

	def show_dec(self,dec_oper):
		dec_result=''
		for i in range(0,len(dec_oper)):
			dec_hex=hex(ord(dec_oper[i]))[2:]
			dec_result=dec_result+'0'*(2-len(dec_hex))+dec_hex
		return str(int(dec_result,16))

	## Get ifname
	def get_ifname(self):

		ifname_space=os.popen("/sbin/ifconfig -s| awk '{print $1}'").read()
		ifname_start=ifname_space.find('\n')
		ifname_name=[]
		while(ifname_start!=-1):
			ifname_end=ifname_space.find('\n',ifname_start+1)
			if ifname_end==-1:
				break
			ifname=ifname_space[ifname_start+1:ifname_end]
			ifname_name.append(ifname)
			ifname_start=ifname_end
		ifname_status=os.popen("/sbin/ifconfig | awk '{print $1,$3}'").read()
		for i in range(0,len(ifname_name)-1):
#		for i in range(0, len(ifname_name)):
			ifname_start=ifname_status.find(ifname_name[i])
			ifname_end=ifname_status.find(ifname_name[i+1])
#			if i==len(ifname_name)-1:
#				ifname_end=len(ifname_status)
#			else:
#				ifname_end=ifname_status.find(ifname_name[i+1])
			ifname_region=ifname_status[ifname_start:ifname_end]
			ifname_index=ifname_region.find('RUNNING')
			if ifname_index!=-1 and 'lo' not in ifname_name[i]:
				return ifname_name[i]

		err_num = '01'
		self.exception(err_num)
#		self.tag=U'出错了 ！'	
#		self.balloons(U'没有连接!')
#		self.quit_common()
		self.quit_common()

	def get_ip_addr(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			ip_addr=fcntl.ioctl(s.fileno(),0x8915,\
					struct.pack('256s', self.ifname[:15]))[20:24]
		except:
#			self.tag=U'出错了 ！'			
#			self.balloons(U'获取ip失败!')
#			self.quit_common()
			err_num = '02'
			self.exception(err_num)
			self.quit_common()

		return ip_addr


	def get_mac_addr(self):
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
			mac_addr=fcntl.ioctl(s.fileno(), 0x8927,\
					struct.pack('256s', self.ifname[:15]))[18:24]
		except:
#			self.tag=U'出错了 '
#			self.balloons(U'获取MAC地址失败!')
#			self.quit_common()
			err_num = '03'
			self.exception(err_num)
			self.quit_common()
		
		return mac_addr

	def get_dns_addr(self):
		try :
			fp=open('/etc/resolv.conf','r')
			content=fp.read()
			fp.close()
			dns=re.findall(r'^nameserver (.*)',content,re.M)

			if len(dns)>1:
				dnsp,dnss=dns[:2]
				dnsp,dnss=socket.inet_aton(dnsp),socket.inet_aton(dnss)
			else:
				dnsp=socket.inet_aton(dns[0]) #not dns here
				dnss='\x00\x00\x00\x00'
		except:
#			self.tag=U'出错了 ！'
#			self.balloons(U'获取DNS地址失败!')
#			self.quit_common()
			err_num = '04'
			self.exception(err_num)
			self.quit_common()

		return dnsp,dnss

	def md5_key(self,md5_content):
		md5_temp=md5.new()
		md5_temp.update(md5_content)
		return md5_temp.digest()


	def read_conf(self):
		#self.init_conf()	
		pathname=conf_path
		if os.path.exists(pathname)==False:
			os.mkdir(pathname)
		file_path=os.path.join(pathname,conf_name)
		list_dir=os.listdir(pathname)
		if conf_name in list_dir:
			f=file(file_path,'r')
			account_pass=f.read()		
			f.close()
			account_end=account_pass.find(',')
			if account_end==-1:
				self.passwd_flag=False		
				self.account=''
				self.password=''
				return False
			self.account=account_pass[:account_end]
			if account_pass[len(account_pass)-1].isdigit()==True:
				password_xor=account_pass[account_end+1:len(account_pass)]
##				password_length=len( password_xor )
#				if password_length>6:
#					mac_hex=self.mac_addr+'\x00'*(password_length-6)
#				else:
#					mac_hex=self.mac_addr[0:password_length]
##				mac_hex='\x01'*password_length
##				self.password=self.hex_xor(mac_hex,password_xor,password_length)
				self.password=password_xor
			else:
				password_xor=account_pass[account_end+1:len(account_pass)]
				password_length=len( password_xor )
#				if password_length>6:
#					mac_hex=self.mac_addr+'\x00'*(password_length-6)
#				else:
#					mac_hex=self.mac_addr[0:password_length]
##				mac_hex='\x01'*password_length
##				self.password=self.hex_xor(mac_hex,password_xor,password_length)
				self.password=password_xor
			self.show_hex(self.password)
			self.passwd_flag=True
			return True

		self.passwd_flag=False		
		self.account=''
		self.password=''
		return False		

	def init_conf(self):
		self.BUFFER=1024
		self.server_brand='Drco'
		self.exception_id={
			'00':_("Unknown errors"),
			'01':_("No active network card"),
			'02':_("Can not get your ip address"),
			'03':_("Can not get your MAC address"),
			'04':_("Can not get your DNS address"),
			'05':_("Fail to bind your port"),
			'06':_("Can not get your server ip address"),
			'07':_("Can not set up a socket"),
			'10':_("You have already LOGIN"),
			'11':_("You should LOGIN first"),
			'20':_("Connection lost when login[request]"),
			'21':_("Connection lost when login[response]"),
			'22':_("Connection lost when keep_alive[request]"),
			'23':_("Connection lost when keep_alive[response]"),
			'24':_("Connection lost when logout[request]"),
			'25':_("Connection lost when logout[response]"),
			'26':_("Connection lost when changing password[request]"),
			'27':_("Connection lost when changing password[response]"),
			'30':_("Incorrect account name or password"),
			'31':_("Login successful!"),
			'32':_("Logout successful!"),
			'33':_("No money left in your account!"),
			'34':_("Account is working now!"),
			'35':_("Logout failed!"),
			'40':_("Password validation not the same"),
			'41':_("New password successfully"),
			'42':_("Incorrect old password"),
			'43':_("Please logout first"),
			# FIXME: not match with error codes
			'50':_("Cannot start No.38 timer"),
			'51':_("Cannot stop No.38 timer"),
			'52':_("Cannot start No.40 timer"),
			'53':_("Cannot stop No.40 timer"),
			'60':_("Unknown type of keep_alive packet"),
		}
		self.server_ip= IP_ADDR
		self.server_port=PORT
		self.ifname=self.get_ifname()
		self.md5_tail='\x14\x00\x07\x0b'
		self.host_ip=self.get_ip_addr()
		self.host_ip_dec=socket.inet_ntoa(self.host_ip)
		self.mac_addr=self.get_mac_addr()

		self.host_packet_id={
			'_login_request_'   :'\x01\x10',
			'_login_auth_'      :'\x03\x01',
			'_logout_request_'  :'\x01\x0e',
			'_logout_auth_'     :'\x06\x01',
			'_passwd_request_'  :'\x01\x0d',
			'_new_passwd_'      :'\x09\x01',
			'_alive_40_client_' :'\x07',
			'_alive_38_client_' :'\xff',
			'_alive_4_client_'  :'\xfe',
			}
		self.server_packet_id={
			'\x02\x10'    :'_login_response_',
			'\x02\x0e'    :'_logout_response_',
			'\x02\x0d'    :'_passwd_response_',
			'\x04\x00'    :'_success_',
			'\x05\x00'    :'_failure_',
			'\x07'        :'_alive_40_server_',
			'\x07\x01\x10':'_alive_38_server_',
			'\x4d\x26'    :'_alive_4_server_',
			'\x4d\x38'    :'_Serv_Info_',
			'\x4d\x3a'    :'_Notice_',
			}

		self.alive_account0=0x1a
		self.alive_account1=0x2e
		self.server_ack_40 = '\x12\x56\xd3\x03'

		self.local_addr = []
		self.local_mask = []

		self.timer_38 = 200
		self.timer_40 = 160

	def listen(self):
		# FIXME: cost much resource for Off-line State
		while self.run_listen:
			# FIXME: CPU Usage ~= 40%
			time.sleep(0.1)
			try:
				data = dataQueue.get(block=False)
			except Queue.Empty:
				pass
			else:
				# for test
				print data
				#
				if data == '_quit_':
					self.run_listen = 0
					self.run_serv_ack = 0
					self.run_38_timer = 0
					self.run_40_timer = 0

				## GUI COMMAND
				elif data == '_login_':
					self.login_request()
				elif data == '_logout_':
					self.logout_request()
				elif data == '_passwd_':
					self.passwd_request()

				## Server ACK
				elif data == '_serv_ack_':
					# FIXME: why put serv_ack in the Queue
					try:
						recv_data = dataQueue.get(block=False)
					except:
						pass
					else:
						self.packet_process(recv_data)

				## Timer Signal
				# FIXME: !!!if _timer_XX is behind _serv_ack_[logout] in dataQueue!!!
				elif self.status == 'ON':
					if data == '_timer_38_':
						## for test
						#print '_timer_38_'
						#
						self.alive_38_request()
					elif data == '_timer_40_':
						## for test
						#print '_timer_40_'
						#
						self.alive_40_request()
				else:
					pass

	def serv_ack(self):
		# FIXME: cost much resource for Off-line State
		while self.run_serv_ack:
			# FIXME: CPU Usage ~= 40%
			time.sleep(0.1)
			try:
				recv_data, recv_addr = self.drcom_sock.recvfrom(self.BUFFER)
			except:
				pass
			else:
				# FIXME: aweful way to be removed
				self.serv_addr=recv_addr
				self.recv_addr=recv_addr
				self.server_ip=self.serv_addr[0]
				dataQueue.put('_serv_ack_')
				dataQueue.put(recv_data)

#	def set_timer(self):
	def set_38_timer(self):
#		while self.run_thread_timer:
		while self.run_38_timer:
			# FIXME: 'self.i' may overflow ?
			try:
				self.i += 1
			except:
				self.i = 0
			time.sleep(0.1)
			# it could start timer in 0 second :)
			if self.i/self.timer_38*self.timer_38 == self.i:
				dataQueue.put('_timer_38_')
			# FIXME: no preparation for starting 2nd timer
#			if self.i/self.timer_40*self.timer_40 == self.i:
#				dataQueue.put('_timer_40_')

	def set_40_timer(self):
		while self.run_40_timer:
			try:
				self.j += 1
			except:
				self.j = 0
			time.sleep(0.1)
			if self.j/self.timer_40*self.timer_40 == self.j:
				dataQueue.put('_timer_40_')

	def packet_process(self, recv_data):
		# FIXME:!!No server_packet_id named '\x4d\x26\x6b' will occur errors!
		# FIXME: Linear judgement for server_packet_id
		if self.status == 'PW':
			if recv_data[0:2] in self.server_packet_id:
				if self.server_packet_id[recv_data[0:2]] == '_success_':
					self.passwd_success(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_failure_':
					self.passwd_failure(recv_data)

		elif self.status == 'OFF':
			## for test
#			self.show_hex(recv_data)
			##
			# FIXME:!!No server_packet_id named '\x4d\x26\x6b' will occur errors!!
			if recv_data [0:2] in self.server_packet_id:
				if self.server_packet_id[recv_data[0:2]] == '_login_response_':
					self.login_auth(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_passwd_response_':
					self.passwd_auth(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_success_':
					self.login_success(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_failure_':
					self.login_failure(recv_data)

		elif self.status == 'ON':

			## for test
			#print len(recv_data)
			#self.show_hex(recv_data)
			##

			# FIXME:!!No server_packet_id named '\x4d\x26\x6b' will occur errors!!
			if recv_data[0:3] in self.server_packet_id:
				if self.server_packet_id[recv_data[0:3]] == '_alive_38_server_':
					# FIXME: Only need to check alive_version once
					self.alive_version_check(recv_data)
			elif recv_data [0:2] in self.server_packet_id:
				if self.server_packet_id[recv_data[0:2]] == '_alive_4_server_'\
					and len(recv_data) == 4:
					self.alive_4_reply(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_logout_response_':
					self.logout_auth(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_success_':
					self.logout_success(recv_data)
				elif self.server_packet_id[recv_data[0:2]] == '_failure_':
					self.logout_failure(recv_data)
			elif recv_data [0:1] in self.server_packet_id:
				if self.server_packet_id[recv_data[0:1]] == '_alive_40_server_'\
					and len(recv_data) == 40:
					self.alive_40_reply(recv_data)
#				elif self.server_packet_id[recv_data[0:2]] == '_Server_Info':
#					pass
#				elif self.server_packet_id[recv_data[0:2]] == '_Notice_':
#					pass


	def login_request(self):

		try:
			if self.status == 'ON':
#				self.tag=U'出错了 ！'
#				self.balloons(U'已经登录!')
				err_num = '10'
				self.exception(err_num)
				return False
		except:
			self.status= 'OFF'

		self.init_conf()
		self.password_save()

		# socket initialization
		self.drcom_sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.drcom_sock.setblocking(0)

		## for test
		if IP_ADDR != 'localhost':
		##
			try:	
				self.drcom_sock.bind((self.host_ip_dec,self.server_port))
	
			except:
#				self.tag=U'出错了 !'
#				self.balloons(U'端口绑定失败!')
				err_num = '05'
				self.exception(err_num)
				# FIXME: it must be successful in closing socket.
				self.drcom_sock.close()
				return False
		
		proc_name='_login_request_'
		send_data=self.host_packet_id[proc_name]+'\x51\x02\x03'+'\x00'*15

		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.server_ip,self.server_port))
			#self.safe_send.release()
		except:
#			self.tag=U'出错了 !'
#			self.balloons(U'失去连接 [请求] !')
			err_num = '20'
			self.exception(err_num)
			# FIXME: it must be successful in closing socket.
			self.drcom_sock.close()
			return False

	def login_auth(self,recv_data):
		# start_login and build the login package
		## for test
		#print '--login_auth--'
		##
		self.service_identifier=recv_data[4:8]
		proc_name='_login_auth_'
		length=len(self.account)+20
		data_head=self.host_packet_id[proc_name]+'\x00'+ chr(length)
		md5_content=self.host_packet_id[proc_name]+\
			self.service_identifier+self.password
		self.login_a_md5=self.md5_key(md5_content)
		usr_name_zero='\x00'*(36-len(self.account))+'\x09\x01'
		mac_length=len(self.mac_addr)
		mac_xor=self.hex_xor(self.mac_addr,self.login_a_md5,mac_length)
		md5_content='\x01'+self.password+self.service_identifier+'\x00'*4
		login_b_md5=self.md5_key(md5_content)
		nic_ip_zero='\x00'*12
		num_nic=1
		data_front=data_head+self.login_a_md5+self.account+usr_name_zero+\
			mac_xor+login_b_md5+chr (num_nic)+\
			self.host_ip+nic_ip_zero
		md5_content=data_front+self.md5_tail
		login_c_md5=self.md5_key(md5_content)[0:8]

		host_name='\x00'*32
		host_dnsp=self.get_dns_addr()[0]
		host_dnss=self.get_dns_addr()[1]

		dhcp='\xff\xff\xff\xff'
		host_unknown0='\x94'+'\x00'*3
		os_major='\x05'+'\x00'*3
		os_minor='\x01'+'\x00'*3
		os_build='\x28\x0A'+'\x00'*2
		host_unknown1='\x02'+'\x00'*3
		kernel_version='\x00'*32  #in windows as servicepack[32]
		host_info=host_name+host_dnsp+dhcp+host_dnss+'\x00'*8+host_unknown0+\
			os_major+os_minor+os_build+host_unknown1+kernel_version
		zero3='\x00'*96
		unknown='\x03\x00\x02\x0C'+'\x00\xF3\x31\x9F\x01\x00'
		auto_logout=0
		multicast_mode=0
		## for test: ip_dog = 0
		self.ip_dog = 1
		##
		send_data=data_front+login_c_md5+chr(self.ip_dog)+'\x00'*4+host_info+zero3+\
			unknown+self.mac_addr+chr(auto_logout)+chr(multicast_mode)

		## for test
		#print len(send_data)
		##
		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.recv_addr))
			#self.safe_send.acquire()
		except:
#			self.tag=U'出错了 !'
#			self.balloons(U'失去连接 [应答] !')
			err_num = '21'
			self.exception(err_num)
			return False

	def login_failure(self, recv_data):

		if len(recv_data)==5:
			if (recv_data[4]=='\x03'):
#				self.balloons(U'帐号或密码错误!')
				err_num = '30'
				self.exception(err_num)
			elif (recv_data[4]=='\x05'):
#				self.balloons(U'帐号需充值!')
				err_num = '33'
				self.exception(err_num)

			elif (recv_data[4]=='\x15'):
#				self.balloons('code 21 error')
				err_num = '00'
				self.exception(err_num)

		elif len(recv_data)==15:
#			self.balloons(U'他人正在使用此帐号!')
			err_num = '34'
			self.exception(err_num)

		elif len(recv_data)==22:
#			self.balloons(U' 客户端版本出错!')
			err_num = '00'
			self.exception(err_num)

		self.status = 'OFF'

	def login_success(self, recv_data):
			
		self.status = 'ON'
#		self.run_thread_timer = 1
		self.run_38_timer = 1
		thread.start_new_thread(self.set_38_timer,())

		time_usage = recv_data[8]+recv_data[7]+recv_data[6]+recv_data[5]
		vol_usage = recv_data[12]+recv_data[11]+recv_data[10]+recv_data[9]
		cash_usage = recv_data[16]+recv_data[15]+recv_data[14]+recv_data[13]
		## for test
		#self.show_hex(time_usage)
		#self.show_hex(vol_usage)
		#self.show_hex(cash_usage)
		##
		self.auth_info=recv_data[23:39]
		self.show_usage(time_usage,vol_usage,cash_usage)

		## local address
		if self.ip_dog == 1:
			if recv_data[16+16+11] == '\x01':
				## handy configuration
				self.handy_config()
				self.auth_module_start()
					
			elif recv_data[16+16+11] == '\x00':
				## automatical configuration
				self.auto_config(recv_data[16+16+11:])
				self.auth_module_start()

			else:
				err_num = '00'
				self.exception(err_num)
					
		err_num = '31'
		self.exception(err_num)

		# Warning: threads_enter/leave() must adds here while X.org upgrades to 7.5.0
		# Otherwise, the whole Window will be frozen.
		gtk.gdk.threads_enter()
		self.tray.set_tooltip(_("Current State: Online"))
		gtk.gdk.threads_leave()


## local addr config

	def auto_config(self,recv_data):

		## clean local_addr array
		self.local_addr = []

		lenth = len(recv_data)/12 * 12
		for i in range(0,lenth,12):
			if recv_data[i] == '\x00':
				addr = recv_data[i+4:i+8]
				mask = recv_data[i+8:i+12]
				self.local_addr.append(addr)
				self.local_addr.append(mask)
			elif recv_data[i] == '\x01':
				break
		## add serv_ip & mask
		## for test
		# serv_ip -- binary, while server_ip -- decimal
		self.serv_ip = socket.inet_aton(self.serv_addr[0])
		#self.show_hex(self.serv_ip)
		#self.show_hex(self.get_dns_addr()[0])
		#self.show_hex(self.host_ip)
		##
		self.local_addr.append(self.serv_ip[0]+'\x00'*3)
		self.local_addr.append('\xff'+'\x00'*3)

	def handy_config(self):
		## for test
		print '--handy_config--'
		##

		## clean local_addr array
		self.local_addr = []

		host_ip = self.host_ip[0] + '\x00'*3 
		mask = '\xff' + '\x00'*3
		self.local_addr.append(host_ip)
		self.local_addr.append(mask)

		dns1_ip=self.get_dns_addr()[0][0]+'\x00'*3
		dns2_ip=self.get_dns_addr()[1][0]+'\x00'*3
		if dns2_ip == '\x00'*4:
			self.local_addr.append(dns1_ip)
			self.local_addr.append(mask)
		else:
			self.local_addr.append(dns1_ip)
			self.local_addr.append(mask)
			self.local_addr.append(dns2_ip)
			self.local_addr.append(mask)

		## add serv_ip & mask
		## for test
		# serv_ip -- binary, while server_ip -- decimal
		self.serv_ip = socket.inet_aton(self.serv_addr[0])
		#self.show_hex(self.serv_ip)
		#self.show_hex(self.get_dns_addr()[0])
		#self.show_hex(self.host_ip)
		##
		self.local_addr.append(self.serv_ip[0]+'\x00'*3)
		self.local_addr.append('\xff'+'\x00'*3)

## auth_module start/stop

	def auth_module_start(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		num = len(self.local_addr) / 2
		data = self.local_addr
		fmt = '16s'+'i'+'4s'* num*2
		param = struct.pack(fmt, self.ifname[:15], num, *data)
		## FIXME: load drcom module first!
		s.setsockopt(socket.IPPROTO_IP, 64+2048+64+1, param)
		pid = os.getpid()
		auto_logout = 0
		auth_cmd = struct.pack('iii16s', 1, pid, auto_logout, self.auth_info)
		s.setsockopt(socket.IPPROTO_IP, 64+2048+64, auth_cmd)


	def auth_module_stop(self):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		auth_cmd = struct.pack('iii16s', 0, 0, 0, self.auth_info)
		s.setsockopt(socket.IPPROTO_IP, 64+2048+64, auth_cmd)


	def logout_request(self):
		try:
			if self.status == 'OFF':
#				self.tag=U'出错了 ！'
#				self.balloons(U'没有登录!')
				err_num = '11'
				self.exception(err_num)
				return False
		except:
			err_num = '11'
			self.exception(err_num)
			return False

		proc_name='_logout_request_'
		send_data=self.host_packet_id[proc_name]+'\x80\x02\x03'+'\x00'*15
		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.serv_addr))
			#self.safe_send.release()
		except:
#			self.tag=U'注销失败 !'
#			self.balloons(U'失去连接 [请求] !')
			err_num = '24'
			self.exception(err_num)


	def logout_auth(self, recv_data):
		self.service_identifier=recv_data[4:8]
		proc_name='_logout_auth_'
		md5_content=self.host_packet_id[proc_name]+self.service_identifier+self.password
		logout_md5=self.md5_key(md5_content)
		mac_xor=self.hex_xor(self.mac_addr,logout_md5,len(self.mac_addr))
		usr_name_zero='\x00'*(36-len(self.account))+'\x09\x01'
		length=len(self.account)+20
		send_data=self.host_packet_id[proc_name]+'\x00'+chr(length)+logout_md5+self.account+\
			usr_name_zero+mac_xor+self.auth_info

		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.serv_addr))
			#self.safe_send.release()
		except:
#			self.tag=U'注销失败 !'
#			self.balloons(U'失去连接 [请求] !')
			err_num = '25'
			self.exception(err_num)
			return False

	def logout_failure(self, recv_data):
		err_num = '35'
		self.exception(err_num)
		self.status = 'ON'

	def logout_success(self, recv_data):

		self.status = 'OFF'
#		self.run_thread_timer = 0
		self.run_38_timer = 0
		self.run_40_timer = 0

		if self.ip_dog == 1:
			try:
				self.auth_module_stop()
			except:
				# FIXME: what'up while failed to stop the module
				pass

		# Warning: threads_enter/leave() must adds here while X.org upgrades to 7.5.0
		# Otherwise, the whole Window will be frozen.
		gtk.gdk.threads_enter()
		self.tray.set_tooltip(_("Current State: Offline"))
		gtk.gdk.threads_leave()

		time_usage=recv_data[8]+recv_data[7]+recv_data[6]+recv_data[5]
		vol_usage=recv_data[12]+recv_data[11]+recv_data[10]+recv_data[9]
		cash_usage = recv_data[16]+recv_data[15]+recv_data[14]+recv_data[13]
		self.show_usage(time_usage,vol_usage,cash_usage)

		err_num = '32'
		self.exception(err_num)


		try:
			self.drcom_sock.close()
		except:
#			self.tag=U'出错了 '
#			self.balloons(U'关闭包失败!')
			err_num = '07'
			self.exception(err_num)
			self.quit_common()
			return False


	def passwd_request(self):
		self.get_newpasswd_account()

		## for test
#		print '--passwd--'
#		print 'status =',self.status
		##
		try:
			if self.status == 'ON':
#				self.tag=U'出错了 ！'
#				self.balloons(U'请先注销登录 !')
				err_num = '43'
				self.exception(err_num)
				return False
		except:
			self.status = 'OFF'

		if self.new_password!=self.new_password_a:
#			self.tag=U'出错了 ！'
#			self.balloons(U' 密码输入不一致 !')
			err_num = '40'
			self.exception(err_num)
			return False

		## for test
#		print '-- socket initial 4 passwd --'
		##

		# socket initialization
		# FIXME: If drcom_sock has defined, is it better to close first?
		#self.drcom_sock.close()
		self.drcom_sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.drcom_sock.setblocking(0)

		## for test
		if IP_ADDR != 'localhost':
		##
			try:	
				self.drcom_sock.bind((self.host_ip_dec,self.server_port))
			except:
#				self.tag=U'出错了 !'
#				self.balloons(U'端口绑定失败!')
				err_num = '05'
				self.exception(err_num)
				# FIXME: it must be successful in closing socket.
				self.drcom_sock.close()
				return False

		proc_name='_passwd_request_'
		send_data=self.host_packet_id[proc_name]+'\x51\x02\x03'+'\x00'*15

		## for test
#		print '--prepare for sending data--'
		##

		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.server_ip,self.server_port))
			#self.safe_send.release()
	
		except:
			err_num = '26'
			self.exception(err_num)
#			self.tag=U'出错了 ！'
#			self.balloons(U'失去连接（请求） !')
			# FIXME: it must be successful in closing socket.
			self.drcom_sock.close()

		## it is totally incorrect!!
#		else:
#			self.status = 'PW'


	def passwd_auth(self, recv_data):

		## for test
		#print '--passwd_auth--'
		##

		proc_name='_new_passwd_'
		## Be care: no missing service_identifier
		self.service_identifier=recv_data[4:8]
		##
		length=len(self.old_account)+20
		passwd_data_head=self.host_packet_id[proc_name]+'\x00'+chr(length)

		## for test
		#print '--md5--'
		##

		md5_content=self.host_packet_id[proc_name]+\
			self.service_identifier+self.old_password
		passwd_a_md5=self.md5_key(md5_content)
		passwd_usr_name_zero='\x00'*(16-len(self.old_account))
		passwd_data_front=passwd_data_head+passwd_a_md5+\
			self.old_account+passwd_usr_name_zero
		md5_content=passwd_a_md5+self.old_password
		passwd_b_md5=self.md5_key(md5_content)
		
		## for test
		#print '--new_passwd--'
		##

		new_passwd=self.new_password+'\x00'*(16-len(self.new_password))
		new_passwd_xor=self.hex_xor(passwd_b_md5, new_passwd, 16)

		passwd_unknown='\x12'+'\x00'*3+'\x16'+'\x00'*3+'\x04'+'\x00'*7
		send_data=passwd_data_front+new_passwd_xor+passwd_unknown
		
		## for test
		#print '--prepare for sending data--'
		##

		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.recv_addr))
			#self.safe_send.release()
		except:
#			self.tag=U'出错了 ！'
#			self.balloons(U'失去连接（应答） !')
			err_num = '27'
			self.exception(err_num)
			return False
		else:
			self.status = 'PW'

	def passwd_failure(self, recv_data):
		if (recv_data[4]=='\x03'):
#			self.balloons(U'帐号或密码错误!')
			err_num = '42'
			self.exception(err_num)
		elif (recv_data[4]=='\x15'):
#			self.balloons('code 21 error')
			err_num = '00'
			self.exception(err_num)
		else:
			err_num = '00'
			self.exception(err_num)

		self.status = 'OFF'

	def passwd_success(self, recv_data):
		self.status = 'OFF'
		self.password=self.new_password
		self.passwordbox.set_text(self.password)
		self.password_save()

#		self.tag=U' 成功 !'
#		self.balloons(U'修改密码成功 !')
		err_num = '41'
		self.exception(err_num)
		
	def alive_version_check(self, recv_data):
		# check version	
		if len(recv_data) == 16:
			self.version = 3.4
		else:
			self.version = 3.7

		## for test
		#print self.version
		##

		# start _timer_40_
		# FIXME: logout -> alive_version_check? No way for "OFF" status :)
		try:
			self.run_40_timer
		except:
			self.run_40_timer = 1
			thread.start_new_thread(self.set_40_timer, ())

		else:
			if self.run_40_timer == 0:
				self.run_40_timer = 1
				thread.start_new_thread(self.set_40_timer,())

	def alive_38_request(self):
		proc_name='_alive_38_client_'
		unknown0 = '\x00\x00'
		send_data=self.host_packet_id[proc_name]+self.login_a_md5+'\x00'*3+self.auth_info+unknown0
		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.serv_addr))
			#self.safe_send.release()
		except:
#			self.tag=U'出错了 !!'
#			self.balloons(U'失去连接 [alive 请求] !')
			err_num = '22'
			self.exception(err_num)
			self.quit_common()

	def alive_40_request(self):
		if self.version == 3.4:
			self.alive_40_request_old()
		elif self.version == 3.7:
			self.alive_40_request_new()

	def alive_40_request_old(self):
		## for test
		#print 'alive_40_request_old'
		##
		proc_name='_alive_40_client_'
		unknown0='\x3e\x00'
		self.alive_account0 += 0x01
		if self.alive_account0 >= 0xff:
			self.alive_account0 -= 0xff
		self.alive_account1 += 0x05
		if self.alive_account1 >= 0xff:
			self.alive_account1 -= 0xff

		account= 1
		send_data=self.host_packet_id[proc_name]+chr(self.alive_account0) +\
			'\x28\x00\x0b' + chr(account) +'\x1c\x00' +unknown0\
			+chr(self.alive_account1) + '\x00'*29
	
		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.serv_addr))
			#self.safe_send.release()
		except:
#			self.tag=U'出错了 !!'
#			self.balloons(U'失去连接 [alive 请求] !')
			err_num = '22'
			self.exception(err_num)
			self.quit_common()

	def alive_40_request_new(self):
		## for test
		#print 'alive_40_request_new'
		##
		proc_name='_alive_40_client_'
		server_ack=self.server_ack_40
		unknown0='\x7a\x03'
		account = 1
		self.alive_account1 += 0x10
		if self.alive_account1 >= 0x3c:
			self.alive_account1 -= 0x3c

		send_data = self.host_packet_id[proc_name]+chr(self.alive_account0) +\
			'\x28\x00\x0b' + chr(account) +'\x1e\x00' +unknown0\
			+chr(self.alive_account1) + '\x00'*5 + server_ack +'\x00'*20
	
		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.serv_addr))
			#self.safe_send.release()
		except:
			err_num = '22'
			self.exception(err_num)
#			self.tag=U'出错了 !!'
#			self.balloons(U'失去连接 [alive 请求] !')
			self.quit_common()

	def alive_40_reply(self, recv_data):
		# FIXME: no execute this function :(

		## for test
		#print 'alive_40_reply'
		##

		pkt_no=recv_data[5:6]
		if pkt_no=='\x02':
			self.server_ack_40=recv_data[16:20]
		elif pkt_no=='\x04':
			return True

		proc_name='_alive_40_client_'
		server_ack=self.server_ack_40
		self.alive_account0 += 1
		if self.alive_account0 >= 0xff:
			self.alive_account0 -= 0xff
		self.alive_account1 += 1
		if self.alive_account1 >= 0x3c:
			self.alive_account1 -= 0x3c

		unknown0='\x7a\x03'
		account= 3
		send_data=self.host_packet_id[proc_name]+chr(self.alive_account0) +\
			'\x28\x00\x0b' + chr(account) +'\x1e\x00' +unknown0\
			+ chr(self.alive_account1) + '\x00'*5 + server_ack +'\x03'+'\x00'*20

		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,(self.serv_addr))
			#self.safe_send.release()
		except:
#			self.tag=U'出错了 !!'
#			self.balloons(U'失去连接 [alive 请求] !')
			err_num = '22'
			self.exception(err_num)
			self.quit_common()

	def alive_4_reply(self, recv_data):

		self.server_ack_4=recv_data[2:4]
		server_ack=self.server_ack_4
		proc_name='_alive_4_client_'
		msg_md5_content=self.login_a_md5+self.password
		a=self.md5_key(msg_md5_content)
		msg_ad=0
 		for i in range(0,16,2):
			msg_ad+=struct.unpack('H',a[i:i+2])[0]
		msg_add=str(msg_ad)
		msg_ad_=chr(int(msg_add[0:1]))+chr(int(msg_add[1:2]))
		xor=self.hex_xor(msg_ad_,server_ack,2)
		msg_=xor[0:1]
		msg__=xor[1:2]
		msg=msg_+msg__

		msg_content='\x01'+ (msg) +self.md5_tail+server_ack
		keep_alive_md5=self.md5_key(msg_content)
		send_data=self.host_packet_id[proc_name]+(msg)+'\x01'+keep_alive_md5+'\x00'+self.auth_info
		try:
			#self.safe_send.acquire()
			self.drcom_sock.sendto(send_data,self.serv_addr)
			#self.safe_send.release()
		except:
#			self.tag=U'出错了 !!'
#			self.balloons(U'失去连接［alive 应答］ !')
			err_num = '23'
			self.exception(err_num)
			self.quit_common()
##
	def on_delete_event(self, widget, event=None, user_data=None):
	        widget.hide()
	        return True

	def on_window_key_release_event(self, widget, event):
	        if event.keyval == gtk.keysyms.Escape:
	            widget.hide()

	def on_tray_button_press_event(self, *args):
        	if self.window.get_property('visible'):
        	    self.window.hide()
        	else:
        	    self.window.present()

	def on_tray_button1_press_event(self, *args):
        	if self.window1.get_property('visible'):
        	    self.window1.hide()
        	else:
        	    self.window1.present()

	def password_save(self):
#		self.init_conf()	
		self.get_account()
		if self.checkbutton.get_active()==True:
			if len(self.account)==0 and len(self.password)==0:
				f=file(os.path.join(conf_path,conf_name),'w')
				f.write('')
				f.close()
			else:
				f=file(os.path.join(conf_path,conf_name),'w')
##				password_length=len( self.password )
#				if password_length > 6:
#					mac_hex=self.mac_addr+'\x00'*(password_length-6)
#				else: 
	#				mac_hex=self.mac_addr[0:password_length]
##				mac_hex='\x01'*password_length
##				password_xor=self.hex_xor(mac_hex,self.password,password_length)
				password_xor = self.password
				f.write(self.account+','+password_xor)
				f.close()
		else:
			f=file(os.path.join(conf_path,conf_name),'w')
			f.write('')
			f.close()
	
	def get_account(self):
		self.account=self.accountbox.get_text()
		self.password=self.passwordbox.get_text()

	def get_newpasswd_account(self):
		self.old_account=self.accountboxa.get_text()
		self.old_password=self.passwordboxa.get_text()
		self.new_password=self.new_passwordbox.get_text()
		self.new_password_a=self.new_password_a_box.get_text()

	def get_x(self):
		
		x = self.tray.get_geometry()[1][0]
		if self.tray.get_visible()==True:
			x += int(self.tray.get_size()/2) 
		else:
			x -= int(self.tray.get_size()/2)
		return x

	def get_y(self):
		
		y = self.tray.get_geometry()[1][1]
		if self.tray.get_visible()==True:
			y += int(self.tray.get_size()/2) 
		else:
			y -= int(self.tray.get_size()/2) 
		return y

	def show_usage(self, time_usage, vol_usage, cash_usage):

		self.info=_('Used ') + self.show_dec(time_usage) + _(' Min, ') +\
					self.show_dec(vol_usage) + _(' KB')
		
		if cash_usage == '\xff\xff\xff\xff':
			## for test
			#print '?'*10
			##
			return True
		self.info += '\n'
		if len(str(self.show_dec(cash_usage)))==4:
			self.info += _('Balance') + self.show_dec(cash_usage)[0:2] + '.' +\
						self.show_dec(cash_usage)[2:4] + _(' yuan.')
		if len(str(self.show_dec(cash_usage)))==3:
			self.info += _('Balance') + self.show_dec(cash_usage)[0:1] + '.' +\
						self.show_dec(cash_usage)[1:3] + _(' yuan.')
		if len(str(self.show_dec(cash_usage)))==2:
			self.info += _('Balance')+'0'+'.'+self.show_dec(cash_usage)[0:2] +\
						_(' yuan.')
		if len(str(self.show_dec(cash_usage)))==1:
			self.info += _('Balance')+'0'+'.'+'0'+self.show_dec(cash_usage)+\
						_(' yuan.')

 	def balloons(self, tag, info):

		_notifyRealm = tag
		_Urgencies = {
       			'low': pynotify.URGENCY_LOW,
       			'critical': pynotify.URGENCY_CRITICAL,
       			'normal': pynotify.URGENCY_NORMAL
				}
		icon=None
		x = self.get_x()
		y = self.get_y()
		body=info
		urgency="low"
		summary=_notifyRealm
		pynotify.init(_notifyRealm)
		notifyInitialized = True
		toast = pynotify.Notification(summary, body)
		timeout = 5000
		toast.set_timeout(timeout)
		toast.set_urgency(_Urgencies[urgency])
		toast.set_hint("x", x)
		toast.set_hint("y", y)
		gnome.sound_init('localhost')
		gnome.sound_play(os.path.join(sound_path))
		toast.show()
		return False

	def gui_login(self, widget):
		dataQueue.put('_login_')
	def gui_logout(self, widget):
		dataQueue.put('_logout_')
	def gui_passwd(self, widget):
		dataQueue.put('_passwd_')


# ----------
#  GUI Part
# ----------
	def __init__(self):
		
		gtk.gdk.threads_init()
		self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window.set_size_request(300, 150)
		self.window.set_title(_("Dr.COM Client"))
		self.window.connect("key_release_event",self.on_window_key_release_event)
		self.window.connect("delete_event", self.on_delete_event)
		self.tray = gtk.status_icon_new_from_file(icon_path)
		self.tray.set_tooltip(_('Current State: Offline'))
		self.tray.connect("activate",self.on_tray_button_press_event)
		self.tray.set_visible(True)
		
#		gtk.gdk.threads_enter()

		self.read_conf()
		self.run_listen = 1
		thread.start_new_thread(self.listen,())
		self.run_serv_ack = 1
		thread.start_new_thread(self.serv_ack,())

		vbox = gtk.VBox(False, 0)
		self.window.add(vbox)
		vbox.show()
	        
		hbox = gtk.HBox(False,0)
		vbox.add(hbox)
		hbox.show()
	
		hbox1 = gtk.HBox(False,0)
		vbox.add(hbox1)
		hbox1.show()

		label = gtk.Label(_("Account "))
		hbox.pack_start(label, True, True, 0)
		label.show()
	
		self.accountbox = gtk.Entry()
		self.accountbox.set_max_length(50)
		self.accountbox.set_visibility(True)
		if self.passwd_flag==True:
			self.accountbox.set_text(self.account)
		hbox.pack_start(self.accountbox, True, True, 0)
		self.accountbox.show()
	
	
		label = gtk.Label("    ")
		hbox.pack_start(label, True, True, 0)
		label.show()
	
		label = gtk.Label(_("Password"))
		hbox1.pack_start(label, True, True, 0)
		label.show()
	
		self.passwordbox = gtk.Entry()
		self.passwordbox.set_max_length(50)
		if self.passwd_flag==True:
			self.passwordbox.set_text(self.password)
		self.passwordbox.set_visibility(False)
		hbox1.pack_start(self.passwordbox, True, True, 0)
		self.passwordbox.show()
	
		label = gtk.Label("    ")
		hbox1.pack_start(label, True, True, 0)
		label.show()
	
		self.checkbutton = gtk.CheckButton(_("Save your Password"))
		if self.passwd_flag==True:
			self.checkbutton.set_active(True)
		else:
			self.checkbutton.set_active(False)
		vbox.pack_start(self.checkbutton, True, True, 0)
		self.checkbutton.show()
	
		hbox2 = gtk.HBox(False,0)
		vbox.add(hbox2)
		hbox2.show()
		

		button = gtk.Button(_('Login'))
		button.connect("clicked", self.on_tray_button_press_event)
#		button.connect("clicked", self.drcom_login)
		button.connect("clicked", self.gui_login)
		hbox2.pack_start(button, True, True, 0)
		button.show()
	
		button = gtk.Button(_('Logout'))
		button.connect("clicked", self.on_tray_button_press_event)
#		button.connect("clicked", self.drcom_logout)
		button.connect("clicked", self.gui_logout)
		hbox2.pack_start(button, True, True, 0)
		button.show()

		button = gtk.Button(_('Quit'))
		button.connect("clicked", self.quit)
		hbox2.pack_start(button, True, True, 0)
		button.show()
		
		item_login = gtk.ImageMenuItem(gtk.STOCK_CONNECT)
		item_logout = gtk.ImageMenuItem(gtk.STOCK_DISCONNECT)
		item_passwd = gtk.ImageMenuItem(_('_Pass_Word'))
		item_about = gtk.ImageMenuItem(gtk.STOCK_ABOUT)
		item_quit = gtk.ImageMenuItem(gtk.STOCK_QUIT)

		item_login.connect('activate', self.gui_login)
		item_logout.connect('activate', self.gui_logout)
		item_passwd.connect('activate', self.passwd)
		item_about.connect('activate', self.show_about)
		item_quit.connect('activate', self.quit)
		

		img = gtk.Image()
		img.set_from_stock(gtk.STOCK_EDIT, 1)
		item_passwd.set_image(img)
		
		menu = gtk.Menu()
		menu.append(item_login)
		menu.append(item_logout)
		menu.append(gtk.SeparatorMenuItem())
		menu.append(item_passwd)
		menu.append(item_about)
		menu.append(gtk.SeparatorMenuItem())
		menu.append(item_quit)
		self.tray.connect('popup-menu', self.pop_menu, menu)
		icon = gtk.gdk.pixbuf_new_from_file(icon_path)
		self.window.set_icon(icon)
		self.window.show()

#		gtk.gdk.threads_leave()

		gtk.main()

	def passwd(self, widget):

		self.window1 = gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window1.set_size_request(300, 150)
		self.window1.set_title(_("New Password"))
		self.window1.connect("key_release_event",self.on_window_key_release_event)
		self.window1.connect("delete_event", self.on_delete_event)
		self.tray.set_visible(True)

		vbox = gtk.VBox(False, 0)
		self.window1.add(vbox)
		vbox.show()

		hbox = gtk.HBox(False,0)
		vbox.add(hbox)
		hbox.show()

		hbox1 = gtk.HBox(False,0)
		vbox.add(hbox1)
		hbox1.show()

		hbox4 = gtk.HBox(False,0)
		vbox.add(hbox4)
		hbox4.show()

		hbox3 = gtk.HBox(False,0)
		vbox.add(hbox3)
		hbox3.show()

		label = gtk.Label(_("     Account       "))
		hbox.pack_start(label, True, True, 0)
		label.show()

		self.accountboxa = gtk.Entry()
		self.accountboxa.set_max_length(50)
		self.accountboxa.set_visibility(True)
#		hbox.pack_start(self.accountboxa, True, True, 0)
#		self.accountboxa.show()
		if self.passwd_flag==True:
			self.accountboxa.set_text(self.account)
		hbox.pack_start(self.accountboxa, True, True, 0)
		self.accountboxa.show()

		label = gtk.Label("    ")
		hbox.pack_start(label, True, True, 0)
		label.show()
		label = gtk.Label(_("  Old Password    "))
		hbox1.pack_start(label, True, True, 0)
		label.show()
			
		self.passwordboxa = gtk.Entry()
		self.passwordboxa.set_max_length(50)
		self.passwordboxa.set_visibility(False)
		hbox1.pack_start(self.passwordboxa, True, True, 0)
		self.passwordboxa.show()
			
		label = gtk.Label("    ")
		hbox1.pack_start(label, True, True, 0)
		label.show()
		
		label = gtk.Label(_("Confirm Password"))
		hbox3.pack_start(label, True, True, 0)
		label.show()
			
		self.new_password_a_box = gtk.Entry()
		self.new_password_a_box.set_max_length(50)
		self.new_password_a_box.set_visibility(False)
		hbox3.pack_start(self.new_password_a_box, True, True, 0)
		self.new_password_a_box.show()
	
		label = gtk.Label("    ")
		hbox3.pack_start(label, True, True, 0)
		label.show()		

		label = gtk.Label(_(" New Password    "))
		hbox4.pack_start(label, True, True, 0)
		label.show()
	
		self.new_passwordbox = gtk.Entry()
		self.new_passwordbox.set_max_length(50)
		self.new_passwordbox.set_visibility(False)
		hbox4.pack_start(self.new_passwordbox, True, True, 0)
		self.new_passwordbox.show()
	
		label = gtk.Label("    ")
		hbox4.pack_start(label, True, True, 0)
		label.show()

		hbox5 = gtk.HBox(False,0)
		vbox.add(hbox5)
		hbox5.show()
				
		button = gtk.Button(_('OK'))
		button.connect("clicked", self.on_tray_button1_press_event)
		
#		button.connect("clicked", self.on_tray_button_press_event)
		button.connect("clicked", self.gui_passwd)
		self.window.hide()
		hbox5.pack_start(button, True, True, 0)
		button.show()
		
		button = gtk.Button(_('Cancel'))
		button.connect("clicked", self.on_tray_button1_press_event)
#		button.connect("clicked", self.on_tray_button_press_event)
		hbox5.pack_start(button, True, True, 0)
		button.show()
		              
		icon = gtk.gdk.pixbuf_new_from_file(icon_path)
		self.window1.set_icon(icon)
		
		self.window1.show()
		gtk.main()

	def pop_dialog(self, title, data):
		dialog = gtk.Dialog(title, None, 0, (gtk.STOCK_OK, gtk.RESPONSE_OK))
		dialog.set_border_width(25)
		dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
		label = gtk.Label(data)
		dialog.vbox.pack_start(label, True, True, 0)
		label.show()
		if dialog.run() == gtk.RESPONSE_OK:
			dialog.destroy()
		return True

	def show_about(self, widget):

		version = '1.0'
		license_file = open(license_path, "r")
		license = license_file.read()
		license_file.close()
		license = str(license)
		authors = ["Wheelz <kernel.zeng@gmail.com>",\
				"Henry Huang <henry.s.huang@gmail.com>",\
				"longshow <longshow@yeah.net>",]

		logo = gtk.gdk.pixbuf_new_from_file(icon_path)
		comments=_("Dr.COM Client")
		translator_credits = "translator-credits"

		about=gtk.AboutDialog()
		gtk.about_dialog_set_email_hook(self.__url_hook, "mailto:")
		gtk.about_dialog_set_url_hook(self.__url_hook, "")
		
		about.set_name(_("Dr.COM Client"))
		about.set_version(version)
		about.set_copyright(_("Copyright © 2009 drcom-client group"))
		about.set_license(license)
		about.set_website("http://drcom-client.sourceforge.net")
		about.set_authors(authors)
		about.set_translator_credits(translator_credits)
		about.set_logo(logo)
        
		icon = gtk.gdk.pixbuf_new_from_file(icon_path)
		about.set_icon(icon)
               
		about.connect("response", lambda d, r: about.destroy())
        
		about.show_all()
		return True

	def __url_hook(self, widget, url, scheme):
		gnome.ui.url_show_on_screen(scheme + url, widget.get_screen())	
  	
	def pop_menu(self, widget, button, time, data=None):
		if data:
			data.show_all()
      		data.popup(None, None, None, 3, time)
		return True

	def quit_common(self):
		self.status = 'OFF'
		self.keep_live_count=0

		# Warning: threads_enter/leave() must adds here while X.org upgrades to 7.5.0
		# Otherwise, the whole Window will be frozen.
		gtk.gdk.threads_enter()
		self.tray.set_tooltip(_('Current State: Offline'))
		gtk.gdk.threads_leave()
		gtk.main()
		
	def quit(self,widget):
		## FIXME: program exits while threads processing
		dataQueue.put('_quit_')
		time.sleep(0.1)
		##
		gtk.main_quit()
		sys.exit(0)

	def exception(self,err_num):

		# Warning: threads_enter/leave() must adds here while X.org upgrades to 7.5.0
		# Otherwise, the whole Window will be frozen.
		gtk.gdk.threads_enter()
		if err_num == '31' or err_num == '32':
			self.balloons(self.exception_id[err_num], self.info)
		elif err_num == '41':
			self.balloons(_('Success'), self.exception_id[err_num])
		else:
			self.balloons(_('Error ')+err_num, self.exception_id[err_num])
		gtk.gdk.threads_leave()

def main():
	f = open("/tmp/gdrcom-log", "w")
	while 1:
		f.write('%s\n' % time.ctime(time.time()))
		f.flush()
		time.sleep(10)

if __name__ == "__main__":
		
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		print >>sys.stderr, "fork #1 failed: %d (%s)" % (e.errno, e.strerror)
		sys.exit(1)

	os.chdir("/")
	os.setsid()
	os.umask(0)

	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError, e:
		print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)
		sys.exit(1)

	drcom_client()
	main()
