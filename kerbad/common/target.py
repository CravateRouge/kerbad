
from asysocks.unicomm.common.target import UniTarget, UniProto
from dns import resolver
import copy, socket

class KerberosTarget(UniTarget):
	def __init__(self, host:str = None, proxies = None, protocol = UniProto.CLIENT_TCP, timeout = 10, port = 88, dns = None):
		UniTarget.__init__(self, host, port , protocol, timeout=timeout, proxies = proxies, dns = dns)
		self.ip = self.getkdcbyname(host)
		# Usually host is used no matter what but dc_ip is used in some scripts so we keep it
		self.dc_ip = self.ip

	def get_newtarget(self, kdc_host, port:int=88, hostname:str = None):			
		return KerberosTarget(
			self.getkdcbyname(kdc_host), 
			port = port, 
			protocol = self.protocol, 
			timeout = self.timeout, 
			proxies=copy.deepcopy(self.proxies),
			dns = self.dns
		)
	
	# Sometimes domain is provided instead of kdc hostname but it's fine
	# usually the dc for the domain is also a kdc
	def getkdcbyname(self, kdc_host):
		try:
			ip = socket.gethostbyname(kdc_host)
		except:
			custom_resolver = resolver.Resolver()
			custom_resolver.nameservers = [self.dns]
			custom_resolver.timeout = self.timeout
			custom_resolver.lifetime = self.timeout * 2
			is_tcp = False		
			if self.protocol == UniProto.CLIENT_TCP:
				is_tcp = True
			try:
				records = custom_resolver.resolve(kdc_host, 'A', tcp=is_tcp)
				ip = records[0].address
			except resolver.NoAnswer:
				records = custom_resolver.resolve(kdc_host, 'AAAA', tcp=is_tcp)
				ip = records[0].address
		return ip

	def __str__(self):
		t = '===KerberosTarget===\r\n'
		for k in self.__dict__:
			if isinstance(self.__dict__[k], list):
				for x in self.__dict__[k]:
					t += '    %s: %s\r\n' % (k, x)
			else:
				t += '%s: %s\r\n' % (k, self.__dict__[k])
			
		return t
