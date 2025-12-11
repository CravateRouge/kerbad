import getpass
import copy
import base64

from kerbad.common.target import KerberosTarget
from kerbad.common.creds import KerberosCredential
from kerbad.common.constants import KerberosSecretType
from kerbad.aioclient import AIOKerberosClient
from kerbad.client import KerbrosClient

from urllib.parse import urlparse, parse_qs, unquote

from asysocks.unicomm.common.target import UniProto
from asysocks.unicomm.common.proxy import UniProxyTarget
from kerbad.protocol.constants import EncryptionType

kerberos_url_help_epilog = """==== Extra Help ====
   WARNING: URL special chars (@, :, /, ?, &, =) must be URL encoded!

   Kerberos connection secret types: 
   - Plaintext: "pw" or "pass" or "password"
   - NT/RC4 key: "nt" or "rc4"
   - AES128/256 key: "aes"
   - CCACHE: "ccache"
   - KIRBI: "kirbi"
   - KEYTAB: "keytab"
   - PFX: "pfx"
   - PFX string (base64): "pfxstr"
   - PEM: "pem"
   - CERTSTORE: "certstore"
   
   Secret types supporting "b64"/"hex" suffix (e.g. "pwb64", "ccachehex"...):
   - "pw", "pfx", "pem", "ccache", "keytab", "kirbi"
   
   Example:
   - Plaintext + SOCKS5 proxy:
      kerberos+password://domain\\user:SecretP%40ssword@127.0.0.1/proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080
   - Encoded Password:
      kerberos+pwhex://domain\\user:53656372657450617373776F7264@127.0.0.1
      kerberos+pw64://domain\\user:U2VjcmV0UGFzc3dvcmQ%3D@127.0.0.1
   - RC4 key:
      kerberos+rc4://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1
   - AES key:
      kerberos+aes://domain\\user:921a7fece11f4d8c72432e41e40d0372@127.0.0.1
   - CCACHE file + Timeout + DNS:
      kerberos+ccache://domain\\user:creds.ccache@127.0.0.1/?timeout=60&dns=192.168.100.1
   - KIRBI file:
      kerberos+kirbi://creds.kirbi@127.0.0.1
   - KEYTAB file:
      kerberos+keytab://domain\\user:creds.keytab@127.0.0.1
   - PFX file:
      kerberos+pfx://TEST.corp\\Administrator:admin@10.10.10.2/?certdata=test.pfx
   - PFX string (b64):
      kerberos+pfxstr://TEST.corp\\Administrator:admin@10.10.10.2/?certdata=BASE64DATA
   - PEM file:
      kerberos+pem://TEST.corp\\Administrator:admin@10.10.10.2/?certdata=test.pem&keydata=test.key
   - CERTSTORE (Windows only):
	  kerberos+certstore://TEST.corp\\Administrator/?cn=Administrator&certstore=MY
   - No auth (preauth not req):
      kerberos+none://TEST.corp\\asrepuser@10.10.10.2/
"""


KerberosClientFactory_param2var = {
	'timeout': ('timeout', [int]),
	'certdata': ('certdata', [str]),
	'keydata': ('keydata', [str]),
	'etype': ('etype', [int]),
	'certstore': ('certstore', [str]),
	'cn': ('commonname', [str]),
	'dns': ('dns', [str]),
}

class KerberosClientFactory:
	def __init__(self, target:KerberosTarget = None, credential = None, proxies = [], certdata = None, keydata = None):
		self.domain = None
		self.username = None
		self.secret_type = None
		self.secret = None
		self.etype = None
		self.certstore = 'MY'
		self.commonname = None

		self.dc_ip = None
		self.protocol = UniProto.CLIENT_TCP
		self.timeout = 10
		self.port = 88

		self.dns = None
		self.target = target #proxy needs to be already in the target!
		self.credential = credential
		self.proxies = proxies
		self.certdata = certdata
		self.keydata = keydata

	def get_target(self):
		if self.target is not None:
			if self.target.proxies is None and self.proxies is not None:
				self.target.proxies = self.proxies
			if self.target.dns is None and self.dns is not None:
				self.target.dns = self.dns
			return copy.deepcopy(self.target)
		res = KerberosTarget(
			self.dc_ip, 
			port=self.port, 
			protocol = UniProto.CLIENT_TCP, 
			proxies = self.proxies,
			timeout = self.timeout,
			dns = self.dns
		)
		return res
	
	def get_credential(self):
		return self.get_creds()

	def get_basetype_and_encoding(self):
		basetype = self.secret_type
		encoding = 'file'
		if self.secret_type.name.endswith('B64'):
			basetype = KerberosSecretType(self.secret_type.name[:-3])
			encoding = 'b64'
		elif self.secret_type.name.endswith('HEX'):
			basetype = KerberosSecretType(self.secret_type.name[:-3])
			encoding = 'hex'
		return basetype, encoding
	
	def get_creds(self):
		if self.credential is not None:
			return copy.deepcopy(self.credential)
		basetype, encoding = self.get_basetype_and_encoding()
		if basetype == KerberosSecretType.KEYTAB:
			return KerberosCredential.from_keytab(self.secret, self.username, self.domain, encoding=encoding)
		if basetype == KerberosSecretType.KIRBI:
			return KerberosCredential.from_kirbi(self.secret, encoding=encoding)
		if basetype == KerberosSecretType.PFXSTR:
			return KerberosCredential.from_pfx_string(self.certdata, self.secret, username = self.username, domain = self.domain)
		if basetype == KerberosSecretType.PFX:
			return KerberosCredential.from_pfx(self.certdata, self.secret, username=self.username, domain=self.domain, encoding=encoding)
		if basetype == KerberosSecretType.CCACHE:
			return KerberosCredential.from_ccache(self.secret, principal=self.username, realm=self.domain, encoding=encoding)
		if basetype == KerberosSecretType.PEM:
			return KerberosCredential.from_pem(self.certdata, self.keydata, username = self.username, domain = self.domain, encoding=encoding)
		if basetype == KerberosSecretType.CERTSTORE:
			return KerberosCredential.from_windows_certstore(self.commonname, certstore_name = self.certstore, dhparams = None, username = self.username, domain = self.domain)

		res = KerberosCredential()
		res.username = self.username
		res.domain = self.domain

		if basetype in [KerberosSecretType.PASSWORD, KerberosSecretType.PW, KerberosSecretType.PASS]:
			if encoding == 'b64':
				self.secret = base64.b64decode(self.secret).decode()
			elif encoding == 'hex':
				self.secret = bytes.fromhex(self.secret).decode()
			res.password = self.secret
		elif self.secret_type in [KerberosSecretType.NT, KerberosSecretType.RC4]:
			if len(self.secret) != 32:
				raise Exception('Incorrect RC4/NT key! %s' % self.secret)
			res.nt_hash = self.secret
			res.kerberos_key_rc4 = self.secret
		elif self.secret_type in [KerberosSecretType.AES128, KerberosSecretType.AES256, KerberosSecretType.AES]:
			if self.secret_type == KerberosSecretType.AES:
				if len(self.secret) == 32:
					res.kerberos_key_aes_128 = self.secret
				elif len(self.secret) == 64:
					res.kerberos_key_aes_256 = self.secret
				else:
					raise Exception('Incorrect AES key! %s' % self.secret)
			elif self.secret_type == KerberosSecretType.AES128:
				if len(self.secret) != 32:
					raise Exception('Incorrect AES128 key! %s' % self.secret)
				res.kerberos_key_aes_128 = self.secret
			else:
				if len(self.secret) != 64:
					raise Exception('Incorrect AES256 key! %s' % self.secret)
				res.kerberos_key_aes_256 = self.secret
		elif self.secret_type == KerberosSecretType.DES:
			if len(self.secret) != 16:
				raise Exception('Incorrect DES key! %s' % self.secret)
			res.kerberos_key_des = self.secret
		elif self.secret_type in [KerberosSecretType.DES3, KerberosSecretType.TDES]:
			if len(self.secret) != 24:
				raise Exception('Incorrect DES3 key! %s' % self.secret)
			res.kerberos_key_des3 = self.secret
		elif self.secret_type == KerberosSecretType.NONE:
			res.nopreauth = True
		else:
			raise Exception('Missing/unknown secret_type!')

		if self.etype is not None:
			res.override_etypes = [EncryptionType(self.etype)]

		return res
	
	def get_client(self):
		return AIOKerberosClient(self.get_creds(), self.get_target())
	
	def get_client_blocking(self):
		return KerbrosClient(self.get_creds(), self.get_target())
	
	def get_client_newcred(self, cred:KerberosCredential):
		return AIOKerberosClient(copy.deepcopy(cred), self.get_target())
	
	def get_client_newcred_blocking(self, cred:KerberosCredential):
		return KerbrosClient(copy.deepcopy(cred), self.get_target())

	@staticmethod
	def from_url(url_str):
		res = KerberosClientFactory()
		url = urlparse(url_str)
		url_dict = url._asdict()
		for prop, val in url_dict.items():
			if type(val) is str and prop != 'query':
				url_dict[prop] = unquote(val)
		url = url._replace(**url_dict)
		res.dc_ip = url.hostname
		schemes = url.scheme.upper().split('+')
		
		if schemes[0] not in ['KERBEROS', 'KERBEROS-TCP, KERBEROS-UDP', 'KRB5', 'KRB5-UDP', 'KRB5-TCP']:
			raise Exception('Unknown protocol! %s' % schemes[0])

		if schemes[0].endswith('UDP') is True:
			res.protocol = UniProto.CLIENT_UDP
		
		ttype = schemes[1]
		if ttype.find('-') != -1 and ttype.upper().endswith('-PROMPT'):
			ttype = ttype.split('-')[0]
			res.secret = getpass.getpass()
		try:
			res.secret_type = KerberosSecretType(ttype)
		except:
			raise Exception('Unknown secret type! %s' % ttype)
		
		if url.username is not None:
			if url.username.find('\\') != -1:
				res.domain , res.username = url.username.split('\\')
			else:
				raise Exception('Domain missing from username!')
		else:
			if res.secret_type != KerberosSecretType.CERTSTORE:
				raise Exception('Missing username!')
		
		if res.secret is None:
			res.secret = url.password
		if url.port is not None:
			res.port = int(url.port)
		
		query = parse_qs(url.query)
		proxy_type = None
		for k in query:
			if k == 'proxytype':
				proxy_type = query[k][0]

			
			if k in KerberosClientFactory_param2var:
				data = query[k][0]
				for c in KerberosClientFactory_param2var[k][1]:
					data = c(data)

					setattr(
						res, 
						KerberosClientFactory_param2var[k][0], 
						data
					)
		
		if proxy_type is not None:
			res.proxies = UniProxyTarget.from_url_params(query, res.dc_ip, res.port)
		
		# Usually DC is also a DNS server
		if not res.dns:
			res.dns = res.dc_ip
		
		if res.username is None:
			if res.secret_type != KerberosSecretType.CERTSTORE:
				raise Exception('Missing username!')
		
		if res.secret_type == KerberosSecretType.PWPROMPT:
			res.secret_type = KerberosSecretType.PASSWORD
			res.secret = getpass.getpass()

		if res.secret_type is None:
			raise Exception('Missing secret_type!')
		if res.dc_ip is None:
			raise Exception('Missing target hostname or IP!')
		
		if res.secret is None and res.secret_type != KerberosSecretType.NONE:
			if res.secret_type not in [KerberosSecretType.PFXSTR, KerberosSecretType.PFX ,KerberosSecretType.PEM, KerberosSecretType.CERTSTORE]:
				raise Exception('Missing secret/password!')
		
		return res
