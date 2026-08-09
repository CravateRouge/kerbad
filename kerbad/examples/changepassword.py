
import logging
import kerbad

LOG = kerbad.getLogger()

import asyncio
from kerbad.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from kerbad.protocol.asn1_structs import PrincipalName
from kerbad.protocol.constants import NAME_TYPE
import traceback

async def change_password(connection_url:str, newpass:str = None, targetuser:str=None):
	try:
		cu = KerberosClientFactory.from_url(connection_url)
		client = cu.get_client()
		kdc_req_body_override = {
			'sname': PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': ['kadmin', 'changepw']}),
		}
		await client.get_TGT(kdc_req_body_extra=kdc_req_body_override)
		response = await client.change_password(newpass, targetuser=targetuser)
		if response.result_code == 0:
			print('Password changed successfully!')
			return
		
		print('Error changing password!')
		print(response)
		return

	except Exception as e:
		traceback.print_exc()
		print(str(e))

async def amain():
	import argparse
	
	parser = argparse.ArgumentParser(description='Kerberoast', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('kerberos_connection_url', help='the kerberos target string in the following format kerberos+<stype>://<domain>\\<username>@<domaincontroller-ip>')
	parser.add_argument('newpassword', help='New password')
	parser.add_argument('-u', '--targetuser', help='Target user to change password for. If not specified, the current user will be used.')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose > 0:
		LOG.setLevel(logging.DEBUG)
	
	await change_password(args.kerberos_connection_url, args.newpassword, args.targetuser)

def main():
	asyncio.run(amain())
	
if __name__ == '__main__':
	main()