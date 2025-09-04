import logging
import kerbad

LOG = kerbad.getLogger()

import asyncio
from kerbad.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from kerbad.common.spn import KerberosSPN
from kerbad.aioclient import AIOKerberosClient
from kerbad.common.kirbi import Kirbi

async def getTGS(kerberos_url:str, spn:str, kirbifile:str = None, ccachefile:str = None, cross_domain:bool = False):
	if isinstance(spn, str):
		spn = KerberosSPN.from_spn(spn)

	cu = KerberosClientFactory.from_url(kerberos_url)
	client = cu.get_client()
	LOG.debug('Getting TGT')
	await client.with_clock_skew(client.get_TGT)
	if cross_domain is True:
		LOG.debug('Getting TGS for other domain krbtgt')
		_, _, _, new_factory = await client.get_referral_ticket(spn.domain)
		client = new_factory.get_client()
	LOG.debug('Getting TGS')
	tgs, encpart, key = await client.with_clock_skew(client.get_TGS, spn)
	if ccachefile is not None:
		client.ccache.to_file(ccachefile)
		print('TGT stored in ccache file %s' % ccachefile)
	
	kirbi = Kirbi.from_ticketdata(tgs, encpart)
	print(str(kirbi))
	if kirbifile is not None:
		kirbi.to_file(kirbifile)
		
	LOG.info('Done!')

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Polls the kerberos service for a TGS for the specified user and specified service', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--ccache', help='CCACHE file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('--kirbi', help='kirbi file to store the TGT ticket in, otherwise kirbi will be printed to stdout')
	parser.add_argument('--cross-domain', action='store_true', help='SPN is in another domain.')
	parser.add_argument('kerberos_url', help='the kerberos target string. ')
	parser.add_argument('spn', help='the SPN to request the TGS for. Must be in the format of service/host@domain')
	
	
	args = parser.parse_args()
	if args.verbose > 0:
		LOG.setLevel(logging.DEBUG)
	
	asyncio.run(getTGS(args.kerberos_url, args.spn, args.kirbi, args.ccache, args.cross_domain))
	
if __name__ == '__main__':
	main()