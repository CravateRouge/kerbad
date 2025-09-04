import os
import logging
import kerbad

LOG = kerbad.getLogger()

from kerbad.common.ccache import CCACHE

def main():
	import argparse
	
	parser = argparse.ArgumentParser(description='Convert ccache file to kirbi file(s)')
	parser.add_argument('ccache', help='path to the ccache file')
	parser.add_argument('kirbidir', help='output directory fir the extracted kirbi file(s)')	
	parser.add_argument('-v', '--verbose', action='count', default=0)
	
	args = parser.parse_args()
	if args.verbose > 0:
		LOG.setLevel(logging.DEBUG)
	
	LOG.info('Parsing CCACHE file')
	cc = CCACHE.from_file(args.ccache)
	LOG.info('Extracting kirbi file(s)')
	cc.to_kirbidir(args.kirbidir)
	LOG.info('Done!')

if __name__ == '__main__':
	main()