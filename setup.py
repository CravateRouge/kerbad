from setuptools import setup, find_packages
import re

VERSIONFILE="minikerberos/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="minikerberos-bAD",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsec.com",
    
	# Maintainer details:
	maintainer="Baptiste Crépin",
	maintainer_email="baptiste@cravaterouge.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/CravateRouge/minikerberos-bAD",

	zip_safe=True,
	#
	# license="LICENSE.txt",
	description="Kerberos manipulation library in pure Python",

	# long_description=open("README.txt").read(),
	python_requires='>=3.6',
	classifiers=[
		"Programming Language :: Python :: 3.6",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	],
	install_requires=[
		'asn1crypto>=1.5.1',
		'cryptography>=44.0.2',
		'asysocks>=0.2.8',
		'unicrypto>=0.0.10',
		'tqdm',
        'six',
	],

	entry_points={
		'console_scripts': [
			'minikerberosbad-ccacheedit   = minikerberos.examples.ccache_editor:main',
			'minikerberosbad-kirbi2ccache = minikerberos.examples.kirbi2ccache:main',
			'minikerberosbad-ccache2kirbi = minikerberos.examples.ccache2kirbi:main',
			'minikerberosbad-ccacheroast  = minikerberos.examples.ccacheroast:main',
			'minikerberosbad-getTGT       = minikerberos.examples.getTGT:main',
			'minikerberosbad-getTGS       = minikerberos.examples.getTGS:main',
			'minikerberosbad-getS4U2proxy = minikerberos.examples.getS4U2proxy:main',
			'minikerberosbad-getS4U2self  = minikerberos.examples.getS4U2self:main',
			'minikerberosbad-getNTPKInit  = minikerberos.examples.getNT:main',
			'minikerberosbad-cve202233647 = minikerberos.examples.CVE_2022_33647:main',
			'minikerberosbad-cve202233679 = minikerberos.examples.CVE_2022_33679:main',
			'minikerberosbad-kerb23hashdecrypt = minikerberos.examples.kerb23hashdecrypt:main',
			'minikerberosbad-kerberoast   = minikerberos.examples.spnroast:main',
            'minikerberosbad-asreproast   = minikerberos.examples.asreproast:main',
            'minikerberosbad-changepw   = minikerberos.examples.changepassword:main',
		],
	}
)
