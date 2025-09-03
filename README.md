# minikerberos-bAD
`minikerberos-bAD` is fork of `minikerberos` a kerberos client library written in `Python>=3.6`. It is the kerberos library used for `bloodyAD`. It also comes with multiple useful examples for pentesters who wish to perform security audits on the kerberos protocol.  

## Installation

Install it via either cloning it from GitHub and using  

```bash
$ git clone https://github.com/CravateRouge/minikerberos-bAD.git
$ cd minikerberos-bAD
$ python3 setup.py install
```  
  
or with `pip` from the Python Package Index (PyPI).
  
```bash
$ pip install minikerberos-bAD --user
```

Consider to use a Python virtual environment.

## Information for developers
`minikerberos-bAD` library contains both asynchronous and blocking versions of the kerberos client with the same API. Besides the usual password/aes/rc4 LTK authentication methods it also supports PKINIT using `pfx` or `pem` formatted certificates as well as certificates stored in windows certificate store. 

## Information for pentesters
`minikerberos-bAD` comes with examples which can be used to perform the usual pentest activities out-of-the-box without additional coding required.

# Examples AKA the pentest tools
Installing `minikerberos-bAD` module via pip will automatically place all examples in the `Scripts` directory by the `setuptools` build environment. All tools named in the following way `minikerberosbad-<toolname>`

## minikerberosbad-getTGT
Fetches a TGT for the given kerberos credential. The kredential must be in a standard `kerberos URL` format.

## minikerberosbad-getTGS
Fetches an TGS ticket (TGSREP) for the given cerberos credential and SPN record.  
SPN must be in `service/hostname@FQDN` format.

## minikerberosbad-kerberoast
Also known as SPNRoast, this tool performs a kerberoast attack against one or multiple users, using the provided kerberos credential.

## minikerberosbad-getNTPKInit
This tool recovers the NT hash for the user specified by the kerberos credential. This only works if PKINIT (cert based auth) is used.

## minikerberosbad-kerb23hashdecrypt
This tool attempts to recover the user's NT hash for a list of kerberoast hashes.  
When you performed a kerberoast attack against one or multiple users, and have a huge list of NT hashes (no password needed) this tool will check each NT hash if it can decrypt the ticket in the kerberoasted hashes.  
Full disclosure, those are not hashes and it hurt me writing the previous sentence.  

## minikerberosbad-getS4U2self
This tool is used when you have credentials to a machine account and would like to impersonate other users on the same machine. Machine account credential should be supplied in the `kerberos URL` format, while the user to be impersonated should be in the usual UserPrincialName format eg `username@FQDN`

## minikerberosbad-getS4U2proxy
This tool is used when you have a machine account which has the permission to perform Kerberos Resource-based Constrained Delegation (RBCD). With this, you can impersonate users. For this to work, the machine account must be allowed to delegate on all protocols, not kerberos-only!

## minikerberosbad-ccacheroast
Performs "Kerberoast" attack on a CCACHE file. You get back the "hashes" for all TGS tickets stored in the CCACHE file.

## minikerberosbad-ccache2kirbi
Converts a CCACHE file to a list of `.kirbi` files.


## minikerberosbad-kirbi2ccache
Converts one or more `.kirbi` files into one CCACHE file

## minikerberosbad-ccacheedit
Command-line CCACHE file editor. It can list/delete credentials in a CCACHE file.

