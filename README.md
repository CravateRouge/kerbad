# Kerbad
`kerbad` is a fork of `minikerberos` a kerberos client library written in `Python>=3.6`. It is the kerberos library used for `bloodyAD`. It also comes with multiple useful examples for pentesters who wish to perform security audits on the kerberos protocol.  

## Installation

Install it via either cloning it from GitHub and using  

```bash
$ git clone https://github.com/CravateRouge/kerbad.git
$ cd kerbad
$ python3 setup.py install
```  
  
or with `pip` from the Python Package Index (PyPI).
  
```bash
$ pip install kerbad --user
```

Consider to use a Python virtual environment.

# Kerberos URL Format

All `kerbad` tools accept credentials through a **Kerberos URL**.

A Kerberos URL describes:

- Authentication method
- Domain and username
- Secret (password, key, ticket, certificate, etc.)
- Domain Controller / KDC address
- Optional Kerberos settings
- Optional proxy settings

---

## Important

**Special URL characters should be URL-encoded**:

| Character | Encoded Value |
|------------|-------------|
| `@` | `%40` |
| `:` | `%3A` |
| `/` | `%2F` |
| `?` | `%3F` |
| `&` | `%26` |
| `=` | `%3D` |

Example:

```text
SecretP@ssword
```

becomes:

```text
SecretP%40ssword
```

---

# General Syntax

```text
kerberos+<secret_type>://<domain>\<username>:<secret>@<dc>
```

With optional parameters:

```text
kerberos+<secret_type>://<domain>\<username>:<secret>@<dc>/?parameter=value
```

Custom port:

```text
kerberos+<secret_type>://<domain>\<username>:<secret>@<dc>:88
```

UDP transport:

```text
kerberos-udp+<secret_type>://<domain>\<username>:<secret>@<dc>
```

---

# Supported Protocol Prefixes

```text
kerberos
kerberos-tcp
kerberos-udp
krb5
krb5-tcp
krb5-udp
```

---

# Username Format

Usernames must be specified as:

```text
DOMAIN\username
```

Example:

```text
TEST\Administrator
```

---

# Supported Authentication Types

## Password

Aliases:

```text
pw
pass
password
```

Example:

```text
kerberos+password://TEST\Administrator:Passw0rd@10.10.10.2
```

---

## Interactive Password Prompt

Instead of placing the password in the URL:

```text
kerberos+password-prompt://TEST\Administrator@10.10.10.2
```

The password will be requested interactively.

---

## NT Hash / RC4 Key

Aliases:

```text
nt
rc4
```

Requirements:

- 32 hexadecimal characters

Example:

```text
kerberos+rc4://TEST\Administrator:921a7fece11f4d8c72432e41e40d0372@10.10.10.2
```

---

## AES Keys

### Automatic AES Detection

```text
kerberos+aes://DOMAIN\user:<key>@dc
```

The key type is determined from its length:

| Length | Type |
|----------|----------|
| 32 chars | AES128 |
| 64 chars | AES256 |

Example:

```text
kerberos+aes://TEST\user:0123456789abcdef0123456789abcdef@10.10.10.2
```

### Explicit AES128

```text
kerberos+aes128://DOMAIN\user:<32-character-key>@dc
```

### Explicit AES256

```text
kerberos+aes256://DOMAIN\user:<64-character-key>@dc
```

---

## DES

Requirements:

- 16 hexadecimal characters

Example:

```text
kerberos+des://DOMAIN\user:<16-character-key>@dc
```

---

## Triple DES

Aliases:

```text
des3
tdes
```

Requirements:

- 24 hexadecimal characters

Example:

```text
kerberos+des3://DOMAIN\user:<24-character-key>@dc
```

---

## CCACHE

Load credentials from a Kerberos CCACHE file.

```text
kerberos+ccache://DOMAIN\user:ticket.ccache@dc
```

Example:

```text
kerberos+ccache://TEST\Administrator:admin.ccache@10.10.10.2
```

---

## KIRBI

Load credentials from a `.kirbi` ticket.

```text
kerberos+kirbi://ticket.kirbi@10.10.10.2
```

Example:

```text
kerberos+kirbi://administrator.kirbi@10.10.10.2
```

---

## KEYTAB

Load credentials from a Keytab file.

```text
kerberos+keytab://DOMAIN\user:account.keytab@dc
```

Example:

```text
kerberos+keytab://TEST\svc-web:web.keytab@10.10.10.2
```

---

## PFX Certificate (PKINIT)

Certificate-based authentication.

```text
kerberos+pfx://DOMAIN\user:<pfx-password>@dc/?certdata=user.pfx
```

Example:

```text
kerberos+pfx://TEST\Administrator:admin@10.10.10.2/?certdata=test.pfx
```

---

## PFX Certificate Provided as Base64

```text
kerberos+pfxstr://DOMAIN\user:<pfx-password>@dc/?certdata=<base64-pfx-data>
```

---

## PEM Certificate (PKINIT)

```text
kerberos+pem://DOMAIN\user@dc/?certdata=user.pem&keydata=user.key
```

Example:

```text
kerberos+pem://TEST\Administrator@10.10.10.2/?certdata=test.pem&keydata=test.key
```

---

## Windows Certificate Store

Windows only.

```text
kerberos+certstore://DOMAIN\user@dc/?cn=Administrator&certstore=MY
```

Example:

```text
kerberos+certstore://TEST\Administrator@10.10.10.2/?cn=Administrator&certstore=MY
```

---

## No Authentication (No Pre-Auth)

Useful for AS-REP roasting scenarios where the account does not require Kerberos preauthentication.

```text
kerberos+none://TEST\asrepuser@10.10.10.2
```

---

# Encoded Secret Types

The following secret types support encoded values:

```text
pw
pfx
pem
ccache
keytab
kirbi
```

---

## Base64 Encoding

Append:

```text
b64
```

Example:

```text
kerberos+pwb64://TEST\user:U2VjcmV0UGFzc3dvcmQ=@10.10.10.2
```

---

## Hex Encoding

Append:

```text
hex
```

Example:

```text
kerberos+pwhex://TEST\user:53656372657450617373776F7264@10.10.10.2
```

---

# URL Parameters

## Kerberos Parameters

### etype

Overrides the supported encryption type.

Example:

```text
?etype=18
```

Common values:

| Value | Encryption Type |
|---------|---------|
| 17 | AES128 |
| 18 | AES256 |
| 23 | RC4-HMAC |

Example:

```text
kerberos+aes://TEST\user:key@10.10.10.2/?etype=18
```

---

### ptype

Overrides the Kerberos principal type.

### ptype

Overrides the Kerberos principal name type (`PrincipalName.name-type`) used in Kerberos requests.

Example:

```text
?ptype=10
```

Common values:

| Value | Name | Description |
|---------|---------|-------------|
| 0 | NT-UNKNOWN | Name type not known. |
| 1 | NT-PRINCIPAL | User principal name. |
| 2 | NT-SRV-INST | Service with instance (`cifs/server`). |
| 3 | NT-SRV-HST | Host-based service. |
| 4 | NT-SRV-XHST | Service with host as remaining components. |
| 5 | NT-UID | Unique identifier. |
| 6 | NT-X500-PRINCIPAL | X.500 Distinguished Name. |
| 7 | NT-SMTP-NAME | SMTP email address. |
| 10 | NT-ENTERPRISE | Enterprise principal name (UPN style, e.g. `user@domain.tld`). |

Example:

```text
?ptype=10
```

---

### timeout

Connection timeout in seconds.

Example:

```text
?timeout=60
```

Default:

```text
10
```

---

### dns

DNS server used for Kerberos name resolution.

Example:

```text
?dns=192.168.100.1
```

If omitted, the Domain Controller hostname/IP is also used as the DNS server.

---

# Certificate Parameters

### certdata

Certificate file path or certificate data depending on the authentication method.

Used by:

- `pfx`
- `pfxstr`
- `pem`

Examples:

```text
?certdata=user.pfx
```

```text
?certdata=BASE64_PFX_DATA
```

```text
?certdata=user.pem
```

---

### keydata

Private key file used with PEM authentication.

Example:

```text
?keydata=user.key
```

Only valid with:

```text
kerberos+pem
```

---

### certstore

Windows certificate store name.

Default:

```text
MY
```

Example:

```text
?certstore=MY
```

Only valid with:

```text
kerberos+certstore
```

---

### cn

Certificate Common Name (CN) used to select a certificate from the Windows certificate store.

Example:

```text
?cn=Administrator
```

Only valid with:

```text
kerberos+certstore
```

---

# Proxy Parameters

Proxy support is automatically enabled when `proxytype` is present.

Example:

```text
kerberos+password://TEST\Administrator:SecretP%40ssword@10.10.10.2/?proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080
```

Common options:

```text
proxytype
proxyhost
proxyport
proxyuser
proxypass
```

Supported proxy settings are parsed by `UniProxyTarget.from_url_params()`.

---

# Complete Example

```text
kerberos+aes://TEST\Administrator:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef@10.10.10.2/?etype=18&ptype=10&timeout=60&dns=192.168.100.1
```

This example specifies:

- AES256 authentication
- Encryption type override (`etype=18`)
- Principal type override (`ptype=10`)
- 60 second timeout
- Custom DNS server (`192.168.100.1`)

## Information for developers
`kerbad` library contains both asynchronous and blocking versions of the kerberos client with the same API. Besides the usual password/aes/rc4 LTK authentication methods it also supports PKINIT using `pfx` or `pem` formatted certificates as well as certificates stored in windows certificate store. 

## Information for pentesters
`kerbad` comes with examples which can be used to perform the usual pentest activities out-of-the-box without additional coding required.

# Examples AKA the pentest tools
Installing `kerbad` module via pip will automatically place all examples in the `Scripts` directory by the `setuptools` build environment. All tools named in the following way `bad<toolname>`

## badTGT
Fetches a TGT for the given kerberos credential. The kredential must be in a standard `kerberos URL` format.

## badTGS
Fetches an TGS ticket (TGSREP) for the given cerberos credential and SPN record.  
SPN must be in `service/hostname@FQDN` format.

## badkerberoast
Also known as SPNRoast, this tool performs a kerberoast attack against one or multiple users, using the provided kerberos credential.

## badNTPKInit
This tool recovers the NT hash for the user specified by the kerberos credential. This only works if PKINIT (cert based auth) is used.

## badkerb23hashdecrypt
This tool attempts to recover the user's NT hash for a list of kerberoast hashes.  
When you performed a kerberoast attack against one or multiple users, and have a huge list of NT hashes (no password needed) this tool will check each NT hash if it can decrypt the ticket in the kerberoasted hashes.  
Full disclosure, those are not hashes and it hurt me writing the previous sentence.  

## badS4U2self
This tool is used when you have credentials to a machine account and would like to impersonate other users on the same machine. Machine account credential should be supplied in the `kerberos URL` format, while the user to be impersonated should be in the usual UserPrincialName format eg `username@FQDN`

## badS4U2proxy
This tool is used when you have a machine account which has the permission to perform Kerberos Resource-based Constrained Delegation (RBCD). With this, you can impersonate users. For this to work, the machine account must be allowed to delegate on all protocols, not kerberos-only!

## badccacheroast
Performs "Kerberoast" attack on a CCACHE file. You get back the "hashes" for all TGS tickets stored in the CCACHE file.

## badccache2kirbi
Converts a CCACHE file to a list of `.kirbi` files.


## badkirbi2ccache
Converts one or more `.kirbi` files into one CCACHE file

## badccacheedit
Command-line CCACHE file editor. It can list/delete credentials in a CCACHE file.

