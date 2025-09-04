@echo off
set projectname=kerbad
set hiddenimports= --hidden-import cryptography --hidden-import cffi --hidden-import cryptography.hazmat.backends.openssl --hidden-import cryptography.hazmat.bindings._openssl --hidden-import unicrypto --hidden-import unicrypto.backends.pycryptodome.DES --hidden-import  unicrypto.backends.pycryptodome.TDES --hidden-import unicrypto.backends.pycryptodome.AES --hidden-import unicrypto.backends.pycryptodome.RC4 --hidden-import unicrypto.backends.pure.DES --hidden-import  unicrypto.backends.pure.TDES --hidden-import unicrypto.backends.pure.AES --hidden-import unicrypto.backends.pure.RC4 --hidden-import unicrypto.backends.cryptography.DES --hidden-import  unicrypto.backends.cryptography.TDES --hidden-import unicrypto.backends.cryptography.AES --hidden-import unicrypto.backends.cryptography.RC4 --hidden-import unicrypto.backends.pycryptodomex.DES --hidden-import  unicrypto.backends.pycryptodomex.TDES --hidden-import unicrypto.backends.pycryptodomex.AES --hidden-import unicrypto.backends.pycryptodomex.RC4
set root=%~dp0
set repo=%root%..\..\%projectname%
IF NOT DEFINED __BUILDALL_VENV__ (GOTO :CREATEVENV)
GOTO :BUILD

:CREATEVENV
python -m venv %root%\env
CALL %root%\env\Scripts\activate.bat
pip install pyinstaller
GOTO :BUILD

:BUILD
cd %repo%\..\
pip install .
cd %repo%\examples
pyinstaller -F ccache_editor.py -n badccacheedit %hiddenimports%
pyinstaller -F ccache2kirbi.py -n badccache2kirbi %hiddenimports%
pyinstaller -F ccacheroast.py -n badccacheroast %hiddenimports%
pyinstaller -F CVE_2022_33647.py -n badcve202233647 %hiddenimports%
pyinstaller -F CVE_2022_33679.py -n badcve202233679 %hiddenimports%
pyinstaller -F getNT.py -n badNTPKInit %hiddenimports%
pyinstaller -F getS4U2proxy.py -n badS4U2proxy %hiddenimports%
pyinstaller -F getS4U2self.py -n badS4U2self %hiddenimports%
pyinstaller -F getTGS.py -n badTGS %hiddenimports%
pyinstaller -F getTGT.py -n badTGT %hiddenimports%
pyinstaller -F kerb23hashdecrypt.py -n badkerb23hashdecrypt %hiddenimports%
pyinstaller -F kirbi2ccache.py -n badkirbi2ccache %hiddenimports%
pyinstaller -F spnroast.py -n badkerberoast %hiddenimports%
pyinstaller -F asreproast.py -n badasreproast %hiddenimports%
pyinstaller -F changepassword.py -n badchangepw %hiddenimports%
cd %repo%\examples\dist & copy *.exe %root%\
GOTO :CLEANUP

:CLEANUP
IF NOT DEFINED __BUILDALL_VENV__ (deactivate)
cd %root%
EXIT /B
