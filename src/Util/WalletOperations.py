import ast, getpass
import os, string, random
from .Process import Win2LinuxPathConversion,runCommand, format_error_message
from .EtherKeyUtils import make_keystore_json, encode_hex, pubtoaddr, privtopub, privtoaddr, decode_keystore_json
from .LogWrapper import LogWrapper

l = LogWrapper.getLogger()

def generateKeyPair (keyGenScript) -> (str,str):
	'''
	Use openssl to generate a secp256k1 key pair to be used in ethereum.
	Windows users uses the linux subsystem for windows to run bash.exe to run the .sh script. cygwin might also be used
	Under linux script runs natively.
	:param scriptFile: config with keyGenScript correctly set.
	:return: public, private as hex string format
	'''

	path = os.path.abspath(keyGenScript)
	if os.name == 'nt':
		path = Win2LinuxPathConversion(path)
		l.debug("NT: running bash keyGenScript script at ",path)
		proc = runCommand(['bash', path])
	else:
		l.debug("POSIX: running native keyGenScript script at " , path)
		proc = runCommand([path])

	stdoutdata, stderrdata = proc.communicate()

	if proc.returncode:
		raise ValueError(format_error_message(
			"Error trying to create a new account",
			path,
			proc.returncode,
			stdoutdata,
			stderrdata,
		))
	stdoutdata = ast.literal_eval(stdoutdata.decode('utf-8'))
	return stdoutdata['pub'],stdoutdata['priv']

def generatePassword(size=12, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
	return ''.join(random.SystemRandom().choice(chars) for _ in range(size))

def passwordPrompt (password = None, msg ='Enter password to unlock owner wallet'):
	return getpass.getpass(msg) if not password else password


def generateWallet(keyGenScript, password = None):

	public, private = generateKeyPair(keyGenScript)
	password = passwordPrompt(password, "Choose account password. Please remember it as it won't be written anywhere!")

	walletJson = str(make_keystore_json(private[2:].encode('utf-8'), password))
	address =  '0x' + encode_hex(pubtoaddr(public[2:].encode('utf-8')))

	return walletJson, public, private, address

def loadWallet(walletJson, password = None):
	password = passwordPrompt(password)
	private = decode_keystore_json(ast.literal_eval(walletJson), password)

	public = '0x' + encode_hex(privtopub(private))
	address = '0x' + encode_hex(privtoaddr(private))
	private = '0x' + bytes.decode(private, 'utf-8')

	return public, private, address

def unlockAccount(address, password, web3, duration = 0):
	password = passwordPrompt(password)
	unlocked = web3.personal.unlockAccount(address, password, duration)
	if not unlocked:
		raise ValueError('Unable to unlock wallet',address,'. wrong password?')
	l.info('Successfully unlocked wallet',address)

def getAccountBalance(web3, address, units = 'ether'):
	return web3.fromWei(web3.eth.getBalance(address), units)

def importAccountToNode(web3, currentAddress, private, password):
	if not password:
		password = passwordPrompt ()
	if not currentAddress in web3.personal.listAccounts:
		address = web3.personal.importRawKey(private, password)
		assert(address == currentAddress)
		l.info('Account', currentAddress, 'imported to local node')
	l.info('Account Balance: ',str(getAccountBalance(web3, currentAddress)))
	unlockAccount(currentAddress,password, web3)