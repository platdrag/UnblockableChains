from web3 import Web3
#from .WalletOperations import encode_hex
from rlp.utils import decode_hex,encode_hex


def bytes2Hex(string) -> str:
	return '0x' + encode_hex(string)


def hexStringToBytes(bytes) :
	return Web3.toBytes(hexstr = bytes).decode('latin-1')


def padHexTo32B(hexStr:str, padBegining = True, prefix = '') -> str :
	if hexStr.startswith('0x'):
		prefix = '0x'
	hexStr = hexStr[len(prefix):]
	l = len(hexStr)
	pad = '0' * (64 - l)
	if padBegining:
		return prefix + pad + hexStr
	else:
		return prefix + hexStr + pad
