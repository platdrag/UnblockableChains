from web3 import Web3

def bytesToHexString(string) -> str:
    return Web3.toHex(string.encode('latin-1'))


def hexStringToBytes(bytes) :
    return Web3.toBytes(hexstr = bytes).decode('latin-1')
