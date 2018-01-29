from web3 import Web3

def bytesToHexString(string) -> str:
    return Web3.toHex(string.encode('latin-1'))


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
