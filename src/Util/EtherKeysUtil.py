
from web3 import Web3


def derivePublicKey(privKey, password = None):
    #TODO: complete!!!
    return "0xaf80b90d25145da28c583359beb47b21796b2fe1a23c1511e443e7a64dfdb27d7434c380f0aa4c500e220aa1a9d068514b1ff4d5019e624e7ba1efe82b340a59"

def deriveAddress(pubkey):
    return '0x'+Web3.sha3(pubkey)[-40:]



