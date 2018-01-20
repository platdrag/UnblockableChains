import logging
import yaml
import os
import sys
from os.path import join as opj
from Util.LogWrapper import *
import yaml
from solc import compile_source
from web3 import Web3, HTTPProvider

import Client.OsInteractions as OsInteractions
from Util.EtherKeysUtil import *

class ServerCommands:

    def __init__(self, confFile):
        self.conf = yaml.safe_load(open(opj('conf','gen', confFile)))

        # TODO: check node is up. load node if not ,wait for connection and sync.
        l.debug ("connecting to local node", self.conf['nodeRpcUrl'])
        self.web3 = Web3(HTTPProvider(self.conf['nodeRpcUrl']))

        # load CnC contract
        self.contract = self.loadContract()
        #TODO: check contract is up, otherwise go to sleep or die

        self.ownerAddress = self.conf['ownerAddress']

        l.info("server wallet address:",self.ownerAddress, "contract:", self.contract)

    def loadContract(self):

        l.info('loading contract from:', self.conf['contract']['address'], self.conf['contract']['abi'])

        contract = self.web3.eth.contract(self.conf['contract']['abi'], self.conf['contract']['address'])
        return contract


if __name__ == "__main__":
    _logger = logging.getLogger('root')
    FORMAT = "[%(funcName)7s()] %(message)s"
    logging.basicConfig(format=FORMAT)
    _logger.setLevel(logging.DEBUG)
    l = LogWrapper(_logger)

    l.info("base dir ", sys.argv[1])
    os.chdir(sys.argv[1])

    cc = ServerCommands('ServerConf.yaml')






