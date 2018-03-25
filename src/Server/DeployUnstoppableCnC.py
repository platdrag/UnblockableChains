import yaml
import os
import sys
import getpass
from os.path import join as opj , exists as exists
import logging
import yaml, ast, json
from solc import compile_source
from web3 import Web3, HTTPProvider
from web3.contract import ConciseContract
from Util.WalletOperations import *
from Util.Process import *
from Util.LogWrapper import LogWrapper
from Util.EtherLogEvents import waitForNodeToSync
import shutil
import signal
import argparse
from Util.TransactionLogger import TransactionLogger

BASE_DEPLOYMENT_FILE = opj('conf', 'deployment', 'DeploymentConf.BASE.yaml')
OVERWRITE_DEPLOYMENT_FILE = opj('conf', 'deployment', 'DeploymentConf.OVERWRITE.yaml')
TRANSACTION_LOG_LOC = opj('logs', 'transaction.log')

def deployContract (web3, conf, contractAddress = None):
	'''
	Deploy a new contract, if not already deployed
	:param web3:
	:param conf:
	:param contractAddress: Deploy new contract if None, else return the existing one.
	:return:
	'''
	with open (conf['contractUri']) as f:
		cs=f.read()

	compiled_sol = compile_source(cs) # Compiled source code
	contract_interface = compiled_sol['<stdin>:'+conf['contractName']]

	# Instantiate and deploy contract
	contract = web3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
	
	if not contractAddress:
		tx_hash = contract.deploy(transaction={'from': conf['ownerAddress'], 'gas': conf['gasLimit_tx'] },
								  args=(conf['ownerPublic'], conf['allowedAddresses']))
		l.debug('transaction deploy contract, tx_hash:',tx_hash)

		# Get tx receipt to get contract address
		l.info('Waiting for contract transaction to be mined...')
		tx_receipt = None
		while not tx_receipt:
			try:
				tx_receipt = web3.eth.getTransactionReceipt(tx_hash)
			except Exception as e:
				l.debug('failed obtaining tx receipt with unknown-tx err, retrying',e)
			time.sleep(1)
			
		contractAddress = tx_receipt['contractAddress']
		conf['contractAddress'] = contractAddress
		
		modifyConfigFile(OVERWRITE_DEPLOYMENT_FILE, 'contractAddress', contractAddress)
		
		l.info('contract successfully deployed: ',contractAddress, 'gas Used:',tx_receipt['gasUsed'])
		transactionCostLogger.insert(tx_hash,'deployContract_'+conf['contractName'],len(compiled_sol))
	else:
		l.info('contract successfully loaded: ', contractAddress)
	l.debug(' abi:', contract_interface['abi'])
	
	conf['abi'] = contract_interface['abi']
	
	# Contract instance in concise mode
	contract_instance = web3.eth.contract(contract_interface['abi'], contractAddress,
										  ContractFactoryClass=ConciseContract)
	#contract_instance.owner()
	return contract_instance



def runGethNode(conf, freshStart = False):
	'''
	Runs the local server geth node. Starts it in full node mode.
	:param conf:
	:param freshStart: if True, delete all node data, and start it fresh.
	:return:
	'''
	opMode = conf['opMode']
	gethLockFile = opj(conf[opMode]['BlockChainData'], 'LOCK.pid')
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

	
	l.info('Deploying in', opMode, 'mode')
	
	if freshStart:
		
		l.warning('Fresh start! removing blockchain dir ', conf[opMode]['BlockChainData'])
		shutil.rmtree(conf[opMode]['BlockChainData'], ignore_errors=True)
		
		if opMode == 'privateNet':
			l.debug('Generating genesis file. Preallocating some coins to owner ',conf['ownerAddress'],' balance')
			conf[opMode]['genesis']['alloc'][conf['ownerAddress']] = { "balance": str(3*10**20) }
			conf[opMode]['genesis']['coinbase'] = conf['ownerAddress']
			
			with open(conf[opMode]['genesisFile'],'w') as f:
				json.dump(conf[opMode]['genesis'],f, indent=1)

			l.info('Initializing blockchain...')
			
			conf['contractAddress'] = None
		
		if 	opMode == 'privateNet' or opMode == 'testRinkeby':
			cmd = [conf['geth'],'--datadir',conf[opMode]['BlockChainData'],'init',conf[opMode]['genesisFile'] ]

			l.debug('Running geth init: ' , ' '.join(cmd))
			with open(opj('logs', 'geth.server.log'), 'a') as f:
				proc = runCommand(cmd, stdout=f)
				proc.communicate()
			
	cmd = conf[opMode]['gethCmd']
	cmd = [x.replace('%DATADIR%', conf[opMode]['BlockChainData']) for x in cmd]
	cmd = [x.replace('%OWNERADDRESS%', conf['ownerAddress']) for x in cmd]
	
	gethLogFile = opj('logs', 'geth.server.log')
	l.info('Running geth node: cmd: ', ' '.join(cmd))
	
	proc = runCommand(cmd, stderr=open(gethLogFile, 'a'))
	
	if proc.returncode:
		std,sterr = proc.communicate()
		raise ValueError(format_error_message("Error trying to run geth node",cmd,proc.returncode,std,sterr))

	time.sleep(3) #allowing for geth to init

	with open(gethLockFile,'w') as f:
		f.write(str(proc.pid))
	l.info('Geth node running. PID:',str(proc.pid), 'Log file location:',gethLogFile)

	return proc

def modifyConfigFile (filename, key, value):
	'''
	Load-Modify-Write a key in a yaml config file.
	:param filename:
	:param key:
	:param value:
	:return:
	'''
	conf = yaml.safe_load(open(filename)) if exists(filename) else {}
	with open(filename, 'w') as f:
		conf[key]=value
		yaml.safe_dump(conf, f, default_flow_style=False)



def loadOrGenerateAccount(conf, regenerateOwnerAccount = False) -> bool:
	'''
	will load an wallet account from config, or generate a new one if empty
	:param conf:
	:param regenerateOwnerAccount: Force account regeneration
	:return:
	'''
	ownerChanged = False
	if not conf['ownerWallet'] or regenerateOwnerAccount:
		l.info("No account set. Generating a new account")
		conf['ownerWallet'],conf['ownerPublic'],conf['ownerPrivate'],conf['ownerAddress'] = generateWallet(conf['keyGenScript'], conf['ownerWalletPassword'])

		l.info('Generated new owner wallet. Persisting changes to conf file')
		modifyConfigFile(OVERWRITE_DEPLOYMENT_FILE, 'ownerWallet', conf['ownerWallet'])

		ownerChanged = True
	else:
		l.info("Loading owner wallet...")
		conf['ownerPublic'], conf['ownerPrivate'], conf['ownerAddress'] = loadWallet(conf['ownerWallet'], conf['ownerWalletPassword'])

	l.info ('User Account Details:')
	l.info('\tPublic key:',conf['ownerPublic'])
	l.info('\tAddress:',conf['ownerAddress'])
	l.debug('\tPrivate key:',conf['ownerPrivate'])
	return ownerChanged



def generateClientsTemplates(web3, conf):
	'''
	Generates a client Template, based on both deployment and client base configuration files
	:param web3:
	:param conf:
	:return:
	'''
	clientConfBase = yaml.safe_load(open(opj('conf', 'clientGen', 'ClientConf.BASE.yaml')))
	clientConfBase['opMode'] = conf['opMode']
	clientConfBase['contract']['name'] = conf['contractName']
	clientConfBase['contract']['abi'] = conf['abi']
	clientConfBase['contract']['address'] = conf['contractAddress']
	if conf['opMode'] == 'privateNet':
		with open(conf['privateNet']['genesisFile'], 'r') as f:
			clientConfBase['privateNet']['genesis'] = json.load(f)
		clientConfBase['privateNet']['enode'] = web3.admin.nodeInfo['enode']


	with open(opj('conf', 'clientGen', 'ClientConf.TEMPLATE.yaml'), 'w') as f:
		yaml.safe_dump(clientConfBase, f)

def generateServerConf(web3, conf):
	'''
	Generates server configuration based on base deployment configuration file
	:param web3:
	:param conf:
	:return:
	'''
	serverConf = {}
	serverConf['contract'] = {}
	serverConf['contract']['name'] = conf['contractName']
	serverConf['contract']['abi'] = conf['abi']
	serverConf['contract']['address'] = conf['contractAddress']

	serverConf['nodeRpcUrl'] = conf['nodeRpcUrl']
	serverConf['ownerWalletPassword'] = conf['ownerWalletPassword']
	serverConf['ownerAddress'] = conf['ownerAddress']
	serverConf['keyGenScript'] = conf['keyGenScript']
	serverConf['instancesDbFile'] = conf['instancesDbFile']
	serverConf['gasLimit_tx'] = conf['gasLimit_tx']
	serverConf['gasLimit_ev'] = conf['gasLimit_ev']

	with open(opj('conf', 'server', 'ServerConf.yaml'), 'w') as f:
		yaml.safe_dump(serverConf, f)

def loadConf():
	'''
	Loads deployment config file. First load BASE file and then the OVERWRITE file.
	'''
	confBase = yaml.safe_load(open(BASE_DEPLOYMENT_FILE))
	confOverwrite = yaml.safe_load(open(OVERWRITE_DEPLOYMENT_FILE)) if exists(OVERWRITE_DEPLOYMENT_FILE) else None
	conf = {**confBase, **(confOverwrite if confOverwrite else {})}
	return conf

def reset():
	'''
	Resets the deployment. Will cause for new generation of everything. use with care.
	'''
	if exists(OVERWRITE_DEPLOYMENT_FILE):
		os.remove(OVERWRITE_DEPLOYMENT_FILE)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(
		prog = 'Deployment script for the Controller backend',
		description = 'This script initiates the controller backend. It will generate owner account, run a local full geth node, '
		              'deploy the smart contract and create all necessary configuration to run controller UI/scripts, and to generate clients.'
		              ' Before running edit configuration file '+BASE_DEPLOYMENT_FILE+'.'
		              ' Run --reset after each time opMode has been changed or if you wish to start over.'
                      'NOTE: After running this script geth node will remain active in the background. If geth gets killed just run this script again with generated config to restart it.'
	)
	parser.add_argument("baseDir", help="Location of base directory. all conf, scripts and bin files are assumed to exist in a subdirectory of base dir.")
	parser.add_argument('--reset', default=False, action='store_true', help="Resets all generated files, configuration and blockchain data.")
	args = parser.parse_args()
	
	os.chdir(args.baseDir)
	
	l = LogWrapper.getDefaultLogger()
	l.info ("Base dir:",args.baseDir)
	
	if args.reset:
		l.warning('!!! Doing a complete reset. Generated data will be deleted in 3 seconds (CTRL+C now if you wish to cancel) !!!')
		for i in range (1,4):
			l.warning(i)
			time.sleep(1)
		reset()
	
	conf = loadConf()
	l.info('Working in', conf['opMode'], 'mode')
	
	solcPath = conf['solc'] + ('.exe' if os.name == 'nt' else '')
	os.environ['SOLC_BINARY'] = opj(os.getcwd(), solcPath)
	
	#Loading/Generating new account for the owner of the contract
	ownerChanged = loadOrGenerateAccount(conf,regenerateOwnerAccount = False)
	
	gethProc = runGethNode(conf, ownerChanged)
	
	#Connecting to the get Node
	web3 = Web3(HTTPProvider(conf['nodeRpcUrl']))
	
	l.info("Node is up at:", web3.admin.nodeInfo.enode)
	
	transactionCostLogger = TransactionLogger(TRANSACTION_LOG_LOC, web3)
	transactionCostLogger.logger.info('======== New Run', time.time(), '========')
	
	
	if conf['opMode'] == 'privateNet':
		l.info("Staring miners...")
		web3.miner.start(1) #For some reason geth doesnt auto start miners... 8|
	
	#Registering the owner account to the node and unlocking it.
	importAccountToNode(web3, conf['ownerAddress'], conf['ownerPrivate'], conf['ownerWalletPassword'])
	
	if conf['opMode'] != 'privateNet':
		waitForNodeToSync(web3)
	
	#deploying the contract to the blockchain
	contract = deployContract (web3, conf, conf['contractAddress'])
	
	#Generating templates with information need for generating a self contained client.
	generateClientsTemplates (web3,conf)
	
	#generates configuration for UI/Server commands scripts
	generateServerConf(web3, conf)

