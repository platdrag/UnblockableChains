from web3.utils.events import get_event_data
from web3.utils.abi import filter_by_name,abi_to_signature
from web3.utils.filters import  LogFilter
from .WalletOperations import encode_hex
from .LogWrapper import LogWrapper
from .PollerQueue import PollerQueue
import time

l = LogWrapper.getDefaultLogger()

def createLogEventFilter(eventName, contractAbi, fromAddress, web3, topicFilters:[]) -> (LogFilter, str):
	eventABI = filter_by_name(eventName, contractAbi)[0]
	eventSignature = abi_to_signature(eventABI)
	eventHash = web3.sha3(encode_hex(eventSignature))
	l.debug('creating log filter. eventSignature:', eventSignature, 'eventHash:', eventHash, 'filters:',topicFilters)

	commandFilter = web3.eth.filter({'address': fromAddress,
											   'topics': [eventHash]+topicFilters})
	return commandFilter, eventABI


def getLogEventArg(tx, eventABI, argName):
	data = get_event_data(eventABI, tx)
	return data['args'][argName]

def getField(tx,field):
	return tx[field]


def waitForNodeToSync(web3):
	l.info('waiting for node to sync...')
	while web3.eth.syncing or web3.eth.blockNumber == 0 or len(web3.admin.peers) < 1:
		bn = web3.eth.syncing['currentBlock'] if web3.eth.syncing else web3.eth.blockNumber
		l.debug('current synced block is:', bn, 'num peers:', len(web3.admin.peers))
		time.sleep(1)
	l.info('chain Sync done!')