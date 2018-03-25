from .LogWrapper import LogWrapper
from .PollerQueue import PollerQueue

'''
Util class to log transaction and their cost in a readable csv format
'''
class TransactionLogger ():
	def logTransactionCost(web3, txhash, transName, dataLength, logger) -> bool:
		
		try:
			receipt = web3.eth.getTransactionReceipt(txhash)
		except:  # catch 'unknown transaction'
			return False
		
		if receipt:
			trans = web3.eth.getTransaction(txhash)
			to = receipt['to'] if receipt['to'] else receipt['contractAddress']
			# txHash, block Number, from, to, transaction name, gas Limit, gas Used, gas Price, total cost, data size
			logger.info(txhash, receipt['blockNumber'], receipt['from'], to, transName, trans['gas'],
			            receipt['gasUsed'],
			            trans['gasPrice'], web3.fromWei(receipt['gasUsed'] * trans['gasPrice'], 'ether'), dataLength,
			            sep='\t')
			return True
		return False
	
	def __init__(self, loggerFilename, web3):
		self.tl = PollerQueue(TransactionLogger.logTransactionCost)
		self.tl.start()
		self.logger = LogWrapper.getLogger(name='transaction', filename=loggerFilename)
		self.web3 = web3
		
	def insert(self, txhash, transName, dataLength):
		self.tl.insert(self.web3, txhash, transName, dataLength, self.logger)