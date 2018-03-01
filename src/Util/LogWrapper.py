import logging
import sys



class LogWrapper():
	
	loggers = {}
	
	@classmethod
	def getLogger(cls, name='root',filename=None, level=logging.DEBUG, override =  False):
		if override or not name in LogWrapper.loggers:
			_logger = logging.getLogger(name)
			FORMAT = "[%(asctime)s %(levelname)5s()] %(message)s"
			dateFmt = "%y-%m-%d %H:%M:%S"
			formatter = logging.Formatter(FORMAT,dateFmt)
			
			_logger.handlers=[]
			if filename:
				ch = logging.FileHandler(filename)
			else:
				ch = logging.StreamHandler()
			
			ch.setFormatter(formatter)
			_logger.addHandler(ch)
			_logger.setLevel(logging.DEBUG)
			
			LogWrapper.loggers[name] = _logger
		
		return LogWrapper(LogWrapper.loggers[name])
	
	

	def __init__(self, logger):
		self.logger = logger

	def info(self, *args, sep=' '):
		self.logger.info(sep.join("{}".format(a) for a in args))

	def debug(self, *args, sep=' '):
		self.logger.debug(sep.join("{}".format(a) for a in args))

	def warning(self, *args, sep=' '):
		self.logger.warning(sep.join("{}".format(a) for a in args))

	def error(self, *args, sep=' '):
		self.logger.error(sep.join("{}".format(a) for a in args))

	def critical(self, *args, sep=' '):
		self.logger.critical(sep.join("{}".format(a) for a in args))

	def exception(self, *args, sep=' '):
		self.logger.exception(sep.join("{}".format(a) for a in args))

	def log(self, *args, sep=' '):
		self.logger.log(sep.join("{}".format(a) for a in args))



if __name__ == "__main__":
	g= LogWrapper.getLogger()
	g.info('hello!!!')
	
	f = LogWrapper.getLogger()
	f.info('hello!!!')
	
	m = LogWrapper.getLogger()
	m.info('hello!!!')
	
	m = LogWrapper.getLogger(filename='moshe.log',name='moshe')
	m.info('hello!!!')
	m = LogWrapper.getLogger(filename='moshe2.log',name='moshe')
	m.info('hello!!!')
	m = LogWrapper.getLogger(filename='moshe2.log',name='moshe',override=True)
	m.info('hello!!!')