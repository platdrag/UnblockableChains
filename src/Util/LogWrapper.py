import logging
import sys


class LogWrapper():

    @classmethod
    def getLogger(cls):
        _logger = logging.getLogger('root')
        FORMAT = "[%(funcName)7s()] %(message)s"
        logging.basicConfig(format=FORMAT)
        _logger.setLevel(logging.DEBUG)
        return LogWrapper(_logger)


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