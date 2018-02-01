import time, sys, json, signal, shutil, atexit, yaml
from os.path import join as opj
from web3 import Web3, HTTPProvider

import Client.OsInteractions as OsInteractions
from web3.utils.events import get_event_data
from web3.utils.abi import filter_by_name,abi_to_signature
from web3.utils.filters import  LogFilter
from web3.contract import ConciseContract
from Util.SolidityTypeConversionUtil import *
from Util.Process import waitFor, kill_proc
from Util.EtherKeysUtil import *

from Util.timeout import TimeoutException


def createLogEventFilter(eventName, contractAbi, fromAddress, web3, topicFilters:[]) -> (LogFilter, string):
    eventABI = filter_by_name(eventName, contractAbi)[0]
    eventSignature = abi_to_signature(eventABI)
    eventHash = web3.sha3(encode_hex(eventSignature))
    l.debug('eventSignature:', eventSignature, 'eventHash:', eventHash)

    commandFilter = web3.eth.filter({'from': fromAddress,
                                               'topics': [eventHash]+topicFilters})
    return commandFilter, eventABI


def getLogEventArg(tx, eventABI, argName):
    data = get_event_data(eventABI, tx)
    return data['args'][argName]


def waitForTransaction(filter: LogFilter, timeout=60):
    i = 10
    while filter.isAlive() and i > 0:
        filter.join(timeout / 10)
        i-=1

    if i <= 0:
        raise TimeoutException(
            "Unable to get a tx confirmation for filter " + filter.filter_id + ". Probably error in transaction or permission issue")
