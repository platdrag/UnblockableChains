from threading import Thread, Condition
from typing import Callable
import time

'''
Takes some function that returns a boolean, tries to execute in a different thread it until it returns True
Can queue multiple calls to same function, call will be tried in round robin. once a call succeeds, it is removed from queue.
'''
class PollerQueue(Thread):
	def __init__(self, func=Callable[..., bool], pollRate = 0.1):
		super().__init__(daemon=True)
		self.condition = Condition()
		self.queue = []
		self.func = func
		self.pollRate = pollRate
	
	def insert(self, *args):
		self.condition.acquire()
		self.queue.append(args)
		self.condition.notify()
		self.condition.release()
	
	def run(self):
		while True:
			self.condition.acquire()
			if self.queue:
				vals = self.queue.pop(0)
				txMined = self.func(*vals)
				if not txMined:
					self.insert(*vals)
				time.sleep(self.pollRate)
			else:
				self.condition.wait()
			self.condition.release()







if __name__ == "__main__":
	def func (currtime,a,b) -> bool:
		checktime = time.time() - 2
		if currtime < checktime:
			print ('done', currtime)
			return True
		else:
			print('not yet done:', currtime, checktime )
	vars = (time.time(),'a','b')
	# func(*vars)
	p = PollerQueue(func)
	p.insert(time.time(),'a','b')
	p.start()
	
	time.sleep(1)
	p.insert(time.time(), 'a', 'b')
	
	time.sleep(10)
	p.insert(time.time(), 'a', 'b')
	