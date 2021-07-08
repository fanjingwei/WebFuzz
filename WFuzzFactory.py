from httpReqFactory import *
from FieldFactory import *

class WFuzzFactory():
	def __init__(self, proxy="127.0.0.1:8080"):
		self.proxy = proxy

	def createFuzzCreater(self, req):
		if isinstance(req, HttpReqPost):
			return PostFuzzCreater(req,self.proxy)
		elif isinstance(req, HttpReqGet):
			return GetFuzzCreater(req, self.proxy)
		return

class FuzzCreater():
	def __init__(self, req, proxy=None):
		self.req = req
		self.proxy = proxy
		self.fuzzFile = "./fuzzwords.txt"
		self.cmd = ""

	def genBaseCmd(self, fuzzFile=None):
		if None != fuzzFile:
			self.fuzzFile = fuzzFile
		if None == self.proxy:
			self.cmd = "wfuzz -z file,"+self.fuzzFile+" "
		else:
			self.cmd = "wfuzz -z file,"+self.fuzzFile+" -p "+self.proxy+" "

	def genHeader(self, specialHeader=None):
		headers = self.req.getHeaders(specialHeader)
		for header in headers:
			self.cmd += "-H \""+ header + "\" "

	def createUrlFuzz(self):
		pass

	def createHeaderFuzz(self):
		pass

	def createBodyFuzz(self):
		pass

class PostFuzzCreater(FuzzCreater):
	def createBodyFuzz(self, fuzzFile=None, withHeader=False, specialHeader=None):
		self.genBaseCmd(fuzzFile)
		if withHeader:
			self.genHeader(specialHeader)
		fieldFuzzCreater = fieldFactory.createFuzzCreater(POS_BODY,self.req.getUrl(),self.req.getBodyPara())
		payloads = fieldFuzzCreater.getFuzzOneByOne()
		cmds = []
		for payload in payloads:
			cmds.append(self.cmd+payload)
		return cmds

class GetFuzzCreater(FuzzCreater):
	def createUrlFuzz(self, fuzzFile=None, withHeader=False, specialHeader=None):
		self.genBaseCmd(fuzzFile)
		if withHeader:
			self.genHeader(specialHeader)
		fieldFuzzCreater = fieldFactory.createFuzzCreater(POS_URL,self.req.getUrl(),None)
		payloads = fieldFuzzCreater.getFuzzOneByOne()
		cmds = []
		for payload in payloads:
			cmds.append(self.cmd+payload)
		return cmds


wfuzzFactory = WFuzzFactory()