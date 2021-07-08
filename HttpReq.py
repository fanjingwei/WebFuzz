class HttpReq():
	def __init__(self, req):
		self.req = req

	def getHeaders(self,specialHeader=None):
		headers = []
		for header in self.req["headers"]:
			if "Host" == header["name"] or "Content-Length" == header["name"]:
				continue
			if None != specialHeader:
				if header["name"] in specialHeader.keys():
					headers.append(header["name"]+":"+specialHeader[header["name"]].replace("\"","\\\""))
				else:
					headers.append(header["name"]+":"+header["value"].replace("\"","\\\""))
			else:
				headers.append(header["name"]+":"+header["value"].replace("\"","\\\""))
		return headers

	def getUrl(self):
		return self.req["url"]

	def getMethod(self):
		return self.req["method"]

	def getHttpVersion(self):
		return self.req["httpVersion"]

	def getUrlPara(self):
		pass

	def getBodyPara(self):
		pass

	def getCookiePara(self):
		return

class HttpReqStatic(HttpReq):
	def getUrlPara(self):
		return

class HttpReqPost(HttpReq):
	def getBodyPara(self):
		return self.req["postData"]

class HttpReqGet(HttpReq):
	def getUrlPara(self):
		return self.req["url"]
