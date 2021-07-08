from HttpReq import *

def createHttpReq(req):
	if "GET" == req["method"] and -1 != req["url"].find("?"):
		return HttpReqGet(req)
	elif "POST" == req["method"]:
		return HttpReqPost(req)
	else:
		return HttpReqStatic(req)
	return HttpReq(req)