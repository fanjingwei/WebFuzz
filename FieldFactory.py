
POS_URL = 1
POS_HEADER = 2
POS_COOKIE = 3
POS_BODY = 4
class FieldFactory():
	def __init__(self):
		pass

	def createFuzzCreater(self, pos, url, fuzzPara):
		if POS_BODY == pos and "application/json" == fuzzPara["mimeType"]:
			return JsonFuzzCreater(url, fuzzPara)
		elif POS_URL == pos:
			return UrlFuzzCreater(url, fuzzPara)

class FieldFuzzCreater():
	def __init__(self, url, fuzzPara):
		self.url = url
		self.fuzzPara = fuzzPara

	def getFuzzOneByOne(self):
		pass

class UrlFuzzCreater(FieldFuzzCreater):
	def getFuzzOneByOne(self):
		[_,paraString] = self.url.split("?")
		paras = paraString.split("&")
		fuzzStrings = []
		for para in paras:
			pos = para.find("=")
			fuzzStrings.append(self.url.replace(para,para[:pos+1]+"FUZZ"))
		return fuzzStrings

class JsonFuzzCreater(FieldFuzzCreater):
	def getFuzzOneByOne(self):
		para = eval(self.fuzzPara["text"])
		fuzzStrings = []
		self.fuzzDictData(para, fuzzStrings, para)
		return fuzzStrings

	def fuzzDictData(self, dictData, fuzzStrings, orgDictData):
		for key in dictData.keys():
			self.fuzzOneField(dictData,key,fuzzStrings,orgDictData)
			if dict == type(dictData[key]):
				self.fuzzDictData(dictData[key],fuzzStrings,orgDictData)
			elif list == type(dictData[key]):
				self.fuzzListData(dictData[key],fuzzStrings,orgDictData)

	def fuzzListData(self, listData, fuzzStrings, orgDictData):
		for i in range(len(listData)):
			self.fuzzOneField(listData,i,fuzzStrings,orgDictData)
			if dict == type(listData[i]):
				self.fuzzDictData(listData[i],fuzzStrings,orgDictData)
			elif list == type(listData[i]):
				self.fuzzListData(listData[i],fuzzStrings,orgDictData)
				
	def fuzzOneField(self, dictData, key, fuzzStrings,orgDictData):
		orgValue = dictData[key]
		dictData[key] = "FUZZ"
		fuzzStrings.append("-d \""+str(orgDictData).replace("\'FUZZ\'","FUZZ").replace("'","\\\"")+"\" " + self.url)
		dictData[key] = orgValue
		return


fieldFactory = FieldFactory()