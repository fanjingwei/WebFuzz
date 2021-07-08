import json
from HttpReq import *
from httpReqFactory import *

class HarAnalyzer():
    def __init__(self, file):
        self.harFileName = file
        self.reqAndRsps = self.decode()
        self.num = len(self.reqAndRsps)
        self.reqs,self.getReqs,self.postReqs,self.staticReqs = self.createReqs()

    def analyse(self):
        reqsNeedFuzz = []
        num = 0
        print("找到以下有Fuzz价值的报文:")
        for i in range(len(self.getReqs)):
            print("Get Req id:",num," URL:",self.getReqs[i].getUrl())
            reqsNeedFuzz.append(self.getReqs[i])
            num+=1
        for i in range(len(self.postReqs)):
            reqsNeedFuzz.append(self.postReqs[i])
            print("Post Req id:",num," URL:",self.postReqs[i].getUrl())
            print("body:",self.postReqs[i].getBodyPara()["text"])
            print("\n")
            num+=1
        return reqsNeedFuzz

    def decode(self):
        with open(self.harFileName, 'r', encoding='utf-8') as f:
            data = json.loads(f.read())
            reqAndRsps = data['log']['entries']
        return reqAndRsps

    def createReqs(self):
        reqs=[]
        getReqs=[]
        postReqs=[]
        staticReqs = []
        for packet in self.reqAndRsps:
            req = createHttpReq(packet["request"])
            reqs.append(req)
            if isinstance(req,HttpReqGet):
                getReqs.append(req)
            elif isinstance(req,HttpReqPost):
                postReqs.append(req)
            elif isinstance(req,HttpReqStatic):
                staticReqs.append(req)


        return reqs,getReqs,postReqs,staticReqs

    def isOutOfRange(self, index):
        if index > self.num:
            return True
        return False

    def getReqById(self, index):
        if self.isOutOfRange(index):
            return None
        return createHttpReq(self.reqAndRsps[index]["request"])

    def getGetReqs(self):
        return self.getReqs+self.staticReqs

    def getPostReqs(self):
        return self.postReqs