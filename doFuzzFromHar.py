from HarAnalyzer import *
from WFuzzFactory import *
import os
import sys,getopt

def createOneReqFuzzCmds(req, proxy, wordlist, headers):
	cmds = []
	fuzzCreater = wfuzzFactory.createFuzzCreater(req,proxy)
	if None != headers:
		cmds = fuzzCreater.createFuzz(fuzzFile=wordlist, withHeader=True, specialHeader=headers)
	else:
		cmds = fuzzCreater.createFuzz(fuzzFile=wordlist)
	return cmds

 #默认命令：python doFuzzFromHar.py -f 10.229.145.118.har -j ./headers.json -n 0

if __name__ =='__main__': 
    opts,args = getopt.getopt(sys.argv[1:],"hf:w:p:t:j:n:")

    token = None
    jsonFile = None
    num = None
    wordlist = "./fuzzwords.txt"
    proxy = None

    for op,arg in opts:
        if "-h" == op:
            print("参数列表：")
            print("-h:显示帮助")
            print("-f:设置Fuzz目标HAR文件，例:-f 10.229.145.118.har")
            print("-w:设置Fuzz的payloads文件，例:-w ./fuzzwords.txt")
            print("-p:设置Fuzz时的代理，例:-p 127.0.0.1:8080")
            print("-t:设置影响认证鉴权的字段，如token、cookie等，例:-t \"{\"token\":\"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0\"}\"")
            print("-j:设置Http报文头中需要替换的字段，token、cookie也可以用此方式代替-t方法，例如:-j ./headers.json")
            print("-n:设置对第n个报文进行单独Fuzz，参照analyseHar.py执行结果，例如:-n 2")
            sys.exit(0)
        else:
            if "-f" == op:
                file = arg
            elif "-w" == op:
            	wordlist = arg
            elif "-p" == op:
            	proxy = arg
            elif "-t" == op:
            	token = arg
            elif "-j" == op:
            	jsonFile = arg
            elif "-n" == op:
            	num = int(arg)
                
    try:
        file
    except NameError:
        print("参数列表：")
        print("-h:显示帮助")
        print("-f:设置Fuzz目标HAR文件，例:-f 10.229.145.118.har")
        print("-w:设置Fuzz的payloads文件，例:-w ./fuzzwords.txt")
        print("-p:设置Fuzz时的代理，例:-p 127.0.0.1:8080")
        print("-t:设置影响认证鉴权的字段，如token、cookie等，例:-t \"{\"token\":\"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0\"}\"")
        print("-j:设置Http报文头中需要替换的字段，token、cookie也可以用此方式代替-t方法，例如:-j ./headers.json")
        print("-n:设置对第n个报文进行单独Fuzz，参照analyseHar.py执行结果，例如:-n 2")
        sys.exit(0)

    if None != token and None != jsonFile:
    	print("-t和-j参数不能同时使用！")
    	sys.exit(0)

    if None != token:
    	headers = dict(token)
    elif None != jsonFile:
    	with open(jsonFile, 'r', encoding='utf-8') as f:
    		headers = json.loads(f.read())
    else:
    	headers = None

    harAnalyzer = HarAnalyzer(file)
    reqsNeedFuzz = harAnalyzer.analyse()
    cmds=[]
    if None != num:
    	if num >= len(reqsNeedFuzz):
    		print("fuzz请求的个数超过最大报文个数")
    		sys.exit(0)
    	cmds = createOneReqFuzzCmds(reqsNeedFuzz[num], proxy, wordlist, headers)
    else:
    	for i in range(len(reqsNeedFuzz)):
    		cmds += createOneReqFuzzCmds(reqsNeedFuzz[i], proxy, wordlist, headers)

    for i in range(len(cmds)):
    	try:
    		print(cmds[i])
    		os.system(cmds[i])
    	except:
    		print("剩余未执行的命令有：")
    		for j in range(i,[len(cmds)]):
    			print(cmds[j])


'''fuzzCmds = fuzzCreater.createBodyFuzz(withHeader=True,specialHeader={"token":"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0"})
    	#print(fuzzCmds)
    	for cmd in fuzzCmds:
    		print(cmd)
    		os.system(cmd)'''