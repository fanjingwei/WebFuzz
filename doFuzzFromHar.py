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

 #Ĭ�����python doFuzzFromHar.py -f 10.229.145.118.har -j ./headers.json -n 0

if __name__ =='__main__': 
    opts,args = getopt.getopt(sys.argv[1:],"hf:w:p:t:j:n:")

    token = None
    jsonFile = None
    num = None
    wordlist = "./fuzzwords.txt"
    proxy = None

    for op,arg in opts:
        if "-h" == op:
            print("�����б�")
            print("-h:��ʾ����")
            print("-f:����FuzzĿ��HAR�ļ�����:-f 10.229.145.118.har")
            print("-w:����Fuzz��payloads�ļ�����:-w ./fuzzwords.txt")
            print("-p:����Fuzzʱ�Ĵ�����:-p 127.0.0.1:8080")
            print("-t:����Ӱ����֤��Ȩ���ֶΣ���token��cookie�ȣ���:-t \"{\"token\":\"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0\"}\"")
            print("-j:����Http����ͷ����Ҫ�滻���ֶΣ�token��cookieҲ�����ô˷�ʽ����-t����������:-j ./headers.json")
            print("-n:���öԵ�n�����Ľ��е���Fuzz������analyseHar.pyִ�н��������:-n 2")
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
        print("�����б�")
        print("-h:��ʾ����")
        print("-f:����FuzzĿ��HAR�ļ�����:-f 10.229.145.118.har")
        print("-w:����Fuzz��payloads�ļ�����:-w ./fuzzwords.txt")
        print("-p:����Fuzzʱ�Ĵ�����:-p 127.0.0.1:8080")
        print("-t:����Ӱ����֤��Ȩ���ֶΣ���token��cookie�ȣ���:-t \"{\"token\":\"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0\"}\"")
        print("-j:����Http����ͷ����Ҫ�滻���ֶΣ�token��cookieҲ�����ô˷�ʽ����-t����������:-j ./headers.json")
        print("-n:���öԵ�n�����Ľ��е���Fuzz������analyseHar.pyִ�н��������:-n 2")
        sys.exit(0)

    if None != token and None != jsonFile:
    	print("-t��-j��������ͬʱʹ�ã�")
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
    		print("fuzz����ĸ�����������ĸ���")
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
    		print("ʣ��δִ�е������У�")
    		for j in range(i,[len(cmds)]):
    			print(cmds[j])


'''fuzzCmds = fuzzCreater.createBodyFuzz(withHeader=True,specialHeader={"token":"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0"})
    	#print(fuzzCmds)
    	for cmd in fuzzCmds:
    		print(cmd)
    		os.system(cmd)'''