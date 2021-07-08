from HarAnalyzer import *
from WFuzzFactory import *
import os

harAnalyzer = HarAnalyzer("10.229.145.118.har")
httpPost = harAnalyzer.getReqById(0)
fuzzCreater = wfuzzFactory.createFuzzCreater(httpPost)
fuzzCmds = fuzzCreater.createBodyFuzz(withHeader=True,specialHeader={"token":"xIMOeNCPRojr54Zn$hN9l6dWCcI2VxHzPtp98TxFLFwLROAMVRd.Tl08JNKxA0daJ3po5dHnQvPE.DdDdlA.Q8vDnaR9auslxAALJv0"})
#print(fuzzCmds)
for cmd in fuzzCmds:
	print(cmd)
	os.system(cmd)


