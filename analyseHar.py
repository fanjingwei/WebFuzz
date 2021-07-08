from HarAnalyzer import *
from WFuzzFactory import *

import sys,getopt

if __name__ =='__main__': 
    opts,args = getopt.getopt(sys.argv[1:],"hf:")

    for op,arg in opts:
        if "-h" == op:
            print("参数列表：")
            print("-h:显示帮助")
            print("-f:设置需要分析的HAR文件，例:-f 10.229.145.118(full).har")
            sys.exit(0)
        else:
            if "-f" == op:
                file = arg
                
    try:
        file
    except NameError:
        print("参数列表：")
        print("-h:显示帮助")
        print("-f:设置需要分析的HAR文件，例:-f 10.229.145.118(full).har")
        sys.exit(0)

    harAnalyzer = HarAnalyzer(file)
    harAnalyzer.analyse()

