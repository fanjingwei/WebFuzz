from HarAnalyzer import *
from WFuzzFactory import *

import sys,getopt

if __name__ =='__main__': 
    opts,args = getopt.getopt(sys.argv[1:],"hf:")

    for op,arg in opts:
        if "-h" == op:
            print("�����б�")
            print("-h:��ʾ����")
            print("-f:������Ҫ������HAR�ļ�����:-f 10.229.145.118(full).har")
            sys.exit(0)
        else:
            if "-f" == op:
                file = arg
                
    try:
        file
    except NameError:
        print("�����б�")
        print("-h:��ʾ����")
        print("-f:������Ҫ������HAR�ļ�����:-f 10.229.145.118(full).har")
        sys.exit(0)

    harAnalyzer = HarAnalyzer(file)
    harAnalyzer.analyse()

