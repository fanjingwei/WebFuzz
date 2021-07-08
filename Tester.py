import unittest
import os
from HarAnalyzer import *
from WFuzzFactory import *

class TestHarAnalyzer(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None

    def test_req_normal(self):
        harAnalyzer = HarAnalyzer("192.168.72.169.har")
        self.assertNotEqual(None, harAnalyzer.getReqById(0))
        #self.assertTrue('FOO'.isupper())
        #with self.assertRaises(TypeError):
        #    s.split(2)

    def test_req_outof_range(self):
        harAnalyzer = HarAnalyzer("192.168.72.169.har")
        self.assertEqual(None, harAnalyzer.getReqById(20))

    def test_req_header_normal(self):
        harAnalyzer = HarAnalyzer("192.168.72.169.har")
        req = harAnalyzer.getReqById(0)
        self.assertEqual(8, len(req.getHeaders()))
        self.assertEqual("http://192.168.72.169:8000/", req.getUrl())
        self.assertEqual("GET", req.getMethod())
        self.assertEqual("HTTP/1.1", req.getHttpVersion())
        req = harAnalyzer.getReqById(1)
        self.assertEqual(2, len(req.getHeaders()))
        self.assertEqual(["Referer:http://192.168.72.169:8000/","User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"], req.getHeaders())

    def test_req_post_fuzz(self):
        harAnalyzer = HarAnalyzer("192.168.72.169.har")
        httpPost = harAnalyzer.getReqById(3)
        fuzzCreater = wfuzzFactory.createFuzzCreater(httpPost)
        fuzzCmds = fuzzCreater.createBodyFuzz()
        self.assertEqual(2,len(fuzzCmds))
        print("\n")
        for cmd in fuzzCmds:
            print(cmd)
            #os.system(cmd)
        self.assertTrue((-1!=fuzzCmds[0].find("\\\"name\\\": FUZZ") or -1!=fuzzCmds[0].find("\\\"password\\\": FUZZ")))
        self.assertTrue(-1!=fuzzCmds[0].find("http://192.168.72.169:8000/BaseInfo"))
        self.assertTrue(fuzzCmds[0].find("-d \"{")<fuzzCmds[0].find("http://192.168.72.169:8000/BaseInfo"))
        self.assertTrue((-1!=fuzzCmds[1].find("\\\"name\\\": FUZZ") or -1!=fuzzCmds[1].find("\\\"password\\\": FUZZ")))

    '''def test_req_post_fuzz_with_json_has_list(self):
        harAnalyzer = HarAnalyzer("10.229.145.118(full).har")
        httpPosts = harAnalyzer.getPostReqs()
        fuzzCreater = wfuzzFactory.createFuzzCreater(httpPosts[0])
        fuzzCmds = fuzzCreater.createBodyFuzz()
        print("\n")
        #for cmd in fuzzCmds:
        #    print(cmd)
            #os.system(cmd)
        self.assertEqual(14,len(fuzzCmds))
        self.assertTrue(-1!=fuzzCmds[0].find("\\\"srcDn\\\": FUZZ"))
        self.assertTrue(-1!=fuzzCmds[1].find("\\\"info\\\": FUZZ"))
        #print(fuzzCmds[2])
        self.assertTrue(-1!=fuzzCmds[2].find("\\\"Projects,EdgeNodeGroups,EdgeNodes\\\": FUZZ"))
        self.assertTrue(-1!=fuzzCmds[3].find("\\\"Projects,EdgeNodeGroups,EdgeNodes\\\": [FUZZ"))
        #self.assertTrue(-1!=fuzzCmds[0].find("http://192.168.72.169:8000/BaseInfo"))
        #self.assertTrue(fuzzCmds[0].find("-d \"{")<fuzzCmds[0].find("http://192.168.72.169:8000/BaseInfo"))
        #self.assertTrue((-1!=fuzzCmds[1].find("\\\"name\\\": FUZZ") or -1!=fuzzCmds[1].find("\\\"password\\\": FUZZ")))'''
        
            

    def test_req_post_fuzz_with_header(self):
        harAnalyzer = HarAnalyzer("192.168.72.169.har")
        httpPost = harAnalyzer.getReqById(3)
        fuzzCreater = wfuzzFactory.createFuzzCreater(httpPost)
        fuzzCmds = fuzzCreater.createBodyFuzz(withHeader=True)
        print("\n")
        for cmd in fuzzCmds:
            print(cmd)
            #os.system(cmd)
        self.assertEqual(2,len(fuzzCmds))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Connection:keep-alive\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Accept:application/json, text/javascript, */*; q=0.01\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"X-Requested-With:XMLHttpRequest\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Content-Type:application/x-www-form-urlencoded; charset=UTF-8\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Origin:http://192.168.72.169:8000\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Referer:http://192.168.72.169:8000/\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Accept-Encoding:gzip, deflate\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Accept-Language:zh-CN,zh;q=0.9\""))

    def test_req_post_fuzz_with_header_replace_by_special_value(self):
        harAnalyzer = HarAnalyzer("192.168.72.169.har")
        httpPost = harAnalyzer.getReqById(3)
        fuzzCreater = wfuzzFactory.createFuzzCreater(httpPost)
        fuzzCmds = fuzzCreater.createBodyFuzz(withHeader=True,specialHeader={"Connection":"closed"})
        print("\n")
        for cmd in fuzzCmds:
            print(cmd)
            #os.system(cmd)
        self.assertEqual(2,len(fuzzCmds))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Connection:closed\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Accept:application/json, text/javascript, */*; q=0.01\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"X-Requested-With:XMLHttpRequest\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Content-Type:application/x-www-form-urlencoded; charset=UTF-8\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Origin:http://192.168.72.169:8000\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Referer:http://192.168.72.169:8000/\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Accept-Encoding:gzip, deflate\""))
        self.assertTrue(-1!=fuzzCmds[0].find("-H \"Accept-Language:zh-CN,zh;q=0.9\""))

    '''def test_req_url_fuzz(self):
        harAnalyzer = HarAnalyzer("10.229.145.118(full).har")
        httpGet = harAnalyzer.getReqById(2)
        fuzzCreater = wfuzzFactory.createFuzzCreater(httpGet)
        fuzzCmds = fuzzCreater.createUrlFuzz()
        self.assertEqual(1,len(fuzzCmds))
        print("\n")
        for cmd in fuzzCmds:
            print(cmd)
            #os.system(cmd)
        self.assertEqual("wfuzz -z file,./fuzzwords.txt -p 127.0.0.1:8080 https://10.229.145.118:30002/api/weblmt/fontawesome-webfont.af7ae505a9eed503f8b8.woff2?v=FUZZ",fuzzCmds[0])

    def test_HarAnalyzer_analy_packet(self):
        harAnalyzer = HarAnalyzer("10.229.145.118(full).har")
        httpGets = harAnalyzer.getGetReqs()
        self.assertEqual(63, len(httpGets))
        httpPosts = harAnalyzer.getPostReqs()
        self.assertEqual(6,len(httpPosts))'''
        


if __name__ == '__main__':
    unittest.main()