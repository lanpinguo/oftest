"""
OpenFlow Test Framework

record class

Provide the interface to record results of per test.  


"""

import sys
import optparse
import logging
import unittest
import time
import os
import imp
import random
import signal
import fnmatch
import copy
#import select
#import pexpect 
#from threading import Thread
#from threading import Lock
#from threading import Condition
#import logging
#from oftest import config

try :
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET



record_prefix = """
<autotest>
"""

record_postfix = """
</autotest>
"""

record_entry_body = """
    <case>
        <testList>
        </testList>
        <failList>
        </failList>
        <startTime>%s</startTime>
        <endTime>%s</endTime> 
        <status>%s</status>
    </case>
"""

record_testName = """

<testName>%s</testName>

"""

class Record():
    """
    Record root class
    """
    
    def __init__(self,record_file = None):
        
        if record_file is None:
            self.record_file = "oft_results.xml"
            #self.record_file = "/work/oftest/oft_results.xml"
        else:
            self.record_file = record_file
            
        self.exist = False

        
        rc = os.path.exists(self.record_file)
        if rc :
            try:
                self.tree = ET.parse(self.record_file)
                self.root = self.tree.getroot()
                self.exist = True
            except Exception, e:
                #logging.info("%s doesn't exist" % self.record_file)
                self.exist = False
                
        if not self.exist:
            record_tree = record_prefix + record_postfix
            self.root = ET.fromstring(record_tree)
            self.tree = ET.ElementTree(self.root)    
            
            
    def addEntry(self,tests,start_time,end_time,status):
        
        self.curRecordEntry = ET.fromstring(record_entry_body % (start_time,end_time,status))
        
        testList = self.curRecordEntry.find("testList")
        for t in tests:
            testName = ET.fromstring(record_testName % t)
            testList.append(testName)
            

            
        self.root.append(self.curRecordEntry)

    def addFailRecord(self,testFail):
        failList = self.curRecordEntry.find("failList")
        testName = ET.fromstring(record_testName % testFail)
        failList.append(testName)
        
        
    def dump(self):
        ET.dump(self.root)
 
        
    def write(self):
         self.tree.write(self.record_file)
    
    
    
    
if __name__ == "__main__":
    """
    self test
    """
    r = Record()
    r.dump()
    
    r.addEntry(["hello","hahah"],time.asctime(),time.asctime(),'fail')
    r.addFailRecord("haha")
    r.dump()
    
    r.write()
    
    
    