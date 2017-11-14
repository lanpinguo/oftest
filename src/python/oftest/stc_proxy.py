# coding:utf-8  
"""
OpenFlow Test Framework

STC class

Provide the interface to the spirent test center to the switch under test.  



"""
  
import rpyc  
import sys  
import time
from threading import Thread
from threading import Lock
from threading import Condition
import logging

    

    
class STC(object):

    def __init__(self,remoteRpcServerIp,port = 6000):
        #self.remote = remote 
        self.logger = logging.getLogger("stc_proxy")
        self.remoteRpcServerIp = remoteRpcServerIp
        self.port = port
        self.remote = None
        try :
            self.remote = rpyc.connect(remoteRpcServerIp,port)  
        except:
            self.logger.info("connect remote chassis failed")

    
    def __del__(self):
        if self.remote:
            self.remote.close() 
        
    def getResult(self):
        timer = 0
        while self.remote.root.isBusy():
            time.sleep(0.1)
            timer += 1
            if timer % 10 == 0 :
                #print ("\r wait time : %d s" % (timer / 10))
                pass
        return self.remote.root.getResult()
    
    def create(self,*args):
        self.remote.root.create(*args)
        return self.getResult()
        
    def config(self,*args):
        self.remote.root.config(*args)
        return self.getResult()        
    
    def get(self,*args):
        self.remote.root.get(*args)
        return self.getResult()

    def subscribe(self,*args):
        self.remote.root.subscribe(*args)
        return self.getResult()
        
    def connect(self,*args):
        self.remote.root.connect(*args)
        return self.getResult()        


    def reserve(self,*args):
        self.remote.root.reserve(*args)
        return self.getResult()     


    def release(self,*args):
        self.remote.root.release(*args)
        return self.getResult()             


    def unsubscribe(self,*args):
        self.remote.root.unsubscribe(*args)
        return self.getResult()  
        
        
    def sleep(self,*args):
        self.remote.root.sleep(*args)
        return self.getResult()  


    def disconnect(self,*args):
        self.remote.root.disconnect(*args)
        return self.getResult()  

    def delete(self,*args):
        self.remote.root.delete(*args)
        return self.getResult()          

        
    def log(self,*args):
        self.remote.root.log(*args)
        return self.getResult()         
        

    def apply(self,*args):
        self.remote.root.apply(*args)
        return self.getResult()  

        
    def perform(self,*args):
        self.remote.root.perform(*args)
        return self.getResult()    





    '''
    API for device operation 
    '''
        
    def dutGetResult(self,timeout = 60000):
        timer = 0
        while self.remote.root.dutIsBusy() and (timer < timeout):
            time.sleep(0.1)
            timer += 0.1
            #print ("wait time : %f s" % timer )

        if timer >= timeout:
            return 'opt_timeout'
        return self.remote.root.dutGetResult()
    
    def dutUpdateSystem(self,dutName,localIp,fileName = None):
        self.remote.root.dutUpdateSystem(dutName,localIp,fileName)
        self.logger.info("dutUpdateSystem")
        return self.dutGetResult()
        
    def dutGetVersion(self,dutName):
        self.remote.root.dutGetVersion(dutName)
        self.logger.info("dutGetVersion")
        return self.dutGetResult()        
    
    def dutBoot(self,dutName):
        self.remote.root.dutBoot(dutName)
        self.logger.info("dutBoot")        
        return self.dutGetResult()  


    def dutGetNewestFile(self,dutName):
        self.remote.root.dutGetNewestFile(dutName)
        self.logger.info("dutGetNewestFile") 
        return self.dutGetResult()          
        
    def dutGetCurrentMode(self,dutName):
        self.remote.root.dutGetCurrentMode(dutName)
        self.logger.info("dutGetCurrentMode") 
        return self.dutGetResult()          

        

        
        
        
