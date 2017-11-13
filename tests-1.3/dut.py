# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2014 Big Switch Networks, Inc.
"""
device  test cases
"""

import logging
import time
import oftest
from oftest import config
import oftest.base_tests as base_tests
import oftest.advanced_tests as advanced_tests
import ofp
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6

import ofdpa_const as ofdpa
import custom

import oftest.netconf as netconf

import tstc_dp_profiles as STC_DP



        
class BasicDemo(base_tests.DataPlaneOnly):
    """
    dut test 
    """      

    def runTest(self):
        
        self.dutProxy = self.dataplane.stc
        


        self.active = True
        while self.active:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'basic':
                self.checkDutMode()
            if cmd == 'new':
                self.getNewestFile()
            elif cmd == 'update':
                self.updateSystem()
            elif cmd == 'boot':
                self.boot()
            elif cmd == 'all':
                self.checkDutMode()
                self.getNewestFile()
                self.updateSystem()
                self.boot()
                self.active = False                                        
            elif cmd == 'exit':
                self.active = False  
                
                              
    def checkDutMode(self):
        print self.dutProxy.dutGetCurrentMode('iTN167C')  



    def getNewestFile(self):
        print self.dutProxy.dutGetNewestFile('iTN167C') 



    def updateSystem(self):
        print self.dutProxy.dutGetVersion('iTN167C')
        self.dutProxy.dutUpdateSystem('iTN167C','192.168.1.11')        


                 
    def boot(self):
        print self.dutProxy.dutBoot('iTN167C') 



   
 
class BasicCheckMode(base_tests.DataPlaneOnly):
    """
    dut test 
    """      

    def runTest(self):
        
        self.dutProxy = self.dataplane.stc

        '''
        iTN167C
        '''
        self.checkDutMode('iTN167C')
   
        '''
        iTN8000
        '''
        self.checkDutMode('iTN8000')


                              
    def checkDutMode(self,dutName):
        curMode = self.dutProxy.dutGetCurrentMode(dutName)
        print curMode
        return curMode  



    def getNewestFile(self,dutName):
        return self.dutProxy.dutGetNewestFile(dutName) 



    def updateSystem(self,dutName,localIp):
        self.dutProxy.dutGetVersion(dutName)
        return self.dutProxy.dutUpdateSystem(dutName,localIp)        


                 
    def boot(self,dutName):
        return self.dutProxy.dutBoot(dutName) 
        
 
 
class BasicUpdate(base_tests.DataPlaneOnly):
    """
    dut test 
    """      

    def runTest(self):
        
        self.dutProxy = self.dataplane.stc

        '''
        iTN167C
        '''
        self.checkDutMode('iTN167C')
        self.getNewestFile('iTN167C')
        self.updateSystem('iTN167C','192.168.1.11')
        self.boot('iTN167C')
        self.timeout = 10*60  #10 minutes
        
        while 'Login' not in self.checkDutMode('iTN167C'):
            print self.timeout
            time.sleep(5)
            self.timeout -= 5
            if self.timeout <= 0:
                break
             
        assert(self.timeout > 0)
                

        '''
        iTN8000
        '''
        self.checkDutMode('iTN8000')
        self.getNewestFile('iTN8000')
        self.updateSystem('iTN8000','192.168.1.10')
        self.boot('iTN8000')
        self.timeout = 10*60  #10 minutes
        
        while 'Login' not in self.checkDutMode('iTN8000'):
            print self.timeout
            time.sleep(5)
            self.timeout -= 5
            if self.timeout <= 0:
                break
             
        assert(self.timeout > 0)

                              
    def checkDutMode(self,dutName):
        curMode = self.dutProxy.dutGetCurrentMode(dutName)
        print curMode
        return curMode  



    def getNewestFile(self,dutName):
        return self.dutProxy.dutGetNewestFile(dutName) 



    def updateSystem(self,dutName,localIp):
        self.dutProxy.dutGetVersion(dutName)
        return self.dutProxy.dutUpdateSystem(dutName,localIp)        


                 
    def boot(self,dutName):
        return self.dutProxy.dutBoot(dutName) 
        
        
        
        