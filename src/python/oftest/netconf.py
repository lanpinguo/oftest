"""
OpenFlow Test Framework

netconf class

Provide the interface to the control channel to the switch under test.  

Class inherits from thread so as to run in background allowing
asynchronous callbacks (if needed, not required).  Also supports
polling.

The controller thread maintains a queue.  Incoming messages that
are not handled by a callback function are placed in this queue for 
poll calls.  

Callbacks and polling support specifying the message type

@todo Support transaction semantics via xid
@todo Support select and listen on an administrative socket (or
use a timeout to support clean shutdown).

Currently only one connection is accepted during the life of
the controller.   There seems
to be no clean way to interrupt an accept call.  Using select that also listens
on an administrative socket and can shut down the socket might work.

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
import select
import pexpect 
from threading import Thread
from threading import Lock
from threading import Condition




        
        
class Netconf():
    """
    Class abstracting the control netconf interface to the switch.  
    """
    def __init__(self, switch=None, switch_addr='127.0.0.1', port=830):
        self.CONNECTED = False
        self.CONFIG_OK = False
        self.AVAILABLE = False

        self.child = pexpect.spawn('netopeer-cli')
        self.child.logfile = file('/work/mylog.txt','w')
        (rc , before , after) = self.wait_cmd(expects = ['netconf>'])
        if rc == 0 :
            self.AVAILABLE = True
            
    def wait_cmd(self,expects,timeout = -1):
        try:
            index = self.child.expect(expects)
            #print(index)
            return (index,self.child.before,self.child.after)
        except pexpect.EOF :
            return (-1,"END OF FILE" ,"")
        except pexpect.TIMEOUT :
            return(-1,"Timeout","")
        
    def connect(self):
        if self.AVAILABLE:
            netconf_cmd = "connect --login raisecom " + "192.168.1.11 "
            self.child.sendline(s = netconf_cmd)
            (rc , before , after) = self.wait_cmd(expects = ['netconf>','yes/no','failed.','password:'])
            if rc == 1:
                self.child.sendline(s = "yes")
                (rc , before , after) = self.wait_cmd( expects = ['netconf>','password:'])
                if rc == 1:
                    self.child.sendline(s = "raisecom")
                    (rc , before , after) = self.wait_cmd( expects = ['netconf>']) 
                    if rc == 0:
                        #print("connect sucessfully")
                        self.CONNECTED = True
                        return (0,'connect sucessfully')
            elif rc == 2:
                #print("device is unavailable")
                #print(self.child.before)
                return (-1,'device unavailable')
            elif rc == 3:
                self.child.sendline(s = "raisecom")
                (rc , before , after) = self.wait_cmd( expects = ['netconf>']) 
                if rc == 0:
                    self.CONNECTED = True
                    #print(self.child.before)
                    #print("connect sucessfully")
                    return (0,'connect sucessfully')
            else :
                #print("connect failed")
                #print(self.child.before)
                return (-1,'connect failed')
        else :
            return (-1,'device unavailable')



    def config(self):
        """
        config function for class
        """

        if self.CONNECTED == True:
            netconf_cmd = 'edit-config --config=' + \
            '/work/cmcc_support/ofconfig/pe1-create_tpoam1.xml' + ' candidate'
            self.child.sendline(s = netconf_cmd)
            (rc , before , after) = self.wait_cmd(expects = ['netconf>'])
            if rc == 0 :
                self.CONFIG_OK = False
                if (self.child.before.find('Result OK')) == -1:
                    if self.child.before.find('NETCONF error: data-exists') != -1:
                        return (0,'data-exists')
                else:
                    self.CONFIG_OK = True
                if self.CONFIG_OK :
                    netconf_cmd = 'commit'
                    self.child.sendline(s = netconf_cmd)
                    (rc , before , after) = self.wait_cmd(expects = ['netconf>'])
                    if rc == 0:
                        #print(child.before)
                        #print(child.before.find('Result OK'))
                        if self.child.before.find('Result OK'):
                            return (0,'Result OK')
                        else:
                            return (-1,'Commit Fail')
                else:
                    return (-1,'CONFIG_OK = False')
        else:
            #print("connection is not created")
            return (-1 , "connection is not created")






