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

try :
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
      
        
class Netconf():
    """
    Class abstracting the control netconf interface to the switch.  
    """
    def __init__(self, switch=None, switch_addr='127.0.0.1', port=830):
        self.CONNECTED = False
        self.CONFIG_OK = False
        self.AVAILABLE = False
        self.switch_addr = switch_addr
        self.child = pexpect.spawn('netopeer-cli')
        logfile = 'netconf-'+ str(switch_addr) + '.log'
        self.child.logfile = file(logfile,'w')
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
            netconf_cmd = "connect --login raisecom " + str(self.switch_addr)
            self.child.sendline(s = netconf_cmd)
            (rc , before , after) = self.wait_cmd(expects = ['netconf>','yes/no','failed.','password:','connect:'])
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
            elif rc == 4:
                if after.find('already connected'):
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



    def config(self,file):
        """
        config function for class
        """

        if self.CONNECTED == True:
            netconf_cmd = 'edit-config --config=' + file + ' candidate'
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


class MEG():
    """
    meg root class
    """
    def __init__(self,megIndex,megName,lmepid,rmepid):
        self.megIndex = megIndex
        self.megName = megName
        self.lmepid = lmepid
        self.rmepid = rmepid 
        try:
            self.tree = ET.parse("ofconfig/tpoam_template.xml")
            self.root = self.tree.getroot()
        except Exception, e:
            print("Error:cannot parse file:tpoam_template.xml")
            sys.exit(1)
        self.fileName = 'ofconfig/tmp/tpoam' + self.megName + '.xml'    
        for res in self.root.findall('{urn:onf:config:yang}resources'):
            g8131_meg = res.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}G.8113.1_MEG')
            resource_id = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}resource-id') 
            resource_id.text = str('mpls_meg_'+str(self.megIndex))
            index = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}index')
            index.text = str(self.megIndex)
            name = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}name')
            name.text = self.megName
            
            
            Local_MEP = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}Local_MEP')
            openFlowMpId = Local_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}openFlowMpId')
            openFlowMpId.text = str(self.lmepid)
            mepId = Local_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mepId')
            mepId.text = str(self.lmepid)
            
            
            Remote_MEP = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}Remote_MEP')
            openFlowMpId = Remote_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}openFlowMpId')
            openFlowMpId.text = str(self.rmepid)
            mepId = Remote_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mepId')
            mepId.text = str(self.rmepid)
        self.tree.write(self.fileName) 
    def delete(self):
        self.fileName = 'ofconfig/tmp/tpoam_delete_' + self.megName + '.xml'    
        for res in self.root.findall('{urn:onf:config:yang}resources'):
            g8131_meg = res.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}G.8113.1_MEG')
            g8131_meg.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'delete'
            #print(g8131_meg.attrib)
            resource_id = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}resource-id') 
            resource_id.text = str('mpls_meg_'+str(self.megIndex))
            index = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}index')
            index.text = str(self.megIndex)
            name = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}name')
            name.text = self.megName
            
            
            Local_MEP = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}Local_MEP')
            openFlowMpId = Local_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}openFlowMpId')
            openFlowMpId.text = str(self.lmepid)
            mepId = Local_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mepId')
            mepId.text = str(self.lmepid)
            
            
            Remote_MEP = g8131_meg.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}Remote_MEP')
            openFlowMpId = Remote_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}openFlowMpId')
            openFlowMpId.text = str(self.rmepid)
            mepId = Remote_MEP.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mepId')
            mepId.text = str(self.rmepid)
        self.tree.write(self.fileName)   
        return self.fileName
        
    def getFileName(self):
        return self.fileName

class MLP_HEAD_END():
    def __init__(self,mepId,liveness_port,dir = None,role = None):
        self.mepId = mepId
        self.liveness_port = liveness_port
        self.dir = dir
        self.role = role     
class MLP():
    """
    mlp root class
    """
    def __init__(self,mlpIndex,mlpName,mlpHeadEnds):
        self.mlpIndex = mlpIndex
        self.mlpName = mlpName
        self.mlpHeadEnds = mlpHeadEnds

        try:
            tree = ET.parse("ofconfig/protection_template.xml")
            root = tree.getroot()
        except Exception, e:
            print("Error:cannot parse file:protection_template.xml")
            sys.exit(1)
        self.fileName = 'ofconfig/tmp/tpoam_' + self.mlpName + '.xml'    
        for res in root.findall('{urn:onf:config:yang}resources'):
            MLP_ProtectionGroup = res.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}MLP_ProtectionGroup')
            resource_id = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}resource-id') 
            resource_id.text = str('protection_group_'+str(self.mlpIndex))
            index = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}index')
            index.text = str(self.mlpIndex)
            name = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}name')
            name.text = self.mlpName
            
            
            mlpHeadEnd = MLP_ProtectionGroup.findall('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mlp-head-end-config')
            liveness_port = mlpHeadEnd[0].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}liveness-logical-port')
            liveness_port.text = str(self.mlpHeadEnds[0].liveness_port)
            mepId = mlpHeadEnd[0].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mep')
            mepId.text = str(self.mlpHeadEnds[0].mepId)

            liveness_port = mlpHeadEnd[1].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}liveness-logical-port')
            liveness_port.text = str(self.mlpHeadEnds[1].liveness_port)
            mepId = mlpHeadEnd[1].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mep')
            mepId.text = str(self.mlpHeadEnds[1].mepId)            
        tree.write(self.fileName)    
    def getFileName(self):
        return self.fileName
    def removeMlpHeadEnd(self,mlpHeadEnd):

        try:
            tree = ET.parse("ofconfig/remove_protection_mep_template.xml")
            root = tree.getroot()
        except Exception, e:
            print("Error:cannot parse file:remove_protection_mep_template.xml")
            sys.exit(1)
        self.fileName = 'ofconfig/tmp/tpoam_remove_mep_' + self.mlpName + '.xml'    
        for res in root.findall('{urn:onf:config:yang}resources'):
            MLP_ProtectionGroup = res.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}MLP_ProtectionGroup')
            resource_id = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}resource-id') 
            resource_id.text = str('protection_group_'+str(self.mlpIndex))
        
            
            mlpEnd = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mlp-head-end-config')
            liveness_port = mlpEnd.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}liveness-logical-port')
            liveness_port.text = str(mlpHeadEnd.liveness_port)
      
        tree.write(self.fileName) 
    def replaceMlpHeadEnd(self,mlpHeadEnd):

        try:
            tree = ET.parse("ofconfig/replace_protection_mep_template.xml")
            root = tree.getroot()
        except Exception, e:
            print("Error:cannot parse file:replace_protection_mep_template.xml")
            sys.exit(1)
        self.fileName = 'ofconfig/tmp/tpoam_replace_mep_' + self.mlpName + '.xml'    
        for res in root.findall('{urn:onf:config:yang}resources'):
            MLP_ProtectionGroup = res.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}MLP_ProtectionGroup')
            resource_id = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}resource-id') 
            resource_id.text = str('protection_group_'+str(self.mlpIndex))
        
            
            mlpEnd = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mlp-head-end-config')
            liveness_port = mlpEnd.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}liveness-logical-port')
            liveness_port.text = str(mlpHeadEnd.liveness_port)
            mepId = mlpEnd.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mep')
            mepId.text = str(mlpHeadEnd.mepId) 
            role = mlpEnd.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}role')
            role.text = mlpHeadEnd.role
        tree.write(self.fileName) 
        
    def delete(self):

        try:
            tree = ET.parse("ofconfig/protection_template.xml")
            root = tree.getroot()
        except Exception, e:
            print("Error:cannot parse file:protection_template.xml")
            sys.exit(1)
        self.fileName = 'ofconfig/tmp/mlp_delete_' + self.mlpName + '.xml'    
        for res in root.findall('{urn:onf:config:yang}resources'):
            MLP_ProtectionGroup = res.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}MLP_ProtectionGroup')
            MLP_ProtectionGroup.attrib['{urn:ietf:params:xml:ns:netconf:base:1.0}operation'] = 'delete'
            resource_id = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}resource-id') 
            resource_id.text = str('protection_group_'+str(self.mlpIndex))
            index = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}index')
            index.text = str(self.mlpIndex)
            name = MLP_ProtectionGroup.find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}name')
            name.text = self.mlpName
            
            
            mlpHeadEnd = MLP_ProtectionGroup.findall('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mlp-head-end-config')
            liveness_port = mlpHeadEnd[0].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}liveness-logical-port')
            liveness_port.text = str(self.mlpHeadEnds[0].liveness_port)
            mepId = mlpHeadEnd[0].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mep')
            mepId.text = str(self.mlpHeadEnds[0].mepId)

            liveness_port = mlpHeadEnd[1].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}liveness-logical-port')
            liveness_port.text = str(self.mlpHeadEnds[1].liveness_port)
            mepId = mlpHeadEnd[1].find('{http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam}mep')
            mepId.text = str(self.mlpHeadEnds[1].mepId)            
        tree.write(self.fileName)  
        return self.fileName

        
if __name__ == "__main__":
    """
    self test
    """

    ends = [MLP_HEAD_END(mepId = 11,liveness_port = 0xF00000008),MLP_HEAD_END(mepId = 12,liveness_port = 0xF00000009)]        
    mlp = MLP(mlpIndex = 5,mlpName = 'MLP_TEST_1',mlpHeadEnds=ends)
    print(mlp.getFileName())
    mlp.delete()
    print(mlp.getFileName())

    
    '''   
    meg = MEG(megIndex = 5,megName = 'meg',lmepid = 20 ,rmepid = 30)
    print(meg.getFileName())
    meg.delete()
    print(meg.getFileName())
    '''    
    
    
    
    
    