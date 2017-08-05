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
from threading import Thread
from threading import Lock
from threading import Condition
import logging
from ncclient import manager
from ncclient.xml_ import *
from lxml import etree
      
 
NETCONF_NS      = 'urn:ietf:params:xml:ns:netconf:base:1.0'  
SPTN_SBI_OAM_NS = 'http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam'  

DEFAULT_NS = SPTN_SBI_OAM_NS

qualify = lambda tag, ns=DEFAULT_NS: tag if ns is None else "{%s}%s" % (ns, tag)  
        
CONF_MOD_MEG = """        
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capable-switch xmlns="urn:onf:config:yang"  xmlns:a="urn:ietf:params:xml:ns:netconf:base:1.0">
        <id>openvswitch</id>
        <resources>
        <G.8113.1_MEG xmlns="http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam"  a:operation= '%s' >
            <resource-id>%s</resource-id>
            <index>%s</index>    
            <name>%s</name>
            <managedInstanceType>%s</managedInstanceType>
            <mipCreation>none</mipCreation>
            <Local_MEP>
                <openFlowMpId>%s</openFlowMpId>
                <serveropenFlowMpId>0</serveropenFlowMpId>
                <mepId>%s</mepId>
                <direction>down</direction>
                <enable>true</enable>
                <CCM>
                    <period>3.33MS</period>
                    <enable>true</enable>
                    <phb>CS7</phb>
                </CCM>
            </Local_MEP>
            <Remote_MEP>
                <openFlowMpId>%s</openFlowMpId>
                <mepId>%s</mepId>
            </Remote_MEP>
        </G.8113.1_MEG>
      </resources>
    </capable-switch>
</config>        
"""


CONF_MOD_MLP = """ 
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capable-switch xmlns="urn:onf:config:yang"  xmlns:a="urn:ietf:params:xml:ns:netconf:base:1.0">
        <id>openvswitch</id>
        <resources>
            <MLP_ProtectionGroup xmlns="http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam" a:operation="%s">
                <resource-id>%s</resource-id>
                <index>%s</index> 
                <architecture>1-to-1</architecture> 
                <scheme>uni-directional</scheme>    
                <name>%s</name>
                <revertive>true</revertive>
                <waitToRestore>1</waitToRestore>
                <adminStatus>disable</adminStatus>
                <holdOffTimer>2</holdOffTimer>
                <layer>%s</layer>
                <mlp-head-end-config>
                    <role>working</role>
                    <direction>tx</direction>
                    <liveness-logical-port>%s</liveness-logical-port>
                    <mep>%s</mep>
                </mlp-head-end-config>
                    <mlp-head-end-config>
                    <role>protection</role>
                    <direction>tx</direction>
                    <liveness-logical-port>%s</liveness-logical-port>
                    <mep>%s</mep>
                </mlp-head-end-config>
            </MLP_ProtectionGroup>
        </resources>
    </capable-switch>
</config>    
"""

CONF_MOD_MLP_HEAD_END = """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"> 
    <capable-switch xmlns="urn:onf:config:yang"  xmlns:a="urn:ietf:params:xml:ns:netconf:base:1.0">
        <id>openvswitch</id>
        <resources>
            <MLP_ProtectionGroup xmlns="http://chinamobile.com.cn/sdn/sptn/sbi/schema/oam" >
                <resource-id>%s</resource-id>        
                <mlp-head-end-config a:operation="%s">
                    <role>%s</role>
                    <liveness-logical-port>%s</liveness-logical-port>
                    <mep>%s</mep>                    
                </mlp-head-end-config>        
            </MLP_ProtectionGroup>
        </resources>    
    </capable-switch>
</config>       
"""

        
class Netconf():
    """
    Class abstracting the control netconf interface to the switch.  
    """
    def __init__(self, username="raisecom",password="raisecom",switch=None, switch_addr='127.0.0.1', port=830):
        self.switch_addr = switch_addr
        self.ncPort = port
        self.username = username
        self.password = password
        
        
        
    def connect(self):
        self.mng = manager.connect(host=str(self.switch_addr),port=self.ncPort,username=self.username,password=self.password,hostkey_verify=False)
        if self.mng:    
            return (0,'success')
        else:
            return (-1,'failed')

    def config(self,config):
        """
        config function for class
        """
        with self.mng.locked(target="candidate"):
            self.mng.edit_config(config=config, default_operation="merge", target="candidate")
            self.mng.commit()
        
        return (0,'Result OK')


 

class MEG():
    """
    meg root class
    """
    
    def __init__(self,megIndex,megName,lmepid,rmepid,type=1,localMpId=0):
        
        self.megIndex = megIndex
        self.megName = megName
        self.lmepid = lmepid
        self.rmepid = rmepid
        self.type = type 
      
        self.localMpId = localMpId
            
        if self.type == 1:
            self.managedInstanceType = 'lsp'            
        elif self.type == 2:
            self.managedInstanceType = 'pw'  
               

       
        
    def delete(self):
        self.strConf = CONF_MOD_MEG % ("delete",
                                     str('mpls_meg_'+str(self.megIndex)),
                                     str(self.megIndex),
                                     self.megName,
                                     self.managedInstanceType,
                                     str(self.localMpId),
                                     str(self.lmepid),
                                     str(self.localMpId),
                                     str(self.rmepid)  ) 
        return self.strConf
        
    def updateLocalMpId(self,localMpId):
        self.localMpId = localMpId    
    
    def getConfig(self):
        self.strConf = CONF_MOD_MEG % ("create",
                                     str('mpls_meg_'+str(self.megIndex)),
                                     str(self.megIndex),
                                     self.megName,
                                     self.managedInstanceType,
                                     str(self.localMpId),
                                     str(self.lmepid),
                                     str(self.localMpId),
                                     str(self.rmepid)  )
        return self.strConf
    
        

class MLP_HEAD_END():
    def __init__(self,mepId,liveness_port,role,dir = None):
        self.mepId = mepId
        self.liveness_port = liveness_port
        self.dir = dir
        self.role = role     
        
        
        
        
class MLP():
    """
    mlp root class
    """
    def __init__(self,mlpIndex,mlpName,mlpHeadEnds,layer = 'lsp'):
        self.mlpIndex = mlpIndex
        self.mlpName = mlpName
        self.layer = layer
        self.mlpHeadEnds = mlpHeadEnds
        self.strConf = ''
        
            
    def getConfig(self):
        
        self.strConf = CONF_MOD_MLP % ('create',
                                       str('protection_group_'+str(self.mlpIndex)),
                                       str(self.mlpIndex),
                                       self.mlpName,
                                       self.layer,
                                       str(self.mlpHeadEnds[0].liveness_port),
                                       str(self.mlpHeadEnds[0].mepId),
                                       str(self.mlpHeadEnds[1].liveness_port),
                                       str(self.mlpHeadEnds[1].mepId)                                      
                                       
                                       ) 
        
        return self.strConf
    
    
    def removeMlpHeadEnd(self,mlpHeadEnd):
    
        self.strConf = CONF_MOD_MLP_HEAD_END % (str('protection_group_'+str(self.mlpIndex)),
                                                'delete',
                                                mlpHeadEnd.role,
                                                str(mlpHeadEnd.liveness_port),
                                                str(mlpHeadEnd.mepId)
                                                )
        return self.strConf
        
        
    def replaceMlpHeadEnd(self,mlpHeadEnd):

        self.strConf = CONF_MOD_MLP_HEAD_END % (str('protection_group_'+str(self.mlpIndex)),
                                                'replace',
                                                mlpHeadEnd.role,
                                                str(mlpHeadEnd.liveness_port),
                                                str(mlpHeadEnd.mepId)
                                                )
        return self.strConf
    
        
    def delete(self):

        self.strConf = CONF_MOD_MLP % ('delete',
                                       str('protection_group_'+str(self.mlpIndex)),
                                       str(self.mlpIndex),
                                       self.mlpName,
                                       self.layer,
                                       str(self.mlpHeadEnds[0].liveness_port),
                                       str(self.mlpHeadEnds[0].mepId),
                                       str(self.mlpHeadEnds[1].liveness_port),
                                       str(self.mlpHeadEnds[1].mepId)                                      
                                       
                                       ) 
        
        return self.strConf

        
if __name__ == "__main__":
    """
    self test
    """
    #meg = MEG(megIndex = 1, megName = 'test', lmepid = 10, rmepid = 20 , type=1, localMpId=30)

    mlpHeadEnd_W = MLP_HEAD_END(10,0xF0000000,'working')
    mlpHeadEnd_P = MLP_HEAD_END(20,0xF0000001,'protection')
    mlp = MLP(1,'lsp-aps1',[mlpHeadEnd_W,mlpHeadEnd_P])
    
    #print mlp.getConfig()
    
    print mlp.delete()
    
    