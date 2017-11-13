# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2014 Big Switch Networks, Inc.
"""
vpws services test cases
"""
import re
import struct
from scapy import volatile  # noqa: E402
from scapy import sendrecv  # noqa: E402
from scapy import config  # noqa: E402
from scapy.layers import l2  # noqa: E402
from scapy.layers import inet  # noqa: E402
from scapy.layers import dhcp  # noqa: E402

# Configuration requires these imports to properly initialize
from scapy import route  # noqa: E402, F401
from scapy import route6  # noqa: E402, F401

import logging
import time
import oftest
from oftest import config
import oftest.base_tests as base_tests
import oftest.advanced_tests as advanced_tests
import ofp
from loxi.pp import pp
import pprint
from oftest.testutils import *
from oftest.parse import parse_ipv6
import ofdpa_const as ofdpa
import oftest.netconf as netconf
import tstc_dp_profiles as STC_DP
import oftest.LLDP_TLV as LLDP_TLV
import oftest.LLDP_Parser as LLDP_Parser


def ofdb_group_type_set(g, x):
    """
    For all Group Types 
    """
    return (((g) & ~0xf0000000) | (((x) & 0xf) << 28))
def ofdb_group_vlanid_set(g, x):
    """
    For Group Types L2 Interface, L2 Multicast, L2 Flood and L3 Multicast
    """
    return(((g) & ~0x0fff0000) | (((x) & 0x0fff) << 16))
def ofdb_group_portid_set(g, x):
    """
    For Group Types L2 Interface
    """
    return(((g) & ~0x0000ffff) | ((x) & 0xffff))
    
def ofdb_group_mpls_index(x):    
    """
    For MPLS Group Sub-Types Label, Interface, protection, Fast Failover/Reroute and L2 Tag  
    """
    return((x) & 0x00ffffff)
def ofdb_group_mpls_index_set(g,x): 
    """
    For MPLS Group Sub-Types Label, Interface, protection, Fast Failover/Reroute and L2 Tag  
    """
    return(((g) & ~0x00ffffff) |  ((x) & 0x00ffffff))
def ofdb_group_mpls_subtype(x):
    """
    For Group Types MPLS Label and Forwarding
    """
    return(((x) & 0x0f000000) >> 24)
def ofdb_group_mpls_subtype_set(g, x):
    """
    For Group Types MPLS Label and Forwarding
    """
    return(((g) & ~0x0f000000) | (((x) & 0x0000000f) << 24))
    
def list2str( mac):
    return ':'.join(["%02x" % x for x in mac])


def lldp_pkt(src,port,systemName,pktlen = 100):
    hwAddr = list2str(src)
    strPort = str(port)
    
    #print(hwAddr)
    #print(strPort)
    
    packet = (
        l2.Ether(dst="01:80:c2:00:00:0e",src=hwAddr,type = 0x88cc) /
        LLDP_TLV.Chassis_ID(macaddr = hwAddr) /
        LLDP_TLV.Port_ID(subtype = 0x07,length = len(strPort) + 1,locallyAssigned = strPort) /
        LLDP_TLV.TTL(seconds = 4919) /
        LLDP_TLV.SystemName(systemName = systemName,length = len(systemName)) /
        LLDP_TLV.EndOfPDU()
    )
    
    #packet = packet/("D" * (pktlen - len(packet)))
    
    return packet    


            
class RES_POOL():
    """
    Global resource pool,manage the mpls label \ liveness port index .etc
    """
    def __init__(self):
        self.livenessPort = 0xF0000000
        self.FailoverGroupIndex = -1
        self.MplsL2VpnGroupIndex = 0
        self.localOpenFlowMpId = 0  
        self.colorBasedCtrId = 0
        self.MplsTunnelLabel1GroupIndex = 0        
        self.MplsInterfaceGroupIndex = 0 
        self.MplsSwapLabelGroupIndex = 0 
                         
    def requestLivenessPortIndex(self):
        self.livenessPort += 1
        #print(self.livenessPort)
        return self.livenessPort
     
    def requestFailoverGroupIndex(self):
        self.FailoverGroupIndex += 1
        #print(self.FailoverGroupIndex)
        return self.FailoverGroupIndex 
     
    def requestMplsL2VpnGroupIndex(self):
        self.MplsL2VpnGroupIndex += 1
        #print(self.MplsL2VpnGroupIndex)
        return self.MplsL2VpnGroupIndex   

    def requestMplsTunnelLabel1GroupIndex(self):
        self.MplsTunnelLabel1GroupIndex += 1
        return self.MplsTunnelLabel1GroupIndex   

    def requestMplsInterfaceGroupIndex(self):
        self.MplsInterfaceGroupIndex += 1
        return self.MplsInterfaceGroupIndex  

    def requestMplsSwapLabelGroupIndex(self):
        self.MplsSwapLabelGroupIndex += 1
        return self.MplsSwapLabelGroupIndex  
 
    def requestOpenFlowMpId(self):
        self.localOpenFlowMpId += 1
        return self.localOpenFlowMpId        

    def requestColorBasedCtrId(self):
        self.colorBasedCtrId += 1
        return self.colorBasedCtrId   


class CAR():
    """
    Global CAR class
    
    @ivar index: The CAR policy index 
    @ivar cir:     
    @ivar cbs:  
    @ivar eir:  
    @ivar colorBlind:
    @ivar mode:
    @ivar ebs: 
    @ivar direction: indicate the applying direction of the car policy.
    """
    def __init__(self,index,cir,cbs,eir,ebs,colorBlind=True,mode=ofdpa.OFDPA_QOS_CAR_MODE_trTCM,\
                 direction=ofdpa.OFDPA_QOS_CAR_DIR_INBOUND):
        self.index = 0x00010000 + index
        self.cir = cir
        self.cbs = cbs
        self.eir = eir
        self.ebs = ebs
        self.mode = mode
        self.colorBlind = colorBlind
        self.direction = direction        
       



class ColorBasedCounter():
    """
    Global ColorBasedCounter class
    
    @ivar index: index into table entry
    @ivar colors: sub-index into table entry 

    """
    def __init__(self,index,color):
        self.index = index
        self.color = color

        
        

class QoS():
    """
    Global Qos class
    
    @ivar index: The Qos index 
    @ivar remarkPattern: The Qos based type ,such as 1-pcp2exp , 2-dscp2exp, 3-exp2pcp,4-exp2dscp 
    @ivar local2exp:  the table recording the relationship between exp , dscp, pcp, etc.
    @ivar car: indicate the speed limitation policy applying to the port.
    @ivar level: indicate the level of qos config , such as 1-pw, 2-lsp, 3-tunnel,etc.
    """
    def __init__(self,index,level=ofdpa.OFDPA_QOS_LEVEL_PW,cars=[],colorMap=[],pcp2tc=[],\
                 tc2pcp=[], tc2exp=[], exp2tc=[], remarkPattern=ofdpa.OFDPA_QOS_MODE_PCP):
        self.index = index
        self.level = level
        self.cars = cars
        self.colorMap = colorMap
        self.pcp2tc = pcp2tc
        self.tc2pcp = tc2pcp
        self.tc2exp = tc2exp
        self.exp2tc = exp2tc
        self.remarkPattern = remarkPattern        
       



class TUNNEL():
    """
    tunnel flow config data model
    """
    def __init__(self,tunnelIndex,lsp_list = [], protMode = ofdpa.OFDPA_PROT_MODE_DISABLE,res = None):
        self.nni2uni = []
        self.uni2nni = []
        self.tunnelIndex = tunnelIndex
        self.livenessPortWorker = None
        self.livenessPortProtector = None
        self.lsp_list = lsp_list
        
        if protMode == ofdpa.OFDPA_PROT_MODE_DISABLE:
            self.bundleHandle = lsp_list[0].bundle_handle()
        elif protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
            '''
            add mpls fast failover group
            '''
            if res is None:
                self.livenessPortWorker = 0xF0000000 + lsp_list[0].lspIndex
                self.livenessPortProtector = 0xF0000000 + lsp_list[1].lspIndex
            else:
                self.livenessPortWorker = res.requestLivenessPortIndex()
                self.livenessPortProtector = res.requestLivenessPortIndex()
            
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_FORWARDING)
            if res is None:
                id = ofdb_group_mpls_index_set(id , self.tunnelIndex)
            else:
                id = ofdb_group_mpls_index_set(id , res.requestFailoverGroupIndex())
            id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_FAST_FAILOVER)
            self.bundleHandle = id
            
            ref_group = lsp_list[0].bundle_handle()
            action_list = [ofp.action.group(group_id = ref_group)  ]                           
            bucket_worker = ofp.bucket(watch_port = self.livenessPortWorker,actions = action_list)
            
            ref_group = lsp_list[1].bundle_handle()
            action_list = [ofp.action.group(group_id = ref_group) ]                           
            bucket_protector = ofp.bucket( watch_port = self.livenessPortProtector,actions = action_list) 

            
            bucket_list = [bucket_worker,bucket_protector]
            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
            self.uni2nni.append(msg)

    def get_flow_db(self):
        return (self.uni2nni,self.nni2uni )
    def bundle_handle(self):
        return self.bundleHandle
    def getMepInfo(self):
        self.worker_mepid = self.lsp_list[0].getLmepId()
        self.protector_mepid = self.lsp_list[1].getLmepId()
        return (self.worker_mepid,self.protector_mepid)
        
        
    def updateLsp(self,oldLsp , newLsp ):
        
        msg = self.uni2nni[0]
        
        '''
        update mpls fast failover group
        '''

        if msg.buckets[0].watch_port == 0xF0000000 + oldLsp.lspIndex:
            self.livenessPortWorker = 0xF0000000 + newLsp.lspIndex
            ref_group = newLsp.bundle_handle()
            self.lsp_list[0] = newLsp #update record
            action_list = [ofp.action.group(group_id = ref_group)  ]                           
            bucket_worker = ofp.bucket(watch_port = self.livenessPortWorker,actions = action_list)
            bucket_protector = msg.buckets[1]    
        elif msg.buckets[1].watch_port == 0xF0000000 + oldLsp.lspIndex:
            self.livenessPortProtector = 0xF0000000 + newLsp.lspIndex
            ref_group = newLsp.bundle_handle()
            self.lsp_list[1] = newLsp #update record
            action_list = [ofp.action.group(group_id = ref_group) ]                           
            bucket_protector = ofp.bucket( watch_port = self.livenessPortProtector,actions = action_list) 
            bucket_worker = msg.buckets[0]    
        else:
            return ([],[]) #old lsp not in the tunnel
        bucket_list = [bucket_worker,bucket_protector]
        newMsg = ofp.message.group_mod(
            command =ofp.OFPGC_MODIFY,
            group_type=ofp.OFPGT_INDIRECT,
            group_id= msg.group_id,
            buckets= bucket_list)
        self.uni2nni[0] = newMsg #update record
        
        return ([newMsg],[])

            
class LSP():
    """
    lsp flow config data model
    """
    def __init__(self,lspIndex, inLabel, outLabel, nniPort, portMac, dstMac, nniVlan = None,Qos = None, colorBasedCtr = None,res = None):
        
        assert(lspIndex != None)
        assert(inLabel != None)
        assert(outLabel != None)
        assert(nniPort != None)
        assert(portMac != None)
        assert(dstMac != None)
                
        self.nni2uni = []
        self.uni2nni = []
        self.Oam_nni2uni = []
        self.Oam_uni2nni = []
        self.lspIndex = lspIndex
        self.inLabel = inLabel
        self.outLabel = outLabel
        self.nniPort = nniPort
        self.bundleHandle = None
        self.nni_vlan = nniVlan
        self.nni_port = nniPort
        self.port_mac = portMac
        self.dst_mac = dstMac
        self.mpls_interface_group_id  = None
        self.meg = None
        self.staLspRxObj = None
        self.staLspTxObj = None
        self.qosApplyMode = 0   
        if Qos is None:
            self.Qos = None
        else:
            self.Qos = Qos 
            if Qos.level == ofdpa.OFDPA_QOS_LEVEL_LSP:
                if Qos.remarkPattern == ofdpa.OFDPA_QOS_MODE_PCP: 
                    self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_PCP
                elif Qos.remarkPattern == ofdpa.OFDPA_QOS_MODE_DSCP:
                    self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_DSCP
        
        self.colorBasedCtr = colorBasedCtr
        
        '''
        add l2 interface group
        '''
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
        id = ofdb_group_vlanid_set(id , self.nni_vlan)
        id = ofdb_group_portid_set(id , self.nni_port)
        action_list = [ofp.action.output(self.nni_port) ]#, ofp.action.pop_vlan()]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)
        
        '''
        add mpls interface group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        if res is None:
            id = ofdb_group_mpls_index_set(id , self.lspIndex)
        else:
            id = ofdb_group_mpls_index_set(id , res.requestMplsInterfaceGroupIndex())  
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_INTERFACE)
        self.mpls_interface_group_id = id
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.set_field(ofp.oxm.eth_src(value = self.port_mac)) ,
                       ofp.action.set_field(ofp.oxm.eth_dst(value = self.dst_mac)) ,
                       ofp.action.set_field(ofp.oxm.vlan_vid(value = self.nni_vlan)) ]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)


        '''
        Add uni2nni color based counter 
        '''
        if self.colorBasedCtr:
            ctr1 = colorBasedCtr[0]
            msg_ctr = ofp.message.sptn_color_based_ctr_add(block_index=ctr1.index,transmit_packets=0,receive_packets=0,color=ctr1.color)
            self.uni2nni.append(msg_ctr)
               


        '''
        add mpls tunnel label 1 group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , self.lspIndex)
        if res is None:
            id = ofdb_group_mpls_index_set(id , self.lspIndex)
        else:
            id = ofdb_group_mpls_index_set(id , res.requestMplsTunnelLabel1GroupIndex())          
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_TUNNEL_LABEL1)
        self.bundleHandle = id
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.push_mpls(ethertype = 0x8847) ,
                       ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)) ,
                       ofp.action.copy_ttl_out() ]
 
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP \
            or self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            #actionRemarkMplsTc = ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00 ])
            actionRemarkMplsTc = ofp.action.sptn_act_set_mpls_tc_from_tunnel_table(qos_index=1,traffic_class = 0, color = 0)
            action_list.append(actionRemarkMplsTc)
        else :
            action_list.append(ofp.action.set_field(ofp.oxm.mpls_tc(value = 0)))


        if self.colorBasedCtr:
            actionSptnActColorBasedCtr = ofp.action.sptn_act_color_based_ctr( color = self.colorBasedCtr[0].color,
                                                                              index = self.colorBasedCtr[0].index )
            action_list.append(actionSptnActColorBasedCtr)

        bucket_list = [ofp.bucket(actions = action_list)]
        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)
        self.staLspTxObj = msg
  
        '''
        temporarily place here
        '''
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP \
            or self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            for i in range(8):
                traffic_class = i 
                msg = ofp.message.sptn_mpls_tunnel_label_remark_action_add(index=2,traffic_class=traffic_class,color=1,mpls_tc=Qos.tc2exp[i],vlan_pcp=0,vlan_dei=0)
                self.uni2nni.append(msg)     
  
        '''
        Add vlan table entry
        '''
        table_id =  ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(self.nni_port),
            ofp.oxm.vlan_vid(self.nni_vlan)
        ])
        
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC),
        ]
        priority = 0

        logging.info("Inserting vlan flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.nni2uni.append(msg)
        
        '''
        Add termination mac table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC
        match = ofp.match([
            ofp.oxm.in_port(self.nni_port),
            ofp.oxm.eth_dst(value = self.port_mac),
            ofp.oxm.eth_type(value = 0x8847),            
        ])
        
        instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1),
        ]
        priority = 0

        logging.info("Inserting termination mac flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.nni2uni.append(msg)
        
        '''
        add nni2uni color based counter
        '''
        if self.colorBasedCtr:
            ctr2 = colorBasedCtr[1]
            msg_ctr = ofp.message.sptn_color_based_ctr_add(block_index=ctr2.index,transmit_packets=0,receive_packets=0,color=ctr2.color)
            self.nni2uni.append(msg_ctr)
        
        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = self.inLabel),
            ofp.oxm.mpls_bos(value = 0),
        ])
        
   
        
        instructions=[
            ofp.instruction.apply_actions(actions = [ofp.action.pop_mpls(ethertype = 0x8847)]),
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_2)
        ]
        
        if self.colorBasedCtr:
            actionSptnActColorBasedCtr_flow = ofp.action.sptn_act_color_based_ctr( color = self.colorBasedCtr[1].color,\
                                                                              index = self.colorBasedCtr[1].index )
            instructions.append(ofp.instruction.write_actions(actions = [actionSptnActColorBasedCtr_flow]))
            
        priority = 0

        logging.info("Inserting  mpls 1 flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.nni2uni.append(msg)
        self.staLspRxObj = msg
        
    def addOam(self,meg):    
        ####################################################################################
        #
        # Create oam
        #
        ####################################################################################        

        self.meg = meg
            
        '''
        Add Flow
        '''
        '''
        Add mpls maintenance point table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8902),            
            ofp.oxm.mpls_tp_mp_id(value = meg.localOfMpId),
            ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
        ])
        
        '''
        apply actions 
        '''
        apy_actions = [ofp.action.output(port = ofp.OFPP_LOCAL ,max_len = 0xffff) ,
        ]
        instructions=[
            #ofp.instruction.clear_actions(),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 0

        logging.info("Inserting mpls maintenance point flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.Oam_nni2uni.append(msg)
        

        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = self.inLabel),
            ofp.oxm.mpls_bos(value = 0),
            ofp.oxm.mpls_tp_ach_channel(value = 0x8902),
            ofp.oxm.mpls_tp_data_first_nibble(value = 1),
            ofp.oxm.mpls_tp_next_label_is_gal(value = 1)
        ])
        
        action = [ofp.action.pop_mpls(ethertype = 0x8847),
            ofp.action.set_field(ofp.oxm.mpls_tp_mp_id(value = meg.localOfMpId)),
            ofp.action.pop_mpls(ethertype = 0x8902),
            ofp.action.sptn_pop_cw_or_ach()
            #ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
        ]
        instructions=[
            ofp.instruction.apply_actions(actions = action),
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT),
        ]
        priority = 0

        logging.info("Inserting  mpls 1 flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.Oam_nni2uni.append(msg)

        '''
        Add injected oam table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_INJECTED_OAM
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8902),            
            ofp.oxm.mpls_tp_mp_id(value = meg.localOfMpId),
            ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
        ])
        
        aply_action = [ofp.action.push_mpls(ethertype = 0x8847),
            ofp.action.set_field(ofp.oxm.mpls_label(value = 13)),
            ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
            ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),
            #ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]), #push cw
            ofp.action.sptn_push_cw(),
            ofp.action.set_field(ofp.oxm.mpls_tp_data_first_nibble(value = 1)),
            ofp.action.set_field(ofp.oxm.mpls_tp_ach_channel(value = 0x8902)),
            ofp.action.push_mpls(ethertype = 0x8847),
            ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)),
            ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),          
            ofp.action.set_field(ofp.oxm.vlan_pcp(value = 1)),            
        ]
        
        write_action = [ ofp.action.group(group_id = self.mpls_interface_group_id),            
        ]
        instructions=[
            ofp.instruction.apply_actions(actions = aply_action),
            ofp.instruction.write_actions(actions = write_action),
        ]
        priority = 0

        logging.info("Inserting injected oam table flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.Oam_uni2nni.append(msg)
        
        return (self.Oam_uni2nni, self.Oam_nni2uni)

    def getLmepId(self):
        '''
        need return local mpId
        '''
        return self.meg.localOfMpId
    def get_flow_db(self):
        return ( self.uni2nni,self.nni2uni)
    def get_oam_flow_db(self):
        return ( self.Oam_uni2nni,self.Oam_nni2uni,self.meg)        
    def set(self,requset):
        pass
    def bundle_handle(self):
        return self.bundleHandle

class PW():
    """
    pw flow config data model
    """
    def __init__(self,pwIndex,inLabel,outLabel,uniPort,tunnel, uniVlan = [],ivid = [],\
                   Qos = None,protMode=0,inLabelPro=None,outLabelPro=None,tunnelPro=None,\
                   res = None, ACMode=None):
        self.nni2uni = []
        self.uni2nni = []
        self.Oam_nni2uni = []
        self.Oam_uni2nni = []
        self.OamPro_nni2uni = []
        self.OamPro_uni2nni = []
        self.stat = []
        self.inLabel = inLabel
        self.outLabel = outLabel
        self.tunnel_handle = tunnel.bundle_handle()
        self.inLabelPro = inLabelPro
        self.outLabelPro = outLabelPro
        self.ACMode = ACMode
        if tunnelPro is None:
            self.tunnel_handlePro = None
        else:
            self.tunnel_handlePro = tunnelPro.bundle_handle() 
        self.uniPort = uniPort
        self.protMode = protMode
        
        self.qosApplyMode = 0 
        self.qosCars = []  
        if Qos is None:
            self.Qos = None
        else:
            self.Qos = Qos 
            if Qos.level == 1:
                if Qos.remarkPattern == ofdpa.OFDPA_QOS_MODE_PCP: 
                    self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_PCP
                elif Qos.remarkPattern == ofdpa.OFDPA_QOS_MODE_DSCP:
                    self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_DSCP
                if len(Qos.cars) != 0:
                    self.qosCars = Qos.cars
        self.uniVlan = []
        for vlan in uniVlan:
            if vlan != 0:
                vlan |= ofdpa.OFDPA_VID_PRESENT
            self.uniVlan.append(vlan)
        self.ivid = []
        for vlan in ivid:
            if vlan != 0:
                vlan |= ofdpa.OFDPA_VID_PRESENT
            self.ivid.append(vlan)
    
        self.pwIndex = pwIndex
        self.local_mpls_l2_port  = 0x00000000 + pwIndex      
        self.network_mpls_l2_port = 0x00020000 + pwIndex       
        self.tunnel_id = 0x00010000 + pwIndex
        self.livenessPortWorker = 0
        self.livenessPortProtector = 0
        if res and protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
            self.livenessPortWorker = res.requestLivenessPortIndex()
            self.livenessPortProtector = res.requestLivenessPortIndex()
      
        self.staPwProRxObj = None
        self.staPwProTxObj = None
        self.staPwRxObj = None
        self.staPwTxObj = None
        self.staAcRxObj = None
        self.staAcTxObj = None     
        ####################################################################################
        #
        # Create pw
        #
        ####################################################################################   
        
           
        '''
        add l2 interface group
        '''
        id = 0
        if self.uniVlan[0] == 0:
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_UNFILTERED_INTERFACE)
        else:
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
        id = ofdb_group_vlanid_set(id , self.uniVlan[0] )
        id = ofdb_group_portid_set(id , self.uniPort)
        action_list = [ofp.action.output(self.uniPort) ,
            ofp.action.set_field(ofp.oxm.mpls_tp_allow_vlan_translation()) ,
        ]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.nni2uni.append(msg)
        self.staAcTxObj = msg
        
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP or \
            self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            for i in range(8):
                '''
                Add Egress DSCP PCP Remark table entry
                '''
                pcpvalue = self.Qos.tc2pcp[i]
                table_id = ofdpa.OFDPA_FLOW_TABLE_ID_EGRESS_DSCP_PCP_REMARK
                match = ofp.match([
                    ofp.oxm.mpls_tp_actset_output(value = self.uniPort),
                    ofp.oxm.mpls_tp_traffic_class(value=i) ,   
                    ofp.oxm.mpls_tp_color(value = 0)
                ])
                
                if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
                    match = ofp.match([
                        ofp.oxm.eth_type(value = 0x0800),
                        ofp.oxm.mpls_tp_actset_output(value = self.uniPort),
                        ofp.oxm.mpls_tp_traffic_class(value=i) ,   
                        ofp.oxm.mpls_tp_color(value = 1)
                     ])                    
                
                '''
                apply actions
                '''
                traffic_class = i 
                apy_actions = []
                if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP:
                    apy_actions = [ ofp.action.set_field(ofp.oxm.vlan_pcp(value=pcpvalue)),
                                   ofp.action.set_field(ofp.oxm.vlan_dei(value=0))    
                    ]
                elif self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
                    apy_actions = [ofp.action.set_field(ofp.oxm.ip_dscp(value=(i<<3)))]      
                   
                instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_EGRESS_TPID),
                    ofp.instruction.apply_actions(actions = apy_actions),
                ]
                priority = 0
        
                logging.info("Inserting Egress DSCP PCP Remark table")
                msg = ofp.message.flow_add(
                        table_id=table_id,
                        match=match,
                        instructions=instructions,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        priority=priority,
                        flags=ofp.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        out_port = ofp.OFPP_ANY, 
                        out_group = ofp.OFPG_ANY,
                        hard_timeout=0,
                        idle_timeout=0)
                self.nni2uni.append(msg)
        
        
        
        
        
        '''
        Add Flow
        '''
               
        if protMode is None or protMode == ofdpa.OFDPA_PROT_MODE_DISABLE:            
            '''
            Add mpls 1 table entry
            '''
            print("normal vpws")
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8847),            
                ofp.oxm.mpls_label(value = self.inLabel),
                ofp.oxm.mpls_bos(value = 1),
            ])
            
            '''
            apply actions
            '''
            #add pop_vlan action for gw test , but there is not the action in sptn standard ttp  
            apy_actions = [ofp.action.pop_mpls(ethertype = 0x8847) ,
                ofp.action.pop_vlan() ,
                ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
                #ofp.action.pop_vlan() ,
                ofp.action.sptn_pop_l2_header(),
                #ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00 ]),
                ofp.action.sptn_pop_cw_or_ach(),
                #ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.network_mpls_l2_port)) ,        
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,        
            ]
            
            gototable = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE
            if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP or \
                self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
                
                apy_actions.append(ofp.action.set_field(ofp.oxm.mpls_tp_qos_index(value = 1)))
                # Add copy field action
                apy_actions.append(ofp.action.experimenter(experimenter = 0x4F4E4600, data = [0x0c,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ]))
                gototable = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_LABEL_TRUST
            
            instructions=[
                ofp.instruction.goto_table(gototable),
                ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
                ofp.instruction.apply_actions(actions = apy_actions),
            ]
            priority = 0
    
            logging.info("Inserting  mpls 1 flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.nni2uni.append(msg)     
            self.staPwRxObj = msg


            if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP or \
                self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
                for i in range(8):
                    '''
                    Add mpls label trust table entry
                    '''
                    expvalue = self.Qos.exp2tc[i]
                    table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_LABEL_TRUST
                    match = ofp.match([
                        ofp.oxm.mpls_tp_qos_index(value = 1),
                        ofp.oxm.packet_regs_0(value=i)           
                    ])
                    
                    '''
                    apply actions
                    '''
                    
                    apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_color(value = 0)) ,
                        ofp.action.set_field(ofp.oxm.mpls_tp_traffic_class(value = expvalue)) ,   
                    ]
                    instructions=[
                        ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
                        ofp.instruction.apply_actions(actions = apy_actions),
                    ]
                    priority = 0
            
                    logging.info("Inserting  mpls label trust table")
                    msg = ofp.message.flow_add(
                            table_id=table_id,
                            match=match,
                            instructions=instructions,
                            buffer_id=ofp.OFP_NO_BUFFER,
                            priority=priority,
                            flags=ofp.OFPFF_SEND_FLOW_REM,
                            cookie=0,
                            out_port = ofp.OFPP_ANY, 
                            out_group = ofp.OFPG_ANY,
                            hard_timeout=0,
                            idle_timeout=0)
                    self.nni2uni.append(msg)
        

        elif protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
            '''
            Add mpls 1 table entry for work
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8847),            
                ofp.oxm.mpls_label(value = self.inLabel),
                ofp.oxm.mpls_bos(value = 1),
            ])
            
            '''
            apply actions
            '''
            apy_actions = [ofp.action.pop_mpls(ethertype = 0x8847) ,
                ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
                ofp.action.set_field(ofp.oxm.mpls_tp_protection_index(value = 1)) ,
                #ofp.action.pop_vlan() ,
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00 ]),
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.network_mpls_l2_port)) ,        
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,        
            ]
            instructions=[
                ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
                ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
                ofp.instruction.apply_actions(actions = apy_actions),
            ]
            priority = 0
    
            logging.info("Inserting  mpls 1 flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.nni2uni.append(msg) 
            self.staPwRxObj = msg    
            

            '''
            Add mpls 1 table entry for protection
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8847),            
                ofp.oxm.mpls_label(value = self.inLabelPro),
                ofp.oxm.mpls_bos(value = 1),
            ])
            
            '''
            apply actions
            '''
            apy_actions = [ofp.action.pop_mpls(ethertype = 0x8847) ,
                ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
                ofp.action.set_field(ofp.oxm.mpls_tp_protection_index(value = 0)) ,
                #ofp.action.pop_vlan() ,
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00 ]),
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.network_mpls_l2_port)) ,        
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,        
            ]
            instructions=[
                ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
                ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
                ofp.instruction.apply_actions(actions = apy_actions),
            ]
            priority = 0
    
            logging.info("Inserting  mpls 1 flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.nni2uni.append(msg)     
            self.staPwProRxObj = msg


        
        '''
        add mpls vpn group
        '''
        ref_group = self.tunnel_handle
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , res.requestMplsL2VpnGroupIndex())
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_L2_VPN_LABEL)
        action_list = [ofp.action.group(group_id = ref_group) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.push_mpls(ethertype = 0x8847) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)) ,
           ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
           #ofp.action.set_field(ofp.oxm.mpls_tc(value = 1)),
           ofp.action.set_mpls_ttl(mpls_ttl = 255)
        ]
        
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP or \
            self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            #actionRemarkMplsTc = ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x07,0x00,0x01,0x00,0x00,0x00,0x00 ])
            actionRemarkMplsTc = ofp.action.sptn_act_set_mpls_tc_from_vpn_table(qos_index=1,traffic_class = 0, color = 0)
            action_list.append(actionRemarkMplsTc)

        
        bucket_list = [ofp.bucket(actions = action_list)]
        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)     
        self.staPwTxObj = msg
        self.vpnGroupWork = id
        
        '''
        temporarily place here
        '''
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP or \
            self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            for i in range(8):
                traffic_class = i 
                tc2exp_value = self.Qos.tc2exp[i]
                msg = ofp.message.sptn_mpls_vpn_label_remark_action_add(index=1,traffic_class=tc2exp_value,color=0,mpls_tc=traffic_class,vlan_pcp=0,vlan_dei=0)
                self.uni2nni.append(msg)   
            
            
        if protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
            '''
            add mpls vpn group for protection 
            '''
            ref_groupPro = self.tunnel_handlePro
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
            id = ofdb_group_mpls_index_set(id , res.requestMplsL2VpnGroupIndex())
            id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_L2_VPN_LABEL)
            self.vpnGroupProtect = id
            action_list = [ofp.action.group(group_id = ref_groupPro) ,
               ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 ]),
               ofp.action.push_mpls(ethertype = 0x8847) ,
               ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]),
               ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabelPro)) ,
               ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
               ofp.action.set_field(ofp.oxm.mpls_tc(value = 1)),
               ofp.action.set_mpls_ttl(mpls_ttl = 255)
            ]
            bucket_list = [ofp.bucket(actions = action_list)]
            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
            self.uni2nni.append(msg)     
            self.staPwProTxObj = msg   
            
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_FORWARDING)
            id = ofdb_group_mpls_index_set(id , res.requestFailoverGroupIndex())
            id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_FAST_FAILOVER)
            
            ref_group = self.vpnGroupWork
            action_list = [ofp.action.group(group_id = ref_group)  ]                           
            bucket_worker = ofp.bucket(watch_port = self.livenessPortWorker,actions = action_list)
            
            ref_group = self.vpnGroupProtect
            action_list = [ofp.action.group(group_id = ref_group) ]                           
            bucket_protector = ofp.bucket( watch_port = self.livenessPortProtector,actions = action_list) 

            
            bucket_list = [bucket_worker,bucket_protector]
            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
            self.uni2nni.append(msg)             

        '''
        Add mpls l2 port table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT
        match = ofp.match([
            ofp.oxm.tunnel_id(value = self.tunnel_id),
            #ofp.oxm.eth_type_masked(value = 0x0800, value_mask = 0xffff),
            ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port),            
        ])
            
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP:
            match = ofp.match([
                ofp.oxm.tunnel_id(value = self.tunnel_id),
                #ofp.oxm.eth_type_masked(value = 0x0800, value_mask = 0xffff),
                ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port),            
            ])
        elif self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            match = ofp.match([
                ofp.oxm.tunnel_id(value = self.tunnel_id),
                ofp.oxm.eth_type(value = 0x0800),
                ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port),            
            ])
        
        '''
        apply actions
        '''
        apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_qos_index(value = 1)) ,
        ]
        
        goto_table = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP:
            goto_table = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST
        elif self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            goto_table = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST
        
        instructions=[
            ofp.instruction.goto_table(goto_table),
            ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 0

        logging.info("Inserting  mpls l2 port flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.uni2nni.append(msg)
        self.staAcRxObj = msg
        
        for car in self.qosCars:
            if car.direction == ofdpa.OFDPA_QOS_CAR_DIR_INBOUND:
                
                '''
                Add meter mod table entry
                '''  
                meter_id = car.index       
                meters = [ofp.meter_band.experimenter( rate=car.eir, burst_size=car.ebs, 
                                                       experimenter=0x1018,
                                                       extra=[0x00,0x01,0x01,0x01,0x02,0x00,0x00,0x00]),
                          ofp.meter_band.experimenter( rate=car.cir, burst_size=car.cbs, 
                                                       experimenter=0x1018,
                                                       extra=[0x00,0x01,0x01,0x01,0x01,0x00,0x00,0x00])]
                          
                logging.info("Inserting  meter mod table ")
                msg = ofp.message.meter_mod(
                            meters=meters,
                            flags=ofp.OFPMF_KBPS,
                            meter_id=meter_id
                        )
                self.uni2nni.append(msg)


                '''
                Add mpls l2 policy action table entry
                '''
                table_id = ofdpa.OFDPA_FLOW_TABLE_ID_L2_POLICER_ACTIONS
                match = ofp.match([
                    ofp.oxm.mpls_tp_color_actions_index(value = 1),
                    ofp.oxm.mpls_tp_color(value = ofdpa.OFDPA_QOS_COLOR_RED),            
                ])
                
               
                instructions=[
                    ofp.instruction.clear_actions(),
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),              
                ]
                priority = 2
        
                logging.info("Inserting  mpls l2 policy action flow table")
                msg = ofp.message.flow_add(
                        table_id=table_id,
                        match=match,
                        instructions=instructions,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        priority=priority,
                        flags=ofp.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        out_port = ofp.OFPP_ANY, 
                        out_group = ofp.OFPG_ANY,
                        hard_timeout=0,
                        idle_timeout=0)
                self.uni2nni.append(msg) 
                                
                '''
                Add mpls l2 policy table entry
                '''
                table_id = ofdpa.OFDPA_FLOW_TABLE_ID_L2_POLICER
                match = ofp.match([
                    ofp.oxm.tunnel_id(value = self.tunnel_id),
                    ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port),            
                ])
                
                '''
                apply actions
                '''
                apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_color_actions_index(value = 1)) ,    
                ]
                instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_L2_POLICER_ACTIONS),
                    ofp.instruction.apply_actions(actions = apy_actions),
                    ofp.instruction.meter(meter_id=meter_id), 
                ]
                priority = 2
        
                logging.info("Inserting  mpls l2 policy flow table")
                msg = ofp.message.flow_add(
                        table_id=table_id,
                        match=match,
                        instructions=instructions,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        priority=priority,
                        flags=ofp.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        out_port = ofp.OFPP_ANY, 
                        out_group = ofp.OFPG_ANY,
                        hard_timeout=0,
                        idle_timeout=0)
                self.uni2nni.append(msg)
        
        
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_PCP:
            for i in range(8):
                '''
                Add mpls pcp trust table entry
                '''
                pcp2tc_value = self.Qos.pcp2tc[i]
                table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST
                match = ofp.match([
                    ofp.oxm.mpls_tp_qos_index(value = self.Qos.index),
                    ofp.oxm.vlan_vid_masked(value=0x1000,value_mask=0x1000),
                    ofp.oxm.vlan_pcp(value=pcp2tc_value),
                    ofp.oxm.vlan_dei(value=0)            
                ])
                
                '''
                apply actions
                '''
                traffic_class = i
                apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_color(value = 0)) ,
                            ofp.action.set_field(ofp.oxm.mpls_tp_traffic_class(value = traffic_class)) ,   
                ]
                instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_QOS_CLASS),
                    ofp.instruction.apply_actions(actions = apy_actions),
                ]
                priority = 0
        
                logging.info("Inserting  mpls pcp trust flow table")
                msg = ofp.message.flow_add(
                        table_id=table_id,
                        match=match,
                        instructions=instructions,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        priority=priority,
                        flags=ofp.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        out_port = ofp.OFPP_ANY, 
                        out_group = ofp.OFPG_ANY,
                        hard_timeout=0,
                        idle_timeout=0)
                self.uni2nni.append(msg)
                
        elif self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_DSCP:
            for i in range(8):
                '''
                Add mpls dscp trust table entry
                '''
                table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST
                match = ofp.match([
                    ofp.oxm.mpls_tp_qos_index(value = 1),
                    ofp.oxm.eth_type(value=0x0800),
                    ofp.oxm.ip_dscp(value=(i<<3)),
                ])
                
                '''
                apply actions
                '''
                traffic_class = i 
                apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_color(value = 1)) ,
                            ofp.action.set_field(ofp.oxm.mpls_tp_traffic_class(value = traffic_class)) ,   
                ]
                instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_QOS_CLASS),
                    ofp.instruction.apply_actions(actions = apy_actions),
                ]
                priority = 0
        
                logging.info("Inserting  mpls dscp trust flow table")
                msg = ofp.message.flow_add(
                        table_id=table_id,
                        match=match,
                        instructions=instructions,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        priority=priority,
                        flags=ofp.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        out_port = ofp.OFPP_ANY, 
                        out_group = ofp.OFPG_ANY,
                        hard_timeout=0,
                        idle_timeout=0)
                self.uni2nni.append(msg)
                
            
            
        if len(ivid) != 0:
            '''
            Add vlan 1 table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN_1
            match = ofp.match([
                ofp.oxm.in_port(self.uniPort),
                ofp.oxm.vlan_vid(self.ivid[0]),
                ofp.oxm.mpls_tp_ovid(value = self.uniVlan[0])                
            ])
            
            '''
            apply actions
            '''
            apy_actions = [
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,
                ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
                ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port)) ,
            
            ]
            
            gotable = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT 
            instructions=[
                ofp.instruction.goto_table(gotable),
                ofp.instruction.apply_actions(actions = apy_actions),
            ]
            priority = 0
    
            logging.info("Inserting vlan 1 flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.uni2nni.append(msg)

        
        '''
        Add vlan table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        
        if ACMode == 'Port':
		    match = ofp.match([
                ofp.oxm.in_port(self.uniPort),
                ofp.oxm.vlan_vid_masked(value = self.uniVlan[0],value_mask = 0)])
        else:
			match = ofp.match([
                ofp.oxm.in_port(self.uniPort),
                ofp.oxm.vlan_vid(self.uniVlan[0])])
        
        '''
        apply actions
        '''
        apy_actions = [
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,
            ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port)) ,
        
        ]  
        
 
        gotable = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT
        
         
        if len(ivid) != 0:
           apy_actions = [
               ofp.action.set_field(ofp.oxm.mpls_tp_ovid(value = self.uniVlan[0])), 
               ofp.action.pop_vlan()
           ]
           gotable = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN_1 
           

        instructions=[
            ofp.instruction.goto_table(gotable),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 0

        logging.info("Inserting vlan flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.uni2nni.append(msg)

        
    def addOam(self,meg,type=ofdpa.OFDPA_PW_PROT_PATH_WORK):    
        ####################################################################################
        #
        # Create oam
        #
        ####################################################################################        


        if type == ofdpa.OFDPA_PW_PROT_PATH_WORK:
            '''
            Add Flow
            '''
            self.meg = meg 
            
            '''
            Add mpls maintenance point table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8902),            
                ofp.oxm.mpls_tp_mp_id(value = meg.lmepid),
                ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
            ])
            
            '''
            apply actions 
            '''
            apy_actions = [ofp.action.output(port = ofp.OFPP_LOCAL ,max_len = 0xffff) ,
            ]
            instructions=[
                #ofp.instruction.clear_actions(),
                ofp.instruction.apply_actions(actions = apy_actions),
            ]
            priority = 0
    
            logging.info("Inserting mpls maintenance point flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.Oam_nni2uni.append(msg)
            
    
            '''
            Add mpls 1 table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8847),            
                ofp.oxm.mpls_label(value = self.inLabel),
                ofp.oxm.mpls_bos(value = 1),
                ofp.oxm.mpls_tp_ach_channel(value = 0x8902),
                ofp.oxm.mpls_tp_data_first_nibble(value = 1),
                ofp.oxm.mpls_tp_next_label_is_gal(value = 1)
            ])
            
            action = [ofp.action.pop_mpls(ethertype = 0x8847),
                ofp.action.set_field(ofp.oxm.mpls_tp_mp_id(value = meg.lmepid)),
                ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)),
                ofp.action.set_field(ofp.oxm.mpls_tp_protection_index(value = 1)),
                ofp.action.dec_mpls_ttl(),
                ofp.action.pop_mpls(ethertype = 0x8902),
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
            ]
            instructions=[
                ofp.instruction.apply_actions(actions = action),
                ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT),
            ]
            priority = 0
    
            logging.info("Inserting  mpls 1 flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.Oam_nni2uni.append(msg)
    
            '''
            Add injected oam table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_INJECTED_OAM
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8902),            
                ofp.oxm.mpls_tp_mp_id(value = meg.lmepid),
                ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
            ])
            
            aply_action = [ofp.action.push_mpls(ethertype = 0x8847),
                ofp.action.set_field(ofp.oxm.mpls_label(value = 13)),
                ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
                ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]), #push cw
                ofp.action.set_field(ofp.oxm.mpls_tp_data_first_nibble(value = 1)),
                ofp.action.set_field(ofp.oxm.mpls_tp_ach_channel(value = 0x8902)),
                ofp.action.push_mpls(ethertype = 0x8847),
                ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)),
                ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),          
                ofp.action.set_field(ofp.oxm.vlan_pcp(value = 1)),            
            ]
            
            write_action = [ ofp.action.group(group_id = self.tunnel_handle),            
            ]
            instructions=[
                ofp.instruction.apply_actions(actions = aply_action),
                ofp.instruction.write_actions(actions = write_action),
            ]
            priority = 0
    
            logging.info("Inserting injected oam table flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.Oam_uni2nni.append(msg)
        elif type == ofdpa.OFDPA_PW_PROT_PATH_PROTECT:
            '''
            Add Flow
            '''
            self.megPro = meg
            
            '''
            Add mpls maintenance point table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8902),            
                ofp.oxm.mpls_tp_mp_id(value = meg.lmepid),
                ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
            ])
            
            '''
            apply actions 
            '''
            apy_actions = [ofp.action.output(port = ofp.OFPP_LOCAL ,max_len = 0xffff) ,
            ]
            instructions=[
                #ofp.instruction.clear_actions(),
                ofp.instruction.apply_actions(actions = apy_actions),
            ]
            priority = 0
    
            logging.info("Inserting mpls maintenance point flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.OamPro_nni2uni.append(msg)
            
    
            '''
            Add mpls 1 table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8847),            
                ofp.oxm.mpls_label(value = self.inLabelPro),
                ofp.oxm.mpls_bos(value = 1),
                ofp.oxm.mpls_tp_ach_channel(value = 0x8902),
                ofp.oxm.mpls_tp_data_first_nibble(value = 1),
                ofp.oxm.mpls_tp_next_label_is_gal(value = 1)
            ])
            
            action = [ofp.action.pop_mpls(ethertype = 0x8847),
                ofp.action.set_field(ofp.oxm.mpls_tp_mp_id(value = meg.lmepid)),
                ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)),
                ofp.action.set_field(ofp.oxm.mpls_tp_protection_index(value = 0)),
                ofp.action.dec_mpls_ttl(),
                ofp.action.pop_mpls(ethertype = 0x8902),
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
            ]
            instructions=[
                ofp.instruction.apply_actions(actions = action),
                ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT),
            ]
            priority = 0
    
            logging.info("Inserting  mpls 1 flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.OamPro_nni2uni.append(msg)
    
            '''
            Add injected oam table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_INJECTED_OAM
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8902),            
                ofp.oxm.mpls_tp_mp_id(value = meg.lmepid),
                ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
            ])
            
            aply_action = [ofp.action.push_mpls(ethertype = 0x8847),
                ofp.action.set_field(ofp.oxm.mpls_label(value = 13)),
                ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
                ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),
                ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]), #push cw
                ofp.action.set_field(ofp.oxm.mpls_tp_data_first_nibble(value = 1)),
                ofp.action.set_field(ofp.oxm.mpls_tp_ach_channel(value = 0x8902)),
                ofp.action.push_mpls(ethertype = 0x8847),
                ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabelPro)),
                ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),          
                ofp.action.set_field(ofp.oxm.vlan_pcp(value = 1)),            
            ]
            
            write_action = [ ofp.action.group(group_id = self.tunnel_handlePro),            
            ]
            instructions=[
                ofp.instruction.apply_actions(actions = aply_action),
                ofp.instruction.write_actions(actions = write_action),
            ]
            priority = 0
    
            logging.info("Inserting injected oam table flow")
            msg = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0,
                    out_port = ofp.OFPP_ANY, 
                    out_group = ofp.OFPG_ANY,
                    hard_timeout=0,
                    idle_timeout=0)
            self.OamPro_uni2nni.append(msg)
        if type == ofdpa.OFDPA_PW_PROT_PATH_PROTECT:
            return (self.OamPro_uni2nni, self.OamPro_nni2uni)
        else:
            return (self.Oam_uni2nni, self.Oam_nni2uni)        

    def getMepInfo(self):
        return (self.meg.lmepid,self.megPro.lmepid)                
    def get_flow_db(self):
        return (self.uni2nni,self.nni2uni)
    def get_oam_flow_db(self):
        return (self.Oam_uni2nni, self.Oam_nni2uni,self.meg)
    def get_pro_oam_flow_db(self):
        return (self.OamPro_uni2nni, self.OamPro_nni2uni,self.megPro)    
    def set(self,requset):
        pass

class SWAP():
    """
    swap flow config data model
    """
    def __init__(self,swapIndex, inLabel, outLabel, nniPort_in, nniPort_out,
                  portMac_in, portMac_out, dstMac,
                  nniVlan_in = None, nniVlan_out = None, Qos = None,res = None):
        self.nni2uni = []
        self.uni2nni = []
        self.Oam_nni2uni = []
        self.Oam_uni2nni = []
        self.swapIndex = swapIndex
        self.inLabel = inLabel
        self.outLabel = outLabel        
        self.bundleHandle = None
        self.nni_vlan_in = nniVlan_in
        self.nni_vlan_out = nniVlan_out
        self.nni_port_in = nniPort_in
        self.nni_port_out = nniPort_out
        self.port_mac_in = portMac_in
        self.port_mac_out = portMac_out
        self.dst_mac = dstMac
        self.mpls_interface_group_id  = None
        self.meg = None
        self.qosApplyMode = None
        
        if Qos is None:
            self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_NONE
        elif Qos.remarkPattern==ofdpa.OFDPA_QOS_MODE_EXP:
            self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_EXP
        else:
            self.qosApplyMode = ofdpa.OFDPA_QOS_MODE_NONE
        
        '''
        add l2 interface group
        '''
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
        id = ofdb_group_vlanid_set(id , self.nni_vlan_out)
        id = ofdb_group_portid_set(id , self.nni_port_out)
        action_list = [ofp.action.output(self.nni_port_out) ]#, ofp.action.pop_vlan()]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)
        
        '''
        add mpls interface group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        if res is None:
            id = ofdb_group_mpls_index_set(id , self.swapIndex)
        else:
            id = ofdb_group_mpls_index_set(id , res.requestMplsInterfaceGroupIndex())  
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_INTERFACE)
        self.mpls_interface_group_id = id
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.set_field(ofp.oxm.eth_src(value = self.port_mac_out)) ,
                       ofp.action.set_field(ofp.oxm.eth_dst(value = self.dst_mac)) ,
                       ofp.action.set_field(ofp.oxm.vlan_vid(value = self.nni_vlan_out)) ]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)

        '''
        temporarily place here
        '''
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_EXP:
            for i in range(8):
                traffic_class = i + 1
                msg = ofp.message.sptn_mpls_vpn_label_remark_action_add(index=1,traffic_class=traffic_class,color=1,mpls_tc=Qos.local2exp[i],vlan_pcp=1,vlan_dei=0)
                self.uni2nni.append(msg)  



        '''
        add mpls l2 swap label group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        if res is None:
            id = ofdb_group_mpls_index_set(id , self.swapIndex)
        else:
            id = ofdb_group_mpls_index_set(id , res.requestMplsSwapLabelGroupIndex())            
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_SWAP_LABEL)
        self.bundleHandle = id
        action_list = [ofp.action.group(group_id = ref_group) ,                       
                       ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)) ]
        bucket_list = [ofp.bucket(actions = action_list)]
        
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_EXP:
            actionRemarkMplsTc = ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x07,0x00,0x01,0x00,0x00,0x00,0x00 ])
            action_list.append(actionRemarkMplsTc)
            
        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)
    


        '''
        Add vlan table entry
        '''
        table_id =  ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(self.nni_port_in),
            ofp.oxm.vlan_vid(self.nni_vlan_in)
        ])
        
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC),
        ]
        priority = 0

        logging.info("Inserting vlan flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.nni2uni.append(msg)
        
        '''
        Add termination mac table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC
        match = ofp.match([
            ofp.oxm.in_port(self.nni_port_in),
            ofp.oxm.eth_dst(value = self.port_mac_in),
            ofp.oxm.eth_type(value = 0x8847),            
        ])
        
        instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1),
        ]
        priority = 0

        logging.info("Inserting termination mac flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.nni2uni.append(msg)
        
        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = self.inLabel),
            ofp.oxm.mpls_bos(value = 0),            
        ])
        
        apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1))]        
        
        gototable = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE
        
        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_EXP:            
            apy_actions.append(ofp.action.set_field(ofp.oxm.mpls_tp_qos_index(value = 1)))
            # Add copy field action
            apy_actions.append(ofp.action.experimenter(experimenter = 0x4F4E4600, data = [0x0c,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 ]))
            gototable = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_LABEL_TRUST
        
        instructions=[
            ofp.instruction.apply_actions(apy_actions),
            ofp.instruction.goto_table(gototable),
            ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
        ]
        priority = 0

        logging.info("Inserting  mpls 1 flow")
        msg = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0,
                out_port = ofp.OFPP_ANY, 
                out_group = ofp.OFPG_ANY,
                hard_timeout=0,
                idle_timeout=0)
        self.nni2uni.append(msg)

        if self.qosApplyMode == ofdpa.OFDPA_QOS_MODE_EXP:
            for i in range(8):
                '''
                Add mpls label trust table entry
                '''
                table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_LABEL_TRUST
                match = ofp.match([
                    ofp.oxm.mpls_tp_qos_index(value = 1),
                    ofp.oxm.mpls_tc(value=i)           
                ])
                
                '''
                apply actions
                '''
                traffic_class = i 
                apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_color(value = 1)) ,
                    ofp.action.set_field(ofp.oxm.mpls_tp_traffic_class(value = traffic_class)) ,   
                ]
                instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
                    ofp.instruction.apply_actions(actions = apy_actions),
                ]
                priority = 0
        
                logging.info("Inserting  mpls label trust table")
                msg = ofp.message.flow_add(
                        table_id=table_id,
                        match=match,
                        instructions=instructions,
                        buffer_id=ofp.OFP_NO_BUFFER,
                        priority=priority,
                        flags=ofp.OFPFF_SEND_FLOW_REM,
                        cookie=0,
                        out_port = ofp.OFPP_ANY, 
                        out_group = ofp.OFPG_ANY,
                        hard_timeout=0,
                        idle_timeout=0)
                self.nni2uni.append(msg)
        

    def get_flow_db(self):
        return ( self.uni2nni,self.nni2uni)      
    def set(self,requset):
        pass
    def bundle_handle(self):
        return self.bundleHandle


        
class DEVICE():
    """
    device root class
    """    
    def __init__(self,agt):
        self.agt = agt
        self.lsp = []
        self.tunnel = []
        self.swap = []
        self.pw = []
        self.mlp = []
        self.status = 0
        self.agt.register(msg_type = ofp.OFPT_ERROR, handler = self.error_handler)
        self.agt.register(msg_type = ofp.OFPT_PACKET_IN, handler = self.packetIn_handler)        

        self.res_pool = RES_POOL()
        self.logger = logging.getLogger("DEVICE")
        
        '''
        store the topology of device connection 
        '''
        self.connTopo = {}
        
        '''
        store all messages sent by the device
        '''
        self.databaseUni2Nni = []
        self.databaseNni2Uni = []

        
    def probeConnTopo(self):
                # These will get put into function
        of_ports = self.agt.port_desc
 
        for dp_port in of_ports:
          
            outpkt , opt = (lldp_pkt(src=dp_port.hw_addr,port = dp_port.port_no,systemName = "%016x" % self.agt.dpid), "lldp packet")
            
            logging.info("PKT OUT test with %s, port %s" % (opt, dp_port.port_no))
            msg = ofp.message.packet_out()
            msg.in_port = ofp.OFPP_CONTROLLER
            msg.data = str(outpkt)
            act = ofp.action.output()
            act.port = dp_port.port_no
            msg.actions.append(act)
            msg.buffer_id = ofp.OFP_NO_BUFFER
            
            logging.info("PacketOutLoad to: " + str(dp_port.port_no))
            
            self.sendMessage(msg)

    def packetout(self,hw_addr,port):
           
        outpkt , opt = (lldp_pkt(src=hw_addr,port = port,systemName = "%016x" % self.agt.dpid), "lldp packet")
        
        logging.info("PKT OUT test with %s, port %s" % (opt, port))
        msg = ofp.message.packet_out()
        msg.in_port = ofp.OFPP_CONTROLLER
        msg.data = str(outpkt)
        act = ofp.action.output()
        act.port = port
        msg.actions.append(act)
        msg.buffer_id = ofp.OFP_NO_BUFFER
        
        #logging.info("PacketOutLoad to: " + str(dp_port.port_no))
        
        self.sendMessage(msg)


    def getDeviceId(self):
            return self.agt.dpid

    def getDevConnTopo(self):
            return self.connTopo

    def getPortMac(self,portNo):
        return self.agt.getPortMac(portNo)

    def updateDevConnTopology(self,localPort,remotePort,remoteSysName):
            self.connTopo[localPort] = '%s@%s' % (remotePort,remoteSysName)

    def packetIn_handler(self,obj,hdr_xid, msg, rawmsg):
        #print("err:")
        #print(hdr_xid)
        #print msg.show()
        #print(self.agt.dpid) 
        
        oxms = { type(oxm): oxm for oxm in msg.match.oxm_list }
        oxm = oxms.get(ofp.oxm.in_port)
        if oxm:
            localPort = ('%d' % oxm.value)
        else:
            return
        
        payload = msg.data
        eth_protocol, eth_payload = LLDP_Parser.unpack_ethernet_frame(payload)[3:]
        rv = {}
        if eth_protocol == LLDP_Parser.LLDP_PROTO_ID:
    
            for tlv_parse_rv in LLDP_Parser.unpack_lldp_frame(eth_payload):
        
                tlv_header, tlv_type, tlv_data_len, tlv_oui, tlv_subtype, tlv_payload = tlv_parse_rv
        
                if tlv_type == LLDP_Parser.LLDP_TLV_TYPE_PORTID:
                    rv['portid'] = re.sub(r'[\x00-\x08]', '', tlv_payload).strip()
                elif tlv_type == LLDP_Parser.LLDP_TLV_DEVICE_NAME:
                    rv['switch'] = tlv_payload
                elif tlv_type == LLDP_Parser.LLDP_TLV_ORGANIZATIONALLY_SPECIFIC:
                    if tlv_oui == LLDP_Parser.LLDP_TLV_OUI_802_1 and tlv_subtype == 3:
                        rv['vlan'] = re.sub(r'[\x00-\x08]', '', tlv_payload).strip()
            #print rv
            self.updateDevConnTopology(localPort,rv['portid'],rv['switch'])
            logInfo = "Device:%016x receive packet from port %s@%s" % (self.agt.dpid,localPort,rv['switch'])
            print(logInfo)
            self.logger.info(logInfo)        
        
    def error_handler(self,obj,hdr_xid, msg, rawmsg):
        #print("err:")
        #print(hdr_xid)
        #print(msg.err_type)
        error_info = "device %s  error \t: %s" % (str(self.agt.switch_addr), str(msg.err_type)) 
        print(error_info) 
        logging.warn(error_info)
        for m in self.databaseNni2Uni:
            if m.xid == hdr_xid:
                print m.show()
                logging.info(m.show())
        for m in self.databaseUni2Nni:
            if m.xid == hdr_xid:
                print m.show()
                logging.info(m.show())                
        if msg.err_type == ofp.OFPET_FLOW_MOD_FAILED or msg.err_type ==  ofp.OFPET_GROUP_MOD_FAILED :
            self.status = -1
        
            
            
            
            
    def apply_status(self):
        return self.status
    
    def sendMessage(self,msg):
        logging.info(msg.show())
        return self.agt.message_send(msg)
       
    
    def addLsp(self,lspIndex, inLabel, outLabel, nniPort, dstMac, nniVlan = None,Qos = None, colorBasedCtrColor = None):
        portMac = self.getPortMac(nniPort) 
        
        if colorBasedCtrColor :
            colorBasedCtr = []
            ctr = ColorBasedCounter(self.res_pool.requestColorBasedCtrId(),colorBasedCtrColor)
            colorBasedCtr.append(ctr)
            ctr = ColorBasedCounter(self.res_pool.requestColorBasedCtrId(),colorBasedCtrColor)
            colorBasedCtr.append(ctr)            
        else:
            colorBasedCtr = None
            
        new_lsp = LSP(lspIndex = lspIndex, inLabel = inLabel, outLabel = outLabel, nniPort = nniPort,\
            portMac = portMac , dstMac = dstMac, nniVlan = nniVlan | ofdpa.OFDPA_VID_PRESENT, Qos = Qos, colorBasedCtr = colorBasedCtr,
            res = self.res_pool)
        
        
        
        (uni2nni , nni2uni) = new_lsp.get_flow_db()
        for msg in uni2nni:
            self.sendMessage(msg)
            self.databaseUni2Nni.append(msg)
            time.sleep(0.01)
        for msg in nni2uni:
            self.sendMessage(msg)
            self.databaseNni2Uni.append(msg)
            time.sleep(0.01)
        #do_barrier(self.agt)
        self.lsp.append(new_lsp)

        return new_lsp
        
        
        
    def addTunnel(self,tunnelIndex,lsp_list, protMode = ofdpa.OFDPA_PROT_MODE_DISABLE):
    
        new_tunnel = TUNNEL(tunnelIndex = tunnelIndex,lsp_list = lsp_list,protMode = protMode,\
                            res=self.res_pool)
        (uni2nni , nni2uni) = new_tunnel.get_flow_db()
        for msg in uni2nni:
            self.sendMessage(msg)
            self.databaseUni2Nni.append(msg)
            time.sleep(0.01)
        for msg in nni2uni:
            self.sendMessage(msg)
            self.databaseNni2Uni.append(msg) 
            time.sleep(0.01)
        #do_barrier(self.agt)
        self.tunnel.append(new_tunnel)
        return new_tunnel

    def addPw(self,pwIndex,inLabel,outLabel,uniPort,tunnel, uniVlan = [],ivid = [],\
                Qos = None,protMode=0,inLabelPro=None,outLabelPro=None,tunnelPro=None, ACMode=None):
    
        new_pw = PW(pwIndex = pwIndex ,inLabel = inLabel,outLabel = outLabel,uniPort = uniPort,\
                     uniVlan = uniVlan, tunnel = tunnel,ivid = ivid, Qos = Qos,protMode=protMode,inLabelPro=inLabelPro,\
                     outLabelPro=outLabelPro,tunnelPro=tunnelPro,res=self.res_pool, ACMode=ACMode)
        (uni2nni , nni2uni) = new_pw.get_flow_db()
        for msg in uni2nni:
            self.sendMessage(msg)
            self.databaseUni2Nni.append(msg)
            time.sleep(0.01)
        for msg in nni2uni:
            self.sendMessage(msg)
            self.databaseNni2Uni.append(msg) 
            time.sleep(0.01)
        #do_barrier(self.agt)
        self.pw.append(new_pw)
        return new_pw

    def addSwap(self,swapIndex, inLabel, outLabel, nniPort_in, nniPort_out, dstMac, nniVlan_in = None,
                 nniVlan_out = None,Qos = None):
        portMac_in = self.getPortMac(nniPort_in)
        portMac_out = self.getPortMac(nniPort_out) 
        new_swap = SWAP(swapIndex = swapIndex, inLabel = inLabel, outLabel = outLabel, 
                        nniPort_in = nniPort_in,
                        nniPort_out = nniPort_out,
                        portMac_in = portMac_in,
                        portMac_out = portMac_out ,
                        dstMac = dstMac,
                        nniVlan_in = nniVlan_in | ofdpa.OFDPA_VID_PRESENT,
                        nniVlan_out = nniVlan_out | ofdpa.OFDPA_VID_PRESENT,
                        Qos = Qos,
                        res = self.res_pool)
        
        (uni2nni , nni2uni) = new_swap.get_flow_db()
        for msg in uni2nni:
            self.sendMessage(msg)
            self.databaseUni2Nni.append(msg)
            
        for msg in nni2uni:
            self.sendMessage(msg)
            self.databaseNni2Uni.append(msg) 
            
        #do_barrier(self.agt)
        self.swap.append(new_swap)
        return new_swap   
    
    def deletePw(self,pwIndex):
        target = None
        for x in self.pw:
            #print(tunnel.tunnelIndex)
            if x.pwIndex == pwIndex:
                target = x
        if target is None:
            return (-1 , 'lsp not found') 

        (uni2nni , nni2uni) = target.get_flow_db()
        #print(uni2nni)
        #Reverse traversal
        for msg in uni2nni[::-1]:
            try:
                dmsg = self.convertFlowMsgC2D(msg)
                self.sendMessage(dmsg)
                self.databaseUni2Nni.append(dmsg)
            except:
                print("error msg")
        for msg in nni2uni[::-1]:
            try:
                dmsg = self.convertFlowMsgC2D(msg)
                self.sendMessage(dmsg)
                self.databaseNni2Uni.append(dmsg) 
            except:
                print("error msg")
        #do_barrier(self.agt)   
        return (0 , 'delete success') 

    def deleteTunnel(self,tunnelIndex):
        targetTunnel = None
        for tunnel in self.tunnel:
            #print(tunnel.tunnelIndex)
            if tunnel.tunnelIndex == tunnelIndex:
                targetTunnel = tunnel
        if targetTunnel is None:
            return (-1 , 'tunnel not found') 

        (uni2nni , nni2uni) = targetTunnel.get_flow_db()
        #print(uni2nni)
        #Reverse traversal
        for msg in uni2nni[::-1]:
            try:
                dmsg = self.convertFlowMsgC2D(msg)
                self.sendMessage(dmsg)
                self.databaseUni2Nni.append(dmsg)
            except:
                print("error msg")
        for msg in nni2uni[::-1]:
            try:
                dmsg = self.convertFlowMsgC2D(msg)
                self.sendMessage(dmsg)
                self.databaseNni2Uni.append(dmsg) 
            except:
                print("error msg")
        #do_barrier(self.agt)   
        return (0 , 'delete success')  

        
    def deleteLsp(self,lspIndex):
        target = None
        for x in self.lsp:
            #print(tunnel.tunnelIndex)
            if x.lspIndex == lspIndex:
                target = x
        if target is None:
            return (-1 , 'lsp not found') 

        (uni2nni , nni2uni) = target.get_flow_db()
        #print(uni2nni)
        #Reverse traversal
        for msg in uni2nni[::-1]:
            try:
                dmsg = self.convertFlowMsgC2D(msg)
                self.sendMessage(dmsg)
                self.databaseUni2Nni.append(dmsg)
            except:
                print("error msg")
        for msg in nni2uni[::-1]:
            try:
                dmsg = self.convertFlowMsgC2D(msg)
                self.sendMessage(dmsg)
                self.databaseNni2Uni.append(dmsg) 
            except:
                print("error msg")
        #do_barrier(self.agt)   
        return (0 , 'delete success') 

   

    def addOam2Lsp(self,meg,lsp):
        '''
        Todo netconf config here
        '''
        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return -1

        if meg is None:
          print('Error: meg is none')
          return -1
        
        #raw_input('Press any key to continue ...')
        if meg.isOpenFlowMpIdNeedUpdated():
            meg.updateOpenFlowMpId(self.res_pool.requestOpenFlowMpId())
                    
      
        (rc , info) = self.agt.netconf.config(meg.getConfig())
        if rc != 0:
            print(info)
            return -1
        
        
        time.sleep(1)  
        
          
        targetLsp = None    
        for tmp in self.lsp:
            if tmp.lspIndex == lsp.lspIndex:
                targetLsp = tmp
        if targetLsp:
            (uni2nni , nni2uni) = targetLsp.addOam(meg = meg)
            for msg in uni2nni:
                self.sendMessage(msg)
                self.databaseUni2Nni.append(msg)
            for msg in nni2uni:
                self.sendMessage(msg)
                self.databaseNni2Uni.append(msg) 
            #do_barrier(self.agt)

    def updateLspOam(self,newMeg,lspIndex):
        '''
        Todo netconf config here
        '''
        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return -1

        if newMeg is None:
          print('Error: meg is none')
          return -1
  
        targetLsp = None    
        for tmp in self.lsp:
            if tmp.lspIndex == lspIndex:
                targetLsp = tmp
        if targetLsp:
            #Only update mepid
            megObj = targetLsp.meg
            megObj.lmepid = newMeg.lmepid
      
        else:
            return -1
        
        (rc , info) = self.agt.netconf.config(megObj.getConfig(opt="replace"))
        if rc != 0:
            print(info)
            return -1
        
        return 0

            
    def addOam2Pw(self,meg,pw,type=ofdpa.OFDPA_PW_PROT_PATH_WORK):
        '''
        Todo netconf config here
        '''
        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return -1

        if meg.isOpenFlowMpIdNeedUpdated():
            meg.updateOpenFlowMpId(self.res_pool.requestOpenFlowMpId())   
        (rc , info) = self.agt.netconf.config(meg.getConfig())
        if rc != 0:
            print(info)
            return -1
        time.sleep(1)    
        target = None    
        for tmp in self.pw:
            if tmp.pwIndex == pw.pwIndex:
                target = tmp
        if target:
            (uni2nni , nni2uni) = target.addOam(meg = meg,type = type)
            for msg in uni2nni:
                self.sendMessage(msg)
                self.databaseUni2Nni.append(msg)
            for msg in nni2uni:
                self.sendMessage(msg)
                self.databaseNni2Uni.append(msg) 
            #do_barrier(self.agt)
        
    def modifyTunnel(self,tunnelIndex,oldLspIndex,newLspIndex):
        oldLsp = None
        newLsp = None
        targetTunnel = None
        for tunnel in self.tunnel:
            #print(tunnel.tunnelIndex)
            if tunnel.tunnelIndex == tunnelIndex:
                targetTunnel = tunnel
        if targetTunnel is None:
            return (-1 , 'tunnel not found')
        for lsp in self.lsp:
            if lsp.lspIndex == oldLspIndex:
                oldLsp = lsp
            elif lsp.lspIndex == newLspIndex:
                newLsp = lsp
        if oldLsp is None or newLsp is None:
            return (-1,'lsp not found')
            
        (uni2nni , nni2uni) = targetTunnel.updateLsp(oldLsp = oldLsp , newLsp = newLsp)
        for msg in uni2nni:
            self.sendMessage(msg)
            self.databaseUni2Nni.append(msg)
        for msg in nni2uni:
            self.sendMessage(msg)
            self.databaseNni2Uni.append(msg) 
        #do_barrier(self.agt)
        return (0,'tunnel modif success')
        
        
        
    def updateMlp(self,mlpIndex,target,protMode = ofdpa.OFDPA_PROT_MODE_ENABLE):
        targetTunnel = None
        for tunnel in self.tunnel:
            #print(tunnel.tunnelIndex)
            if tunnel.tunnelIndex == target:
                targetTunnel = tunnel
        if targetTunnel is None:
            return (-1 , 'tunnel not found')

        targetMlp = None
        for mlp in self.mlp:
            if mlp.mlpIndex == mlpIndex:
                targetMlp = mlp
        if targetMlp is None:
            return (-1 , 'mlp not found')

            
        (lmep_w,lmep_p) = targetTunnel.getMepInfo()
        worker = netconf.MLP_HEAD_END(mepId = lmep_w,liveness_port = targetTunnel.livenessPortWorker,\
            role = 'working')    
        protector = netconf.MLP_HEAD_END(mepId = lmep_p,liveness_port = targetTunnel.livenessPortProtector,\
            role = 'protection')
        
        print(worker.mepId)
        print(protector.mepId)
        
        if targetMlp.mlpHeadEnds[0].mepId != worker.mepId:
            '''
            REMOVE HEAD END
            '''  
            mlpConf = targetMlp.removeMlpHeadEnd(mlpHeadEnd = targetMlp.mlpHeadEnds[0])
            
            if self.agt.netconf.connected() == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')

            
            (rc , info) = self.agt.netconf.config(mlpConf)
            if rc != 0:
                print(info)
                return (-1 , 'removeMlpHeadEnd failed')

            '''
            REPLACE HEAD END
            '''   
            mlpConf = targetMlp.replaceMlpHeadEnd(mlpHeadEnd = worker)
            if self.agt.netconf.connected() == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')

            
            (rc , info) = self.agt.netconf.config(mlpConf)
            if rc != 0:
                print(info)
                return (-1 , 'repalceMlpHeadEnd failed')
                        
            targetMlp.mlpHeadEnds[0] = worker  #updae record
          
        if targetMlp.mlpHeadEnds[1].mepId != protector.mepId:
            '''
            REMOVE HEAD END
            ''' 
            mlpConf = targetMlp.removeMlpHeadEnd(mlpHeadEnd = targetMlp.mlpHeadEnds[1])
  
            if self.agt.netconf.connected() == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')

            
            (rc , info) = self.agt.netconf.config(mlpConf)
            if rc != 0:
                print(info)
                return (-1 , 'removeMlpHeadEnd failed')

            '''
            REPLACE HEAD END
            '''            
            mlpConf = targetMlp.replaceMlpHeadEnd(mlpHeadEnd = protector)
            if self.agt.netconf.connected() == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')

            
            (rc , info) = self.agt.netconf.config(mlpConf)
            if rc != 0:
                print(info)
                return (-1 , 'repalceMlpHeadEnd failed')
                                    
            targetMlp.mlpHeadEnds[1] = protector #updae record
        return (0 , 'updateMlp success')
    
    
    
    def addMlp(self,mlpIndex ,mlpName ,target, protMode = ofdpa.OFDPA_PROT_MODE_ENABLE):
        '''
        Todo netconf config here
        '''
        
        if protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
            objTarget = None
            for obj in self.tunnel:
                #print(tunnel.tunnelIndex)
                if obj.tunnelIndex == target:
                    objTarget = obj
            if objTarget is None:
                return (-1 , 'tunnel not found')
        elif protMode == 2:
            objTarget = None
            for obj in self.pw:
                if obj.pwIndex == target:
                    objTarget = obj
            if objTarget is None:
                return (-1 , 'pw not found')        
        
        (lmep_w,lmep_p) = objTarget.getMepInfo()
        
        
        worker = netconf.MLP_HEAD_END(mepId = lmep_w,liveness_port = objTarget.livenessPortWorker,\
            role = 'working')   
         
        protector = netconf.MLP_HEAD_END(mepId = lmep_p,liveness_port = objTarget.livenessPortProtector,\
            role = 'protection')
        
        ends = [worker,protector]        
        mlpNew = netconf.MLP(mlpIndex = mlpIndex,mlpName = mlpName,mlpHeadEnds=ends)
        self.mlp.append(mlpNew)
        
        
        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1 , 'connect not exist')

            
        (rc , info) = self.agt.netconf.config(mlpNew.getConfig())
        if rc != 0:
            print(info)
            return (-1 , 'config failed')
            
        return (0 , 'add success')
    
    
    
    def deleteMlp(self,mlpIndex):
        '''
        Todo netconf config here
        '''
        targetMlp = None
        for mlp in self.mlp:
            if mlp.mlpIndex == mlpIndex:
                targetMlp = mlp
        if targetMlp is None:
            return (-1 , 'mlp not found')

        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1 , 'connect not exist')

            
        (rc , info) = self.agt.netconf.config( targetMlp.delete())
        if rc != 0:
            print(info)
            return (-1 , 'config failed')
            
        return (0 , 'delete success')
    
    
    def convertFlowMsgC2D(self,msg):
        if isinstance(msg,ofp.message.group_add) or isinstance(msg,ofp.message.group_mod):
            #print('construct group delete msg')
            out = ofp.message.group_delete(
                group_type = msg.group_type,
                group_id = msg.group_id,
                buckets = msg.buckets)
        elif isinstance(msg,ofp.message.flow_add):
            #print('construct flow delete msg')
            out = ofp.message.flow_delete_strict(
                table_id = msg.table_id,
                match = msg.match,
                instructions = msg.instructions,
                buffer_id = msg.buffer_id,
                priority = msg.priority,
                flags = msg.flags,
                cookie = msg.cookie,
                cookie_mask = msg.cookie_mask,
                out_port = msg.out_port,
                out_group = msg.out_group,
                hard_timeout = msg.hard_timeout,
                idle_timeout = msg.idle_timeout)
        elif isinstance(msg,ofp.message.meter_mod):
            print('construct meter delete msg')
            out = ofp.message.meter_mod(
                command = ofp.OFPMC_DELETE,
                meters = msg.meters,
                flags = msg.flags,
                meter_id = msg.meter_id ) 
        elif isinstance(msg,ofp.message.sptn_mpls_vpn_label_remark_action_add):
            out = ofp.message.sptn_mpls_vpn_label_remark_action_delete(
                index = msg.index,
                traffic_class = msg.traffic_class,
                color = msg.color,
                mpls_tc = msg.mpls_tc,
                vlan_pcp = msg.vlan_pcp,
                vlan_dei = msg.vlan_dei)
        elif isinstance(msg,ofp.message.sptn_mpls_tunnel_label_remark_action_add):
            out = ofp.message.sptn_mpls_tunnel_label_remark_action_delete(
                index = msg.index,
                traffic_class = msg.traffic_class,
                color = msg.color,
                mpls_tc = msg.mpls_tc,
                vlan_pcp = msg.vlan_pcp,
                vlan_dei = msg.vlan_dei)
        elif isinstance(msg, ofp.message.sptn_color_based_ctr_add):
            out = ofp.message.sptn_color_based_ctr_delete(
                block_index = msg.block_index,
                transmit_packets = msg.transmit_packets,
                receive_packets = msg.receive_packets,
                color = msg.color)
        else:
            return None
        #print(out)
        return out
    
    
    def removeOamFromLsp(self,lspIndex):
        '''
        Todo netconf config here
        '''
        targetLsp = None    
        for tmp in self.lsp:
            if tmp.lspIndex == lspIndex:
                targetLsp = tmp
        if targetLsp:
            (uni2nni , nni2uni , meg) = targetLsp.get_oam_flow_db()
            #print(uni2nni)
            #Reverse traversal
            for msg in uni2nni[::-1]:
                try:
                    self.sendMessage(self.convertFlowMsgC2D(msg))
                    self.databaseUni2Nni.append(msg)
                except:
                    print("error msg")
            for msg in nni2uni[::-1]:
                try:
                    self.sendMessage(self.convertFlowMsgC2D(msg))
                except:
                    print("error msg")
            #do_barrier(self.agt)   
        else :
            return (-1,'lsp not found')
            
        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1,'no connect')
        
        (rc , info) = self.agt.netconf.config( meg.delete())
        if rc != 0:
            print(info)
            return (-1,'config fail')
        time.sleep(1)  
        return (0,'delete success')
   
    def removeOamFromPw(self,pwIndex,type=1):
        '''
        Todo netconf config here
        '''
        targetPw = None    
        for tmp in self.pw:
            if tmp.pwIndex == pwIndex:
                targetPw = tmp
        if targetPw:
            
            if type == 1:
                (uni2nni , nni2uni , meg) = targetPw.get_oam_flow_db()
            elif type == 2:
                (uni2nni , nni2uni , meg) = targetPw.get_pro_oam_flow_db()
            #print(uni2nni)
            #Reverse traversal
            for msg in uni2nni[::-1]:
                try:
                    self.sendMessage(self.convertFlowMsgC2D(msg))
                    self.databaseUni2Nni.append(msg)
                except:
                    print("error msg")
            for msg in nni2uni[::-1]:
                try:
                    self.sendMessage(self.convertFlowMsgC2D(msg))
                except:
                    print("error msg")
            #do_barrier(self.agt)   
        else :
            return (-1,'pw not found')
            
        if self.agt.netconf.connected() == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1,'no connect')
        
        (rc , info) = self.agt.netconf.config(meg.delete())
        if rc != 0:
            print(info)
            return (-1,'config fail')
        time.sleep(1)  
        return (0,'delete success')
   

    def getLspStat(self,lspIndex):
        
        target = None    
        for tmp in self.lsp:
            if tmp.lspIndex == lspIndex:
                target = tmp
        if target:
            #get LSP Tx counter
            if isinstance(target.staLspTxObj, ofp.message.group_add):
                msg = ofp.message.sptn_color_based_ctr_multipart_request(block_index= target.colorBasedCtr[0].index,color=0xff)
                (resp,pkt) = self.agt.transact(msg)
                if isinstance(resp,ofp.message.sptn_color_based_ctr_multipart_reply):
                    for lsp_stats in resp.entries:
                        #print(' ')
                        #print("group_id            :" + hex(group_stats.group_id))
                        #print("duration_sec        :" + str(group_stats.duration_sec))
                        #print("packet_count        :" + str(group_stats.packet_count))
                        #print("byte_count          :" + str(group_stats.byte_count))
                        lspTx = [lsp_stats.packets,lsp_stats.bytes]
                else:
                    print("error type")
                    return ([-1,-1],[-1,-1],-1) 
            else:
                return ([-1,-1],[-1,-1],-1)                
            
            #get LSP Rx counter
            if isinstance(target.staLspRxObj, ofp.message.flow_add):
                msg = ofp.message.sptn_color_based_ctr_multipart_request(block_index= target.colorBasedCtr[1].index,color=0xff)
                (resp,pkt) = self.agt.transact(msg)
                if isinstance(resp,ofp.message.sptn_color_based_ctr_multipart_reply):
                    for lsp_stats in resp.entries:
                        #print(' ')
                        #print("table_id            :" + str(flow_stats.table_id))
                        #print("duration_sec        :" + str(flow_stats.duration_sec))
                        #print("packet_count        :" + str(flow_stats.packet_count))
                        #print("byte_count          :" + str(flow_stats.byte_count))
                        lspRx = [lsp_stats.packets,lsp_stats.bytes]
                        return (lspRx,lspTx)
                else:
                    print("error type")
                    return ([-1,-1],[-1,-1],-1)
        
        else:
            print("lsp not found")
            return ([-1,-1],[-1,-1],-1)
        
        
        
    def getPwStat(self,pwIndex):
 
        target = None    
        for tmp in self.pw:
            if tmp.pwIndex == pwIndex:
                target = tmp
        if target:
            #get PW Tx counter
            if isinstance(target.staPwTxObj, ofp.message.group_add):
                msg = ofp.message.group_stats_request(group_id = target.staPwTxObj.group_id)
                (resp,pkt) = self.agt.transact(msg)
                if isinstance(resp,ofp.message.group_stats_reply):
                    for group_stats in resp.entries:
                        #print(' ')
                        #print("group_id            :" + hex(group_stats.group_id))
                        #print("duration_sec        :" + str(group_stats.duration_sec))
                        #print("packet_count        :" + str(group_stats.packet_count))
                        #print("byte_count          :" + str(group_stats.byte_count))
                        pwTx = [group_stats.packet_count,group_stats.byte_count]
                else:
                    print("error type")
                    return ([-1,-1],[-1,-1],-1) 
            else:
                return ([-1,-1],[-1,-1],-1)                
            
            #get PW Rx counter
            if isinstance(target.staPwRxObj, ofp.message.flow_add):
                match = target.staPwRxObj.match
            else:
                return ([-1,-1],[-1,-1],-1)
            msg = ofp.message.flow_stats_request(table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1 ,
                                                 out_port = ofp.OFPP_ANY,
                                                 out_group = ofp.OFPG_ANY,
                                                 match =match
                                                 )
            (resp,pkt) = self.agt.transact(msg)
            if isinstance(resp,ofp.message.flow_stats_reply):
                for flow_stats in resp.entries:
                    #print(' ')
                    #print("table_id            :" + str(flow_stats.table_id))
                    #print("duration_sec        :" + str(flow_stats.duration_sec))
                    #print("packet_count        :" + str(flow_stats.packet_count))
                    #print("byte_count          :" + str(flow_stats.byte_count))
                    pwRx = [flow_stats.packet_count,flow_stats.byte_count]
                    
            else:
                print("error type")
                return ([-1,-1],[-1,-1],-1)
            
            
            if target.protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
                #get PW Tx counter
                if isinstance(target.staPwProTxObj, ofp.message.group_add):
                    msg = ofp.message.group_stats_request(group_id = target.staPwProTxObj.group_id)
                    (resp,pkt) = self.agt.transact(msg)
                    if isinstance(resp,ofp.message.group_stats_reply):
                        for group_stats in resp.entries:
                            #print(' ')
                            #print("group_id            :" + hex(group_stats.group_id))
                            #print("duration_sec        :" + str(group_stats.duration_sec))
                            #print("packet_count        :" + str(group_stats.packet_count))
                            #print("byte_count          :" + str(group_stats.byte_count))
                            pwProTx = [group_stats.packet_count,group_stats.byte_count]
                    else:
                        print("error type")
                        return ([-1,-1],[-1,-1],-1) 
                else:
                    return ([-1,-1],[-1,-1],-1)                
                
                #get PW Rx counter
                if isinstance(target.staPwProRxObj, ofp.message.flow_add):
                    match = target.staPwProRxObj.match
                else:
                    return ([-1,-1],[-1,-1],-1)
                msg = ofp.message.flow_stats_request(table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1 ,
                                                     out_port = ofp.OFPP_ANY,
                                                     out_group = ofp.OFPG_ANY,
                                                     match =match
                                                     )
                (resp,pkt) = self.agt.transact(msg)
                if isinstance(resp,ofp.message.flow_stats_reply):
                    for flow_stats in resp.entries:
                        #print(' ')
                        #print("table_id            :" + str(flow_stats.table_id))
                        #print("duration_sec        :" + str(flow_stats.duration_sec))
                        #print("packet_count        :" + str(flow_stats.packet_count))
                        #print("byte_count          :" + str(flow_stats.byte_count))
                        pwProRx = [flow_stats.packet_count,flow_stats.byte_count]
                        
                else:
                    print("error type")
                    return ([-1,-1],[-1,-1],-1) 
            if target.protMode == ofdpa.OFDPA_PROT_MODE_ENABLE:
                return (pwRx + pwProRx ,pwTx + pwProTx,flow_stats.duration_sec)
            else:               
                return (pwRx,pwTx,flow_stats.duration_sec)
        else:
            print("pw not found")
            return ([-1,-1],[-1,-1],-1)

    def getAcStat(self,pwIndex):
        target = None    
        for tmp in self.pw:
            if tmp.pwIndex == pwIndex:
                target = tmp
        if target:
            #get AC Rx counter
            if isinstance(target.staAcTxObj, ofp.message.group_add):
                msg = ofp.message.group_stats_request(group_id = target.staAcTxObj.group_id)
                (resp,pkt) = self.agt.transact(msg)
                if isinstance(resp,ofp.message.group_stats_reply):
                    for group_stats in resp.entries:
                        #print(' ')
                        #print("group_id            :" + hex(group_stats.group_id))
                        #print("duration_sec        :" + str(group_stats.duration_sec))
                        #print("packet_count        :" + str(group_stats.packet_count))
                        #print("byte_count          :" + str(group_stats.byte_count))
                        acTx = [group_stats.packet_count,group_stats.byte_count]
                else:
                    print("error type")
                    return ([-1,-1],[-1,-1],-1) 
            else:
                return ([-1,-1],[-1,-1],-1)                
            
            #get AC Tx counter
            if isinstance(target.staAcRxObj, ofp.message.flow_add):
                match = target.staAcRxObj.match
            else:
                return ([-1,-1],[-1,-1],-1)
            msg = ofp.message.flow_stats_request(table_id = target.staAcRxObj.table_id ,
                                                 out_port = ofp.OFPP_ANY,
                                                 out_group = ofp.OFPG_ANY,
                                                 match =match
                                                 )
            (resp,pkt) = self.agt.transact(msg)
            if isinstance(resp,ofp.message.flow_stats_reply):
                for flow_stats in resp.entries:
                    #print(' ')
                    #print("table_id            :" + str(flow_stats.table_id))
                    #print("duration_sec        :" + str(flow_stats.duration_sec))
                    #print("packet_count        :" + str(flow_stats.packet_count))
                    #print("byte_count          :" + str(flow_stats.byte_count))
                    acRx = [flow_stats.packet_count,flow_stats.byte_count]
                    return (acRx,acTx,flow_stats.duration_sec)
            else:
                print("error type")
                return ([-1,-1],[-1,-1],-1)
        
        else:
            print("pw not found")
            return ([-1,-1],[-1,-1],-1)

    def getPortStat(self,portIndex):
        
        #get Port Tx counter
        msg = ofp.message.port_stats_request(port_no = portIndex)
        (resp,pkt) = self.agt.transact(msg)
        if isinstance(resp,ofp.message.port_stats_reply):
        ###entries in E:\autotest\oftest\src\python\loxi\of13\common.py
            for port_stats in resp.entries:
                ###E:\autotest\oftest\src\python\loxi\of13\message.py
                portTx = [port_stats.tx_packets,port_stats.tx_bytes,port_stats.tx_dropped,port_stats.tx_errors]
                portRx = [port_stats.rx_packets,port_stats.rx_bytes,port_stats.rx_dropped,\
                            port_stats.rx_errors,port_stats.rx_frame_err,port_stats.rx_over_err,port_stats.rx_crc_err]
                return(portTx,portRx,port_stats.collisions,port_stats.duration_sec,port_stats.duration_nsec)
        else:
            print("error type")
            return([-1,-1],[-1,-1,-1,-1],[-1,-1,-1,-1,-1,-1,-1],-1,-1,-1)
            

class DeviceOnline(advanced_tests.AdvancedProtocol):
    """
    vpws test case for lsp  permanent protection 
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for agt in self.controller.device_agents:
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')






class TopologyDiscover(advanced_tests.AdvancedDataPlane):
    """
    Generate lots of packet-out messages

    Test packet-out function by sending lots of packet-out msgs
    to the switch.  This test tracks the number of packets received in 
    the dataplane, but does not enforce any requirements about the 
    number received.
    """
    def runTest(self):
        # Construct packet to send to dataplane
        # Send packet to dataplane
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                #print(id,agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')
        
        self.pe1.probeConnTopo()
        self.pe2.probeConnTopo()
        
        time.sleep(5)
        
        print "PE1 %016x Topology:" % self.pe1.getDeviceId()
        print self.pe1Config['CONN_TOPO']
        print self.pe1.getDevConnTopo()
        
        print "PE2 %016x Topology:" % self.pe2.getDeviceId()
        print self.pe2Config['CONN_TOPO']
        print self.pe2.getDevConnTopo()
        
        self.assertEquals(self.pe1Config['CONN_TOPO'], self.pe1.getDevConnTopo(),'Probed topo is wrong')
        self.assertEquals(self.pe2Config['CONN_TOPO'], self.pe2.getDevConnTopo(),'Probed topo is wrong')


class DevicePacketout(advanced_tests.AdvancedDataPlane):
    """
    Generate lots of packet-out messages

    Test packet-out function by sending lots of packet-out msgs
    to the switch.  This test tracks the number of packets received in 
    the dataplane, but does not enforce any requirements about the 
    number received.
    """
    def runTest(self):
        # Construct packet to send to dataplane
        # Send packet to dataplane
        self.pe1 = None
        self.pe2 = None 


        self.pe1Config = config["device_map"]["pe1"]

        print("\r\n")
        print(hex(self.pe1Config['DPID']))

        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 1 and self.waitDeviceOnline > 0:
            for agt in self.controller.device_agents:
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
               
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 1,'no enough device is online')
        

        print('test start ...')
        while True:
            self.pe1.packetout(hw_addr = [0x00,0x0e,0x5e,0x00,0x00,0x03],port = 16846846) 




class Basic(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for sptn Qos  
    """      
    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')



        print(self.deviceIsOnline)
        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'basic':
                self.addBasic()
            elif cmd == 'sta':
                self.showStatistic()
            elif cmd == 'exit':
                break
            elif cmd == "del":
                self.deleteVpws()
            else:
                print('unknown cmd') 
                
                              


    def addBasic(self):
        uniVlan = [10]
        try:
            if len(self.pe1Config['ELECTRIC_PORTS']) != 0: 
                pe1UniPort = self.pe1Config['ELECTRIC_PORTS'][0]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe1NniPort_w = self.pe1Config['OPTICAL_PORTS'][0]
                pe1NniPort_p = self.pe1Config['OPTICAL_PORTS'][1]               


            if len(self.pe2Config['ELECTRIC_PORTS']) != 0: 
                pe2UniPort = self.pe2Config['ELECTRIC_PORTS'][0]
            elif len(self.pe2Config['OPTICAL_PORTS']) != 0:
                pe2UniPort = self.pe2Config['OPTICAL_PORTS'][12]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe2NniPort_w = self.pe2Config['OPTICAL_PORTS'][9]
                pe2NniPort_p = self.pe2Config['OPTICAL_PORTS'][11]  
                
        except:
                raise ("no ports found")
        nniVlan = 100
        
        pe1PortMacW = self.pe1.getPortMac(pe1NniPort_w) 
        pe2PortMacW = self.pe2.getPortMac(pe2NniPort_w) 

  
        if self.pe1 != None:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 1000,outLabel = 2000,nniPort = pe1NniPort_w,\
                                    nniVlan = nniVlan, dstMac = pe2PortMacW)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            uniVlan = [10]
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 10 ,outLabel = 20,uniPort = pe1UniPort, \
                                uniVlan = uniVlan, tunnel = tunnel)
            uniVlan = [11]
            pw = self.pe1.addPw(pwIndex = 2,inLabel = 11 ,outLabel = 21,uniPort = pe1UniPort, \
                                uniVlan = uniVlan, tunnel = tunnel)          
 
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        

        if self.pe2 != None:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 2000,outLabel = 1000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMacW)
                            
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 3,inLabel = 20 ,outLabel = 10,uniPort = pe2UniPort,\
                                 uniVlan = uniVlan, tunnel = tunnel)
            uniVlan = [11]
            pw = self.pe2.addPw(pwIndex = 4,inLabel = 21 ,outLabel = 11,uniPort = pe2UniPort,\
                                 uniVlan = uniVlan, tunnel = tunnel)            

   
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')

    def showStatistic(self):
        pass
                                   
    def deleteVpws(self):
        if self.pe1 != None:
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 2)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp') +  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

        
        if self.pe2 != None:
          
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deletePw(pwIndex = 2)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp') +  info  + '('  +  str(rc)  + ')')


class BasicStats(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for sptn Qos  
    """      
    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')
        
        
        
        while True:
            cmd = raw_input('cmd: ')
            print(cmd)
            if cmd == 'basic':
                self.addBasic()
            elif cmd == 'sta':
                self.showStatistic()
            elif cmd == 'exit':
                break
            elif cmd == "del":
                self.deleteVpws()
            else:
                print('unknown cmd') 
   
   


    def addBasic(self):
        uniPort = 3
        uniVlan = [10]
        nniPort_w = 4


        nniVlan = 100
        pe1PortMacW = self.pe1.getPortMac(nniPort_w) 
     
        pe2PortMacW = self.pe2.getPortMac(nniPort_w) 

        if self.pe1 != None:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 1000,outLabel = 2000,nniPort = nniPort_w,\
                                    nniVlan = nniVlan, dstMac = pe2PortMacW, colorBasedCtrColor=True)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            uniVlan = [10]
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 10 ,outLabel = 20,uniPort = uniPort, \
                                uniVlan = uniVlan, tunnel = tunnel)
            uniVlan = [11]
            pw = self.pe1.addPw(pwIndex = 2,inLabel = 11 ,outLabel = 21,uniPort = uniPort, \
                                uniVlan = uniVlan, tunnel = tunnel)          
 
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        

        if self.pe2 != None:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 2000,outLabel = 1000,nniPort = nniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMacW, colorBasedCtrColor=True)
                            
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 3,inLabel = 20 ,outLabel = 10,uniPort = uniPort,\
                                 uniVlan = uniVlan, tunnel = tunnel)
            uniVlan = [11]
            pw = self.pe2.addPw(pwIndex = 4,inLabel = 21 ,outLabel = 11,uniPort = uniPort,\
                                 uniVlan = uniVlan, tunnel = tunnel)            

   
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')

    def showStatistic(self):
        self.showLspStatistic()
        self.showPortStatistic()

    def showPortStatistic(self):
        if self.pe1 != None:
            print("PE1 STAT----------------------")
            print("Port 9")
            (portTx,portRx,collisions,duration_sec,duration_nsec) = self.pe1.getPortStat(portIndex = 3)
            print("Port9 Tx Packets                   :"+str(portTx[0])) 
            print("Port9 Rx Packets                   :"+str(portRx[0]))        
            print("Port9 Tx Bytes                     :"+str(portTx[1])) 
            print("Port9 Rx Bytes                     :"+str(portRx[1])) 
            print("Port9 Tx Dropped                   :"+str(portTx[2])) 
            print("Port9 Rx Dropped                   :"+str(portRx[2]))
            print("Port9 Tx Errors                    :"+str(portTx[3])) 
            print("Port9 Rx Errors                    :"+str(portRx[3]))
            print("Port9 Rx FrameErrors               :"+str(portRx[4]))
            print("Port9 Rx OverErrors                :"+str(portRx[5]))
            print("Port9 Rx CRCErrors                 :"+str(portRx[6]))
            print("Collisions                        :"+str(collisions))
            print("Duration sec                    :"+str(duration_sec))
            print("Duration nsec                  :"+str(duration_nsec))
            print("Port 9")
            
            print("Port 10")
            (portTx,portRx,collisions,duration_sec,duration_nsec) = self.pe1.getPortStat(portIndex = 4)
            print("Port10 Tx Packets                   :"+str(portTx[0])) 
            print("Port10 Rx Packets                   :"+str(portRx[0]))        
            print("Port10 Tx Bytes                     :"+str(portTx[1])) 
            print("Port10 Rx Bytes                     :"+str(portRx[1])) 
            print("Port10 Tx Dropped                   :"+str(portTx[2])) 
            print("Port10 Rx Dropped                   :"+str(portRx[2]))
            print("Port10 Tx Errors                    :"+str(portTx[3])) 
            print("Port10 Rx Errors                    :"+str(portRx[3]))
            print("Port10 Rx FrameErrors               :"+str(portRx[4]))
            print("Port10 Rx OverErrors                :"+str(portRx[5]))
            print("Port10 Rx CRCErrors                 :"+str(portRx[6]))
            print("Collisions                        :"+str(collisions))
            print("Duration sec                    :"+str(duration_sec))
            print("Duration nsec                  :"+str(duration_nsec))
            print("Port 10")
        
        if self.pe2 != None:
            print("PE2 STAT----------------------")
            print("Port 6")
            (portTx,portRx,collisions,duration_sec,duration_nsec) = self.pe2.getPortStat(portIndex = 3)
            print("Port6 Tx Packets                   :"+str(portTx[0])) 
            print("Port6 Rx Packets                   :"+str(portRx[0]))        
            print("Port6 Tx Bytes                     :"+str(portTx[1])) 
            print("Port6 Rx Bytes                     :"+str(portRx[1])) 
            print("Port6 Tx Dropped                   :"+str(portTx[2])) 
            print("Port6 Rx Dropped                   :"+str(portRx[2]))
            print("Port6 Tx Errors                    :"+str(portTx[3])) 
            print("Port6 Rx Errors                    :"+str(portRx[3]))
            print("Port6 Rx FrameErrors               :"+str(portRx[4]))
            print("Port6 Rx OverErrors                :"+str(portRx[5]))
            print("Port6 Rx CRCErrors                 :"+str(portRx[6]))
            print("Collisions                        :"+str(collisions))
            print("Duration sec                    :"+str(duration_sec))
            print("Duration nsec                  :"+str(duration_nsec))
            print("Port 6")
            
            print("Port 5")
            (portTx,portRx,collisions,duration_sec,duration_nsec) = self.pe2.getPortStat(portIndex = 4)
            print("Port5 Tx Packets                   :"+str(portTx[0])) 
            print("Port5 Rx Packets                   :"+str(portRx[0]))        
            print("Port5 Tx Bytes                     :"+str(portTx[1])) 
            print("Port5 Rx Bytes                     :"+str(portRx[1])) 
            print("Port5 Tx Dropped                   :"+str(portTx[2])) 
            print("Port5 Rx Dropped                   :"+str(portRx[2]))
            print("Port5 Tx Errors                    :"+str(portTx[3])) 
            print("Port5 Rx Errors                    :"+str(portRx[3]))
            print("Port5 Rx FrameErrors               :"+str(portRx[4]))
            print("Port5 Rx OverErrors                :"+str(portRx[5]))
            print("Port5 Rx CRCErrors                 :"+str(portRx[6]))
            print("Collisions                        :"+str(collisions))
            print("Duration sec                    :"+str(duration_sec))
            print("Duration nsec                  :"+str(duration_nsec))
            print("Port 5")
    
    def showLspStatistic(self):
        if self.pe1 != None:
            print("PE1 LSP----------------------")
            print("lsp 1")
            (lspRx,lspTx) = self.pe1.getLspStat(lspIndex = 1)
            print("Lsp1 Tx Packets                   :"+str(lspTx[0])) 
            print("Lsp1 Rx Packets                   :"+str(lspRx[0]))        
            print("Lsp1 Tx Bytes                     :"+str(lspTx[1])) 
            print("Lsp1 Rx Bytes                     :"+str(lspRx[1]))    
            print("lsp 1")
                
     
        if self.pe2 != None:
            print("PE2 LSP----------------------")
            print("lsp 1")
            (lspRx,lspTx) = self.pe2.getLspStat(lspIndex = 1)
            print("Lsp1 Tx Packets                   :"+str(lspTx[0])) 
            print("Lsp1 Rx Packets                   :"+str(lspRx[0]))        
            print("Lsp1 Tx Bytes                     :"+str(lspTx[1])) 
            print("Lsp1 Rx Bytes                     :"+str(lspRx[1]))    
            print("lsp 1")
                                   
    def deleteVpws(self):
        if self.pe1 != None:
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 2)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp') +  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

        
        if self.pe2 != None:
          
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deletePw(pwIndex = 2)
            print(('%-24s: ' % 'deletePw') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel') +  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp') +  info  + '('  +  str(rc)  + ')')


class LspProt(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for lsp  permanent protection 
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')




        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'addmlp':
                self.addG8131Mlp()
            elif cmd == 'basic':
                self.addBasicVpws()
            elif cmd == 'update':
                self.updateMepId()
            elif cmd == 'restore':
                self.restoreMepId()                
            elif cmd == 'all':
                self.addBasicVpws()
                self.addG8131Mlp()  
            elif cmd == 'del':
                self.deleteVpws()
            elif cmd == 'exit':
                break 
                
                              


    def addBasicVpws(self):
        uniVlan = [10]
        try:
            if len(self.pe1Config['ELECTRIC_PORTS']) != 0: 
                pe1UniPort = self.pe1Config['ELECTRIC_PORTS'][0]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe1NniPort_w = self.pe1Config['OPTICAL_PORTS'][0]
                pe1NniPort_p = self.pe1Config['OPTICAL_PORTS'][1]               


            if len(self.pe2Config['ELECTRIC_PORTS']) != 0: 
                pe2UniPort = self.pe2Config['ELECTRIC_PORTS'][0]
            elif len(self.pe2Config['OPTICAL_PORTS']) != 0:
                pe2UniPort = self.pe2Config['OPTICAL_PORTS'][12]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe2NniPort_w = self.pe2Config['OPTICAL_PORTS'][9]
                pe2NniPort_p = self.pe2Config['OPTICAL_PORTS'][11]  
                
        except:
                raise ("no ports found")
                

        
        nniVlan = 100
        pe1PortMac_w = self.pe1.getPortMac(pe1NniPort_w) 
        pe1PortMac_p = self.pe1.getPortMac(pe1NniPort_p)
        
        if self.pe2 == None:
            pe2PortMac = [0x0e,0x5e,0x05,0x12,0xff,0xa0]
        else:
            pe2PortMac_w = self.pe2.getPortMac(pe2NniPort_w)  
            pe2PortMac_p = self.pe2.getPortMac(pe2NniPort_p)  

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 3000,outLabel = 4000,nniPort = pe1NniPort_w,nniVlan = nniVlan,\
                dstMac = pe2PortMac_w)
            lsp_p = self.pe1.addLsp(lspIndex = 2, inLabel = 3001,outLabel = 4001,nniPort = pe1NniPort_p,nniVlan = nniVlan,\
                dstMac = pe2PortMac_p)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 2000 ,outLabel = 2500,uniPort = pe1UniPort, uniVlan = uniVlan, tunnel = tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40 )
            self.pe1.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            

            
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 4000,outLabel = 3000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMac_w)
            lsp_p = self.pe2.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = pe2NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = pe2UniPort, uniVlan = uniVlan, tunnel =   tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.pe2.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            
            
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
      
      
    def updateMepId(self):
        self.pe1Sel = 0
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 50 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config self.pe2
            '''
            meg_new = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 60 ,rmepid = 30 )
            self.pe2.updateLspOam(meg_new, 2)            
            
     
    def restoreMepId(self):
        self.pe1Sel = 0
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
          
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config self.pe2
            '''
            meg_new = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.updateLspOam(meg_new, 2)   
                 
                 
    def addG8131Mlp(self): 
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')



    def deleteVpws(self):
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

class LspProtRcDC(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for lsp  permanent protection 
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')




        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'addmlp':
                self.addG8131Mlp()
            elif cmd == 'basic':
                self.addBasicVpws()
            elif cmd == 'update':
                self.updateMepId()
            elif cmd == 'restore':
                self.restoreMepId()                
            elif cmd == 'all':
                self.addBasicVpws()
 
            elif cmd == 'del':
                self.deleteVpws()
            elif cmd == 'exit':
                break 
                
                              


    def addBasicVpws(self):
        uniVlan = [10]
        try:
            if len(self.pe1Config['ELECTRIC_PORTS']) != 0: 
                pe1UniPort = self.pe1Config['ELECTRIC_PORTS'][0]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe1NniPort_w = self.pe1Config['OPTICAL_PORTS'][0]
                pe1NniPort_p = self.pe1Config['OPTICAL_PORTS'][1]               


            if len(self.pe2Config['ELECTRIC_PORTS']) != 0: 
                pe2UniPort = self.pe2Config['ELECTRIC_PORTS'][0]
            elif len(self.pe2Config['OPTICAL_PORTS']) != 0:
                pe2UniPort = self.pe2Config['OPTICAL_PORTS'][12]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe2NniPort_w = self.pe2Config['OPTICAL_PORTS'][9]
                pe2NniPort_p = self.pe2Config['OPTICAL_PORTS'][11]  
                
        except:
                raise ("no ports found")
                

        
        nniVlan = 100
        pe1PortMac_w = self.pe1.getPortMac(pe1NniPort_w) 
        pe1PortMac_p = self.pe1.getPortMac(pe1NniPort_p)
        
        if self.pe2 == None:
            pe2PortMac = [0x0e,0x5e,0x05,0x12,0xff,0xa0]
        else:
            pe2PortMac_w = self.pe2.getPortMac(pe2NniPort_w)  
            pe2PortMac_p = self.pe2.getPortMac(pe2NniPort_p)  

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 3000,outLabel = 4000,nniPort = pe1NniPort_w,nniVlan = nniVlan,\
                dstMac = pe2PortMac_w)
            lsp_p = self.pe1.addLsp(lspIndex = 2, inLabel = 3001,outLabel = 4001,nniPort = pe1NniPort_p,nniVlan = nniVlan,\
                dstMac = pe2PortMac_p)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40 )
            self.pe1.addOam2Lsp(lsp = lsp_p, meg = meg_p)     
            
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')            
                   
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 2000 ,outLabel = 2500,uniPort = pe1UniPort, uniVlan = uniVlan, tunnel = tunnel)

            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 4000,outLabel = 3000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMac_w)
            lsp_p = self.pe2.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = pe2NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.pe2.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
                        
            
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = pe2UniPort, uniVlan = uniVlan, tunnel =   tunnel)
    

            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
      
      
    def updateMepId(self):
        self.pe1Sel = 0
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 50 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config self.pe2
            '''
            meg_new = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 60 ,rmepid = 30 )
            self.pe2.updateLspOam(meg_new, 2)            
            
     
    def restoreMepId(self):
        self.pe1Sel = 0
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
          
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config self.pe2
            '''
            meg_new = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.updateLspOam(meg_new, 2)   
                 
                 
    def addG8131Mlp(self): 
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')



    def deleteVpws(self):
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            


class LspProt_Scenario_2(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for lsp  permanent protection 
    
    simulate the raisecom d-control configuration method
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        self.p1 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        self.p1Config = config["device_map"]["p1"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        print(hex(self.p1Config['DPID']))     
           
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 3 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
                elif self.p1 == None and agt.dpid == self.p1Config['DPID']:
                    self.p1 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1  
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 3,'no enough device is online')




        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'addmlp':
                self.addG8131Mlp()
            elif cmd == 'basic':
                self.addBasicVpws()
            elif cmd == 'update':
                self.updateMepId()
            elif cmd == 'restore':
                self.restoreMepId()                
            elif cmd == 'del':
                self.deleteVpws()
            elif cmd == 'exit':
                break 
                
                              


    def addBasicVpws(self):
        uniVlan = [10]
        
        pe1UniPort = 3
        pe1NniPort_w = 1
        pe1NniPort_p = 2

        p1UniPort = 13
        p1NniPort_w = 15
        p1NniPort_p = 12
        p1NniPortEast = 10
        p1NniPortWest = 16
        p1PortMacEast = self.p1.getPortMac(p1NniPortEast) 
        p1PortMacWest = self.p1.getPortMac(p1NniPortWest)
        
        
        pe2UniPort = 3 
        pe2NniPort_w = 4
        pe2NniPort_p = 5
        
        nniVlan = 100
        pe1PortMac_w = self.pe1.getPortMac(pe1NniPort_w) 
        pe1PortMac_p = self.pe1.getPortMac(pe1NniPort_p)
        
        p1PortMac_w = self.p1.getPortMac(p1NniPort_w) 
        p1PortMac_p = self.p1.getPortMac(p1NniPort_p)
        
        if self.pe2 == None:
            pe2PortMac = [0x0e,0x5e,0x05,0x12,0xff,0xa0]
        else:
            pe2PortMac_w = self.pe2.getPortMac(pe2NniPort_w)  
            pe2PortMac_p = self.pe2.getPortMac(pe2NniPort_p)  

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 6000,outLabel = 4000,nniPort = pe1NniPort_w,nniVlan = nniVlan,\
                dstMac = p1PortMacEast)
            lsp_p = self.pe1.addLsp(lspIndex = 2, inLabel = 3001,outLabel = 4001,nniPort = pe1NniPort_p,nniVlan = nniVlan,\
                dstMac = p1PortMac_p)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 2000 ,outLabel = 2500,uniPort = pe1UniPort, uniVlan = uniVlan, tunnel = tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40 )
            self.pe1.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            

            
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.p1Sel = 1
        if self.p1 != None and self.p1Sel == 1:
            '''
            config swap
            ''' 
            swap_E2W = self.p1.addSwap(swapIndex = 1, inLabel = 4000, outLabel = 5000, nniPort_in = p1NniPortEast, 
                                       nniPort_out = p1NniPortWest, dstMac = p1PortMac_w, nniVlan_in = nniVlan, nniVlan_out = nniVlan)

            swap_W2E = self.p1.addSwap(swapIndex = 2, inLabel = 3000, outLabel = 6000, nniPort_in = p1NniPortWest, 
                                       nniPort_out = p1NniPortEast, dstMac = pe1PortMac_w, nniVlan_in = nniVlan, nniVlan_out = nniVlan)
       
            '''
            config p1
            ''' 
            lsp_w = self.p1.addLsp(lspIndex = 1, inLabel = 5000,outLabel = 3000,nniPort = p1NniPort_w,
                nniVlan = nniVlan,dstMac = p1PortMacWest)
            lsp_p = self.p1.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = p1NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.p1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            uniVlan = [10]
            pw = self.p1.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = p1UniPort, uniVlan = uniVlan, tunnel =   tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.p1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.p1.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            
            
            self.assertEqual(self.p1.apply_status(), 0,
                     'response status != expect status 0')
      
        self.pe2Sel = 0
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 4000,outLabel = 3000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMac_w)
            lsp_p = self.pe2.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = pe2NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = pe2UniPort, uniVlan = uniVlan, tunnel =   tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.pe2.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            
            
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
            
            
                  
    def updateMepId(self):
        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 50 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
            
            
     
    def restoreMepId(self):
        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
          
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
   
                 
                 
    def addG8131Mlp(self): 
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.p1 != None and self.p1Sel == 1:
            (rc,info) = self.p1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')



    def deleteVpws(self):
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')

class LspProt_Scenario_3(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for lsp  permanent protection 
    simulate the GreenWell d-control configuration method
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')




        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'addmlp':
                self.addG8131Mlp()
            elif cmd == 'basic':
                self.addBasicVpws()
            elif cmd == 'update':
                self.updateMepId()
            elif cmd == 'restore':
                self.restoreMepId()                
            elif cmd == 'all':
                self.addBasicVpws()
                self.addG8131Mlp()  
            elif cmd == 'del':
                self.deleteVpws()
            elif cmd == 'exit':
                break 
                
                              


    def addBasicVpws(self):
        uniVlan = [10]
        try:
            if len(self.pe1Config['ELECTRIC_PORTS']) != 0: 
                pe1UniPort = self.pe1Config['ELECTRIC_PORTS'][0]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe1NniPort_w = self.pe1Config['OPTICAL_PORTS'][0]
                pe1NniPort_p = self.pe1Config['OPTICAL_PORTS'][1]               


            if len(self.pe2Config['ELECTRIC_PORTS']) != 0: 
                pe2UniPort = self.pe2Config['ELECTRIC_PORTS'][0]
            elif len(self.pe2Config['OPTICAL_PORTS']) != 0:
                pe2UniPort = self.pe2Config['OPTICAL_PORTS'][12]

            if len(self.pe1Config['OPTICAL_PORTS']) != 0:
                pe2NniPort_w = self.pe2Config['OPTICAL_PORTS'][9]
                pe2NniPort_p = self.pe2Config['OPTICAL_PORTS'][11]  
                
        except:
                raise ("no ports found")
                

        
        nniVlan = 100
        pe1PortMac_w = self.pe1.getPortMac(pe1NniPort_w) 
        pe1PortMac_p = self.pe1.getPortMac(pe1NniPort_p)
        
        if self.pe2 == None:
            pe2PortMac = [0x0e,0x5e,0x05,0x12,0xff,0xa0]
        else:
            pe2PortMac_w = self.pe2.getPortMac(pe2NniPort_w)  
            pe2PortMac_p = self.pe2.getPortMac(pe2NniPort_p)  

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 3000,outLabel = 4000,nniPort = pe1NniPort_w,nniVlan = nniVlan,\
                dstMac = pe2PortMac_w)
            lsp_p = self.pe1.addLsp(lspIndex = 2, inLabel = 3001,outLabel = 4001,nniPort = pe1NniPort_p,nniVlan = nniVlan,\
                dstMac = pe2PortMac_p)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 2000 ,outLabel = 2500,uniPort = pe1UniPort, uniVlan = uniVlan, tunnel = tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20, localOfMpId=10,remoteOfMpId=20 )
            self.pe1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40, localOfMpId=30,remoteOfMpId=40 )
            self.pe1.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            

            
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 4000,outLabel = 3000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMac_w)
            lsp_p = self.pe2.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = pe2NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = pe2UniPort, uniVlan = uniVlan, tunnel =   tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10, localOfMpId=20,remoteOfMpId=10 )
            self.pe2.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30, localOfMpId=40,remoteOfMpId=30)
            self.pe2.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            
            
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
      
      
    def updateMepId(self):
        self.pe1Sel = 0
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 50 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config self.pe2
            '''
            meg_new = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 60 ,rmepid = 30 )
            self.pe2.updateLspOam(meg_new, 2)            
            
     
    def restoreMepId(self):
        self.pe1Sel = 0
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
          
            meg_new = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.updateLspOam(meg_new, 1)
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config self.pe2
            '''
            meg_new = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.updateLspOam(meg_new, 2)   
                 
                 
    def addG8131Mlp(self): 
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')



    def deleteVpws(self):
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')  
    
    
class ExceptionCcmUnm(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for exception case (Unknown Mep Id) 
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for agt in self.controller.device_agents:
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')




        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'addmlp':
                self.addG8131Mlp()
            elif cmd == 'basic':
                self.addBasicVpws()
            elif cmd == 'del':
                self.deleteVpws()
            elif cmd == 'exit':
                break 
                
                              


    def addBasicVpws(self):
        uniVlan = [10]
        
        uniPort = 3
        nniPort_w = 4
        nniPort_p = 5

        pe2UniPort = 3 
        pe2NniPort_w = 4
        pe2NniPort_p = 5
        
        nniVlan = 100
        pe1PortMac_w = self.pe1.getPortMac(nniPort_w) 
        pe1PortMac_p = self.pe1.getPortMac(nniPort_p)
        
        if self.pe2 == None:
            pe2PortMac = [0x0e,0x5e,0x05,0x12,0xff,0xa0]
        else:
            pe2PortMac_w = self.pe2.getPortMac(pe2NniPort_w)  
            pe2PortMac_p = self.pe2.getPortMac(pe2NniPort_p)  

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 3000,outLabel = 4000,nniPort = nniPort_w,nniVlan = nniVlan,\
                dstMac = pe2PortMac_w)
            lsp_p = self.pe1.addLsp(lspIndex = 2, inLabel = 3001,outLabel = 4001,nniPort = nniPort_p,nniVlan = nniVlan,\
                dstMac = pe2PortMac_p)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 2000 ,outLabel = 2500,uniPort = uniPort, uniVlan = uniVlan, tunnel = tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 50 ,rmepid = 20 )
            self.pe1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40 )
            self.pe1.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            

            
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.pe2Sel = 0
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 4000,outLabel = 3000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMac_w)
            lsp_p = self.pe2.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = pe2NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = pe2UniPort, uniVlan = uniVlan, tunnel =   tunnel)
            
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.pe2.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 60 ,rmepid = 30 )
            self.pe2.addOam2Lsp(lsp = lsp_p, meg = meg_p)
            
            
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
                 
    def addG8131Mlp(self): 
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')



    def deleteVpws(self):
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')    
                        
class QosPCP(advanced_tests.AdvancedProtocol):
    """
    vpws test case for sptn Qos  
    """      
    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')


        while True:
            cmd = raw_input('cmd: ')
            #print(cmd)
            if cmd == 'basic':
                self.addBasic()
            elif cmd == 'delete':
                self.delete()
            elif cmd == 'exit':
                break 
            else:
                print('unknown cmd') 
                
                              

    def addBasic(self):
        uniPort = 3
        uniVlan = [10]
        nniPort_w = 4
        nniPort_p = 5

        nniVlan = 100
        pe1PortMacW = self.pe1.getPortMac(nniPort_w) 
        pe1PortMacP = self.pe1.getPortMac(nniPort_p)
        
        pe2PortMacW = self.pe2.getPortMac(nniPort_w) 
        pe2PortMacP = self.pe2.getPortMac(nniPort_p)  
        

        # qos for pw 
        pcp2tc = [0,7,6,5,4,3,2,1]
        tc2pcp = [0,6,5,4,3,2,1,7]
        exp2tc = [6,4,3,2,1,7,0,5]
        tc2exp = [0,6,5,4,3,2,1,7]
        remarkPattern = ofdpa.OFDPA_QOS_MODE_PCP
        pwQos = QoS(index = 1,pcp2tc=pcp2tc, tc2pcp=tc2pcp, tc2exp=tc2exp, exp2tc=exp2tc,remarkPattern=remarkPattern)
        
        # qos for lsp
        tc2exp = [0,1,2,3,4,5,6,7]
        remarkPattern = ofdpa.OFDPA_QOS_MODE_PCP
        lspQos = QoS(index = 2,tc2exp=tc2exp,remarkPattern=remarkPattern,level=ofdpa.OFDPA_QOS_LEVEL_LSP)

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 1000,outLabel = 2000,nniPort = nniPort_w,\
                                    nniVlan = nniVlan, dstMac = pe2PortMacW,Qos=lspQos)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 10 ,outLabel = 20,uniPort = uniPort, \
                                uniVlan = uniVlan, tunnel = tunnel,Qos=pwQos)
          
 
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.pe2Sel = 0
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 2000,outLabel = 1000,nniPort = nniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMacW,Qos=lspQos)
                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 20 ,outLabel = 10,uniPort = uniPort,\
                                 uniVlan = uniVlan, tunnel = tunnel,Qos=pwQos)
            

   
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
                 


    def delete(self):
        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:

            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
             
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            


class QosPCPStats(advanced_tests.AdvancedProtocol):
    """
    vpws test case for sptn Qos  
    """      
    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]
        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')


        while True:
            cmd = raw_input('cmd: ')
            print(cmd)
            if cmd == 'b':
                self.addBasic()
            elif cmd == 'd':
                self.delete()
            elif cmd == 'exit':
                break 
            else:
                print('unknown cmd') 
                
                              

    def addBasic(self):
        uniPort = 3
        uniVlan = [10]
        nniPort_w = 4
        nniPort_p = 2

        nniVlan = 100
        pe1PortMacW = self.pe1.getPortMac(nniPort_w) 
        pe1PortMacP = self.pe1.getPortMac(nniPort_p)
        
        pe2PortMacW = self.pe2.getPortMac(nniPort_w) 
        pe2PortMacP = self.pe2.getPortMac(nniPort_p)  
        

        # qos for pw 
        local2exp = [0,7,6,5,4,3,2,1]
        remarkPattern = ofdpa.OFDPA_QOS_MODE_PCP
        pwQos = QoS(index = 1,local2exp=local2exp,remarkPattern=remarkPattern)
        
        # qos for lsp
        local2exp = [0,1,2,3,4,5,6,7]
        remarkPattern = ofdpa.OFDPA_QOS_MODE_PCP
        lspQos = QoS(index = 2,local2exp=local2exp,remarkPattern=remarkPattern,level=ofdpa.OFDPA_QOS_LEVEL_LSP)

        if self.pe1 != None:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 1000,outLabel = 2000,nniPort = nniPort_w,\
                                    nniVlan = nniVlan, dstMac = pe2PortMacW,Qos=lspQos, colorBasedCtrColor = 0xFF)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 10 ,outLabel = 20,uniPort = uniPort, \
                                uniVlan = uniVlan, tunnel = tunnel,Qos=pwQos)
          
 
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        if self.pe2 != None:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 2000,outLabel = 1000,nniPort = nniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMacW,Qos=lspQos, colorBasedCtrColor = 0xFF)
                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w])
            
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 20 ,outLabel = 10,uniPort = uniPort,\
                                 uniVlan = uniVlan, tunnel = tunnel,Qos=pwQos)
            

   
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
                 


    def delete(self):
        pass            
            
            
class LspProtUnderStc(advanced_tests.AdvancedDataPlane):
    """
    vpws test case for lsp  permanent protection 
    """      

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        self.pe1Config = config["device_map"]["pe1"]
        self.pe2Config = config["device_map"]["pe2"]  
        self.dp = STC_DP.DpProfile_MultiStream(dataplane = self.dataplane)
        self.pe1UniPort = 3
        self.pe2UniPort = 13
        

        print("\r\n")
        print(hex(self.pe1Config['DPID']))
        print(hex(self.pe2Config['DPID']))
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 3000 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for id,agt in self.controller.device_agents:
                print(id,hex(agt.dpid))
                #print(agt.dpid)
                if self.pe1 == None and agt.dpid == self.pe1Config['DPID']: 
                    self.pe1 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == self.pe2Config['DPID']:
                    self.pe2 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            print('.')
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 2,'no enough device is online')


        self.addBasicVpws()
        self.addG8131Mlp()   
        self.totalCount = self.dp.config( stcProject = self.dataplane.project[0],
                                          txPort = self.dataplane.ports[self.pe1UniPort],
                                          rxPort = self.dataplane.ports[self.pe2UniPort])
        print self.totalCount
        self.assertEquals((self.totalCount >= 10000), True,'packets lost!! Test Fail!!')
        
        #delete openflow config
        print "delete vpws service"
        self.deleteVpws()
                
                   


    def addBasicVpws(self):
        uniVlan = [10]
        
        uniPort = self.pe1UniPort 
        nniPort_w = 1
        nniPort_p = 2

        pe2UniPort = self.pe2UniPort  
        pe2NniPort_w = 9
        pe2NniPort_p = 11
        
        nniVlan = 100
        pe1PortMac_w = self.pe1.getPortMac(nniPort_w) 
        pe1PortMac_p = self.pe1.getPortMac(nniPort_p)
        
        if self.pe2 == None:
            pe2PortMac = [0x0e,0x5e,0x05,0x12,0xff,0xa0]
        else:
            pe2PortMac_w = self.pe2.getPortMac(pe2NniPort_w)  
            pe2PortMac_p = self.pe2.getPortMac(pe2NniPort_p)  

        self.pe1Sel = 1
        if self.pe1 != None and self.pe1Sel == 1:
            '''
            config self.pe1
            '''
            lsp_w = self.pe1.addLsp(lspIndex = 1, inLabel = 3000,outLabel = 4000,nniPort = nniPort_w,nniVlan = nniVlan,\
                dstMac = pe2PortMac_w)
            lsp_p = self.pe1.addLsp(lspIndex = 2, inLabel = 3001,outLabel = 4001,nniPort = nniPort_p,nniVlan = nniVlan,\
                dstMac = pe2PortMac_p)
                
            tunnel = self.pe1.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            
            pw = self.pe1.addPw(pwIndex = 1,inLabel = 2000 ,outLabel = 2500,uniPort = uniPort, uniVlan = uniVlan, tunnel = tunnel)
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe1.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40 )
            self.pe1.addOam2Lsp(lsp = lsp_p, meg = meg_p)


            
            self.assertEqual(self.pe1.apply_status(), 0,
             'response status != expect status 0')
        
        self.pe2Sel = 1
        if self.pe2 != None and self.pe2Sel == 1:
            '''
            config pe2
            ''' 
            lsp_w = self.pe2.addLsp(lspIndex = 1, inLabel = 4000,outLabel = 3000,nniPort = pe2NniPort_w,
                nniVlan = nniVlan,dstMac = pe1PortMac_w)
            lsp_p = self.pe2.addLsp(lspIndex = 2, inLabel = 4001,outLabel = 3001,nniPort = pe2NniPort_p,
                nniVlan = nniVlan,dstMac = pe1PortMac_p)

                
            tunnel = self.pe2.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], protMode = ofdpa.OFDPA_PROT_MODE_ENABLE)
            uniVlan = [10]
            pw = self.pe2.addPw(pwIndex = 1,inLabel = 2500 ,outLabel = 2000,uniPort = pe2UniPort, uniVlan = uniVlan, tunnel =   tunnel)
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.pe2.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe2.addOam2Lsp(lsp = lsp_p, meg = meg_p)

            
            self.assertEqual(self.pe2.apply_status(), 0,
                     'response status != expect status 0')
                 
    def addG8131Mlp(self): 
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print(('%-24s: ' % 'addG8131Mlp')+  info  + '('  +  str(rc)  + ')')



    def deleteVpws(self):
        if self.pe1 != None and self.pe1Sel == 1:
            (rc,info) = self.pe1.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe1.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe1.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe1.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe1.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            

        
        if self.pe2 != None and self.pe2Sel == 1:
            (rc,info) = self.pe2.deleteMlp(mlpIndex = 1)
            print(('%-24s: ' % 'deleteMlp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)

            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 1)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')
            (rc,info)  = self.pe2.removeOamFromLsp(lspIndex = 2)
            print(('%-24s: ' % 'removeOamFromLsp')+  info  + '('  +  str(rc)  + ')')

            
            time.sleep(1)
            
            (rc,info) = self.pe2.deletePw(pwIndex = 1)
            print(('%-24s: ' % 'deletePw')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)

            (rc,info) = self.pe2.deleteTunnel(tunnelIndex = 1)
            print(('%-24s: ' % 'deleteTunnel')+  info  + '('  +  str(rc)  + ')')

            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 1)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
            time.sleep(1)
            
            (rc,info) = self.pe2.deleteLsp(lspIndex = 2)
            print(('%-24s: ' % 'deleteLsp')+  info  + '('  +  str(rc)  + ')')
            
