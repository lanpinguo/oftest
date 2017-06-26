# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2014 Big Switch Networks, Inc.
"""
vpws services test cases
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
    
    


class demo(advanced_tests.AdvancedProtocol):
    """
    Verify that creating a mpls LSP
    """
    experimenter_id = 0x1018
    def runTest(self):
        pe3 = None
        pe4 = None
        
        for d in self.controller.device_agents:
            if d.dpid == 0xe5e512ff90000: 
                pe3 = d
            elif d.dpid == 0xe5e501c5a0000:
                pe4 = d 
        #delete_all_flows(self.controller)
        if pe3 :
            '''
            Add group
            '''
            uni_port = 3
            nni_port = 4
            uni_vlan = 10 | ofdpa.OFDPA_VID_PRESENT
            '''
            add l2 interface group
            '''
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
            id = ofdb_group_vlanid_set(id , uni_vlan)
            id = ofdb_group_portid_set(id , uni_port)
            action_list = [ofp.action.output(uni_port) ,
                ofp.action.set_field(ofp.oxm.mpls_tp_allow_vlan_translation()) ,
            ]
            bucket_list = [ofp.bucket(actions = action_list)]

            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
                
            pe3.message_send(msg)

            do_barrier(pe3)        

        if pe4 :
            '''
            Add group
            '''
            uni_port = 3
            nni_port = 4
            uni_vlan = 10 | ofdpa.OFDPA_VID_PRESENT
            '''
            add l2 interface group
            '''
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
            id = ofdb_group_vlanid_set(id , uni_vlan)
            id = ofdb_group_portid_set(id , uni_port)
            action_list = [ofp.action.output(uni_port) ,
                ofp.action.set_field(ofp.oxm.mpls_tp_allow_vlan_translation()) ,
            ]
            bucket_list = [ofp.bucket(actions = action_list)]

            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
                
            pe4.message_send(msg)

            do_barrier(pe4)        

class TUNNEL():
    """
    tunnel flow config data model
    """
    def __init__(self,tunnelIndex,lsp_list = [], proMode = None):
        self.nni2uni = []
        self.uni2nni = []
        self.tunnelIndex = tunnelIndex
        self.livenessPortWorker = None
        self.livenessPortProtector = None
        self.lsp_list = lsp_list
        
        if proMode == 0:
            self.bundleHandle = lsp_list[0].bundle_handle()
        elif proMode == 1:
            '''
            add mpls fast failover group
            '''
            self.livenessPortWorker = 0xF0000000 + lsp_list[0].lspIndex
            self.livenessPortProtector = 0xF0000000 + lsp_list[1].lspIndex
            
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_FORWARDING)
            id = ofdb_group_mpls_index_set(id , self.tunnelIndex)
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
 
class SWAP():
    """
    swap flow config data model
    """
    def __init__(self,swapIndex, inLabel, outLabel, nniPort_in, nniPort_out, portMac_in, portMac_out, dstMac, nniVlan_in = None, nniVlan_out = None, Qos = None):
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
        id = ofdb_group_mpls_index_set(id , self.swapIndex)
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
        add mpls l2 swap label group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , self.swapIndex)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_SWAP_LABEL)
        self.bundleHandle = id
        action_list = [ofp.action.group(group_id = ref_group) ,                       
                       ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)) ]
        bucket_list = [ofp.bucket(actions = action_list)]

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
        
        instructions=[
            ofp.instruction.apply_actions(actions = [ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1))]),
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
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
        

    def get_flow_db(self):
        return ( self.uni2nni,self.nni2uni)      
    def set(self,requset):
        pass
    def bundle_handle(self):
        return self.bundleHandl
           
class LSP():
    """
    lsp flow config data model
    """
    def __init__(self,lspIndex, inLabel, outLabel, nniPort, portMac, dstMac, nniVlan = None,Qos = None):
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
        id = ofdb_group_mpls_index_set(id , self.lspIndex)
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
        add mpls tunnel label 1 group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , self.lspIndex)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_TUNNEL_LABEL1)
        self.bundleHandle = id
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.push_mpls(ethertype = 0x8847) ,
                       ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)) ,
                       ofp.action.copy_ttl_out() ,
                       ofp.action.set_field(ofp.oxm.mpls_tc(value = 0))]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.uni2nni.append(msg)

  
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
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_2),
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
            ofp.oxm.mpls_bos(value = 0),
            ofp.oxm.mpls_tp_ach_channel(value = 0x8902),
            ofp.oxm.mpls_tp_data_first_nibble(value = 1),
            ofp.oxm.mpls_tp_next_label_is_gal(value = 1)
        ])
        
        action = [ofp.action.pop_mpls(ethertype = 0x8847),
            ofp.action.set_field(ofp.oxm.mpls_tp_mp_id(value = meg.lmepid)),
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
        return self.meg.lmepid
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
    def __init__(self,pwIndex,inLabel,outLabel,uniPort,tunnel, uniVlan = [],  Qos = None):
        self.nni2uni = []
        self.uni2nni = []
        self.inLabel = inLabel
        self.outLabel = outLabel
        self.tunnel_handle = tunnel.bundle_handle()
        self.uniPort = uniPort
        
        self.uniVlan = []
        for vlan in uniVlan:
            vlan |= ofdpa.OFDPA_VID_PRESENT
            self.uniVlan.append(vlan)
            
        self.pwIndex = pwIndex
        self.local_mpls_l2_port  = 0x00000000 + pwIndex      
        self.network_mpls_l2_port = 0x00020000 + pwIndex       
        self.tunnel_id = 0x00010000 + pwIndex       
        ####################################################################################
        #
        # Create pw
        #
        ####################################################################################        
        '''
        add l2 interface group
        '''
        id = 0
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

        '''
        Add Flow
        '''
        '''
        Add mpls 1 table entry
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
           # ofp.action.pop_vlan() ,
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
       
        '''
        add mpls vpn group
        '''
        ref_group = self.tunnel_handle
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , self.pwIndex)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_L2_VPN_LABEL)
        action_list = [ofp.action.group(group_id = ref_group) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.push_mpls(ethertype = 0x8847) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.set_field(ofp.oxm.mpls_label(value = self.outLabel)) ,
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


        '''
        Add mpls l2 port table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT
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
        instructions=[
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST),
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
       
        '''
        Add vlan table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(self.uniPort),
            ofp.oxm.vlan_vid(self.uniVlan[0]),
        ])
        
        '''
        apply actions
        '''
        apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,
            ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.local_mpls_l2_port)) ,
        
        ]
        instructions=[
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT),
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
        

        
    def get_flow_db(self):
        return (self.uni2nni,self.nni2uni)
    def set(self,requset):
        pass
        

        
class DEVICE():
    """
    device root class
    """    
    def __init__(self,agt):
        self.agt = agt
        self.lsp = []
        self.swap = []
        self.tunnel = []
        self.pw = []
        self.mlp = []
        self.status = 0
        self.agt.register(msg_type = ofp.OFPT_ERROR, handler = self.error_handler)
        self.netconf_connected = False
    def error_handler(self,obj,hdr_xid, msg, rawmsg):
        #print("err:")
        #print(hdr_xid)
        #print(msg.err_type)
        if msg.err_type == ofp.OFPET_FLOW_MOD_FAILED or msg.err_type ==  ofp.OFPET_GROUP_MOD_FAILED :
            self.status = -1
    def apply_status(self):
        return self.status
    def addLsp(self,lspIndex, inLabel, outLabel, nniPort, dstMac, nniVlan = None,Qos = None):
        #portMac = self.agt.port_desc[nniPort - 1].hw_addr 
        for pd in self.agt.port_desc:
            if nniPort == pd.port_no:
                portMac = pd.hw_addr
                break;
        new_lsp = LSP(lspIndex = lspIndex, inLabel = inLabel, outLabel = outLabel, nniPort = nniPort,\
            portMac = portMac , dstMac = dstMac, nniVlan = nniVlan | ofdpa.OFDPA_VID_PRESENT,Qos = Qos)
        (uni2nni , nni2uni) = new_lsp.get_flow_db()
        for msg in uni2nni:
            self.agt.message_send(msg)
        for msg in nni2uni:
            self.agt.message_send(msg)
        do_barrier(self.agt)
        self.lsp.append(new_lsp)

        return new_lsp
    
    def addSwap(self,swapIndex, inLabel, outLabel, nniPort_in, nniPort_out, dstMac, nniVlan_in = None, nniVlan_out = None):
        #portMac_in = self.agt.port_desc[nniPort_in - 1].hw_addr
        for pd in self.agt.port_desc:
            if nniPort_in == pd.port_no:
                portMac_in = pd.hw_addr
                break;
        #portMac_out = self.agt.port_desc[nniPort_out - 1].hw_addr 
        for pd in self.agt.port_desc:
            if nniPort_out == pd.port_no:
                portMac_out = pd.hw_addr
                break;        
        new_swap = SWAP(swapIndex = swapIndex, inLabel = inLabel, outLabel = outLabel, nniPort_in = nniPort_in,\
            nniPort_out = nniPort_out, portMac_in = portMac_in, portMac_out = portMac_out , dstMac = dstMac, nniVlan_in = nniVlan_in | ofdpa.OFDPA_VID_PRESENT,\
            nniVlan_out = nniVlan_out | ofdpa.OFDPA_VID_PRESENT)
        (uni2nni , nni2uni) = new_swap.get_flow_db()
        for msg in uni2nni:
            self.agt.message_send(msg)
        for msg in nni2uni:
            self.agt.message_send(msg)
        do_barrier(self.agt)
        self.swap.append(new_swap)
        return new_swap    
        
        
    def addTunnel(self,tunnelIndex,lsp_list, proMode = None):
    
        new_tunnel = TUNNEL(tunnelIndex = tunnelIndex,lsp_list = lsp_list,proMode = proMode)
        (uni2nni , nni2uni) = new_tunnel.get_flow_db()
        for msg in uni2nni:
            self.agt.message_send(msg)
        for msg in nni2uni:
            self.agt.message_send(msg)
        do_barrier(self.agt)
        self.tunnel.append(new_tunnel)
        return new_tunnel

    def addPw(self,pwIndex,inLabel,outLabel,uniPort,tunnel, uniVlan = [],  Qos = None):
    
        new_pw = PW(pwIndex = pwIndex ,inLabel = inLabel,outLabel = outLabel,uniPort = uniPort, uniVlan = uniVlan, tunnel = tunnel, Qos = Qos)
        (uni2nni , nni2uni) = new_pw.get_flow_db()
        for msg in uni2nni:
            self.agt.message_send(msg)
        for msg in nni2uni:
            self.agt.message_send(msg)
        do_barrier(self.agt)
        self.pw.append(new_pw)
        return new_pw


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
                self.agt.message_send(self.convertFlowMsgC2D(msg))
            except:
                print("error msg")
        for msg in nni2uni[::-1]:
            try:
                self.agt.message_send(self.convertFlowMsgC2D(msg))
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
                self.agt.message_send(self.convertFlowMsgC2D(msg))
            except:
                print("error msg")
        for msg in nni2uni[::-1]:
            try:
                self.agt.message_send(self.convertFlowMsgC2D(msg))
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
                self.agt.message_send(self.convertFlowMsgC2D(msg))
            except:
                print("error msg")
        for msg in nni2uni[::-1]:
            try:
                self.agt.message_send(self.convertFlowMsgC2D(msg))
            except:
                print("error msg")
        #do_barrier(self.agt)   
        return (0 , 'delete success') 

    def addOam2Lsp(self,meg,lsp):
        '''
        Todo netconf config here
        '''
        if self.netconf_connected == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return -1
            self.netconf_connected = True
            
        (rc , info) = self.agt.netconf.config(file = meg.getFileName())
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
            for msg in nni2uni:
                self.agt.message_send(msg)
            for msg in uni2nni:
                self.agt.message_send(msg)

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
            self.agt.message_send(msg)
        for msg in nni2uni:
            self.agt.message_send(msg)
        #do_barrier(self.agt)
        return (0,'tunnel modif success')
        
        
        
    def updateMlp(self,mlpIndex,target,proMode = 1):
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
            targetMlp.removeMlpHeadEnd(mlpHeadEnd = targetMlp.mlpHeadEnds[0])
            
            if self.netconf_connected == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')
            self.netconf_connected = True
            
            (rc , info) = self.agt.netconf.config(file = targetMlp.getFileName())
            if rc != 0:
                print(info)
                return (-1 , 'removeMlpHeadEnd failed')

            '''
            REPLACE HEAD END
            '''   
            targetMlp.replaceMlpHeadEnd(mlpHeadEnd = worker)
            if self.netconf_connected == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')
            self.netconf_connected = True
            
            (rc , info) = self.agt.netconf.config(file = targetMlp.getFileName())
            if rc != 0:
                print(info)
                return (-1 , 'repalceMlpHeadEnd failed')
                        
            targetMlp.mlpHeadEnds[0] = worker  #updae record
          
        if targetMlp.mlpHeadEnds[1].mepId != protector.mepId:
            '''
            REMOVE HEAD END
            ''' 
            targetMlp.removeMlpHeadEnd(mlpHeadEnd = targetMlp.mlpHeadEnds[1])
  
            if self.netconf_connected == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')
            self.netconf_connected = True
            
            (rc , info) = self.agt.netconf.config(file = targetMlp.getFileName())
            if rc != 0:
                print(info)
                return (-1 , 'removeMlpHeadEnd failed')

            '''
            REPLACE HEAD END
            '''            
            targetMlp.replaceMlpHeadEnd(mlpHeadEnd = protector)
            if self.netconf_connected == False:
                (rc , info) = self.agt.netconf.connect()
                if rc != 0:
                    print(info)
                    return (-1 , 'connect not exist')
            self.netconf_connected = True
            
            (rc , info) = self.agt.netconf.config(file = targetMlp.getFileName())
            if rc != 0:
                print(info)
                return (-1 , 'repalceMlpHeadEnd failed')
                                    
            targetMlp.mlpHeadEnds[1] = protector #updae record
        return (0 , 'updateMlp success')
    def addMlp(self,mlpIndex ,mlpName ,target, proMode = 1):
        '''
        Todo netconf config here
        '''
        targetTunnel = None
        for tunnel in self.tunnel:
            #print(tunnel.tunnelIndex)
            if tunnel.tunnelIndex == target:
                targetTunnel = tunnel
        if targetTunnel is None:
            return (-1 , 'tunnel not found')
        (lmep_w,lmep_p) = targetTunnel.getMepInfo()
        worker = netconf.MLP_HEAD_END(mepId = lmep_w,liveness_port = targetTunnel.livenessPortWorker,\
            role = 'working')    
        protector = netconf.MLP_HEAD_END(mepId = lmep_p,liveness_port = targetTunnel.livenessPortProtector,\
            role = 'protection')
        ends = [worker,protector]        
        mlpNew = netconf.MLP(mlpIndex = mlpIndex,mlpName = mlpName,mlpHeadEnds=ends)
        self.mlp.append(mlpNew)
        if self.netconf_connected == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1 , 'connect not exist')
            self.netconf_connected = True
            
        (rc , info) = self.agt.netconf.config(file = mlpNew.getFileName())
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

        if self.netconf_connected == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1 , 'connect not exist')
            self.netconf_connected = True
            
        (rc , info) = self.agt.netconf.config(file = targetMlp.delete())
        if rc != 0:
            print(info)
            return (-1 , 'config failed')
            
        return (0 , 'delete success')
    def convertFlowMsgC2D(self,msg):
        if isinstance(msg,ofp.message.group_add) or isinstance(msg,ofp.message.group_mod):
            print('construct group delete msg')
            out = ofp.message.group_delete(
                group_type = msg.group_type,
                group_id = msg.group_id,
                buckets = msg.buckets)
        elif isinstance(msg,ofp.message.flow_add):
            print('construct flow delete msg')
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
                    self.agt.message_send(self.convertFlowMsgC2D(msg))
                except:
                    print("error msg")
            for msg in nni2uni[::-1]:
                try:
                    self.agt.message_send(self.convertFlowMsgC2D(msg))
                except:
                    print("error msg")
            #do_barrier(self.agt)   
        else :
            return (-1,'lsp not found')
            
        if self.netconf_connected == False:
            (rc , info) = self.agt.netconf.connect()
            if rc != 0:
                print(info)
                return (-1,'no connect')
            self.netconf_connected = True
        
        (rc , info) = self.agt.netconf.config(file = meg.delete())
        if rc != 0:
            print(info)
            return (-1,'config fail')
        time.sleep(1)  
        return (0,'delete success')
   
    def addOam2Pw(self,lsp):
        pass        
    def removeOamFromPw(self,pw):
        pass  

        
class vpwsLSPPro(advanced_tests.AdvancedProtocol):
    """
    vpws test case for lsp  permanent protection 
    """      
    def runTest(self):
        self.pe3 = None
        self.pe4 = None 
        self.p5 = None
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 15 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for agt in self.controller.device_agents:
                if self.pe3 == None and agt.dpid == custom.PE3_CONFIG['DPID']: 
                    self.pe3 = DEVICE(agt = agt)
                    self.deviceIsOnline += 1
                elif self.pe4 == None and agt.dpid == custom.PE4_CONFIG["DPID"]:
                    self.pe4 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1 
                elif self.p5 == None and agt.dpid == custom.P5_CONFIG["DPID"]:
                    self.p5 = DEVICE(agt = agt) 
                    self.deviceIsOnline += 1                                        
            self.waitDeviceOnline -= 1
            time.sleep(1) # sleep 1s
        self.assertEquals(self.deviceIsOnline, 3,'no enough device is online')
        
        self.addBasicVpws()
                         
                
    def addBasicVpws(self):
        uniPort_west = 28
        uniPort_east = 28        
        uniVlan = [1001]
        nniPort_west_w = 19
        nniPort_west_p = 18
        nniPort_east_w = 19
        nniPort_east_p = 17                
        nniPort_swap1 = 18
        nniPort_swap2 = 17 
        nniVlan = 100      
        nniVlan_in = 100
        nniVlan_out = 100

        
        #pe3PortMacW = self.pe3.agt.port_desc[nniPort_west_w - 1].hw_addr
        pe3PortMacW = []
        for pd in self.pe3.agt.port_desc:
            if pd.port_no == nniPort_west_w:
                pe3PortMacW = pd.hw_addr
                break
                
        #pe3PortMacP = self.pe3.agt.port_desc[nniPort_west_p - 1].hw_addr 
        pe3PortMacP = []
        for pd in self.pe3.agt.port_desc:
            if pd.port_no == nniPort_west_p:
                pe3PortMacP = pd.hw_addr
                break      

                
        #p5PortMac_in = self.p5.agt.port_desc[nniPort_swap1-1].hw_addr
        p5PortMac_in = []
        for pd in self.p5.agt.port_desc:
            if pd.port_no == nniPort_swap1:
                p5PortMac_in = pd.hw_addr
                break  
        #p5PortMac_out = self.p5.agt.port_desc[nniPort_swap2-1].hw_addr
        p5PortMac_out = []        
        for pd in self.p5.agt.port_desc:
            if pd.port_no == nniPort_swap2:
                p5PortMac_out = pd.hw_addr
                break    

                
        #pe4PortMacW = self.pe4.agt.port_desc[nniPort_east_w - 1].hw_addr 
        pe4PortMacW = []        
        for pd in self.pe4.agt.port_desc:
            if pd.port_no == nniPort_east_w:
                pe4PortMacW = pd.hw_addr
                break          
        #pe4PortMacP = self.pe4.agt.port_desc[nniPort_east_p - 1].hw_addr
        pe4PortMacP = []
        for pd in self.pe4.agt.port_desc:
            if pd.port_no == nniPort_east_p:
                pe4PortMacP = pd.hw_addr
                break          
            
  
        if self.pe3 != None:
            '''
            config self.pe3
            '''
            lsp_w = self.pe3.addLsp(lspIndex = 1, inLabel = 1000,outLabel = 2000,nniPort = nniPort_west_w,nniVlan = nniVlan,\
                dstMac = p5PortMac_in)
            lsp_p = self.pe3.addLsp(lspIndex = 2, inLabel = 1001,outLabel = 2001,nniPort = nniPort_west_p,nniVlan = nniVlan,\
                dstMac = pe4PortMacP)            
                
            tunnel = self.pe3.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], proMode = 1)
            
            pw = self.pe3.addPw(pwIndex = 1,inLabel = 10 ,outLabel = 20,uniPort = uniPort_west, uniVlan = uniVlan, tunnel = tunnel)
          
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 10 ,rmepid = 20 )
            self.pe3.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 30 ,rmepid = 40 )
            self.pe3.addOam2Lsp(lsp = lsp_p, meg = meg_p)

           

            
            self.assertEqual(self.pe3.apply_status(), 0,
             'response status != expect status 0')
        
        if self.pe4 != None:
            '''
            config self.pe4
            ''' 
            lsp_w = self.pe4.addLsp(lspIndex = 1, inLabel = 3000,outLabel = 4000,nniPort = nniPort_east_w,
                nniVlan = nniVlan,dstMac = p5PortMac_out)
            lsp_p = self.pe4.addLsp(lspIndex = 2, inLabel = 2001,outLabel = 1001,nniPort = nniPort_east_p,
                nniVlan = nniVlan,dstMac = pe3PortMacP)
            
                
            tunnel = self.pe4.addTunnel(tunnelIndex = 1, lsp_list = [lsp_w,lsp_p], proMode = 1)
            
            pw = self.pe4.addPw(pwIndex = 1,inLabel = 20 ,outLabel = 10,uniPort = uniPort_east, uniVlan = uniVlan, tunnel = tunnel)
            
            meg_w = netconf.MEG(megIndex = 1,megName ='lspmeg-w' , lmepid = 20 ,rmepid = 10 )
            self.pe4.addOam2Lsp(lsp = lsp_w, meg = meg_w)
     
            meg_p = netconf.MEG(megIndex = 2,megName ='lspmeg-p' , lmepid = 40 ,rmepid = 30 )
            self.pe4.addOam2Lsp(lsp = lsp_p, meg = meg_p)

           
            
            self.assertEqual(self.pe4.apply_status(), 0,
                     'response status != expect status 0')
                 
        if self.p5 != None:
            '''
            config self.p5
            ''' 
            swap_west = self.p5.addSwap(swapIndex = 1, inLabel = 2000,outLabel = 3000, nniPort_in = nniPort_swap1,
                nniPort_out = nniPort_swap2, nniVlan_in = nniVlan_in,nniVlan_out = nniVlan_out,dstMac = pe4PortMacW)
            swap_east = self.p5.addSwap(swapIndex = 2, inLabel = 4000,outLabel = 1000, nniPort_in = nniPort_swap2,
                nniPort_out = nniPort_swap1, nniVlan_in = nniVlan_in,nniVlan_out = nniVlan_out,dstMac = pe3PortMacW)

            self.assertEqual(self.p5.apply_status(), 0,
                     'response status != expect status 0')

            

        if self.pe3 != None:
            (rc,info) = self.pe3.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print('addG8131Mlp:'+ str(rc) + '-' + info)
        if self.pe4 != None:
            (rc,info) = self.pe4.addMlp(mlpIndex = 1,mlpName = 'lsp-aps1',target = 1)
            print('addG8131Mlp:'+ str(rc) + '-' + info)
    
    def deleteVpws(self):
        if self.pe3 != None:
            (rc,info) = self.pe3.deleteMlp(mlpIndex = 1)
            print('deleteMlp:'+ str(rc) + '-' + info)
            
            time.sleep(1)

            (rc,info)  = self.pe3.removeOamFromLsp(lspIndex = 1)
            print('removeOamFromLsp:'+ str(rc) + '-' + info)
            (rc,info)  = self.pe3.removeOamFromLsp(lspIndex = 2)
            print('removeOamFromLsp:'+ str(rc) + '-' + info)
            (rc,info)  = self.pe3.removeOamFromLsp(lspIndex = 3)
            print('removeOamFromLsp:'+ str(rc) + '-' + info)
            
            time.sleep(1)
            
            (rc,info) = self.pe3.deletePw(pwIndex = 1)
            print('deletePw:'+ str(rc) + '-' + info)

            time.sleep(1)

            (rc,info) = self.pe3.deleteTunnel(tunnelIndex = 1)
            print('deleteTunnel:'+ str(rc) + '-' + info)

            time.sleep(1)
            
            (rc,info) = self.pe3.deleteLsp(lspIndex = 1)
            print('deleteLsp:'+ str(rc) + '-' + info)
            
            time.sleep(1)
            
            (rc,info) = self.pe3.deleteLsp(lspIndex = 2)
            print('deleteLsp:'+ str(rc) + '-' + info)
            
            time.sleep(1)
      
            (rc,info) = self.pe3.deleteLsp(lspIndex = 3)
            print('deleteLsp:'+ str(rc) + '-' + info)
        
        if self.pe4 != None:
            (rc,info) = self.pe4.deleteMlp(mlpIndex = 1)
            print('deleteMlp:'+ str(rc) + '-' + info)
            
            time.sleep(1)

            (rc,info)  = self.pe4.removeOamFromLsp(lspIndex = 1)
            print('removeOamFromLsp:'+ str(rc) + '-' + info)
            (rc,info)  = self.pe4.removeOamFromLsp(lspIndex = 2)
            print('removeOamFromLsp:'+ str(rc) + '-' + info)
            (rc,info)  = self.pe4.removeOamFromLsp(lspIndex = 3)
            print('removeOamFromLsp:'+ str(rc) + '-' + info)
            
            time.sleep(1)
            
            (rc,info) = self.pe4.deletePw(pwIndex = 1)
            print('deletePw:'+ str(rc) + '-' + info)

            time.sleep(1)

            (rc,info) = self.pe4.deleteTunnel(tunnelIndex = 1)
            print('deleteTunnel:'+ str(rc) + '-' + info)

            time.sleep(1)
            
            (rc,info) = self.pe4.deleteLsp(lspIndex = 1)
            print('deleteLsp:'+ str(rc) + '-' + info)
            
            time.sleep(1)
            
            (rc,info) = self.pe4.deleteLsp(lspIndex = 2)
            print('deleteLsp:'+ str(rc) + '-' + info)
            
            time.sleep(1)
      
            (rc,info) = self.pe4.deleteLsp(lspIndex = 3)
            print('deleteLsp:'+ str(rc) + '-' + info)        
        
        
        
        
        
