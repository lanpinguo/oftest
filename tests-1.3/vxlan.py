# -*- coding: utf-8 -*- 
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
    

    

      

class basic_vpws():                                             
    """
    root device 
    """
    experimenter_id = 0x1018

    def __init__(self,dev_agt,config,dst_mac = None):
        
        self.pe = dev_agt
        self.uni_port = config['UNI_PORT']
        self.uni_vlan = config['UNI_VLAN'] | ofdpa.OFDPA_VID_PRESENT
        self.nni_port = config['NNI_PORT']
        self.nni_vlan = config['NNI_VLAN'] | ofdpa.OFDPA_VID_PRESENT
        self.tunnel_id = config['TUNNEL_ID'] 
        self.lsp_ing_label = config['LSP_ING_LABEL'] 
        self.lsp_egr_label = config['LSP_EGR_LABEL'] 
        self.pw_ing_label = config['PW_ING_LABEL'] 
        self.pw_egr_label = config['PW_EGR_LABEL'] 
        
        self.vlanid = 10
        self.firstPhysicalPort = 3
        self.secondPhysicalPort = 4        
        self.firstMacAddress = [0x00,0x00,0x00,0x00,0x00,0x01]
        self.secondMacAddress = [0x00,0x00,0x00,0x00,0x00,0x02]
        
        self.port_mac = self.pe.port_desc[self.nni_port].hw_addr   #config['PORT_MAC']
        if dst_mac :
            self.dst_mac = dst_mac
        else :
            self.dst_mac = config['DST_MAC']
        self.mpls_interface_index = 0
        self.tunnel_index = 0
        self.mpls_tunnel_group_id = []
        self.mpls_l2_port = 0x20001     
        self.hard_timeout=0,
        self.idle_timeout=0
        self.port = self.pe.port_desc
        
        
        
    def create_new_vpws(self):
        
        ####################################################################################
        #
        # Create VPWS
        #
        ####################################################################################

        '''
        set up L2 Interface groups on physical ports  1
        '''
        id_1 = 0
        id_1 = ofdb_group_type_set(id_1,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
        id_1 = ofdb_group_vlanid_set(id_1 , self.vlanid)           
        id_1 = ofdb_group_portid_set(id_1 , self.firstPhysicalPort)
        action_list = [ofp.action.output(self.firstPhysicalPort) ]#, ofp.action.pop_vlan()]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id_1,
            buckets= bucket_list)
        self.pe.message_send(msg)
        
        '''
        set up L2 Interface groups on physical ports  2
        '''
        id_2 = 0
        id_2 = ofdb_group_type_set(id_2,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
        id_2 = ofdb_group_vlanid_set(id_2 , self.vlanid)           
        id_2 = ofdb_group_portid_set(id_2 , self.secondPhysicalPort)
        action_list = [ofp.action.output(self.secondPhysicalPort) ]#, ofp.action.pop_vlan()]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id_2,
            buckets= bucket_list)
        self.pe.message_send(msg)        
               
        '''
        Add vlan table entry 1
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(self.firstPhysicalPort),
            ofp.oxm.vlan_vid_masked(value = ofdpa.OFDPA_VID_PRESENT | self.vlanid , value_mask = ofdpa.OFDPA_VID_PRESENT | 0xfff),        
        ])
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC),
        ]        

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,)
        
        self.pe.message_send(request)
        
        do_barrier(self.pe)            

        '''
        Add vlan table entry  2
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(self.secondPhysicalPort),
            ofp.oxm.vlan_vid_masked(value = ofdpa.OFDPA_VID_PRESENT | self.vlanid , value_mask = ofdpa.OFDPA_VID_PRESENT | 0xfff),        
        ])
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC),
        ]        

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,)
        
        self.pe.message_send(request)
        
        do_barrier(self.pe)       
 
                        
        '''
       set up first Bridging flow entry 1
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_BRIDGING
        match = ofp.match([
            ofp.oxm.eth_dst_masked(value = self.firstMacAddress , value_mask = [0xff,0xff,0xff,0xff,0xff,0xff]),
            ofp.oxm.vlan_vid_masked(value = ofdpa.OFDPA_VID_PRESENT | self.vlanid , value_mask = ofdpa.OFDPA_VID_PRESENT | 0xfff),        
        ])
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_ACL_POLICY),
                    ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id_1)]),
        ]        


        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,)
        
        self.pe.message_send(request)
        
        do_barrier(self.pe)     
 
        '''
       set up first Bridging flow entry 2
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_BRIDGING
        match = ofp.match([
            ofp.oxm.eth_dst_masked(value = self.secondMacAddress , value_mask = [0xff,0xff,0xff,0xff,0xff,0xff]),
            ofp.oxm.vlan_vid_masked(value = ofdpa.OFDPA_VID_PRESENT | self.vlanid , value_mask = ofdpa.OFDPA_VID_PRESENT | 0xfff),        
        ])
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_ACL_POLICY),
                    ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id_2)]),
        ]        

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,)
        
        self.pe.message_send(request)
        
        do_barrier(self.pe)
                   
class VpwsBasic(advanced_tests.AdvancedProtocol):
    """
    Verify that creating a  vpws
    """

    def runTest(self):
        self.pe1 = None
        self.pe2 = None 
        
        self.deviceIsOnline = 0
        self.waitDeviceOnline = 5 # wait timeout = 20s
        while self.deviceIsOnline < 2 and self.waitDeviceOnline > 0:
            for agt in self.controller.device_agents:
                if self.pe1 == None and agt.dpid == custom.PE1_CONFIG['DPID']: 
                    self.pe1 = basic_vpws(agt,config = custom.PE1_CONFIG) 
                    self.deviceIsOnline += 1
                elif self.pe2 == None and agt.dpid == custom.PE2_CONFIG["DPID"]:
                    self.pe2 = basic_vpws(agt,config = custom.PE2_CONFIG) 
                    self.deviceIsOnline += 1                    
            self.waitDeviceOnline -= 1
            time.sleep(1) # sleep 1s
        self.assertNotEquals(self.deviceIsOnline, 0,'no enough device is online')
        self.pe1.dst_mac = self.pe2.port[self.pe2.nni_port].hw_addr
        self.pe1.create_new_vpws()

        self.pe2.dst_mac = self.pe1.port[self.pe1.nni_port].hw_addr
        self.pe2.create_new_vpws()
        