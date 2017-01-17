# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2014 Big Switch Networks, Inc.
"""
vpws services test cases
"""

import logging

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
    
    
class CreateLsp(base_tests.SimpleDataPlane):
    """
    Verify that creating a mpls LSP
    """
   
    def runTest(self):

        #delete_all_flows(self.controller)
        '''
        Add group
        '''
        uni_port = 3
        uni_vlan = 10
        lsp_ing_label = 1000
        lsp_egr_label = 2000
        nni_port = 4
        nni_vlan = 100 | ofdpa.OFDPA_VID_PRESENT
        
        '''
        add l2 interface group
        '''
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
        id = ofdb_group_vlanid_set(id , nni_vlan)
        id = ofdb_group_portid_set(id , nni_port)
        action_list = [ofp.action.output(nni_port) ]#, ofp.action.pop_vlan()]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.controller.message_send(msg)
        '''
        add mpls interface group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , 0)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_INTERFACE)
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.set_field(ofp.oxm.eth_src(value = [0x00,0x0e,0x5e,0x00,0x00,0x02])) ,
                       ofp.action.set_field(ofp.oxm.eth_dst(value = [0x00,0x0e,0x5e,0x00,0x00,0x03])) ,
                       ofp.action.set_field(ofp.oxm.vlan_vid(value = nni_vlan)) ]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.controller.message_send(msg)        
 
        '''
        add mpls tunnel label 1 group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , 0)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_TUNNEL_LABEL1)
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.push_mpls(ethertype = 0x8847) ,
                       ofp.action.set_field(ofp.oxm.mpls_label(value = 1000)) ,
                       ofp.action.copy_ttl_out() ,
                       ofp.action.set_field(ofp.oxm.mpls_tc(value = 0))]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.controller.message_send(msg)  

       
        do_barrier(self.controller)


        '''
        Add vlan table entry
        '''
        table_id =  ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(nni_port),
            ofp.oxm.vlan_vid(nni_vlan)
        ])
        
        instructions=[
                    ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC),
        ]
        priority = 1000

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=1000,
                idle_timeout=0)
        self.controller.message_send(request)
        
        '''
        Add termination mac table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC
        match = ofp.match([
            ofp.oxm.in_port(nni_port),
            ofp.oxm.eth_dst(value = [0x00,0x0e,0x5e,0x00,0x00,0x02]),
            ofp.oxm.eth_type(value = 0x8847),            
        ])
        
        instructions=[
                    ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1),
        ]
        priority = 1000

        logging.info("Inserting termination mac flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=1000,
                idle_timeout=0)
        self.controller.message_send(request)
        
        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = 1000),
            ofp.oxm.mpls_bos(value = 0),
        ])
        
        instructions=[
            ofp.instruction.apply_actions(actions = [ofp.action.pop_mpls(ethertype = 0x8847)]),
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_2),
        ]
        priority = 1000

        logging.info("Inserting  mpls 1 flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=1000,
                idle_timeout=0)
        self.controller.message_send(request)
        
        do_barrier(self.controller)

        
        # Send a packet through so that we can check stats were preserved
        #self.dataplane.send(in_port, str(simple_tcp_packet(pktlen=100)))
        #verify_flow_stats(self, ofp.match(), table_id=table_id, pkts=1)

        # Send a flow-add with the same table_id, match, and priority, causing
        # an overwrite
        #logging.info("Overwriting flow")
        '''
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_port2)]),
                ],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=0,
                cookie=0xabcd,
                hard_timeout=3000,
                idle_timeout=4000)
        self.controller.message_send(request)
        do_barrier(self.controller)
        '''
        # Should not get a flow-removed message
        msg, _ = self.controller.poll(exp_msg=ofp.message.flow_removed,
                                      timeout=oftest.ofutils.default_negative_timeout)
        self.assertEquals(msg, None)

        # Check that the fields in the flow stats entry match the second flow-add
        stats = get_flow_stats(self, match)
        self.assertEquals(len(stats), 1)
        entry = stats[0]
        logging.debug(entry.show())
        self.assertEquals(entry.instructions, request.instructions)
        self.assertEquals(entry.flags, request.flags)
        self.assertEquals(entry.cookie, request.cookie)
        self.assertEquals(entry.hard_timeout, request.hard_timeout)
        self.assertEquals(entry.idle_timeout, request.idle_timeout)

        # Flow stats should have been preserved
        verify_flow_stats(self, ofp.match(), table_id=table_id, pkts=1)

class CreatePw(base_tests.SimpleDataPlane):
    """
    Verify that creating a mpls LSP
    """
    experimenter_id = 0x1018
    def runTest(self):

        #delete_all_flows(self.controller)
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
        self.controller.message_send(msg)

        '''
        Add Flow
        '''
        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = 100),
            ofp.oxm.mpls_bos(value = 1),
        ])
        
        '''
        apply actions
        '''
        apy_actions = [ofp.action.pop_mpls(ethertype = 0x8847) ,
            ofp.action.set_field(ofp.oxm.tunnel_id(value = 0x10002)) ,
            ofp.action.pop_vlan() ,
            ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00 ]),
            ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = 0x20001)) ,        
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,        
        ]
        instructions=[
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
            ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 1000

        logging.info("Inserting  mpls 1 flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=1000,
                idle_timeout=0)
        self.controller.message_send(request)
       
        '''
        add mpls vpn group
        '''
        ref_group = 0x93000000
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , 0)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_L2_VPN_LABEL)
        action_list = [ofp.action.group(group_id = ref_group) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.push_mpls(ethertype = 0x8847) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.set_field(ofp.oxm.mpls_label(value = 100)) ,
           ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
           ofp.action.set_field(ofp.oxm.mpls_tc(value = 1)),
           ofp.action.set_mpls_ttl(mpls_ttl = 255)
        ]
        bucket_list = [ofp.bucket(actions = action_list)]
        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.controller.message_send(msg)     


        '''
        Add mpls l2 port table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT
        match = ofp.match([
            ofp.oxm.tunnel_id(value = 0x10002),
            ofp.oxm.eth_type(value = 0x0800),
            ofp.oxm.mpls_tp_mpls_l2_port(value = 1),            
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
        priority = 1000

        logging.info("Inserting  mpls l2 port flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=1000,
                idle_timeout=0)
        self.controller.message_send(request)
       
        '''
        Add vlan table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(uni_port),
            ofp.oxm.vlan_vid(uni_vlan),
        ])
        
        '''
        apply actions
        '''
        apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,
            ofp.action.set_field(ofp.oxm.tunnel_id(value = 0x10002)) ,
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = 1)) ,
        
        ]
        instructions=[
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 1000

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=1000,
                idle_timeout=0)
        self.controller.message_send(request)
        
        do_barrier(self.controller)

        
class CreateLsp256(base_tests.SimpleDataPlane):
    """
    Verify that creating a mpls LSP
    """
   
    def runTest(self):


        for i in range(1,custom.PE1_VPWS_MAX) :
            uni_port = custom.PE1_UNI_PORT
            uni_vlan = custom.PE1_UNI_VLAN + i
            lsp_ing_label = custom.PE1_LSP_ING_LABEL + i
            lsp_egr_label = custom.PE1_LSP_EGR_LABEL + i
            nni_port = custom.PE1_NNI_PORT
            nni_vlan = custom.PE1_NNI_VLAN | ofdpa.OFDPA_VID_PRESENT + i
            tunnel_id = custom.PE1_TUNNEL_ID + i
            port_mac = custom.PE1_PORT_MAC
            dst_mac = custom.PE1_DST_MAC     

            '''
            Add group
            '''

            '''
            add l2 interface group
            '''
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE)
            id = ofdb_group_vlanid_set(id , nni_vlan)
            id = ofdb_group_portid_set(id , nni_port)
            action_list = [ofp.action.output(nni_port) ]#, ofp.action.pop_vlan()]
            bucket_list = [ofp.bucket(actions = action_list)]

            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
            self.controller.message_send(msg)
            '''
            add mpls interface group
            '''
            ref_group = id
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
            id = ofdb_group_mpls_index_set(id , i)
            id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_INTERFACE)
            action_list = [ofp.action.group(group_id = ref_group) ,
                           ofp.action.set_field(ofp.oxm.eth_src(value = port_mac)) ,
                           ofp.action.set_field(ofp.oxm.eth_dst(value = dst_mac)) ,
                           ofp.action.set_field(ofp.oxm.vlan_vid(value = nni_vlan)) ]
            bucket_list = [ofp.bucket(actions = action_list)]

            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
            self.controller.message_send(msg)        
     
            '''
            add mpls tunnel label 1 group
            '''
            ref_group = id
            id = 0
            id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
            id = ofdb_group_mpls_index_set(id , 0)
            id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_TUNNEL_LABEL1)
            action_list = [ofp.action.group(group_id = ref_group) ,
                           ofp.action.push_mpls(ethertype = 0x8847) ,
                           ofp.action.set_field(ofp.oxm.mpls_label(value = 1000)) ,
                           ofp.action.copy_ttl_out() ,
                           ofp.action.set_field(ofp.oxm.mpls_tc(value = 0))]
            bucket_list = [ofp.bucket(actions = action_list)]

            msg = ofp.message.group_add(
                group_type=ofp.OFPGT_INDIRECT,
                group_id= id,
                buckets= bucket_list)
            self.controller.message_send(msg)  

           
            do_barrier(self.controller)


            '''
            Add vlan table entry
            '''
            table_id =  ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
            match = ofp.match([
                ofp.oxm.in_port(nni_port),
                ofp.oxm.vlan_vid(nni_vlan)
            ])
            
            instructions=[
                        ofp.instruction.goto_table( ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC),
            ]
            priority = 1000

            logging.info("Inserting vlan flow")
            request = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0x1234,
                    hard_timeout=1000,
                    idle_timeout=0)
            self.controller.message_send(request)
            
            '''
            Add termination mac table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_TERMINATION_MAC
            match = ofp.match([
                ofp.oxm.in_port(nni_port),
                ofp.oxm.eth_dst(value = [0x00,0x0e,0x5e,0x00,0x00,0x02]),
                ofp.oxm.eth_type(value = 0x8847),            
            ])
            
            instructions=[
                        ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1),
            ]
            priority = 1000

            logging.info("Inserting termination mac flow")
            request = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0x1234,
                    hard_timeout=1000,
                    idle_timeout=0)
            self.controller.message_send(request)
            
            '''
            Add mpls 1 table entry
            '''
            table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
            match = ofp.match([
                ofp.oxm.eth_type(value = 0x8847),            
                ofp.oxm.mpls_label(value = 1000),
                ofp.oxm.mpls_bos(value = 0),
            ])
            
            instructions=[
                ofp.instruction.apply_actions(actions = [ofp.action.pop_mpls(ethertype = 0x8847)]),
                ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_2),
            ]
            priority = 1000

            logging.info("Inserting  mpls 1 flow")
            request = ofp.message.flow_add(
                    table_id=table_id,
                    match=match,
                    instructions=instructions,
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=ofp.OFPFF_SEND_FLOW_REM,
                    cookie=0x1234,
                    hard_timeout=1000,
                    idle_timeout=0)
            self.controller.message_send(request)
            
            do_barrier(self.controller)

class demo(advanced_tests.AdvancedProtocol):
    """
    Verify that creating a mpls LSP
    """
    experimenter_id = 0x1018
    def runTest(self):
        pe1 = None
        pe2 = None
        
        for d in self.controller.device_agents:
            if d.dpid == 0xe5e512ff90000: 
                pe1 = d
            elif d.dpid == 0xe5e501c5a0000:
                pe2 = d 
        #delete_all_flows(self.controller)
        if pe1 :
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
                
            pe1.message_send(msg)

            do_barrier(pe1)        

        if pe2 :
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
                
            pe2.message_send(msg)

            do_barrier(pe2)        

class keepControllerOnline(advanced_tests.AdvancedProtocol):
    """
    Verify that creating a mpls LSP
    """
    experimenter_id = 0x1018
    def runTest(self):
        while True:
            pass
            
            
            
class vpws_basic_pe():
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
        
    def create_new_lsp(self):
        
        ####################################################################################
        #
        # Create LSP
        #
        ####################################################################################

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
        self.pe.message_send(msg)
        '''
        add mpls interface group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , self.mpls_interface_index)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_INTERFACE)
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.set_field(ofp.oxm.eth_src(value = self.port_mac)) ,
                       ofp.action.set_field(ofp.oxm.eth_dst(value = self.dst_mac)) ,
                       ofp.action.set_field(ofp.oxm.vlan_vid(value = self.nni_vlan)) ]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.pe.message_send(msg)        

        '''
        add mpls tunnel label 1 group
        '''
        ref_group = id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , 0)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_TUNNEL_LABEL1)
        self.mpls_tunnel_group_id.append(id)
        action_list = [ofp.action.group(group_id = ref_group) ,
                       ofp.action.push_mpls(ethertype = 0x8847) ,
                       ofp.action.set_field(ofp.oxm.mpls_label(value = self.lsp_egr_label)) ,
                       ofp.action.copy_ttl_out() ,
                       ofp.action.set_field(ofp.oxm.mpls_tc(value = 0))]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.pe.message_send(msg)  

       
        do_barrier(self.pe)


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
        priority = 1000

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
        
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
        priority = 1000

        logging.info("Inserting termination mac flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
        
        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = self.lsp_ing_label),
            ofp.oxm.mpls_bos(value = 0),
        ])
        
        instructions=[
            ofp.instruction.apply_actions(actions = [ofp.action.pop_mpls(ethertype = 0x8847)]),
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_2),
        ]
        priority = 1000

        logging.info("Inserting  mpls 1 flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
        
        do_barrier(self.pe)
        tunnel_index = self.tunnel_index
        self.tunnel_index += 1
        return (self.mpls_tunnel_group_id, tunnel_index)
        
    def create_new_pw(self,mpls_tunnel_group_id):
        
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
        id = ofdb_group_vlanid_set(id , self.uni_vlan)
        id = ofdb_group_portid_set(id , self.uni_port)
        action_list = [ofp.action.output(self.uni_port) ,
            ofp.action.set_field(ofp.oxm.mpls_tp_allow_vlan_translation()) ,
        ]
        bucket_list = [ofp.bucket(actions = action_list)]

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.pe.message_send(msg)

        '''
        Add Flow
        '''
        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = self.pw_ing_label),
            ofp.oxm.mpls_bos(value = 1),
        ])
        
        '''
        apply actions
        '''
        apy_actions = [ofp.action.pop_mpls(ethertype = 0x8847) ,
            ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
            ofp.action.pop_vlan() ,
            ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00 ]),
            ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = self.mpls_l2_port)) ,        
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,        
        ]
        instructions=[
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_TYPE),
            ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 1000

        logging.info("Inserting  mpls 1 flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
       
        '''
        add mpls vpn group
        '''
        ref_group = mpls_tunnel_group_id
        id = 0
        id = ofdb_group_type_set(id,ofdpa.OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL)
        id = ofdb_group_mpls_index_set(id , 0)
        id = ofdb_group_mpls_subtype_set(id , ofdpa.OFDPA_MPLS_L2_VPN_LABEL)
        action_list = [ofp.action.group(group_id = ref_group) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.push_mpls(ethertype = 0x8847) ,
           ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x03,0x00,0x00,0x00,0x00,0x00,0x00 ]),
           ofp.action.set_field(ofp.oxm.mpls_label(value = self.pw_egr_label)) ,
           ofp.action.set_field(ofp.oxm.mpls_bos(value = 1)),
           ofp.action.set_field(ofp.oxm.mpls_tc(value = 1)),
           ofp.action.set_mpls_ttl(mpls_ttl = 255)
        ]
        bucket_list = [ofp.bucket(actions = action_list)]
        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_INDIRECT,
            group_id= id,
            buckets= bucket_list)
        self.pe.message_send(msg)     


        '''
        Add mpls l2 port table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT
        match = ofp.match([
            ofp.oxm.tunnel_id(value = self.tunnel_id),
            ofp.oxm.eth_type(value = 0x0800),
            ofp.oxm.mpls_tp_mpls_l2_port(value = 1),            
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
        priority = 1000

        logging.info("Inserting  mpls l2 port flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
       
        '''
        Add vlan table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_VLAN
        match = ofp.match([
            ofp.oxm.in_port(self.uni_port),
            ofp.oxm.vlan_vid(self.uni_vlan),
        ])
        
        '''
        apply actions
        '''
        apy_actions = [ofp.action.set_field(ofp.oxm.mpls_tp_mpls_type(value = 1)) ,
            ofp.action.set_field(ofp.oxm.tunnel_id(value = self.tunnel_id)) ,
            ofp.action.set_field(ofp.oxm.mpls_tp_mpls_l2_port(value = 1)) ,
        
        ]
        instructions=[
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 1000

        logging.info("Inserting vlan flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
        
        do_barrier(self.pe)

def add_oam(self,lmepId = 0,obj):
        
        ####################################################################################
        #
        # Create oam
        #
        ####################################################################################        

        '''
        Add Flow
        '''
        '''
        Add mpls maintenance point table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8902),            
            ofp.oxm.mpls_tp_mp_id(value = lmepId),
            ofp.oxm.mpls_tp_oam_y1731_opcode(value = 1),
        ])
        
        '''
        apply actions 
        '''
        apy_actions = [ofp.action.output(port = ofp.OFPP_LOCAL ,max_len = 0xffff) ,
        ]
        instructions=[
            ofp.instruction.clear_actions(),
            ofp.instruction.write_actions(actions = [ofp.action.group(group_id = id)]),
            ofp.instruction.apply_actions(actions = apy_actions),
        ]
        priority = 1000

        logging.info("Inserting mpls maintenance point flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)        

        '''
        Add mpls 1 table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_1
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8847),            
            ofp.oxm.mpls_label(value = self.lsp_ing_label),
            ofp.oxm.mpls_bos(value = 0),
            ofp.oxm.mpls_tp_ach_channel(value = 0x8902),
            ofp.oxm.mpls_tp_data_first_nibble(value = 1),
            ofp.oxm.mpls_tp_next_label_is_gal(value = 1)
        ])
        
        action = [ofp.action.pop_mpls(ethertype = 0x8847),
            ofp.action.set_field(ofp.oam.mpls_tp_mp_id(value = lmepId)),
            ofp.action.pop_mpls(ethertype = 0x8902),
            ofp.action.experimenter(experimenter = 0x1018, data = [0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00 ]),
        ]
        instructions=[
            ofp.instruction.apply_actions(actions = action),
            ofp.instruction.goto_table(ofdpa.OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT),
        ]
        priority = 1000

        logging.info("Inserting  mpls 1 flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)

        '''
        Add injected oam table entry
        '''
        table_id = ofdpa.OFDPA_FLOW_TABLE_ID_INJECTED_OAM
        match = ofp.match([
            ofp.oxm.eth_type(value = 0x8902),            
            ofp.oxm.mpls_tp_mp_id(value = lmepId),
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
            ofp.action.set_field(ofp.oxm.mpls_label(value = self.lsp_egr_label)),
            ofp.action.set_field(ofp.oxm.mpls_tp_ttl(value = 64)),          
            ofp.action.set_field(ofp.oxm.vlan_pcp(value = 1)),            
        ]
        
        write_action = [ ofp.action.group(group_id = self.mpls_interface_group_id),            
        ]
        instructions=[
            ofp.instruction.apply_actions(actions = aply_action),
            ofp.instruction.write_actions(actions = write_action),
        ]
        priority = 1000

        logging.info("Inserting injected oam table flow")
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=instructions,
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=priority,
                flags=ofp.OFPFF_SEND_FLOW_REM,
                cookie=0x1234,
                hard_timeout=0,
                idle_timeout=0)
        self.pe.message_send(request)
        
        do_barrier(self.pe)       
        

class Scenario_VpwsBasic(advanced_tests.AdvancedProtocol):
    """
    Verify that creating a  vpws
    """

    def runTest(self):
        pe1 = None
        pe2 = None 
        
        for d in self.controller.device_agents:
            if d.dpid == custom.PE1_CONFIG['DPID']: 
                pe1 = vpws_basic_pe(d,config = custom.PE1_CONFIG)
            elif d.dpid == custom.PE2_CONFIG["DPID"]:
                pe2 = vpws_basic_pe(d,config = custom.PE2_CONFIG)  
  
        pe1.dst_mac = pe2.port[pe2.nni_port].hw_addr
        (mpls_tunnel_group_pe1, tunnel_index_pe1) = pe1.create_new_lsp()
        pe1.create_new_pw(mpls_tunnel_group_pe1[tunnel_index_pe1])

        pe2.dst_mac = pe1.port[pe1.nni_port].hw_addr
        (mpls_tunnel_group_pe2, tunnel_index_pe1) = pe2.create_new_lsp()
        pe2.create_new_pw(mpls_tunnel_group_pe2[tunnel_index_pe1])        
        
class Scenario_VpwsLspProtection(advanced_tests.AdvancedProtocol):
    """
    Verify that creating a  vpws
    """

    def runTest(self):
        pe1 = None
        pe2 = None 
        
        for d in self.controller.device_agents:
            if d.dpid == custom.PE1_CONFIG['DPID']: 
                pe1 = vpws_basic_pe(d,config = custom.PE1_CONFIG)
            elif d.dpid == custom.PE2_CONFIG["DPID"]:
                pe2 = vpws_basic_pe(d,config = custom.PE2_CONFIG)  
  
        pe1.dst_mac = pe2.port[pe2.nni_port].hw_addr
        (mpls_tunnel_group_pe1, tunnel_index_pe1) = pe1.create_new_lsp()
        pe1.create_new_pw(mpls_tunnel_group_pe1[tunnel_index_pe1])

        pe2.dst_mac = pe1.port[pe1.nni_port].hw_addr
        (mpls_tunnel_group_pe2, tunnel_index_pe1) = pe2.create_new_lsp()
        pe2.create_new_pw(mpls_tunnel_group_pe2[tunnel_index_pe1])        
        
                        