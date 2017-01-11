# Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2011, 2012 Open Networking Foundation
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# See the file LICENSE.pyloxi which should have been included in the source distribution

'''
PE1 CONFIG
'''
PE1_DPID = 0xe5e512ff90000 
PE1_UNI_PORT = 3
PE1_UNI_VLAN = 10
PE1_LSP_ING_LABEL = 1000
PE1_LSP_EGR_LABEL = 2000
PE1_NNI_PORT = 4
PE1_NNI_VLAN = 100 
PE1_TUNNEL_ID = 0X10001
PE1_VPWS_MAX = 2
PE1_PORT_MAC = [0x00,0x0e,0x5e,0x00,0x00,0x02]
PE1_DST_MAC = [0x00,0x0e,0x5e,0x00,0x00,0x03]
'''
PE2 CONFIG
'''
PE2_DPID = 0xe5e501c5a0000
PE2_UNI_PORT = 3
PE2_UNI_VLAN = 10
PE2_LSP_ING_LABEL = 1000
PE2_LSP_EGR_LABEL = 2000
PE2_NNI_PORT = 4
PE2_NNI_VLAN = 100 
PE2_TUNNEL_ID = 0X10001
PE1_VPWS_MAX = 256
