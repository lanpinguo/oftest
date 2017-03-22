# Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2011, 2012 Open Networking Foundation
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# See the file LICENSE.pyloxi which should have been included in the source distribution

'''
PE1 CONFIG
'''
PE1_CONFIG = {

    'DPID'          : 1                                ,
    'UNI_PORT'      : 3                                ,
    'UNI_VLAN'      : 10                               ,
    'LSP_ING_LABEL' : 1000                             ,
    'LSP_EGR_LABEL' : 2000                             ,
    'PW_ING_LABEL'  : 10                               ,
    'PW_EGR_LABEL'  : 20                               ,
    'NNI_PORT'      : 4                                ,
    'NNI_VLAN'      : 100                              ,
    'TUNNEL_ID'     : 0X10001                          ,
    'VPWS_MAX'      : 2                                ,
    'PORT_MAC'      : [0x00,0x0e,0x5e,0x00,0x00,0x02]  ,
    'DST_MAC'       : [0x00,0x0e,0x5e,0x00,0x00,0x03]  ,
}                                                      

'''
PE2 CONFIG
'''
PE2_CONFIG = {

    "DPID"          : 2                                ,
    "UNI_PORT"      : 3                                ,
    "UNI_VLAN"      : 10                               ,
    "LSP_ING_LABEL" : 2000                             ,
    "LSP_EGR_LABEL" : 1000                             ,
    "PW_ING_LABEL"  : 20                               ,
    "PW_EGR_LABEL"  : 10                               ,
    "NNI_PORT"      : 4                                ,
    "NNI_VLAN"      : 100                              ,
    "TUNNEL_ID"     : 0X10001                          ,
    "VPWS_MAX"      : 2                                ,
    "PORT_MAC"      : [0x00,0x0e,0x5e,0x00,0x00,0x02]  ,
    "DST_MAC"       : [0x00,0x0e,0x5e,0x00,0x00,0x03]  ,
}                                                     
