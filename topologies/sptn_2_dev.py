"""
test topology for sptn
"""

# Update this dictionary to suit your environment.
dev1_connTopology = {
    '6':'4@0000000000001001'                            ,
    '2':'2@0000000000001001'                            ,    
}
dev_1 = {

    'DPID'          : 0x0000000000001000               ,
    'CONN_TOPO'     : dev1_connTopology                 ,
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
}                                                      




dev2_connTopology = {
    '4':'6@0000000000001000'                            ,
    '2':'2@0000000000001000'
}
dev_2 = {

    "DPID"          : 0x0000000000001001               ,
    'CONN_TOPO'     : dev2_connTopology                 ,
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
}  

dev_map = {
    "pe1"   : dev_1,
    "pe2"   : dev_2,
}

def topology_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    """
    global dev_map
    config["device_map"] = dev_map.copy()
