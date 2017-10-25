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
    'CONN_TOPO'     : dev1_connTopology                ,
    'ELECTRIC_PORTS': [3,4,5,6]                        ,
    'OPTICAL_PORTS' : [1,2]                            ,
    'VPWS_MAX'      : 256                              ,
}                                                      




dev2_connTopology = {
    '4':'6@0000000000001000'                            ,
    '2':'2@0000000000001000'
}
dev_2 = {

    "DPID"          : 0x0000000000001002               ,
    'CONN_TOPO'     : dev2_connTopology                ,
    'ELECTRIC_PORTS': []                               ,
    'OPTICAL_PORTS' : [ 1,2,3,4,5,6,7,8,9,10,11,12,13,
                        14,15,16,17,18,19,20,21,22,23,
                        24,25,26,27,28,29,30,31,32,33,
                        37,41,45 ]                     ,
    'VPWS_MAX'      : 256                              ,
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
