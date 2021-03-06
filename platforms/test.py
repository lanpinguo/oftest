"""
Sprient Test Center  platform

This platform uses Sprient Test Center interfaces.
"""

# Update this dictionary to suit your environment.
remote_port_map = {
#    3 : "10/7",
#    13 : "10/8",
#    25 : "eth4",
#    26 : "eth5"
}

protocal_port_map = {
    0 : "ens38",
}


def platform_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    """
    global remote_port_map
    config["port_map"] = remote_port_map.copy()
    config["caps_table_idx"] = 0
    config["protocalPort_map"] = protocal_port_map.copy()
    config["ofconfig_dir"] = "/work/oftest/ofconfig"
