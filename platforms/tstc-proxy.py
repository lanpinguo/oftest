"""
Sprient Test Center  platform

This platform uses Sprient Test Center interfaces.
"""

# Update this dictionary to suit your environment.
remote_port_map = {
    3 : "7/7",
    13 : "7/8",
#    25 : "eth4",
#    26 : "eth5"
}

def platform_config_update(config):
    """
    Update configuration for the remote platform

    @param config The configuration dictionary to use/update
    """
    global remote_port_map
    config["port_map"] = remote_port_map.copy()
    config["caps_table_idx"] = 0
    config["chassisIp"] = "172.16.66.12"
    config["stcSeriverIp"] = "192.168.1.101"
    config["stcServierPort"] = 6000
