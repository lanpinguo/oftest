# Copyright (c) 2008 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2011, 2012 Open Networking Foundation
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# See the file LICENSE.pyloxi which should have been included in the source distribution

"""
VLAN Id None
"""
OFDPA_VID_NONE = 0x0000

"""
VLAN Id present
"""
OFDPA_VID_PRESENT = 0x1000


"""
Table type
"""
OFDPA_FLOW_TABLE_ID_INGRESS_PORT                      =    0    # Ingress Port Table  
OFDPA_FLOW_TABLE_ID_PORT_DSCP_TRUST                   =    5    # Port DSCP Trust Table  
OFDPA_FLOW_TABLE_ID_PORT_PCP_TRUST                    =    6    # Port PCP Trust Table  
OFDPA_FLOW_TABLE_ID_TUNNEL_DSCP_TRUST                 =    7    # Tunnel DSCP Trust Table  
OFDPA_FLOW_TABLE_ID_TUNNEL_PCP_TRUST                  =    8    # Tunnel PCP Trust Table  
OFDPA_FLOW_TABLE_ID_INJECTED_OAM                      =    9    # Injected OAM Table  
OFDPA_FLOW_TABLE_ID_VLAN                              =   10    # VLAN Table  
OFDPA_FLOW_TABLE_ID_VLAN_1                            =   11    # VLAN 1 Table  
OFDPA_FLOW_TABLE_ID_MAINTENANCE_POINT                 =   12    # Maintenance Point Flow Table  
OFDPA_FLOW_TABLE_ID_MPLS_L2_PORT                      =   13    # MPLS L2 Port Table  
OFDPA_FLOW_TABLE_ID_MPLS_DSCP_TRUST                   =   15    # MPLS QoS DSCP Trust Table  
OFDPA_FLOW_TABLE_ID_MPLS_PCP_TRUST                    =   16    # MPLS QoS PCP Trust Table  
OFDPA_FLOW_TABLE_ID_L2_POLICER                        =   18    # L2 Policer  
OFDPA_FLOW_TABLE_ID_L2_POLICER_ACTIONS                =   19    # L2 Policer Actions  
OFDPA_FLOW_TABLE_ID_TERMINATION_MAC                   =   20    # Termination MAC Table  
OFDPA_FLOW_TABLE_ID_L3_TYPE                           =   21    # L3 Type Table  
OFDPA_FLOW_TABLE_ID_MPLS_0                            =   23    # MPLS 0 Table  
OFDPA_FLOW_TABLE_ID_MPLS_1                            =   24    # MPLS 1 Table  
OFDPA_FLOW_TABLE_ID_MPLS_2                            =   25    # MPLS 2 Table  
OFDPA_FLOW_TABLE_ID_MPLS_MAINTENANCE_POINT            =   26    # MPLS-TP Maintenance Point Flow Table  
OFDPA_FLOW_TABLE_ID_MPLS_L3_TYPE                      =   27    # MPLS L3 Type Flow Table  
OFDPA_FLOW_TABLE_ID_MPLS_TYPE                         =   29    # MPLS Type Flow Table  
OFDPA_FLOW_TABLE_ID_UNICAST_ROUTING                   =   30    # Unicast Routing Table  
OFDPA_FLOW_TABLE_ID_MULTICAST_ROUTING                 =   40    # Multicast Routing Table  
OFDPA_FLOW_TABLE_ID_BRIDGING                          =   50    # Bridging Table  
OFDPA_FLOW_TABLE_ID_ACL_POLICY                        =   60    # ACL Table  
OFDPA_FLOW_TABLE_ID_COLOR_BASED_ACTIONS               =   65    # Color Based Actions  
OFDPA_FLOW_TABLE_ID_EGRESS_VLAN                       =  210    # Egress VLAN Table  
OFDPA_FLOW_TABLE_ID_EGRESS_VLAN_1                     =  211    # Egress VLAN 1 Table  
OFDPA_FLOW_TABLE_ID_EGRESS_MAINTENANCE_POINT          =  226    # Egress Maintenance Point Flow Table  
OFDPA_FLOW_TABLE_ID_EGRESS_DSCP_PCP_REMARK            =  230    # Egress DSCP PCP Remark Flow Table  
OFDPA_FLOW_TABLE_ID_EGRESS_TPID                       =  235    # Egress TPID Flow Table  





"""
Group type
"""

# Group type L2 Interface  
OFDPA_GROUP_ENTRY_TYPE_L2_INTERFACE = 0 
# Group type L2 Rewrite  
OFDPA_GROUP_ENTRY_TYPE_L2_REWRITE   = 1 
# Group type L3 Unicast  
OFDPA_GROUP_ENTRY_TYPE_L3_UNICAST   = 2 
# Group type L2 Multicast  
OFDPA_GROUP_ENTRY_TYPE_L2_MULTICAST = 3 
# Group type L2 Flood  
OFDPA_GROUP_ENTRY_TYPE_L2_FLOOD     = 4 
# Group type L3 Interface  
OFDPA_GROUP_ENTRY_TYPE_L3_INTERFACE = 5 
# Group type L3 Multicast  
OFDPA_GROUP_ENTRY_TYPE_L3_MULTICAST = 6 
# Group type L3 ECMP  
OFDPA_GROUP_ENTRY_TYPE_L3_ECMP      = 7 
# Group type L2 Overlay  
OFDPA_GROUP_ENTRY_TYPE_L2_OVERLAY   = 8 
# Group type MPLS Label  
OFDPA_GROUP_ENTRY_TYPE_MPLS_LABEL   = 9 
# Group type MPLS Forwarding  
OFDPA_GROUP_ENTRY_TYPE_MPLS_FORWARDING   = 10 
# Group type L2 Unfiltered Interface  
OFDPA_GROUP_ENTRY_TYPE_L2_UNFILTERED_INTERFACE   = 11 

# Must be last  
OFDPA_GROUP_ENTRY_TYPE_LAST = 12

"""
MPLS Label Group Sub-type Enumerator 
"""
OFDPA_MPLS_INTERFACE       = 0
OFDPA_MPLS_L2_VPN_LABEL    = 1
OFDPA_MPLS_L3_VPN_LABEL    = 2
OFDPA_MPLS_TUNNEL_LABEL1   = 3
OFDPA_MPLS_TUNNEL_LABEL2   = 4
OFDPA_MPLS_SWAP_LABEL      = 5


