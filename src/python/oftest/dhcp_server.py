#!/usr/bin/python
import random
import argparse
import logging
import string
import struct
import time
# Quiet scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy import volatile  # noqa: E402
from scapy import sendrecv  # noqa: E402
from scapy import config  # noqa: E402
from scapy.layers import l2  # noqa: E402
from scapy.layers import inet  # noqa: E402
from scapy.layers import dhcp  # noqa: E402

# Configuration requires these imports to properly initialize
from scapy import route  # noqa: E402, F401
from scapy import route6  # noqa: E402, F401
from threading import Thread
from threading import Lock
from threading import Condition
#from psutil import net_if_addrs
from subprocess import *

import sys, os, warnings
warnings.simplefilter("ignore", DeprecationWarning)
import datetime
from ncclient import manager
from lxml import etree



def macTransfer(str):
    hwAddr = []
    for s in str.split(':'):
        #hwAddr.append(struct.pack("!B",int(s,16)))
        hwAddr.append(s.decode('hex'))
    return ''.join(hwAddr)

def ip2int_v4(strIp):
    intIp = 0
    shift = 24
    for sub in strIp.split('.'):
        intIp |= (int(sub)<<shift)
        shift -= 8
    return intIp  

def ip2str_v4(intIp):  
    strList = []
    for shift in [24,16,8,0]:
        strList.append('%d' % ((intIp >> shift) & 0xFF))
    return '.'.join(strList)            
    
def s2m( data):
    strList = []
    for d in data:
        strList.append(struct.pack("!B", d))
    
    return ''.join(strList)

    
default_timeout = 2
"""
Wait on a condition variable until the given function returns non-None or a timeout expires.
The condition variable must already be acquired.
The timeout value -1 means use the default timeout.
There is deliberately no support for an infinite timeout.
"""
def timed_wait(cv, fn, timeout=-1):
    if timeout == -1:
        timeout = default_timeout

    end_time = time.time() + timeout
    while True:
        val = fn()
        if val != None:
            return val

        remaining_time = end_time - time.time()
        cv.wait(remaining_time)

        if time.time() > end_time:
            return None


# build xml
config_e = """        
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capable-switch xmlns="urn:onf:config:yang"  xmlns:a="urn:ietf:params:xml:ns:netconf:base:1.0">
      <id>RAISECOM</id>
      <logical-switches>
        <switch>
          <id>raisecom</id>
          <datapath-id>00:00:00:00:00:00:00:0a</datapath-id>
          <controllers>
              <controller >
                <id>1</id>
                <role>equal</role>
                <ip-address>192.168.1.105</ip-address>
                <port>6633</port>
                <protocol>tcp</protocol>
              </controller>
          </controllers>
        </switch>
      </logical-switches>

    </capable-switch>
</config> 
"""

def set_controller(host, user, password):
    with manager.connect(host=host, port=830, username=user, password=password,
                     hostkey_verify=False, device_params={'name':'default'},
                     look_for_keys=False, allow_agent=False) as m:
        with m.locked(target="candidate"):
            m.edit_config(config=config_e, default_operation="merge", target="candidate")
            m.commit()        
        
        
class REQUESTER(object):

    def __init__(self,hwAddr,xid):
        self.xid = xid
        self.hwAddr = hwAddr
        self.yiaddr = '0.0.0.0'
        self.yiaddr_acked = False
        self.vlan = None
        self.vendor_class_id = 'unknown'
        self.client_id = 'unknown'
        self.stage = None
        
    def getXid(self):
        return self.xid
    
    
    
    
    
class DHCP_Server(Thread):
        
    def __init__(self,config,callback=None):
        Thread.__init__(self)
        self.killed = False
        self.acked = None
        self.iface=config['iface']
        self.router=config['router']
        self.myIP = config['myIP']
        self.startIP=config['startIP']
        self.maxIpCount = config['maxIP']
        self.etherSrc = config['myHwAddr']
        self.subnetMask = config['subnetMask']
        #self.xid = None  #random.randrange(1,0xffffffff)
        self.assignRecord = []
        self.devices=[]
        self.cv = Condition()
        self.notify_fn = callback
        
    def service_start(self):
        self.start()
        
    def ip_addr_allocate(self,hwAddr):
        findedRecord = None
        for ip,addr in self.assignRecord:
            if addr == hwAddr:
                findedRecord = (ip,addr)
                break
            
        newRecord = None
        if findedRecord is None:
            usedFlag = False
            for ip in range(ip2int_v4(self.startIP),(ip2int_v4(self.startIP) + self.maxIpCount)):
                for usedIp,addr in self.assignRecord:
                    if usedIp == ip:
                        usedFlag = True
                        break
                if usedFlag:
                    continue
                else:
                    newRecord = (ip,hwAddr)
                    self.assignRecord.append(newRecord)
                    break
            return ip2str_v4(newRecord[0])
        else:
            return ip2str_v4(findedRecord[0])
        #return '192.168.1.151'    

    def dhcp_offer(self,device,fromBackdoor=False):
        if device.yiaddr == '0.0.0.0':
            yiaddr = self.ip_addr_allocate(device.hwAddr)
            device.yiaddr = yiaddr
        else:
            yiaddr = device.yiaddr
        print('offer ip: %s' % yiaddr)     
        packet = (
            l2.Ether(dst="ff:ff:ff:ff:ff:ff",src=self.etherSrc) /
            inet.IP(src=self.myIP, dst="255.255.255.255") /
            inet.UDP(sport=67, dport=68) /
            dhcp.BOOTP(op=2,chaddr=macTransfer(device.hwAddr),yiaddr=yiaddr,xid=device.xid) /
            dhcp.DHCP(options=[
                ("message-type", "offer"), 
                ("lease_time",7200),
                ("server_id",self.myIP),
                ("vendor_class_id",device.vendor_class_id),
                "end"])
        )
        #print(str(packet).encode('hex'))
        #print(macTransfer("00:0e:5e:00:00:0a"))
        try:
            if fromBackdoor == False:
                sendrecv.sendp(packet,iface=self.iface,count=1,verbose=False)
        except:
            raise

        
 
    def dhcp_ack(self,device,fromBackdoor=False):
        yiaddr = device.yiaddr
        print('ack ip: %s' % yiaddr)    
        packet = (
            l2.Ether(dst="ff:ff:ff:ff:ff:ff",src=self.etherSrc) /
            inet.IP(src=self.myIP, dst=yiaddr) /
            inet.UDP(sport=67, dport=68) /
            dhcp.BOOTP(op=2,chaddr=macTransfer(device.hwAddr),yiaddr=yiaddr,xid=device.xid) /
            dhcp.DHCP(options=[
                ("message-type", "ack"),
                ("lease_time",7200),
                ("server_id",self.myIP),
                ("subnet_mask", self.subnetMask),
                ("router",self.router),
                ("vendor_class_id",device.vendor_class_id),
                #("client_id",device.client_id),
                "end"])
        )
        try:
            if fromBackdoor == False:
                sendrecv.sendp(packet,iface=self.iface,count=1,verbose=False)
        except:
            raise

        device.yiaddr_acked=True
            
            
    def packet_parse(self,pkt,fromBackdoor=False):

        etherSrc = pkt[l2.Ether].src
        
        # do not process packet sended by self
        if self.etherSrc == etherSrc:
            return
            
        requester = None
        print('search the record ...')
        for dev in self.devices:
            if dev.hwAddr == etherSrc:
                requester = dev
                break
                
        if requester is None:
            requester = REQUESTER(hwAddr=etherSrc,xid=pkt[dhcp.BOOTP].xid)
            #insert new object to the devices list
            self.devices.append(requester)
        
        
        
        with self.cv:
            pktType = None
            for o in pkt[dhcp.DHCP].options:
                #print type(o)
                #print o  
                if o in ["end", "pad"]:
                    break
                if o[0] == 'message-type':
                    pktType = o[1]
                elif o[0] == "vendor_class_id":
                    requester.vendor_class_id = o[1]
                    #print("vendor_class_id: {}".format(requester.vendor_class_id))
                elif o[0] == "client_id":
                    requester.client_id = o[1]
                    #print("client_id: {}".format(requester.client_id))
            #print 'pktType %d' % pktType
            if pktType == 1 :
                requester.xid=pkt[dhcp.BOOTP].xid
                self.dhcp_offer(requester,fromBackdoor)
                self.cv.notify_all()  
                
            elif pktType == 2  :
                self.cv.notify_all()
                
            elif pktType == 3 :
                self.dhcp_ack(requester,fromBackdoor)
                if self.notify_fn :
                    self.notify_fn(hwaddr=requester.hwAddr,ip=requester.yiaddr)
                self.cv.notify_all()   
                
            elif pktType == 5 :
                self.acked = True
                self.cv.notify_all()                
 
 
 
    def dhcp_response(self,response):
        #print("Source: {}".format(response[l2.Ether].src))
        #print("Destination: {}".format(response[l2.Ether].dst))

        #print("Your IP: {}".format(response[dhcp.BOOTP].yiaddr))
        #print("Client Hw Address: {}".format(response[dhcp.BOOTP].chaddr.encode('hex')))
        #print("xid: {}".format(response[dhcp.BOOTP].xid))
        self.packet_parse(pkt=response)
    
    def getOfferedAddr(self,timeout = None):
        with self.cv:
            ret = timed_wait(self.cv, lambda: self.ciaddr[0] if len(self.ciaddr) > 0 else None,timeout = timeout)
        return ret

    def isAcked(self,timeout = None):
        with self.cv:
            ret = timed_wait(self.cv, lambda: self.acked ,timeout = timeout)
            if ret != None:
                return self.acked
            else:
                return False
    
        
    def run(self):
        """
        Activity function for class
        """
        #print("rev task is running")
        while not self.killed:
            #sendrecv.sniff(filter="udp and (port 67 or 68)", prn=lambda p: self.print_dhcp_response(p))
            sendrecv.sniff(filter="udp and (port 67 or 68)", prn=self.dhcp_response, timeout = 1)
        print("rev task exit")
        
    def kill(self):
        self.killed = True
        self.join()
        

    def register(self,handler):
        self.notify_fn = handler
        
        
        
def notify_oftest(hwaddr,ip):
    print(("%-10s:" %'hwaddr') + hwaddr)
    print(("%-10s:" %'ip') + ip) 
    set_controller(ip, 'raisecom', 'raisecom')   

def main():
    
    config = {
        'iface'       : 'eth1'              ,
        'router'      : '192.168.1.1'       ,
        'myIP'        : '192.168.1.105'     ,
        'startIP'     : '192.168.1.150'     ,
        'maxIP'       : 50                  ,
        'myHwAddr'    : '00:0e:5e:00:00:02' ,
        'subnetMask'  : '255.255.255.0'         
        
        }

    server = DHCP_Server(config=config,callback=notify_oftest)
    #server.register(notify_oftest)
    time.sleep(1)
    server.service_start()
    while True:
        cmd = raw_input('cmd: ')
        if cmd == 'exit':
            break
        else:
            print('unknown cmd') 
    
    server.kill()
    
if __name__ == "__main__":
    main()
