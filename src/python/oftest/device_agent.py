# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2014 Big Switch Networks, Inc.
"""
Device class
"""

import sys
import os
import socket
import time
import struct
import select
import logging
from threading import Thread
from threading import Lock
from threading import Condition
import ofutils
import loxi

# Configured openflow version
import ofp as cfg_ofp

##@todo Find a better home for these identifiers (controller)    
RCV_SIZE_DEFAULT = 32768    
    
class DeviceAgent(Thread):
    """
    Class abstracting the switch.  
    """

    def __init__(self,switch_socket = None,switch_addr = None, dpid=None, ip='127.0.0.1',max_port = None,max_pkts=1024):
        Thread.__init__(self)
        # feature related
        if max_port == None :
            self.max_port = 2
        else :
            self.max_port = max_port
        self.dpid = dpid
        self.ip = ip
        self.port_desc = None
        self.netconf = None
        # Socket related
        self.rcv_size = RCV_SIZE_DEFAULT
        self.switch_socket = switch_socket
        self.switch_addr = switch_addr
        self.tx_lock = Lock()

        # Used to wake up the event loop from another thread
        self.waker = ofutils.EventDescriptor()

        # Counters
        self.socket_errors = 0
        self.parse_errors = 0
        self.packets_total = 0
        self.packets_expired = 0
        self.packets_handled = 0
        self.poll_discards = 0
        
        # State
        self.sync = Lock()
        self.handlers = {}
        self.keep_alive = True
        self.active = True
        self.initial_hello = True

        # OpenFlow message/packet queue
        # Protected by the packets_cv lock / condition variable
        self.packets = []
        self.packets_cv = Condition()
        self.packet_in_count = 0        
        
        # Settings
        self.max_pkts = max_pkts
        self.dbg_state = "init"
        self.logger = logging.getLogger("device_agent")
        
        
        # Transaction and message type waiting variables 
        #   xid_cv: Condition variable (semaphore) for packet waiters
        #   xid: Transaction ID being waited on
        #   xid_response: Transaction response message
        self.xid_cv = Condition()
        self.xid = None
        self.xid_response = None

        self.buffered_input = ""
        
    def getPortMac(self, port) :
        #if port > len(self.port_desc) or port < 1:
        #    return []
        for pd in self.port_desc:
            if pd.port_no == port:
                return pd.hw_addr
        return []
        
    def message_send(self, msg):
        """
        Send the message to the switch

        @param msg A string or OpenFlow message object to be forwarded to
        the switch.
        """

        if not self.switch_socket:
            # Sending a string indicates the message is ready to go
            raise Exception("no socket")

        if msg.xid == None:
            msg.xid = ofutils.gen_xid()

        outpkt = msg.pack()

        self.logger.debug("Msg out: version %d class %s len %d xid %d",
                          msg.version, type(msg).__name__, len(outpkt), msg.xid)

        with self.tx_lock:
            if self.switch_socket.sendall(outpkt) is not None:
                raise AssertionError("failed to send message to switch")

        return 0 # for backwards compatibility
        
    def transact(self, msg, timeout=-1):
        """
        Run a message transaction with the switch

        Send the message in msg and wait for a reply with a matching
        transaction id.  Transactions have the highest priority in
        received message handling.

        @param msg The message object to send; must not be a string
        @param timeout The timeout in seconds; if -1 use default.
        """

        if msg.xid == None:
            msg.xid = ofutils.gen_xid()

        self.logger.debug("Running transaction %d" % msg.xid)

        with self.xid_cv:
            if self.xid:
                self.logger.error("Can only run one transaction at a time")
                return (None, None)

            self.xid = msg.xid
            self.xid_response = None
            self.message_send(msg)

            self.logger.debug("Waiting for transaction %d" % msg.xid)
            ofutils.timed_wait(self.xid_cv, lambda: self.xid_response, timeout=timeout)

            if self.xid_response:
                (resp, pkt) = self.xid_response
                self.xid_response = None
            else:
                (resp, pkt) = (None, None)

        if resp is None:
            self.logger.warning("No response for xid " + str(self.xid))
        return (resp, pkt)
        
        
    def run(self):
        """
        Activity function for class

        Assumes connection to switch already exists.  Listens on
        switch_socket for messages until an error (or zero len pkt)
        occurs.

        When there is a message on the socket, check for handlers; queue the
        packet if no one handles the packet.

        See note for controller describing the limitation of a single
        connection for now.
        """

        self.dbg_state = "running"
        print("device_agent: " + str(self.name) + "   --socket " + str(self.switch_addr))
        while self.active:
            try:
                ready, sel_out, sel_err = select.select([self.switch_socket], [], [], 1)
            except:
                #print sys.exc_info()
                self.logger.error("Select error, disconnecting")
                self.disconnect()
            if len(ready) != 0:
                self._socket_ready_handle()

            
    def wakeup(self):
        """
        Wake up the event loop, presumably from another thread.
        """
        self.waker.notify()
        
    def shutdown(self):
        """
        Shutdown the controller closing all sockets

        @todo Might want to synchronize shutdown with self.sync...
        """

        self.active = False
        try:
            self.switch_socket.shutdown(socket.SHUT_RDWR)
        except:
            self.logger.info("Ignoring switch soc shutdown error")
        self.switch_socket = None

        # Wakeup condition variables on which controller may be wait
        with self.xid_cv:
            self.xid_cv.notifyAll()

        self.wakeup()
        self.dbg_state = "down"        

    def _pkt_handle(self, pkt):
        """
        Check for all packet handling conditions

        Parse and verify message 
        Check if XID matches something waiting
        Check if message is being expected for a poll operation
        Check if keep alive is on and message is an echo request
        Check if any registered handler wants the packet
        Enqueue if none of those conditions is met

        an echo request in case keep_alive is true, followed by
        registered message handlers.
        @param pkt The raw packet (string) which may contain multiple OF msgs
        """

        # snag any left over data from last read()
        pkt = self.buffered_input + pkt
        self.buffered_input = ""

        # Process each of the OF msgs inside the pkt
        offset = 0
        while offset < len(pkt):
            if offset + 8 > len(pkt):
                break

            # Parse the header to get type
            hdr_version, hdr_type, hdr_length, hdr_xid = cfg_ofp.message.parse_header(pkt[offset:])

            # Use loxi to resolve to ofp of matching version
            ofp = loxi.protocol(hdr_version)

            # Extract the raw message bytes
            if (offset + hdr_length) > len(pkt):
                break
            rawmsg = pkt[offset : offset + hdr_length]
            offset += hdr_length

            #if self.filter_packet(rawmsg, hdr):
            #    continue

            msg = ofp.message.parse_message(rawmsg)
            if not msg:
                self.parse_errors += 1
                self.logger.warn("Could not parse message")
                continue

            self.logger.debug("Msg in: version %d class %s len %d xid %d",
                              hdr_version, type(msg).__name__, hdr_length, hdr_xid)

            with self.sync:
                # Check if transaction is waiting
                with self.xid_cv:
                    if self.xid and hdr_xid == self.xid:
                        self.logger.debug("Matched expected XID " + str(hdr_xid))
                        self.xid_response = (msg, rawmsg)
                        self.xid = None
                        self.xid_cv.notify()
                        continue

                # Check if keep alive is set; if so, respond to echo requests
                if self.keep_alive:
                    if hdr_type == ofp.OFPT_ECHO_REQUEST:
                        self.logger.debug("Responding to echo request")
                        rep = ofp.message.echo_reply()
                        rep.xid = hdr_xid
                        # Ignoring additional data
                        self.message_send(rep)
                        continue

                # Generalize to counters for all packet types?
                if msg.type == ofp.OFPT_PACKET_IN:
                    self.packet_in_count += 1

                # Log error messages
                if isinstance(msg, ofp.message.error_msg):
                    #pylint: disable=E1103
                    if msg.err_type in ofp.ofp_error_type_map:
                        type_str = ofp.ofp_error_type_map[msg.err_type]
                        if msg.err_type == ofp.OFPET_HELLO_FAILED:
                            code_map = ofp.ofp_hello_failed_code_map
                        elif msg.err_type == ofp.OFPET_BAD_REQUEST:
                            code_map = ofp.ofp_bad_request_code_map
                        elif msg.err_type == ofp.OFPET_BAD_ACTION:
                            code_map = ofp.ofp_bad_action_code_map
                        elif msg.err_type == ofp.OFPET_FLOW_MOD_FAILED:
                            code_map = ofp.ofp_flow_mod_failed_code_map
                        elif msg.err_type == ofp.OFPET_PORT_MOD_FAILED:
                            code_map = ofp.ofp_port_mod_failed_code_map
                        elif msg.err_type == ofp.OFPET_QUEUE_OP_FAILED:
                            code_map = ofp.ofp_queue_op_failed_code_map
                        else:
                            code_map = None

                        if code_map and msg.code in code_map:
                            code_str = code_map[msg.code]
                        else:
                            code_str = "unknown"
                    else:
                        type_str = "unknown"
                        code_str = "unknown"
                    self.logger.warn("Received error message: xid=%d type=%s (%d) code=%s (%d)",
                                     hdr_xid, type_str, msg.err_type, code_str, msg.code if code_str != "unknown" else -1)
                    if msg.version >= 3 and isinstance(msg, ofp.message.bsn_error):
                        self.logger.warn("BSN error, msg '%s'", msg.err_msg)

                # Now check for message handlers; preference is given to
                # handlers for a specific packet
                handled = False
                if hdr_type in self.handlers.keys():
                    handled = self.handlers[hdr_type](self,hdr_xid, msg, rawmsg)
                if not handled and ("all" in self.handlers.keys()):
                    handled = self.handlers["all"](self,hdr_xid, msg, rawmsg)

                if not handled: # Not handled, enqueue
                    with self.packets_cv:
                        if len(self.packets) >= self.max_pkts:
                            self.packets.pop(0)
                            self.packets_expired += 1
                        self.packets.append((msg, rawmsg))
                        self.packets_cv.notify_all()
                    self.packets_total += 1
                else:
                    self.packets_handled += 1
                    self.logger.debug("Message handled by callback")

        # end of 'while offset < len(pkt)'
        #   note that if offset = len(pkt), this is
        #   appends a harmless empty string
        self.buffered_input += pkt[offset:]
    def register(self, msg_type, handler):
        """
        Register a callback to receive a specific message type.

        Only one handler may be registered for a given message type.

        WARNING:  A lock is held during the handler call back, so 
        the handler should not make any blocking calls

        @param msg_type The type of message to receive.  May be DEFAULT 
        for all non-handled packets.  The special type, the string "all"
        will send all packets to the handler.
        @param handler The function to call when a message of the given 
        type is received.
        """
        # Should check type is valid
        if not handler and msg_type in self.handlers.keys():
            del self.handlers[msg_type]
            return
        self.handlers[msg_type] = handler


    def _socket_ready_handle(self):
        """
        Handle an input-ready socket

        @returns 0 on success, -1 on error
        """

        try:
            pkt = self.switch_socket.recv(self.rcv_size)
        except:
            self.logger.warning("Error on switch read")
            return -1

        if len(pkt) == 0: # no packet
            self.logger.warning("Zero-length switch read")
            self.logger.info(str(self))
            return -1

        self._pkt_handle(pkt)
        return 0
        
        
    def kill(self):
        """
        Force the controller thread to quit
        """
        self.active = False
        self.wakeup()
        self.join()