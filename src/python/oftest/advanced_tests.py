"""
Advanced classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import logging
import unittest
import os

import oftest
from oftest import config
import oftest.controller_mc as controller
import oftest.dataplane as dataplane
import oftest.netconf as netconf
import ofp

class AdvancedTest(unittest.TestCase):
    def __str__(self):
        return self.id().replace('.runTest', '')

    def setUp(self):
        oftest.open_logfile(str(self))
        logging.info("** START TEST CASE " + str(self))

    def tearDown(self):
        logging.info("** END TEST CASE " + str(self))

class AdvancedProtocol(AdvancedTest):
    """
    Root class for setting up the controller
    """

    def setUp(self):
        AdvancedTest.setUp(self)

        self.controller = controller.ControllerMc(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.start()

        try:
            #@todo Add an option to wait for a pkt transaction to ensure version
            # compatibilty?
            self.controller.connect(timeout=20)

            # By default, respond to echo requests
            self.controller.keep_alive = True
            ''' 
            if not self.controller.active:
                raise Exception("Controller startup failed")
            if len(self.controller.device_agents) == 0:
                print(len(self.controller.device_agents))
                raise Exception("Controller startup failed (no switch addr)")
               
            for d in self.controller.device_agents:
                logging.info("Connected " + str(d.switch_addr))
                logging.info("netconf will create at " + str(d.switch_addr[0]))
                request = ofp.message.features_request()
                reply, pkt = d.transact(request)
                self.assertTrue(reply is not None,
                                "Did not complete features_request for handshake")
                if reply.version == 1:
                    self.supported_actions = reply.actions
                    logging.info("Supported actions: " + hex(self.supported_actions))
                d.dpid = reply.datapath_id
                d.netconf = netconf.Netconf(switch_addr = d.switch_addr[0])
                
                
                request = ofp.message.port_desc_stats_request()
                reply, pkt = d.transact(request)
                d.port_desc = reply.entries
                #print(reply.entries[0].hw_addr)
            '''
                
        except:
            self.controller.kill()
            del self.controller
            raise

    def inheritSetup(self, parent):
        """
        Inherit the setup of a parent

        This allows running at test from within another test.  Do the
        following:

        sub_test = SomeTestClass()  # Create an instance of the test class
        sub_test.inheritSetup(self) # Inherit setup of parent
        sub_test.runTest()          # Run the test

        Normally, only the parent's setUp and tearDown are called and
        the state after the sub_test is run must be taken into account
        by subsequent operations.
        """
        logging.info("** Setup " + str(self) + " inheriting from "
                          + str(parent))
        self.controller = parent.controller
        self.supported_actions = parent.supported_actions
        
    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        AdvancedTest.tearDown(self)

    def assertTrue(self, cond, msg):
        if not cond:
            logging.error("** FAILED ASSERTION: " + msg)
        unittest.TestCase.assertTrue(self, cond, msg)
'''
class AdvancedDataPlane(AdvancedProtocol):
    """
    Root class that sets up the controller and dataplane
    """
    def setUp(self):
        AdvancedProtocol.setUp(self)
        self.dataplane = oftest.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def inheritSetup(self, parent):
        """
        Inherit the setup of a parent

        See AdvancedProtocol.inheritSetup
        """
        AdvancedProtocol.inheritSetup(self, parent)
        self.dataplane = parent.dataplane

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        AdvancedProtocol.tearDown(self)
'''

