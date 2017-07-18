# coding:utf-8  
  
import rpyc  
import sys  
import time


    
class DpProfile():        

    def __init__(self,dataplane = None):
        self.dataplane = dataplane
        
        if dataplane :
            self.stc = dataplane.stc
 
    def config(self,stcProject,txPort,rxPort):
        chassisAddress = self.dataplane.chassisIp
    
        TxPort = txPort
    
        RxPort = rxPort
     
       
        # Switch to the loopback mode to capture transmitted packets.
        #print "Switch to the loopback mode to capture transmitted packets.   "
        #portReturn = self.stc.config( EthernetCopper[0], "-DataPathMode", "LOCAL_LOOPBACK")
        #print portReturn 
        

        StreamBlock = [" ", " "]
        StreamBlock[0] = self.stc.create(  "StreamBlock" ,
                                            "-under" , 
                                            TxPort,
                                            "-frameConfig",
                                            "\"\"",
                                            "-FrameLengthMode" , 
                                            "FIXED",
                                            "-FixedFrameLength" ,
                                            "256" ,
                                            "-maxFrameLength",
                                            "1200",
                                            "-name",
                                            "StreamBlock_1")


        StrEthII = self.stc.create( "ethernet:EthernetII",
                                     "-under",
                                     StreamBlock[0],
                                     "-name",
                                     "eht_1",
                                     "-srcMac",
                                     "11:11:11:11:11:11" ,
                                     "-dstMac" ,
                                     "22:22:22:22:22:22" )
    
        # Add a Vlan container object.
        vlanContainer = self.stc.create( "vlans", "-under", StrEthII)
          
        # Add a Vlan header.
        self.stc.create( "Vlan", "-under", vlanContainer ,"-pri", "000", "-cfi" , "0" , "-id", "10")
                                      
                                     
        #Add IPv4ͷ 
        strIPv4 = self.stc.create( "ipv4:IPv4",
                                    "-under",
                                    StreamBlock[0],
                                    "-name",
                                    "Ipv4_1", 
                                    "-sourceAddr",
                                    "10.10.10.10",
                                    "-destAddr",
                                    "20.20.20.20")
    
        #Add TCP
        strTcp = self.stc.create( "tcp:Tcp",
                                    "-under ",
                                    StreamBlock[0],
                                    "-name",
                                    "tcp1",
                                    "-sourcePort",
                                    "10",
                                    "-destPort ",
                                    "20 ")    
    
    
        #����StreamBlock(1)��modifier ����ѡ�� RangeModifer ��RandomModifier ��TableModifier
    
        #StreamBlock1 ԴIp ���
    
        RandomModifier1 = self.stc.create(  "RandomModifier",
                                             "-under" ,
                                             StreamBlock[0],
                                             "-Mask" ,
                                             "{0.0.0.255}"  ,
                                             "-RecycleCount" ,
                                             "10" ,
                                             "-EnableStream" ,
                                             "FALSE" ,
                                             "-OffsetReference" ,
                                             "{Ipv4_1.sourceAddr}")
                                    
        #lstStreamBlockInfo = self.stc.perform( "StreamBlockGetInfo", "-StreamBlock", StreamBlock[0])  

        StreamBlock[1] = self.stc.create(  "StreamBlock" ,
                                            "-under" , 
                                            RxPort,
                                            "-frameConfig",
                                            "\"\"",
                                            "-FrameLengthMode" , 
                                            "FIXED",
                                            "-FixedFrameLength" ,
                                            "256" ,
                                            "-maxFrameLength",
                                            "1200",
                                            "-name",
                                            "StreamBlock_1")


        StrEthII_2 = self.stc.create( "ethernet:EthernetII",
                                     "-under",
                                     StreamBlock[1],
                                     "-name",
                                     "eht_1",
                                     "-srcMac",
                                     "11:11:11:11:11:11" ,
                                     "-dstMac" ,
                                     "22:22:22:22:22:22" )
    
        # Add a Vlan container object.
        vlanContainer_2 = self.stc.create( "vlans", "-under", StrEthII_2)
          
        # Add a Vlan header.
        self.stc.create( "Vlan", "-under", vlanContainer_2 ,"-pri", "000", "-cfi" , "0" , "-id", "10")
                                      
                                     
        #Add IPv4ͷ 
        strIPv4_2 = self.stc.create( "ipv4:IPv4",
                                    "-under",
                                    StreamBlock[1],
                                    "-name",
                                    "Ipv4_1", 
                                    "-sourceAddr",
                                    "10.10.10.10",
                                    "-destAddr",
                                    "20.20.20.20")
    
        #Add TCP
        strTcp_2 = self.stc.create( "tcp:Tcp",
                                    "-under ",
                                    StreamBlock[1],
                                    "-name",
                                    "tcp1",
                                    "-sourcePort",
                                    "10",
                                    "-destPort ",
                                    "20 ")    
    
    
        #����StreamBlock(1)��modifier ����ѡ�� RangeModifer ��RandomModifier ��TableModifier
    
        #StreamBlock1 ԴIp ���
    
        RandomModifier_2 = self.stc.create(  "RandomModifier",
                                             "-under" ,
                                             StreamBlock[1],
                                             "-Mask" ,
                                             "{0.0.0.255}"  ,
                                             "-RecycleCount" ,
                                             "10" ,
                                             "-EnableStream" ,
                                             "FALSE" ,
                                             "-OffsetReference" ,
                                             "{Ipv4_1.sourceAddr}")

    
                                             
        # generator1
    
        generator1 = self.stc.get( TxPort, "-children-Generator") 
    
        self.stc.config(generator1, "-Name", "Generator_1")
    
        generatorConfig1 = self.stc.get(generator1, "-children-GeneratorConfig")

        self.stc.config( generatorConfig1,
                          "-SchedulingMode",
                          "PORT_BASED" ,
                          "-DurationMode",
                          "BURSTS" ,
                          "-BurstSize",
                          " 1",
                          "-Duration",
                          "10000", 
                          "-LoadMode",
                          "FIXED",
                          "-FixedLoad",
                          "1",
                          "-LoadUnit",
                          "PERCENT_LINE_RATE")
        
        
        
        # generator2                         
        generator2 = self.stc.get( RxPort, "-children-Generator") 
    
        self.stc.config(generator2, "-Name", "Generator_1")
        generatorConfig2 = self.stc.get(generator2, "-children-GeneratorConfig")
        self.stc.config( generatorConfig2,
                          "-SchedulingMode",
                          "PORT_BASED" ,
                          "-DurationMode",
                          "BURSTS" ,
                          "-BurstSize",
                          " 1",
                          "-Duration",
                          "10000", 
                          "-LoadMode",
                          "FIXED",
                          "-FixedLoad",
                          "1",
                          "-LoadUnit",
                          "PERCENT_LINE_RATE")                         
    
    
    
    
    
    
        #analyzer 1   
        analyzer1 = self.stc.get( RxPort, "-children-Analyzer")

        self.stc.config( analyzer1, "-Name", "Analyzer_1")
    
        analyzerConfig1 = self.stc.get( analyzer1 , "-children-AnalyzerConfig")

        self.stc.config(  analyzerConfig1, 
                           "-TimestampLatchMode" ,
                           "END_OF_FRAME" ,
                           "-JumboFrameThreshold" ,
                           "1500" ,
                           "-OversizeFrameThreshold" ,
                           "2000" ,
                           "-UndersizeFrameThreshold" ,
                           "64" ,
                           "-AdvSeqCheckerLateThreshold" ,
                           "1000" ,
                           "-Name" ,
                           "AnalyzerConfig_2")
        
    
        #analyzer 2   
        analyzer2 = self.stc.get( TxPort, "-children-Analyzer")

        self.stc.config( analyzer2, "-Name", "Analyzer_2")
    
        analyzerConfig2 = self.stc.get( analyzer2 , "-children-AnalyzerConfig")

        self.stc.config(  analyzerConfig2, 
                           "-TimestampLatchMode" ,
                           "END_OF_FRAME" ,
                           "-JumboFrameThreshold" ,
                           "1500" ,
                           "-OversizeFrameThreshold" ,
                           "2000" ,
                           "-UndersizeFrameThreshold" ,
                           "64" ,
                           "-AdvSeqCheckerLateThreshold" ,
                           "1000" ,
                           "-Name" ,
                           "AnalyzerConfig_2")
    
        generatorResult = self.stc.subscribe( "-Parent" ,
                                               stcProject ,
                                               "-ResultParent" ,
                                               TxPort ,
                                               "-ConfigType",
                                               "Generator",
                                               "-resulttype",
                                               "GeneratorPortResults",
                                               "-filenameprefix",
                                               "result")

        generatorResult2 = self.stc.subscribe( "-Parent" ,
                                               stcProject ,
                                               "-ResultParent" ,
                                               RxPort ,
                                               "-ConfigType",
                                               "Generator",
                                               "-resulttype",
                                               "GeneratorPortResults",
                                               "-filenameprefix",
                                               "result")   
        
         
        analyzerResult = self.stc.subscribe( "-Parent",
                                              stcProject,
                                              "-ResultParent",
                                              RxPort ,
                                              "-ConfigType",
                                              "Analyzer" ,
                                              "-resulttype",
                                              "AnalyzerPortResults",
                                              "-filenameprefix",
                                              "result" )
        analyzerResult2 = self.stc.subscribe( "-Parent",
                                              stcProject,
                                              "-ResultParent",
                                              TxPort ,
                                              "-ConfigType",
                                              "Analyzer" ,
                                              "-resulttype",
                                              "AnalyzerPortResults",
                                              "-filenameprefix",
                                              "result" )   

        """
        resultReturn = self.stc.connect(chassisAddress)
    

    
        resultReturn = self.stc.reserve( "//" + chassisAddress + "/" + slotPort1)
    
        resultReturn = self.stc.reserve( "//" + chassisAddress + "/" + slotPort2)
    
        """
    
        captureRx = self.stc.get(RxPort, "-children-capture")

        captureTx = self.stc.get(TxPort, "-children-capture")

    
        
  
    
        self.stc.config(captureRx, "-mode" ,"REGULAR_MODE", "-BufferMode", "WRAP" ,"-srcMode" ,"RX_MODE" )
        self.stc.config(captureTx, "-mode" ,"REGULAR_MODE", "-BufferMode", "WRAP" ,"-srcMode" ,"TX_RX_MODE" )
        #self.stc.perform StreamBlockUpdate -streamBlock "$StreamBlock(1)"
    
        #self.stc.perform StreamBlockUpdate -streamBlock "$StreamBlock(2)"
    

    
        resultReturn = self.stc.perform( "setupPortMappings")
    
        #ִ��apply
        print "apply"
        resultReturn = self.stc.apply()


        #start analyzer

        analyzerCurrent = self.stc.get(RxPort ,"-children-analyzer")
        self.stc.perform ("analyzerStart" ,"-analyzerList" ,analyzerCurrent)
    
        analyzerCurrent2 = self.stc.get(TxPort ,"-children-analyzer")
        self.stc.perform ("analyzerStart" ,"-analyzerList" ,analyzerCurrent2)    
 
        
        #start capture
        self.stc.perform( "CaptureStart", "-captureProxyId" ,captureRx)
        self.stc.perform( "CaptureStart", "-captureProxyId" ,captureTx)
        
        
        #start generator
        generatorCurrent = self.stc.get(TxPort, "-children-generator")
    
        self.stc.perform("generatorStart", "-generatorList", generatorCurrent)

        #start generator
        generatorCurrent2 = self.stc.get(RxPort, "-children-generator")
    
        self.stc.perform("generatorStart", "-generatorList", generatorCurrent2)
  
        
        #sleep 10s
        self.stc.sleep( "10")
    
    
        # stop generator    
        self.stc.perform( "generatorStop", "-generatorList" ,generatorCurrent)
        self.stc.perform( "generatorStop", "-generatorList" ,generatorCurrent2)
        
            
        #stop capture
        self.stc.perform( "CaptureStop" ,"-captureProxyId" ,captureRx)
        self.stc.perform( "CaptureStop" ,"-captureProxyId" ,captureTx)
    
        #save captured data
        print "Save Capture Data"
        self.stc.perform( "CaptureDataSave", "-captureProxyId", captureRx ,"-FileName" ,"test_stc_rx.pcap" ,"-FileNameFormat" ,"PCAP")
        self.stc.perform( "CaptureDataSave", "-captureProxyId", captureTx ,"-FileName" ,"test_stc_tx.pcap" ,"-FileNameFormat" ,"PCAP")
    
        #stop analyzer    
        self.stc.perform( "analyzerStop","-analyzerList" ,analyzerCurrent)
        self.stc.perform( "analyzerStop","-analyzerList" ,analyzerCurrent2)    
        
        # This is the same handle as above.

        hAnalyzerPortResults = self.stc.get( analyzerCurrent, "-children-AnalyzerPortResults")
    
        
        print "\n\nAnalyzer Port Results 1"
             
        print "\tJumbo:\t %s " % self.stc.get(hAnalyzerPortResults ,"-JumboFrameCount")
        print "\tSig:\t %s " % self.stc.get(hAnalyzerPortResults ,"-sigFrameCount")
        print "\tUnder:\t %s " % self.stc.get(hAnalyzerPortResults ,"-UndersizeFrameCount")
        print "\tOver:\t %s " % self.stc.get(hAnalyzerPortResults ,"-oversizeFrameCount")
        print "\tMaxLen:\t %s " % self.stc.get(hAnalyzerPortResults ,"-MaxFrameLength")
        
        self.totalFrameCount = int(self.stc.get(hAnalyzerPortResults ,"-totalFrameCount"))
        print "\tTotal:\t %d " % self.totalFrameCount
  
     
        hAnalyzerPortResults2 = self.stc.get( analyzerCurrent2, "-children-AnalyzerPortResults")
    
        
        print "\n\nAnalyzer Port Results 2"
             
        print "\tJumbo:\t %s " % self.stc.get(hAnalyzerPortResults2 ,"-JumboFrameCount")
        print "\tSig:\t %s " % self.stc.get(hAnalyzerPortResults2 ,"-sigFrameCount")
        print "\tUnder:\t %s " % self.stc.get(hAnalyzerPortResults2 ,"-UndersizeFrameCount")
        print "\tOver:\t %s " % self.stc.get(hAnalyzerPortResults2 ,"-oversizeFrameCount")
        print "\tMaxLen:\t %s " % self.stc.get(hAnalyzerPortResults2 ,"-MaxFrameLength")
        
        self.totalFrameCount2 = int(self.stc.get(hAnalyzerPortResults2 ,"-totalFrameCount"))
        print "\tTotal:\t %d " % self.totalFrameCount2        

       
        return self.totalFrameCount



class DpProfile_MultiStream(DpProfile):
    
    def configMultiStream(self,stcProject,portA,portB):
        hPortA = portA
        hPortB = portB
        hProject = stcProject
 
        # Attach ports.  
        print "[clock format [clock seconds] -format %m-%d-%Y%l:%M:%S%p] Attaching Ports ..."
        self.stc.perform( "attachPorts", "-portList", "[list %s %s]" % (hPortA,hPortB) ,"-autoConnect", "TRUE")
        
        # Initialize generator/analyzer.
        hGenerator = self.stc.get(hPortA ,"-children-Generator")
        hAnalyzer = self.stc.get( hPortB ,"-children-Analyzer")
         
        # Create the AnalyzerFrameConfigFilter filter. Clear the -FrameConfig attribute value. 
        print "Configuring analyzer frame config filter ..."
        hAnalyzerFrameConfigFilter = self.stc.create( "AnalyzerFrameConfigFilter", "-under" ,hAnalyzer, "-FrameConfig" ,"\"\"")

        '''        
        analyzerEthII = self.stc.create( "ethernet:EthernetII" ,"-under" ,hAnalyzerFrameConfigFilter, "-name" ,"af1_eth" ,"-srcMac" ,
                         "\"00:00:00:00:00:00/FF:FF:FF:FF:FF:FF#FF:FF:FF:FF:FF:FF\"")
        

        # Add a Vlan container object.
        analyzerVlanContainer = self.stc.create( "vlans", "-under", analyzerEthII)
          
        # Add a Vlan header.
        self.stc.create( "Vlan", "-under", analyzerVlanContainer ,"-pri", "000", "-cfi" , "0" , "-id", "10")
        ''' 
         
         
        self.stc.create( "ipv4:IPv4", "-under" ,hAnalyzerFrameConfigFilter, "-name", "af1_ip",
          "-destAddr" ,"\"192.168.1.1/192.168.1.3#255.255.255.255\"" )

        # Create a stream block.
        print"Configuring stream block ..."
        hStreamBlock = self.stc.create( "streamBlock", "-under" ,hPortA, "-insertSig" ,"TRUE" , 
                    "-frameConfig" ,"\"\"" ,"-frameLengthMode" ,"FIXED", "-maxFrameLength", "1200" ,"-FixedFrameLength" ,"128")

        # Add an EthernetII Protocol Data Unit (PDU).
        print"\nAdding headers"
        StrEthII = self.stc.create( "ethernet:EthernetII", "-under" ,hStreamBlock, "-name" ,"sb1_eth" ,"-srcMac" ,"00:00:20:00:00:00" , 
                        "-dstMac", "00:00:00:00:00:40" )
        
        # Add a Vlan container object.
        vlanContainer = self.stc.create( "vlans", "-under", StrEthII)
          
        # Add a Vlan header.
        self.stc.create( "Vlan", "-under", vlanContainer ,"-pri", "000", "-cfi" , "0" , "-id", "10")
        
        
        self.stc.create( "ipv4:IPv4" ,"-under" , hStreamBlock ,"-name" ,"sb1_ip" ,"-sourceAddr", "10.0.0.2" ,"-destAddr", "192.168.1.1")

        # Use modifier to generate multiple streams.
        print"\nCreating Modifiers on Stream Block"
        hRangeModifer1 = self.stc.create(   "RangeModifier",
                                            "-under" ,hStreamBlock,
                                            "-ModifierMode", "INCR",
                                            "-Mask" ,"000000FF" ,
                                            "-StepValue" ,"0A000001" ,
                                            "-Data" ,"0A000002" ,
                                            "-RecycleCount ","100" ,
                                            "-RepeatCount ","0" ,
                                            "-DataType" ,"BYTE" ,
                                            "-EnableStream" ,"true" ,
                                            "-Offset" ,"0",
                                            "-OffsetReference" ,"sb1_ip.sourceAddr")
        
        hRangeModifer2 = self.stc.create(   "RangeModifier" ,
                                            "-under" ,hStreamBlock ,
                                            "-ModifierMode", "INCR" ,
                                            "-Mask" ,"FFFFFFFF" ,
                                            "-StepValue" ,"1" ,
                                            "-Data", "C0A80101" ,
                                            "-RecycleCount" ,"11" ,
                                            "-RepeatCount" ,"0" ,
                                            "-DataType", "BYTE" ,
                                            "-EnableStream" ,"true" ,
                                            "-Offset" ,"0" ,
                                            "-OffsetReference", "sb1_ip.destAddr")

    
        # Configure generator
        print"Configuring Generator"
        hGeneratorConfig = self.stc.get( hGenerator, "-children-GeneratorConfig")
        
        self.stc.config( hGeneratorConfig ,
                        "-DurationMode", "BURSTS" ,
                        "-BurstSize", "1" ,
                        "-Duration" ,"10000" ,
                        "-LoadMode", "FIXED" ,
                        "-FixedLoad", "100" ,
                        "-LoadUnit" ,"PERCENT_LINE_RATE" ,
                        "-SchedulingMode", "PORT_BASED")

        # Subscribe to realtime results
        print"Subscribe to realtime results"
        
        self.stc.subscribe( "-Parent" ,hProject ,
                      "-configType" ,"Analyzer" ,
                      "-resultParent", hPortB ,
                      "-resultType" ,"FilteredStreamResults"  ,
                      "-filenamePrefix" ,"FilteredStreamResults" ,
                      "-interval" ,"1")
                             
        # Apply configuration.  
        print"Apply configuration" 
        res = self.stc.apply()
        print res

        print "[clock format [clock seconds] -format %m-%d-%Y%l:%M:%S%p]"
        print "Starting Capture..."
        
        # Get the capture object. (Automatically created)
        hCapture = self.stc.get(hPortB ,"-children-capture")
        self.stc.config( hCapture ,"-mode" ,"REGULAR_MODE" ,"-srcMode" ,"TX_RX_MODE")  
        self.stc.perform( "CaptureStart" ,"-captureProxyId" ,hCapture)


        # Start the analyzer and generator.
        print"Start Analyzer"
        self.stc.perform( "AnalyzerStart", "-AnalyzerList" ,hAnalyzer)
        print"Current analyzer state" + self.stc.get(hAnalyzer, "-state")
          
        print"Start Generator"
        self.stc.perform( "GeneratorStart", "-GeneratorList", hGenerator)
        print "Current generator state " +  self.stc.get(hGenerator, "-state")
        
        print"Wait 10 seconds ..."
        self.stc.sleep("10")

        # Stop the analyzer.  
        self.stc.perform( "AnalyzerStop" ,"-AnalyzerList" ,hAnalyzer)
    
        # Retrieve the resultChild objects. There will be one handle for each filtered stream entry.
        print"\n\nFiltered Frame Results:"

        hResults = self.stc.get(hPortB + ".Analyzer", "-children-FilteredStreamResults").split(' ')
        #print hResults
        for h in hResults:
            filteredName_1 = self.stc.get(h,"-FilteredName_1")
            print "filteredName_1:\t\t" + filteredName_1

            filteredValue_1 = self.stc.get(h,"-FilteredValue_1")
            print "filteredValue_1:\t\t" +  filteredValue_1
            
            filteredName_2 = self.stc.get(h,"-FilteredName_2")
            print "filteredName_2:\t\t" +  filteredName_2            

            filteredValue_2 = self.stc.get(h,"-FilteredValue_2")
            print "filteredValue_2:\t\t" +  filteredValue_2
            
            framesReceived = self.stc.get(h,"-FrameCount")
            print "framesReceived:\t\t" +  framesReceived            
            
            bitsReceivedRate = self.stc.get(h,"-BitRate")
            print "bitsReceivedRate:\t\t" +  bitsReceivedRate               
            
            bitReceived = self.stc.get(h,"-BitCount")
            print "bitReceived:\t\t" +  bitReceived   
            
            framesReceivedRate = self.stc.get(h,"-FrameRate")
            print "framesReceivedRate:\t\t" +  framesReceivedRate   
            
            L1BitReceivedRate = self.stc.get(h,"-L1BitRate")
            print "L1BitReceivedRate:\t\t" +  L1BitReceivedRate   
            
            bytesReceived = self.stc.get(h,"-OctetCount")
            print "bytesReceived:\t\t" +  bytesReceived                           
            
            bytesReceivedRate = self.stc.get(h,"-OctetRate")
            print "bytesReceivedRate:\t\t" +  bytesReceivedRate   
            
            avgInterarrivalTime = self.stc.get(h,"-AvgInterarrivalTime")
            print "avgInterarrivalTime:\t\t" +  avgInterarrivalTime   
            
            avgLatency = self.stc.get(h,"-AvgLatency")
            print "avgLatency:\t\t" +  avgLatency               
            
            StreamIndex = self.stc.get(h,"-StreamIndex")
            print "StreamIndex:\t\t" +  StreamIndex   
            
            droppedFrameCount = self.stc.get(h,"-DroppedFrameCount")
            print "droppedFrameCount:\t\t" +  droppedFrameCount   
            
            droppedFramePercent = self.stc.get(h,"-DroppedFramePercent")
            print "droppedFramePercent:\t\t" +  droppedFramePercent   
            
            droppedFrameRate = self.stc.get(h,"-DroppedFrameRate")
            print "droppedFrameRate:\t\t" +  droppedFrameRate   
            
            fcsErrorFrameReceived = self.stc.get(h,"-FcsErrorFrameCount")
            print "fcsErrorFrameReceived:\t\t" +  fcsErrorFrameReceived                                                   
                                                            
            
            # Get the filtered Names and Values.  This is a nice way to display what unique elements
            # were tracked.
            '''
            szResults = ""
            
            for i in range(1,10):
                for element in aResults:
                    if element == "-FrameCount":
                        szResult = aResults[aResults.index(element) + 1]
            
            print "FrameCount %s" % szResults
           '''
            
        print " Retrieving Captured frames..."
    
        self.stc.perform( "CaptureStop", "-captureProxyId", hCapture)
    
        # Save captured frames to a file.
        self.stc.perform( "CaptureDataSave", "-captureProxyId",hCapture, "-FileName", "\"portB_capture.pcap\"", "-FileNameFormat", "PCAP",
                           "-IsScap", "FALSE")
        
        print "Captured frames:\t" + self.stc.get(hCapture, "-PktCount")
   
        
        self.totalFrameCount = 10000
        print "\tTotal:\t %d " % self.totalFrameCount        

       
        return self.totalFrameCount
    
     


