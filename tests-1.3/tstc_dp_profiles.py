# coding:utf-8  
  
import rpyc  
import sys  
import time


    
class DpProfile():        

    def __init__(self,dataplane = None):
        self.dataplane = dataplane
        
        if dataplane :
            self.stc = dataplane.stc
 
    def config(self,txPort,rxPort):
        chassisAddress = self.dataplane.chassisIp
    
        slotPort1 = txPort
    
        slotPort2 = rxPort
     

        ProjectA  = self.stc.create("project")
        print  ProjectA   
    

        TxPort = self.stc.create( "port","-under" , ProjectA)

        RxPort = self.stc.create( "port","-under" , ProjectA)

        portReturn = self.stc.config( TxPort, " -location " , "//" + chassisAddress + '/' + slotPort1)

        portReturn = self.stc.config( RxPort , " -location " , "//" + chassisAddress + '/' + slotPort2)

        
    
        

        EthernetCopper = [" "," "]
        EthernetCopper[0] = self.stc.create( "EthernetCopper" ,"-under",TxPort, "-Name" ,"ethernetCopper_1")
    
        EthernetCopper[1] = self.stc.create( "EthernetCopper" ,"-under",RxPort, "-Name" ,"ethernetCopper_2")   
        
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
                                    
        lstStreamBlockInfo = self.stc.perform( "StreamBlockGetInfo", "-StreamBlock", StreamBlock[0])  


    
                                             
        #�ڷ��Ͷ˿ڴ��� generator
    
        generator1 = self.stc.get( TxPort, "-children-Generator") 
    
        self.stc.config(generator1, "-Name", "Generator_1")
    
        #���� generator1 ,
    
        generatorConfig1 = self.stc.get(generator1, "-children-GeneratorConfig")

        #-------------------------------����˵��--------------------------------------------
        #SchedulingModes���ԣ���ѡ������PORT_BASED ��RATE_BASED ��PRIORITY_BASED ��MANUAL_BASED
        #DurationMode���ԣ���ѡ������CONTINUOUS ��BURSTS ��SECONDS �ȣ�
        #LoadUnit���ԣ���ѡ������PERCENT_LINE_RATE ��FRAMES_PER_SECOND ��BITS_PER_SECOND ��
        #                  KILOBITS_PER_SECOND ��MEGABITS_PER_SECOND ��INTER_BURST_GAP
        #---------------------------------------------------------------------------------
    
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
                          
                          
    
        #�ڽ��ն˿ڴ���analyzer   
        analyzer1 = self.stc.get( RxPort, "-children-Analyzer")

        #����analyzer
    
        self.stc.config( analyzer1, "-Name", "Analyzer_1")
    
        analyzerConfig1 = self.stc.get( analyzer1 , "-children-AnalyzerConfig")

    
        #-------------------------------����˵��--------------------------------------------
        #TimestampLatchMode ���� ����ѡ������START_OF_FRAME ��END_OF_FRAME
        #
        #---------------------------------------------------------------------------------
    
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
                           "AnalyzerConfig_1")
    
        #����ʵʱ�����ȡ
        #��������� ��ű���ͬ·���£�����ļ���Ϊ result
    
        generatorResult = self.stc.subscribe( "-Parent" ,
                                               ProjectA ,
                                               "-ResultParent" ,
                                               TxPort ,
                                               "-ConfigType",
                                               "Generator",
                                               "-resulttype",
                                               "GeneratorPortResults",
                                               "-filenameprefix",
                                               "result")
    
        analyzerResult = self.stc.subscribe( "-Parent",
                                              ProjectA,
                                              "-ResultParent",
                                              RxPort ,
                                              "-ConfigType",
                                              "Analyzer" ,
                                              "-resulttype",
                                              "AnalyzerPortResults",
                                              "-filenameprefix",
                                              "result" )
    
        #���ӻ���
    
        resultReturn = self.stc.connect(chassisAddress)
    
        #ռ�ö˿�
    
        resultReturn = self.stc.reserve( "//" + chassisAddress + "/" + slotPort1)
    
        resultReturn = self.stc.reserve( "//" + chassisAddress + "/" + slotPort2)
    
        #����ץ���˿�
    
        captureRx = self.stc.get(RxPort, "-children-capture")

        captureTx = self.stc.get(TxPort, "-children-capture")

    
        
        
    
        #-----------------------------------����˵��-------------------------------------
        #
        #mode ���ԣ���ѡ������REGULAR_MODE��ץ���б��ģ� SIG_MODE��ץ��signature�ı��ġ�
        #Buffermode ���ԣ� ��ѡ������WRAP ��������д��ʱ���ع�������ץ����   STOP_ON_FULL ����������д��ʱ��ֹͣ
        #srcMode ���ԣ���ѡ������ TX_MODE �� RX_MODE �� TX_RX_MODE
        #
        #-----------------------------------------------------------------------------
    
        self.stc.config(captureRx, "-mode" ,"REGULAR_MODE", "-BufferMode", "WRAP" ,"-srcMode" ,"RX_MODE" )
        self.stc.config(captureTx, "-mode" ,"REGULAR_MODE", "-BufferMode", "WRAP" ,"-srcMode" ,"TX_RX_MODE" )
        #self.stc.perform StreamBlockUpdate -streamBlock "$StreamBlock(1)"
    
        #self.stc.perform StreamBlockUpdate -streamBlock "$StreamBlock(2)"
    
        #�����߼��˿�������˿ڵ�ӳ��
    
        resultReturn = self.stc.perform( "setupPortMappings")
    
        #ִ��apply
        print "apply"
        resultReturn = self.stc.apply()

        #-------------------------------------------------------------------------------
        #                                     �������
        #-------------------------------------------------------------------------------
    
        #��ʼanalyzer

        analyzerCurrent = self.stc.get(RxPort ,"-children-analyzer")
    
        self.stc.perform ("analyzerStart" ,"-analyzerList" ,analyzerCurrent)
    
        #����ץ��

        self.stc.perform( "CaptureStart", "-captureProxyId" ,captureRx)
        self.stc.perform( "CaptureStart", "-captureProxyId" ,captureTx)
        #��ʼ����

        generatorCurrent = self.stc.get(TxPort, "-children-generator")
    
        self.stc.perform("generatorStart", "-generatorList", generatorCurrent)
    
        #�ȴ�ִ�н���

        self.stc.sleep( "20")
    
        # ֹͣ����
    
        self.stc.perform( "generatorStop", "-generatorList" ,generatorCurrent)
    
        #ֹͣץ��
        self.stc.perform( "CaptureStop" ,"-captureProxyId" ,captureRx)
        self.stc.perform( "CaptureStop" ,"-captureProxyId" ,captureTx)
    
        #����ץ�����
        print "Save Capture Data"
        self.stc.perform( "CaptureDataSave", "-captureProxyId", captureRx ,"-FileName" ,"test_stc_rx.pcap" ,"-FileNameFormat" ,"PCAP")
        self.stc.perform( "CaptureDataSave", "-captureProxyId", captureTx ,"-FileName" ,"test_stc_tx.pcap" ,"-FileNameFormat" ,"PCAP")
    
        #ֹͣanalyzer
    
        self.stc.perform( "analyzerStop","-analyzerList" ,analyzerCurrent)
    
        
    # This is the same handle as above.
    #
        hAnalyzerPortResults = self.stc.get( analyzerCurrent, "-children-AnalyzerPortResults")
    
        
        print "\n\nAnalyzer Port Results"
             
        print "\tJumbo:\t %s " % self.stc.get(hAnalyzerPortResults ,"-JumboFrameCount")
        print "\tSig:\t %s " % self.stc.get(hAnalyzerPortResults ,"-sigFrameCount")
        print "\tUnder:\t %s " % self.stc.get(hAnalyzerPortResults ,"-UndersizeFrameCount")
        print "\tOver:\t %s " % self.stc.get(hAnalyzerPortResults ,"-oversizeFrameCount")
        print "\tMaxLen:\t %s " % self.stc.get(hAnalyzerPortResults ,"-MaxFrameLength")
        
        self.totalFrameCount = int(self.stc.get(hAnalyzerPortResults ,"-totalFrameCount"))
        print "\tTotal:\t %d " % self.totalFrameCount
     
        
        #�ͷŶ˿�
    
        self.stc.release( self.stc.get(TxPort, "-location"))
    
        self.stc.release( self.stc.get(RxPort, "-location"))
    
        #�����Ͽ�����
    
        self.stc.disconnect( chassisAddress)
    
        #ɾ�� project
        print "delete project"
        self.stc.delete( ProjectA)
    
        self.stc.perform( "ResetConfig" ,"-config", "system1")
        
        return self.totalFrameCount
