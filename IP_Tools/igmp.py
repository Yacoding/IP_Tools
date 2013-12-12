'''
Created on 12 Dec 2013

@author: kelsey
'''
import socket
import select
import struct
import threading
from datetime import datetime
import time.sleep as sleep
import os
from IP_Tools import RawPacketIO

BUFSIZE = 2000
    
class IcmpGen(RawPacketIO.socketGen):
    
    def __init__(self):
        super.__init__(protocol='igmp')
        self.keepRunning = {}
        
        self.socketMutex = threading.Lock()
        
    def sendAndRecvResponse(self, pkt, dest, timeout = 60):

        s = self.openSocket(dest)
           
        self.socketMutex.acquire()
        startTime = datetime.now()
        self.send(s, pkt.raw)
        buf = self.recv(s)
        endTime = datetime.now()
        self.socketMutex.release()
        
        self.closeSocket(s)
        return packet(buf[20:]), (endTime - startTime)
    
    def sendGroupQuery(self, dst):
        
        pkt = packet()
# TODO: finish
        pkt.createPacket({'type':IGMP_GRPMEMQRY, 'payload':'abc', 'id':1, 'seq':1})
        recv_packet, timetaken = self.sendAndRecvResponse(pkt, dst)
        
        print "< ICMP test Time taken %d.%06d packet receieved %s >" % ( timetaken.seconds, timetaken.microseconds, recv_packet)
        
    def simpleGroupQuery(self, dataStr, s, dst, _id, seq_start, seq_end, interPacketInterval = 0.001):
        pkt = packet()
# TODO: finish
        pkt.createPacket({'type':IGMP_GRPMEMQRY, 'payload':'abc', 'id':_id, 'seq':seq_start})
        
        for i in range(seq_start, seq_end + 1):
            pkt.createPacket({'seq':i})
            self.send(s, pkt.raw)
            dataStr.addRecordData(i, 'start time', datetime.now())
            sleep(interPacketInterval)
        
        self.closeSocket(s)
        
        
    def igmpRecvr(self, threadID, s, dataStr):
        '''
        This should be run in a seperate thread to catch all incoming ICMP packets
        The controlling thread should set object.keepRunning[threadID] to False
        to terminate the thread
        '''
        self.keepRunning[threadID] = True
        timeout = 3
        
        rdlist = [s]
        while self.keepRunning[threadID]:
            rd = select.select(rdlist, None, None, timeout)
            if rd:
                try:
                    buf = self.recv(s)
                    pkt = packet(buf[20:])
                    dataStr.addRecordData(pkt.seq, 'end time', datetime.now())
                except ValueError:
                    continue
        
IGMP_GRPMEMQRY = 0x11 # "Group Membership Query",
IGMP_V1_MEMREP = 0x12 # "Version 1 - Membership Report",
IGMP_V2_MEMREP = 0x16 # "Version 2 - Membership Report",
IGMP_LEAVEGRP  = 0x17 # "Leave Group"}

IGMP_TYPE = \
{\
    IGMP_GRPMEMQRY : 'Group Membership Query',
    IGMP_V1_MEMREP : 'Version 1 - Membership Report',
    IGMP_V2_MEMREP : 'Version 2 - Membership Report',
    IGMP_LEAVEGRP  : 'Leave Group',
}
        
class packet(object):
    '''
    A class to contruct and interpret a buffer as an ICMP packet
    '''

    def __init__(self, packet = None):
        '''
        Constructor.
        If called with a parameter it will attempt to interpret that
        parameter as a buffer containing an ICMP packet.
        Sets up the function pointers to the different handlers.
        '''
        self.packetInterpreter = \
            {\
             IGMP_GRPMEMQRY: self._intprt_group_member_query,
             IGMP_V1_MEMREP: self._intprt_v1_member_report,
             IGMP_V2_MEMREP: self._intprt_v2_member_report,
             IGMP_LEAVEGRP:  self._intprt_leave_group,
             }
            
        self.packetCreator = \
            {\
             IGMP_GRPMEMQRY: self._create_group_member_query,
             IGMP_V1_MEMREP: self._create_v1_member_report,
             IGMP_V2_MEMREP: self._create_v2_member_report,
             IGMP_LEAVEGRP:  self._create_leave_group,
             }
            
        self.type = IGMP_GRPMEMQRY
        self.code = 0
        self.payloadparams = '' # used to construct a raw payload
        self.payloadraw = '' # raw format that can be sent
        self.payloadrepr = '' # format that can be printed
        self.id = 0
        self.seq = 0
        self.raw = ''
        
        if packet != None:
            self.fromPacket(packet)
            
        
    def _intprt_group_member_query(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
        
    def _intprt_v1_member_report(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_v2_member_report(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_leave_group(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
        
    def _create_group_member_query(self): pass
        
    def _create_v1_member_report(self): pass
    
    def _create_v2_member_report(self): pass
    
    def _create_leave_group(self): pass
  
               
    def __repr__(self):
        return "<ICMP packet %s %d %d %d %s>" % (IGMP_TYPE[self.type], self.code, self.id, self.seq, self.payloadrepr)
    
    def fromPacket(self, packet):
        '''
        Convert a buffer to a packet
        '''
        pack_format = '!BBHHH'
        payload_len = len(packet) - 8
        
        if payload_len > 0:
            pack_format += "%ss" % payload_len
        
        self.type, self.code, checksum, self.id, self.seq, self.payloadraw = struct.unpack(pack_format, packet)
        
        if self.type in self.packetInterpreter:
            self.packetInterpreter[self.type]()
        else:
            raise ValueError("Packet was not an ICMP packet")
        
        
    def createPacket(self, params = {}):
        '''
        Create a packet and convert it to the internal raw format.
        '''
        self.raw = None
        if 'type' in params:
            self.type = params['type']
        if 'code' in params:
            self.code = params['code']
        if 'id' in params:
            self.id = params['id']
        if 'seq' in params:
            self.seq = params['seq']
        if 'payload' in params:
            self.payloadparams = params['payload']
        
        self.packetCreator[self.type]()    

        return self.toRaw(True)
        
        
    def toRaw(self, forceRebuild = False):
        '''
        create a raw packet from this to send with RawPacketIO
        '''
        if (self.raw == None) or (forceRebuild == True):
            self.payloadraw = self.payloadparams
            id_seq = struct.pack('!HH', self.id, self.seq)
            buf = chr(self.type) + chr(self.code) + '\000\000' + id_seq + self.payloadraw
            
            # calculate checksum
            checksum = RawPacketIO.checksum(buf)
            csum = struct.pack('H', checksum)
            self.raw = buf[0:2] + csum + buf[4:]
            
        return self.raw
    
import sys
from Tools.PacketDataCollector import dataStore 
#import pydevd
if __name__ == "__main__":
    '''
    Test cases and examples of how to use the classes in this file
    '''
    
    if os.geteuid() != 0:
        print "This must be run as root"
        exit()
        
#    icmp.simplePing(sys.argv[1])
#    print >> sys.stderr, "No test cases defined yet"
#    import Tools.ConfFileParser

    ds = dataStore("ICMP test results")
    icmp = IcmpGen()
    sckt = icmp.openSocket(sys.argv[1])
       
    #start icmp recv task
    thread1 = threading.Thread( target = icmp.icmpRecvr, args = ('thread1', sckt, ds) )
    thread1.start()
    
    # start sending the pings
    icmp.sendPing(ds, sckt, sys.argv[1], 0, 0, 20)
    
    sleep(60)
    
    # stop the receiving thread
    icmp.keepRunning['thread1'] = False
    #Wait for receiving thread to end
    thread1.join()
#    pydevd.settrace()
    
#     if len(sys.argv) < 2:
#         print >> sys.stderr, "No configuration file specified"
#         exit()
#     cfp = Tools.ConfFileParser(sys.argv[1])
#     cfp.readConfigFile()        