#!/usr/bin/env python
'''
Created on 14 Nov 2013

@author: kelsey
'''
#from IP_Tools.RawPacketIO import rawPacket
import select
import struct
import threading
from datetime import datetime
import time.sleep as sleep
import os
from IP_Tools import RawPacketIO


ARP_DUMMY= 0

ARP_TYPE = \
{\
    ARP_DUMMY: 'ARP dummy', # TODO: remove when I find the actual types
}

BUFSIZE = 2000
    
class ArpGen(RawPacketIO.socketGen):
    
    def __init__(self):
        super.__init__(protocol='arp')
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
    
    def simpleArpReq(self, dst):
        
        pkt = packet()
        pkt.createPacket({'type':ARP_DUMMY, 'payload':'abc', 'id':1, 'seq':1})
        recv_packet, timetaken = self.sendAndRecvResponse(pkt, dst)
        
        print "< ICMP test Time taken %d.%06d packet receieved %s >" % ( timetaken.seconds, timetaken.microseconds, recv_packet)
        
    def sendArpReq(self, dataStr, s, dst, _id, seq_start, seq_end, interPacketInterval = 0.001):
        pkt = packet()
        pkt.createPacket({'type':ARP_DUMMY, 'payload':'abc', 'id':_id, 'seq':seq_start})
        
        for i in range(seq_start, seq_end + 1):
            pkt.createPacket({'seq':i})
            self.send(s, pkt.raw)
            dataStr.addRecordData(i, 'start time', datetime.now())
            sleep(interPacketInterval)
        
        self.closeSocket(s)
        
        
    def ArpRecvr(self, threadID, s, dataStr):
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
        self.type_name = 'arp'
        self.type_lookup = ARP_TYPE
        
        self.packetInterpreter = \
            {\
             ARP_DUMMY:    self._intprt_arp_dummy,
             }
            
        self.packetCreator = \
            {\
             ARP_DUMMY:    self._create_arp_dummy,
             }
            
        self.type = ARP_DUMMY
        
        super.__init__()
        
        if packet != None:
            self.fromPacket(packet)
            
        
    def _intprt_arp_dummy(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
        
    def _create_arp_dummy(self): pass
               
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
    arp = ArpGen()
    sckt = arp.openSocket(sys.argv[1])
       
    #start icmp recv task
    thread1 = threading.Thread( target = arp.arpRecvr, args = ('thread1', sckt, ds) )
    thread1.start()
    
    # start sending the pings
    arp.sendPing(ds, sckt, sys.argv[1], 0, 0, 20)
    
    sleep(60)
    
    # stop the receiving thread
    arp.keepRunning['thread1'] = False
    #Wait for receiving thread to end
    thread1.join()
#    pydevd.settrace()
    
#     if len(sys.argv) < 2:
#         print >> sys.stderr, "No configuration file specified"
#         exit()
#     cfp = Tools.ConfFileParser(sys.argv[1])
#     cfp.readConfigFile()        