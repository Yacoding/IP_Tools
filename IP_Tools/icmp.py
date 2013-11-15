#!/usr/bin/env python
'''
Created on 14 Nov 2013

@author: kelsey
'''
#from IP_Tools.RawPacketIO import rawPacket
import socket
import select
import struct
import threading
from datetime import datetime
import time.sleep as sleep
import os
from IP_Tools import RawPacketIO

ICMP_MINLEN = 8
ICMP_MASKLEN = 12

ICMP_ECHOREPLY = 0
ICMP_UNREACH = 3
ICMP_SOURCEQUENCH = 4
ICMP_REDIRECT = 5
ICMP_ECHO = 8
ICMP_TIMXCEED = 11
ICMP_PARAMPROB = 12
ICMP_TSTAMP = 13
ICMP_TSTAMPREPLY = 14
ICMP_IREQ = 15
ICMP_IREQREPLY = 16
ICMP_MASKREQ = 17
ICMP_MASKREPLY = 18

ICMP_TYPE = \
{\
    ICMP_ECHOREPLY : 'Echo Reply',
    ICMP_UNREACH : 'Unreachable',
    ICMP_SOURCEQUENCH : 'Source Quench',
    ICMP_REDIRECT : 'Redirect',
    ICMP_ECHO : 'Echo',
    ICMP_TIMXCEED : 'Time Exceeded',
    ICMP_PARAMPROB : 'Param Problem', 
    ICMP_TSTAMP : 'Timestamp',
    ICMP_TSTAMPREPLY : 'Timestamp reply',
    ICMP_IREQ : 'IReq',
    ICMP_IREQREPLY : 'IReq reply',
    ICMP_MASKREQ : 'Mask Req.',
    ICMP_MASKREPLY : 'Mask Reply',
}

ICMP_UNREACH_NET = 0
ICMP_UNREACH_HOST = 1
ICMP_UNREACH_PROTOCOL = 2
ICMP_UNREACH_PORT = 3
ICMP_UNREACH_NEEDFRAG = 4
ICMP_UNREACH_SRCFAIL = 5

ICMP_REDIRECT_NET = 0
ICMP_REDIRECT_HOST = 1
ICMP_REDIRECT_TOSNET = 2
ICMP_REDIRECT_TOSHOST = 3
    
ICMP_TIMXCEED_INTRANS = 0
ICMP_TIMXCEED_REASS = 1

BUFSIZE = 2000
    
class IcmpGen(object):
    
    def __init__(self):
        self.keepRunning = {}
        
        self.socketMutex = threading.Lock()
    
    def openSocket(self, dest):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        s.connect((socket.gethostbyname(dest),22)) # port shouldn't really matter we're sending icmp proto
        ## setuid back to normal user
        os.setuid(os.getuid())
        return s
    
    def closeSocket(self, s):
        self.socketMutex.acquire()
        s.close()
        self.socketMutex.release()
        return
    
    def send(self, s, pkt):
        self.socketMutex.acquire()
        s.send(pkt)
        self.socketMutex.release()
        return 
    
    def recv(self, s):
        self.socketMutex.acquire()
        s.recv(BUFSIZE)
        self.socketMutex.release()
        return
    
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
    
    def simplePing(self, dst):
        
        pkt = packet()
        pkt.createPacket({'type':ICMP_ECHO, 'payload':'abc', 'id':1, 'seq':1})
        recv_packet, timetaken = self.sendAndRecvResponse(pkt, dst)
        
        print "< ICMP test Time taken %d.%06d packet receieved %s >" % ( timetaken.seconds, timetaken.microseconds, recv_packet)
        
    def sendPing(self, dataStr, s, dst, _id, seq_start, seq_end, interPacketInterval = 0.001):
        pkt = packet()
        pkt.createPacket({'type':ICMP_ECHO, 'payload':'abc', 'id':_id, 'seq':seq_start})
        
        for i in range(seq_start, seq_end + 1):
            pkt.createPacket({'seq':i})
            self.send(s, pkt.raw)
            dataStr.addRecordData(i, 'start time', datetime.now())
            sleep(interPacketInterval)
        
        self.closeSocket(s)
        
        
    def icmpRecvr(self, threadID, s, dataStr):
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
    classdocs
    '''

    def __init__(self, packet = None):
        '''
        Constructor
        '''
        self.packetInterpreter = \
            {\
             ICMP_ECHOREPLY:    self._intprt_echoreply,
             ICMP_UNREACH:      self._intprt_unreach,
             ICMP_SOURCEQUENCH: self._intprt_sourcequench,
             ICMP_REDIRECT:     self._intprt_redirect,
             ICMP_ECHO:         self._intprt_echo,
             ICMP_TIMXCEED:     self._intprt_timxceed,
             ICMP_PARAMPROB:    self._intprt_paramprob,
             ICMP_TSTAMP:       self._intprt_tstamp,
             ICMP_TSTAMPREPLY:  self._intprt_tstampreply,
             ICMP_IREQ:         self._intprt_ireq,
             ICMP_IREQREPLY:    self._intprt_ireqreply,
             ICMP_MASKREQ:      self._intprt_maskreq,
             ICMP_MASKREPLY:    self._intprt_maskreply,
             }
            
        self.packetCreator = \
            {\
             ICMP_ECHOREPLY:    self._create_echoreply,
             ICMP_UNREACH:      self._create_unreach,
             ICMP_SOURCEQUENCH: self._create_sourcequench,
             ICMP_REDIRECT:     self._create_redirect,
             ICMP_ECHO:         self._create_echo,
             ICMP_TIMXCEED:     self._create_timxceed,
             ICMP_PARAMPROB:    self._create_paramprob,
             ICMP_TSTAMP:       self._create_tstamp,
             ICMP_TSTAMPREPLY:  self._create_tstampreply,
             ICMP_IREQ:         self._create_ireq,
             ICMP_IREQREPLY:    self._create_ireqreply,
             ICMP_MASKREQ:      self._create_maskreq,
             ICMP_MASKREPLY:    self._create_maskreply,
             }
            
        self.type = ICMP_ECHO
        self.code = 0
        self.payloadparams = '' # used to construct a raw payload
        self.payloadraw = '' # raw format that can be sent
        self.payloadrepr = '' # format that can be printed
        self.id = 0
        self.seq = 0
        self.raw = ''
        
        if packet != None:
            self.fromPacket(packet)
            
        
    def _intprt_echoreply(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
        
    def _intprt_unreach(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_sourcequench(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_redirect(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_echo(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_timxceed(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_paramprob(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_tstamp(self):
        self.payloadrepr = "Payload: original timestamp %d" \
            % (struct.unpack('i', self.payloadraw[:4]))
    
    def _intprt_tstampreply(self):
        self.payloadrepr = "Payload: original timestamp %d, receive timestamp %d, transmit timestamp %d" \
            % (struct.unpack('i' * 3, self.payloadraw[:12]))
    
    def _intprt_ireq(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_ireqreply(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_maskreq(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
    
    def _intprt_maskreply(self):
        pack_format = "%ss" % len(self.payloadraw)
        self.payloadrepr = "Payload: raw - %s" % (struct.unpack(pack_format, self.payloadraw))
               
        
    def _create_echoreply(self): pass
        
    def _create_unreach(self): pass
    
    def _create_sourcequench(self): pass
    
    def _create_redirect(self): pass
    
    def _create_echo(self): pass
    
    def _create_timxceed(self): pass
    
    def _create_paramprob(self): pass
    
    def _create_tstamp(self): pass
    
    def _create_tstampreply(self): pass
    
    def _create_ireq(self): pass
    
    def _create_ireqreply(self): pass
    
    def _create_maskreq(self): pass
    
    def _create_maskreply(self): pass
               
    def __repr__(self):
        return "<ICMP packet %s %d %d %d %s>" % (ICMP_TYPE[self.type], self.code, self.id, self.seq, self.payloadrepr)
    
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
        create a packet
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
#pydevd.patch_django_autoreload(patch_remote_debugger=True, patch_show_console=True)
if __name__ == "__main__":
 
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