'''
Created on 13 Nov 2013

@author: kelsey
'''
import socket
import time
import threading
import os

class socketGen(object):
    '''
    Base class for socket generators
    '''    
    BUFSIZE = 2000
    def __init__(self, protocol='', bufSize = socketGen.BUFSIZE, port=22):
        self.keepRunning = {}
        
        self.socketMutex = threading.Lock()
        self.protocol = protocol
        self.bufSize = bufSize
        self.port = port
    
    def openSocket(self, dest, protocol):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname(self.protocol))
        s.connect((socket.gethostbyname(dest), self.port)) # port shouldn't really matter we're sending icmp proto
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
        s.recv(self.bufSize)
        self.socketMutex.release()
        return       


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    s = 0
    if (len(msg) % 2) != 0:
        msg = msg + '\000'
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return (~s & 0xffff)

class raw_IP_IO(object):
    
    def __init__(self):
        pass
    

class rawPacket(object):
    '''
    classdocs
    
    TODO: this may have problems take a look here for writing raw packets
    http://mbrownnyc.wordpress.com/2010/02/09/networking-python-script-to-repeatedly-query-the-all-hosts-igmp-group-for-igmp-snooping/
    '''

    def __init__(self, params):
        '''
        Constructor
        '''
        if 'outputInterface' in params:
            self.outputInterface = params['outputInterface']
        else:
            self.outputInterface = 'eth0'
            
        if 'payload' in params:
            self.payload = params['payload']
        else:
            self.payload = ''
            
        self.returnValue = ''
        self.starttime = 0
        self.endtime = 0
        
    def __repr__(self):
        return "<rawPacket op_i/f %s %s>" % (self.outputInterface, self.payload)
        
    def send(self):
        '''
        Send the packet
        '''
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x8100)
        self.socket.bind((self.outputInterface, 0x8100))
        
        self.starttime = time.time()
        self.returnValue = self.socket.send(self.payload)
        
    def recv(self):
        '''
        Get the response
        '''
        self.returnValue = self.socket.recv()
        self.endtime = time.time()
        return self.returnValue, self.getTimeTaken()
        
    def getReturnValue(self):
        '''
        retrieve the return packet based upon send
        '''
        return self.returnValue
        
    def getTimeTaken(self):
        '''
        get the time take for the send and response
        '''
        return self.endtime - self.starttime
    
    def setPacketData(self, packet):
        '''
        set the full packet data to send caller is responsible for content correctness
        '''
        self.payload = packet
        
    def setPacketDataFromHex(self, hexData):
        '''
        Set the payload from data in the format 34 45 56 67 78 89 a3 a4 ...
        '''
        self.payload = ''
        for i in hexData.split(' '):
            self.payload += chr(int(i, 16))
    
    def setOutputConfig(self, outputInterface):
        '''
        set the configuration for sending the packet
        '''
        self.outputInterface = outputInterface

        
if __name__ == "__main__":
 
    import sys
    print >> sys.stderr, "No test cases defined yet"
#    import Tools.ConfFileParser

    
#     if len(sys.argv) < 2:
#         print >> sys.stderr, "No configuration file specified"
#         exit()
#     cfp = Tools.ConfFileParser(sys.argv[1])
#     cfp.readConfigFile()
    

