'''
Created on 13 Nov 2013

@author: kelsey
'''
import socket
import time

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
    

