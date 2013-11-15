'''
Created on 15 Nov 2013

@author: kelsey
'''
from threading import Lock

class dataStore(object):
    '''
    classdocs
    '''
    
    def __init__(self, name):
        '''
        Constructor
        '''
        self.name = name
        
        self.records = {}
        
        self.mutex = Lock()
        
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        self.mutex.acquite()
        string = "<dataStore %s>\n" % self.name
        for key in sorted(self.records.iterkeys()):
            string += ("\t<id %d - " % key)
            for val in self.records[key]:
                string += str(val) + ":" + str(self.records[key][val]) + " "
            string += ">\n"
        self.mutex.release()
        return string
    
    def addRecordData(self, key, field, value):
        self.mutex.acquite()
        if not (key in self.records):
            self.records[key] = {}
        self.records[key][field] = value
        self.mutex.release()
        
    def getRecordData(self, key):
        self.mutex.acquite()
        if key in self.records:
            result = self.records[key]
        else:
            result = None
        self.mutex.release()
        return result
        
    def deleteRecord(self, key):
        self.mutex.acquire()
        if key in self.records:
            del self.records[key]
        self.mutex.release()
            
            
if __name__ == "__main__":
    
    print "Testing dataStore class"
    print "=================================================="
    print "Creating dataStore object"
    
    ds = dataStore('icmp_send and receive')
    
    print "Adding 5 records"
    ds.addRecordData(1, 'start time', 5)
    ds.addRecordData(2, 'start time', 6)
    ds.addRecordData(3, 'start time', 7)
    ds.addRecordData(4, 'start time', 8)
    ds.addRecordData(5, 'start time', 9)
    print "done.\n"
    
    print "Current data store is:"
    print str(ds)
    print "done.\n"
    
    print "Adding a second field to 2 records"
    ds.addRecordData(2, 'end time', 26)
    ds.addRecordData(4, 'end time', 28)
    print "done.\n"

    print "Current data store is:"
    print str(ds)
    print "done.\n"
        
    print "Updating a field"
    ds.addRecordData(2, 'start time', 11)
    ds.addRecordData(3, 'start time', 12)
    print "done.\n"

    print "Current data store is:"
    print str(ds)
    print "done.\n"
    
    print "Getting specific records"
    print "record with key 3: " + str(ds.getRecordData(3))
    print "record with key 1: " + str(ds.getRecordData(1))

    print "Current data store is:"
    print str(ds)
    print "done.\n"
    
    print "Deleting records"
    ds.deleteRecord(2)
    ds.deleteRecord(4)
    print "done."
    print "Attempting to delete a record already deleted"
    ds.deleteRecord(2)
    print "done."

    print "Current data store is:"
    print str(ds)
    print "done.\n"
    