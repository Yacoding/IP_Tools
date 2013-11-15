'''
Created on 14 Nov 2013

@author: kelsey
'''
import sys
import ConfigParser

class ConfFileParser(object):
    '''
    classdocs
    '''

    def __init__(self, filename):
        '''
        Constructor
        '''
        self.filename = filename
        self.conf = []
        self.configFile = ConfigParser.RawConfigParser()
        
    def readConfigFile(self):
        try:
            self.configFile.read(self.filename) 
            for cfg in self.configFile.sections():
                row = self._readConfigFileSection(self.configFile, cfg)  
                self.conf.append(row)
            return self.conf
        except:
            print >> sys.stderr, "Problem reading config file - exiting!"
        return None
        
    def _readConfigFileSection( self, config, section ):
        """
        Reads the config file 1 section per run
        """
        dict1 = {}
        dict1['config'] = section
        options = config.options(section)
        for option in options:
            try:
                dict1[option] = config.get(section, option)
            except:
                print >> sys.stderr, ("Exception on %s!" % option)
                dict1[option] = None
        return dict1
    
    def getConfigs(self):
        return self.conf
    
    def getNextConf(self):
        for x in self.conf:
            yield x
    
    def getConfigNumber(self, conf_num):
        if conf_num < len(self.conf): 
            return self.conf[conf_num]
        else:
            return None    