import sys
import os


class recoveringFile:
    def __init__(self, fileName):
        self.rf = open(fileName, "wb")
    
    def writeToFile(self, strToW):
        self.rf.write(bytes([int(strToW, 16)]))
    
    def closeFile(self):
        self.rf.close()


