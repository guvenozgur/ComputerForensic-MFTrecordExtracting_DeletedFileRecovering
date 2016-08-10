import os
import sys
import MftReader

class getData:

    def __init__(self):
        self.fileBlock = []
        self.reader = MftReader.sectorReader()
   
    def obtainData(self, location, size):
        
        
        print("loc2:", location)
        self.fileBlock = self.fileBlock + self.reader.desiredRead(location, size*512)

        print("len:", len(self.fileBlock))
        print(self.fileBlock[0])
        return self.fileBlock
