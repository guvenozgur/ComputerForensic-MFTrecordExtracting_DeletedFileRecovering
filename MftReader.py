import sys
import os

class sectorReader:
    def __init__(self):
        self.source = os.open("/dev/sdi", os.O_RDONLY)
        self.sectorSize = 1024
    
    def openSource(self, secNum):
        os.lseek(self.source, int(secNum), 0)
        self.sectorDataByte = os.read(self.source, self.sectorSize)
        self.sectorData = []
        self.read()
        self.closeResource()
        return self.sectorData

    
    def read(self):
        for i in range(0, 1024):
                if( len((hex(self.sectorDataByte[i])).split('x')[1]) == 1):
                    self.sectorData.append('0'+(hex(self.sectorDataByte[i])).split('x')[1] ) 
                else:
                    self.sectorData.append((hex(self.sectorDataByte[i])).split('x')[1])
        if __name__ == '__main__':
            for i in range(0, 1024):
                if(len(str(self.sectorData[i])) == 1):
                    print(self.sectorData[i], sep = " ", end = "    ")
                else:
                    print(self.sectorData[i], sep = " ", end = "   ")

                if((i+1)%8 == 0 and i != 0):
                    print("")
    

    
    def desiredRead(self, secNum, desiredSize):
        os.lseek(self.source, int(secNum), 0)
        self.sectorDataByte = os.read(self.source, desiredSize)
        self.sectorData = []
        self.read2(desiredSize)
        self.closeResource()
        return self.sectorData

    def read2(self, desiredSize):
        for i in range(0, desiredSize):
                if( len((hex(self.sectorDataByte[i])).split('x')[1]) == 1):
                    self.sectorData.append('0'+(hex(self.sectorDataByte[i])).split('x')[1] ) 
                else:
                    self.sectorData.append((hex(self.sectorDataByte[i])).split('x')[1])
        if __name__ == '__main__':
            for i in range(0, 1024):
                if(len(str(self.sectorData[i])) == 1):
                    print(self.sectorData[i], sep = " ", end = "    ")
                else:
                    print(self.sectorData[i], sep = " ", end = "   ")

                if((i+1)%8 == 0 and i != 0):
                    print("")

    def closeResource(self):
        os.close(self.source)
