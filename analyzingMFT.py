import sys
import os
import MftReader
import recovering
import getDeletedData

class MFTanalyzer:
    def __init__(self):
        self.readingBlock = MftReader.sectorReader() 
        self.NtfsBootRecord = []
        self.metadataOfBootRecord = []
        self.metadataCollected = []
        self.MFTdata = []
        self.offset = 0
        self.fileNameforRecover = ""
        self.blockAdd = 0
        

    # BSadd: NTFS Boot Sector Address
    def NTFSbootSector(self, BSadd):

        # 1 block is 512 bytes in decimal.
        # BSadd is in hexadecimal, firstly we convert it to decimal.
        # To find location of NTFS master boot record we calculate 512*BSadd.
        self.blockAdd = int(str(BSadd), 16) * 512
        print("block address::", self.blockAdd)
        self.NtfsBootRecord = self.readingBlock.openSource(self.blockAdd)
        # 1st element of metadataOfBootRecord is OEM id. Its length is 8 bytes. 
        self.metadataOfBootRecord.append((self.NtfsBootRecord[3]) +
                                         (self.NtfsBootRecord[4]) +
                                         (self.NtfsBootRecord[5]) +
                                         (self.NtfsBootRecord[6]) +
                                         (self.NtfsBootRecord[7]) +
                                         (self.NtfsBootRecord[8]) +
                                         (self.NtfsBootRecord[9]) +
                                         (self.NtfsBootRecord[10])
        )
        
        # 2nd element of metadataOfBootRecord indicates number of bytes per sector.
        # It is hold in little endian format in boot record. We convert it before append array. 
        # Its length is 2 bytes.
        self.metadataOfBootRecord.append(str(int((self.NtfsBootRecord[12])+ (self.NtfsBootRecord[11]), 16)))
        print("Number of bytes per sector:", self.metadataOfBootRecord[1])
        # 3th element of metadataOfBootRecord indicates number of sectors per cluster.
        self.metadataOfBootRecord.append(str(int(self.NtfsBootRecord[13], 16)))
        print("Number of sectors per cluster:", self.metadataOfBootRecord[2])
        # 4th element of metadataOfBootRecord indicates media descriptor. e.g. F8: harddisk, F0: high density floppy.
        self.metadataOfBootRecord.append(self.NtfsBootRecord[21])
        
        # 5th element of metadataOfBootRecord indicates total sectors.
        self.metadataOfBootRecord.append( int( self.NtfsBootRecord[47] +
                                               self.NtfsBootRecord[46] +
                                               self.NtfsBootRecord[45] +
                                               self.NtfsBootRecord[44] +
                                               self.NtfsBootRecord[43] +
                                               self.NtfsBootRecord[42] +
                                               self.NtfsBootRecord[41] +
                                               self.NtfsBootRecord[40] ,16))
        
       

        # 6th element of metadataOfBootRecord indicates the starting byte location of MFT
        # To find this value, we first get the lcn(logical cluster number) of MFT 
        # Then, using value found, we find starting sector number of MFT
        # Lastly we found location of the 1st byte of MFT
        MFTlcn =int(( self.NtfsBootRecord[55] +
                     self.NtfsBootRecord[54] + 
                     self.NtfsBootRecord[53] +
                     self.NtfsBootRecord[52] +
                     self.NtfsBootRecord[51] +
                     self.NtfsBootRecord[50] +
                     self.NtfsBootRecord[49] +
                     self.NtfsBootRecord[48]), 16)
        
        print("MFTlcn:", MFTlcn)
        MFTsec = MFTlcn*int(self.metadataOfBootRecord[2])
        print("MFTsec:", MFTsec)
        # MFTlogicalAdd is logical starting address of the MFT.
        # Logical address gives us location according to atrting address of partition
        MFTlogicalAdd = MFTsec*int(self.metadataOfBootRecord[1])
        print("MFTbyte:", MFTlogicalAdd)
        # We need to find physical address of the MFTanalyzer
        # To do that, we add starting address of partition to logical address
        MFTphsyAdd = MFTlogicalAdd + self.blockAdd
        self.metadataOfBootRecord.append(MFTphsyAdd)
        print("MFT physical:", self.metadataOfBootRecord[5]) 

        # We done in this method. Next step is to analyze MFT attributes.
        self.MFTattributes(int(self.metadataOfBootRecord[5]))
        for i in self.metadataCollected:
            print(i)
            print("\n*************************************************\n")

    def MFTattributes(self, MFTaddr):
        freeBlock = 0
        location = 0
        while(freeBlock < 50 ):
            # Obtaining desired MFT record:
            self.MFTrecord = MftReader.sectorReader()
            self.MFTdata = self.MFTrecord.openSource(MFTaddr + location*1024)
            
            #print("".join(self.MFTdata[0:4]))
            
            if ("".join(self.MFTdata[0:4]) != "46494c45"):
                freeBlock = freeBlock + 1
            
            # I use multi-dimensional array to hold metadata for each MFT entry
            if("".join(self.MFTdata[0:4]) == "46494c45"):
                # An array is used to store metadata of each MFT. 
                # At the end of the analysis, this array is appended to medataCollected array.
                metadataTemp = []
                

                # 1st element of the metadataTemp is 'Sequence Number' which shows the number of time that MFT record has been reused.
                metadataTemp.append(self.MFTdata[17] + self.MFTdata[16]) 
                


                # 2nd element of the metadataTemp is 'Hard Link Count'.
                metadataTemp.append(self.MFTdata[19]+self.MFTdata[18])
                

                # 3th element of the metadataTemp is the offset to first attribute.
                metadataTemp.append(self.MFTdata[21]+self.MFTdata[20])
                

                # 4th element of the metadataTemp is the flag
                metadataTemp.append(self.MFTdata[23] + self.MFTdata[22])
                

                # 5th element of the metadataTemp shows the used size of MFT entry
                metadataTemp.append(self.MFTdata[27] + self.MFTdata[26] + self.MFTdata [25] + self.MFTdata[24])
               

                # We hold the location of the next attribute in offset variable. 
                self.offset = int(metadataTemp[2], 16)
                temp = 0
                while("".join(self.MFTdata[self.offset]) != "ff" and temp!=self.offset):
                    # 6th element of metadataTemp is an array which includes metadata for each MFT record
                    temp = self.offset
                    # Unknown attribute
                    if(self.MFTdata[self.offset] == "00" ):
                        metadataTemp.append(self.unknownA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Standard_Information attribute
                    elif(self.MFTdata[self.offset] == "10" ):
                        metadataTemp.append(self.standardInfoA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Attribute_List attribute
                    elif(self.MFTdata[self.offset] == "20" ):
                        metadataTemp.append(self.attListA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # File_Name attribute
                    elif(self.MFTdata[self.offset] == "30"):
                        metadataTemp.append(self.fileNameA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Object_ID attribute
                    elif(self.MFTdata[self.offset] == "40"):
                        metadataTemp.append(self.objectIdA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])    
                    # Security_Descriptor attribute
                    elif(self.MFTdata[self.offset] == "50"):
                        metadataTemp.append(self.securityDescriptorA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Volume Name attribute
                    elif(self.MFTdata[self.offset] == "60"):
                        metadataTemp.append(self.volNameA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Volume Information attribute 
                    elif(self.MFTdata[self.offset] == "70"):
                        metadataTemp.append(self.volInfoA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Data attribute
                    elif(self.MFTdata[self.offset] == "80"):
                        metadataTemp.append(self.dataA(metadataTemp[3]))
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Index Root attribute
                    elif(self.MFTdata[self.offset] == "90"):
                        metadataTemp.append(self.indexRootA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Index Allocation attribute
                    elif(self.MFTdata[self.offset] == "a0"):
                        metadataTemp.append(self.indexRootA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    # Bitmap attribute
                    elif(self.MFTdata[self.offset] == "b0"):
                        metadataTemp.append(self.bitMapA())
                        print("offset:", self.offset)
                        if(self.offset > 1024):
                            break
                        print("data:", self.MFTdata[self.offset])
                    
                    
                self.metadataCollected.append(metadataTemp)
            location = location + 1

    # 10
    def standardInfoA(self):
        standardInfo = []

        ## -- Standard Information Header Begin
        # 1st element is attribute type:
        standardInfo.append(self.MFTdata[self.offset+3] + 
                            self.MFTdata[self.offset+2] + 
                            self.MFTdata[self.offset+1] + 
                            self.MFTdata[self.offset] 
        )

        # 2nd element is length including header
        standardInfo.append(int( self.MFTdata[self.offset+4],16))
        
        # 3th element is non-resident flag
        standardInfo.append(self.MFTdata[self.offset+8])

        # 4th element is attribute flags
        standardInfo.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])

        # 5th element is length of the attribute
        standardInfo.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))

        ## -- Standard Information Header End

        attributeOffset = 24 + self.offset

        # 6th element is file creation time 
        standardInfo.append(self.MFTdata[attributeOffset + 7] +
                            self.MFTdata[attributeOffset + 6] +
                            self.MFTdata[attributeOffset + 5] +
                            self.MFTdata[attributeOffset + 4] +
                            self.MFTdata[attributeOffset + 3] + 
                            self.MFTdata[attributeOffset + 2] +
                            self.MFTdata[attributeOffset + 1] +
                            self.MFTdata[attributeOffset + 0]  )

        # 7th element is file altered time
        standardInfo.append(self.MFTdata[attributeOffset + 15] +
                            self.MFTdata[attributeOffset + 14] +
                            self.MFTdata[attributeOffset + 13] +
                            self.MFTdata[attributeOffset + 12] +
                            self.MFTdata[attributeOffset + 11] + 
                            self.MFTdata[attributeOffset + 10] +
                            self.MFTdata[attributeOffset + 9]  +
                            self.MFTdata[attributeOffset + 8]   )

        # 8th element is MFT changed TimeoutError
        standardInfo.append(self.MFTdata[attributeOffset + 23] +
                            self.MFTdata[attributeOffset + 22] +
                            self.MFTdata[attributeOffset + 21] +
                            self.MFTdata[attributeOffset + 20] +
                            self.MFTdata[attributeOffset + 19] + 
                            self.MFTdata[attributeOffset + 18] +
                            self.MFTdata[attributeOffset + 17] +
                            self.MFTdata[attributeOffset + 16]  ) 

        # 9th element is file read TimeoutError
        standardInfo.append(self.MFTdata[attributeOffset + 31] +
                            self.MFTdata[attributeOffset + 30] +
                            self.MFTdata[attributeOffset + 29] +
                            self.MFTdata[attributeOffset + 28] +
                            self.MFTdata[attributeOffset + 27] + 
                            self.MFTdata[attributeOffset + 26] +
                            self.MFTdata[attributeOffset + 25] +
                            self.MFTdata[attributeOffset + 24]  ) 
        
        # 10th element is DOS file permission
        standardInfo.append(self.MFTdata[attributeOffset + 35] + 
                            self.MFTdata[attributeOffset + 34] +
                            self.MFTdata[attributeOffset + 33] +
                            self.MFTdata[attributeOffset + 32]  )

        # 11th element is max number of version
        standardInfo.append(int(self.MFTdata[attributeOffset + 39] + 
                                self.MFTdata[attributeOffset + 38] +
                                self.MFTdata[attributeOffset + 37] +
                                self.MFTdata[attributeOffset + 36],16))

        # 12th element is version number
        standardInfo.append(int(self.MFTdata[attributeOffset + 42] + 
                                self.MFTdata[attributeOffset + 41] +
                                self.MFTdata[attributeOffset + 40] +
                                self.MFTdata[attributeOffset + 39],16))
       
        # 13th element is class id
        standardInfo.append(int(self.MFTdata[attributeOffset + 46] + 
                                self.MFTdata[attributeOffset + 45] +
                                self.MFTdata[attributeOffset + 44] +
                                self.MFTdata[attributeOffset + 43],16))

        self.offset = self.offset + int(standardInfo[1])
        return standardInfo

    def fileNameA(self):
        fileName = []

        ## -- Standard Information Header Begin
        # 1st element is attribute type:
        fileName.append(self.MFTdata[self.offset+3] + 
                        self.MFTdata[self.offset+2] + 
                        self.MFTdata[self.offset+1] + 
                        self.MFTdata[self.offset]    )     
        # 2nd element is length including header
        fileName.append(int( self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        fileName.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        fileName.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        fileName.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Standard Information Header End

        attributeOffset = 24 + self.offset
        # 6th element is file reference to the parent directory
        fileName.append(self.MFTdata[attributeOffset + 7] +
                        self.MFTdata[attributeOffset + 6] +
                        self.MFTdata[attributeOffset + 5] +
                        self.MFTdata[attributeOffset + 4] +
                        self.MFTdata[attributeOffset + 3] +
                        self.MFTdata[attributeOffset + 2] +
                        self.MFTdata[attributeOffset + 1] +
                        self.MFTdata[attributeOffset + 0]  )
        # 7th element is file creation time
        fileName.append(self.MFTdata[attributeOffset + 15] +
                        self.MFTdata[attributeOffset + 14] +
                        self.MFTdata[attributeOffset + 13] +
                        self.MFTdata[attributeOffset + 12] +
                        self.MFTdata[attributeOffset + 11] +
                        self.MFTdata[attributeOffset + 10] +
                        self.MFTdata[attributeOffset + 9]  +
                        self.MFTdata[attributeOffset + 8]   )
        # 8th element is file altered time
        fileName.append(self.MFTdata[attributeOffset + 23] +
                        self.MFTdata[attributeOffset + 22] +
                        self.MFTdata[attributeOffset + 21] +
                        self.MFTdata[attributeOffset + 20] +
                        self.MFTdata[attributeOffset + 19] +
                        self.MFTdata[attributeOffset + 18] +
                        self.MFTdata[attributeOffset + 17] +
                        self.MFTdata[attributeOffset + 16]  )
        # 9th element is MFT changed time
        fileName.append(self.MFTdata[attributeOffset + 31] +
                        self.MFTdata[attributeOffset + 30] +
                        self.MFTdata[attributeOffset + 29] +
                        self.MFTdata[attributeOffset + 28] +
                        self.MFTdata[attributeOffset + 27] +
                        self.MFTdata[attributeOffset + 26] +
                        self.MFTdata[attributeOffset + 25] +
                        self.MFTdata[attributeOffset + 24]  )
        # 10th element is file read time
        fileName.append(self.MFTdata[attributeOffset + 39] +
                        self.MFTdata[attributeOffset + 38] +
                        self.MFTdata[attributeOffset + 37] +
                        self.MFTdata[attributeOffset + 36] +
                        self.MFTdata[attributeOffset + 35] +
                        self.MFTdata[attributeOffset + 34] +
                        self.MFTdata[attributeOffset + 33] +
                        self.MFTdata[attributeOffset + 32]  )
        # 11th element is allocation size of the file
        fileName.append(int(self.MFTdata[attributeOffset + 47] +
                            self.MFTdata[attributeOffset + 46] +
                            self.MFTdata[attributeOffset + 45] +
                            self.MFTdata[attributeOffset + 44] +
                            self.MFTdata[attributeOffset + 43] +
                            self.MFTdata[attributeOffset + 42] +
                            self.MFTdata[attributeOffset + 41] +
                            self.MFTdata[attributeOffset + 40], 16)  )
        # 12th element is real size of the file
        fileName.append(int(self.MFTdata[attributeOffset + 55] +
                            self.MFTdata[attributeOffset + 54] +
                            self.MFTdata[attributeOffset + 53] +
                            self.MFTdata[attributeOffset + 52] +
                            self.MFTdata[attributeOffset + 51] +
                            self.MFTdata[attributeOffset + 50] +
                            self.MFTdata[attributeOffset + 49] +
                            self.MFTdata[attributeOffset + 48], 16)  )
        # 13th element is flag
        # e.g. 0x0001: Read-Only, 0x020: Archive
        fileName.append(self.MFTdata[attributeOffset + 59] +
                        self.MFTdata[attributeOffset + 58] +
                        self.MFTdata[attributeOffset + 57] +
                        self.MFTdata[attributeOffset + 56]  )
        # 14th element is used by EAs and reparse
        fileName.append(self.MFTdata[attributeOffset + 63] +
                        self.MFTdata[attributeOffset + 62] +
                        self.MFTdata[attributeOffset + 61] +
                        self.MFTdata[attributeOffset + 60]  )
        
        # 15th element is filename length in characters
        fileName.append(int(self.MFTdata[attributeOffset + 64], 16))
        # 16th element is file name
        i = 0
        fName = ""
        while i < int(fileName[14]):
            fName = fName + chr(int(self.MFTdata[attributeOffset + 66 + (i*2)], 16))
            i = i + 1
        fileName.append(fName)
        print("File name:", fName)
        self.fileName = fName
        self.offset = self.offset + int(fileName[1])
        return fileName

    def securityDescriptorA(self):
        securityDes = []

        ## -- Standard Information Header Begin
        # 1st element is attribute type:
        securityDes.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )              
        # 2nd element is length including header
        securityDes.append(int( self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        securityDes.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        securityDes.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        securityDes.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Standard Information Header End
        
        self.offset = self.offset + int(securityDes[1])
        return securityDes
    
    def dataA(self, flag):
        data = []

        ## -- Standard Information Header Begin
        # 1st element is attribute type:
        data.append(self.MFTdata[self.offset+3] + 
                    self.MFTdata[self.offset+2] + 
                    self.MFTdata[self.offset+1] + 
                    self.MFTdata[self.offset]    )             
        # 2nd element is length including header
        data.append(int( self.MFTdata[self.offset+4], 16))
        # 3th element is non-resident flag
        data.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        data.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        
        # if attribute is resident:
        if( int(data[2]) == 0): 
            # 5th element is length of the attribute
            data.append(int(self.MFTdata[self.offset + 19] +
                                    self.MFTdata[self.offset + 18] + 
                                    self.MFTdata[self.offset + 17] +
                                    self.MFTdata[self.offset + 16]
                                    ,16))
            # 6th element is offset to content
            data.append(int( self.MFTdata[self.offset + 21] + 
                             self.MFTdata[self.offset + 20], 16))
            #recovering deleted resident file
            if(int(flag, 16) == 0):
                rf = recovering.recoveringFile(self.fileName)
                i = 0
                while( i < int(data[4])):
                    print(self.MFTdata[self.offset + int(data[5]) + i])
                    rf.writeToFile(self.MFTdata[self.offset +int(data[5] + i)])
                    i = i + 1
                
                rf.closeFile()

        # if attribute is non-resident
        elif( int(data[2]) == 1):
            # 5th element is starting virtual cluster number of the runlist
            data.append(int( self.MFTdata[self.offset+23] +
                             self.MFTdata[self.offset+22] +
                             self.MFTdata[self.offset+21] +
                             self.MFTdata[self.offset+20] +
                             self.MFTdata[self.offset+19] +
                             self.MFTdata[self.offset+18] +
                             self.MFTdata[self.offset+17] +
                             self.MFTdata[self.offset+16] , 16))
            # 6th element is ending virtual cluster number of the runlist
            data.append(int( self.MFTdata[self.offset+31] +
                             self.MFTdata[self.offset+30] +
                             self.MFTdata[self.offset+29] +
                             self.MFTdata[self.offset+28] +
                             self.MFTdata[self.offset+27] +
                             self.MFTdata[self.offset+26] +
                             self.MFTdata[self.offset+25] +
                             self.MFTdata[self.offset+24] , 16))
            
            # 7th element is offset to the runlist
            data.append(self.MFTdata[self.offset + 33] +
                        self.MFTdata[self.offset + 32])
            # 8th element is compression unit size
            data.append(int(self.MFTdata[self.offset + 35] + 
                            self.MFTdata[self.offset + 34], 16))
            # 9th elements is allocated size of attribute content 
            data.append(int(self.MFTdata[self.offset + 47] + 
                            self.MFTdata[self.offset + 46] +
                        	self.MFTdata[self.offset + 45] +
                        	self.MFTdata[self.offset + 44] +
                        	self.MFTdata[self.offset + 43] +
                        	self.MFTdata[self.offset + 42] +
                        	self.MFTdata[self.offset + 41] +
                        	self.MFTdata[self.offset + 40]   ,16))

            # 10th elements is actual size of attribute content 
            data.append(int(self.MFTdata[self.offset + 55] + 
                        	self.MFTdata[self.offset + 54] +
                        	self.MFTdata[self.offset + 53] +
                        	self.MFTdata[self.offset + 52] +
                        	self.MFTdata[self.offset + 51] +
                        	self.MFTdata[self.offset + 50] +
                        	self.MFTdata[self.offset + 49] +
                        	self.MFTdata[self.offset + 48]   ,16))
            
            # 11th elements is initialized size of attribute content 
            data.append(int(self.MFTdata[self.offset + 63] + 
                        	self.MFTdata[self.offset + 62] +
                        	self.MFTdata[self.offset + 61] +
                        	self.MFTdata[self.offset + 60] +
                        	self.MFTdata[self.offset + 59] +
                        	self.MFTdata[self.offset + 58] +
                        	self.MFTdata[self.offset + 57] +
                        	self.MFTdata[self.offset + 56]  ,16))

            # Recovering non-resident deleted file 
            if(int(flag, 16) == 0):
                print("Offset to runlist:", int(data[6]))
                print("starting virtual cluster number:", data[4])
                print("ending virtual cluster number:", data[5])
                print("compression unit size:", data[7])
                print("allocated size of attribute content:", data[8])
                print("actual size of attribute :", data[9])
                print("initialized size of attribute :", data[10])
                
                
               	rnc = list(self.MFTdata[self.offset + int(data[6], 16)])
                run1 = int(rnc[0])
                run2 = int(rnc[1])

                l = run2
                contClusters = ""
                
                while(l <= run2 and l> 0):
                    print("l:", l, "aa:", (self.offset+int(data[6])+l))
                    contClusters = contClusters + self.MFTdata[self.offset + int(data[6], 16) + l]
                    l = l - 1
                
                #print("num of cluster:", contClusters)
                m = run1
                beginningOfcluster = ""
                while(m <= run1 and m > 0):
                    beginningOfcluster = beginningOfcluster + self.MFTdata[self.offset + int(data[6], 16) + run2 + m]
                    m = m - 1

                #print("beginning:", beginningOfcluster)
               
                # Determining location of the file:
                
                # self.metadataOfBootRecord[2] holds the number of sectors per cluster
                clusterToSector = int(beginningOfcluster, 16) * int(self.metadataOfBootRecord[2])
                # self.metadataOfBootRecord[1] holds the number of bytes per sector
                sectorTobyte = clusterToSector * int(self.metadataOfBootRecord[1])

                # sectorTobyte gives us the location of the file from beginning of partition, but we need to find physical location
                beginningLocation = sectorTobyte + self.blockAdd
                
                # Determining end location of the file:
                endSector = int(contClusters, 16) * int(self.metadataOfBootRecord[2])
                # sectorTobyte2 = clustertoSector2 * int(self.metadataOfBootRecord[1]) 

                print("location:", beginningLocation)
                print("end sector:", endSector)

                getFile = getDeletedData.getData()
                recoveredBytes = getFile.obtainData(beginningLocation, endSector)
                
                rnf = recovering.recoveringFile(self.fileName)
                j = 0
                while( j < len(recoveredBytes)):
                    rnf.writeToFile(recoveredBytes[j])
                    j = j + 1
                
                rnf.closeFile()

        ## -- Standard Information Header End
        
        self.offset = self.offset + int(data[1])
        return data

    def bitMapA(self):
        bitmap = []


        ## -- Bitmap Header Begin
        # 1st element is attribute type:
        bitmap.append(self.MFTdata[self.offset+3] + 
                      self.MFTdata[self.offset+2] + 
                      self.MFTdata[self.offset+1] + 
                      self.MFTdata[self.offset]    )            
        # 2nd element is length including header
        bitmap.append(int(self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        bitmap.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        bitmap.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        bitmap.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(bitmap[1])
        return bitmap

    def volNameA(self):
        volName = []


        ## -- volName Header Begin
        # 1st element is attribute type:
        volName.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )          
        # 2nd element is length including header
        volName.append(int( self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        volName.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        volName.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        volName.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        self.offset = self.offset + int(volName[1])
        return volName
    
    def volInfoA(self):
        volInfo = []


        ## -- volInfo Header Begin
        # 1st element is attribute type:
        volInfo.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )              
        # 2nd element is length including header
        volInfo.append(int(self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        volInfo.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        volInfo.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        volInfo.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(volInfo[1])
        return volInfo


    def indexRootA(self):
        inRoot = []


        ## -- inRoot Header Begin
        # 1st element is attribute type:
        inRoot.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )               
        # 2nd element is length including header
        inRoot.append(int(self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        inRoot.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        inRoot.append(self.MFTdata[self.offset + 13] +
                            self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        inRoot.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(inRoot[1])
        return inRoot

    def indexAllocA(self):
        inAlloc = []

        ## -- inAlloc Header Begin
        # 1st element is attribute type:
        inAlloc.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )            
        # 2nd element is length including header
        inAlloc.append(int(self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        inAlloc.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        inAlloc.append(self.MFTdata[self.offset + 13] +
                       self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        inAlloc.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(inAlloc[1])
        return inAlloc
    
    def objectIdA(self):
        objectId = []

        ## -- objectId Header Begin
        # 1st element is attribute type:
        objectId.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )            
        # 2nd element is length including header
        objectId.append(int(self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        objectId.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        objectId.append(self.MFTdata[self.offset + 13] +
                       self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        objectId.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(objectId[1])
        return objectId
    
    def attListA(self):
        attList = []

        ## -- attList Header Begin
        # 1st element is attribute type:
        attList.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )            
        # 2nd element is length including header
        attList.append(int( self.MFTdata[self.offset+4],16))
        # 3th element is non-resident flag
        attList.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        attList.append(self.MFTdata[self.offset + 13] +
                       self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        attList.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(attList[1])
        return attList
    
    def unknownA(self):
        unknown = []

        ## -- unknown Header Begin
        # 1st element is attribute type:
        unknown.append(self.MFTdata[self.offset+3] + 
                           self.MFTdata[self.offset+2] + 
                           self.MFTdata[self.offset+1] + 
                           self.MFTdata[self.offset]    )            
        # 2nd element is length including header
        unknown.append(int(self.MFTdata[self.offset+4], 16))
        # 3th element is non-resident flag
        unknown.append(self.MFTdata[self.offset+8])
        # 4th element is attribute flags
        unknown.append(self.MFTdata[self.offset + 13] +
                       self.MFTdata[self.offset + 12])
        # 5th element is length of the attribute
        unknown.append(int(self.MFTdata[self.offset + 19] +
                                self.MFTdata[self.offset + 18] + 
                                self.MFTdata[self.offset + 17] +
                                self.MFTdata[self.offset + 16]
                                ,16))
        ## -- Bitmap Header End
        
        self.offset = self.offset + int(unknown[1])
        return unknown 








