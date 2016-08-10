import sys
import os
import MftReader
import analyzingMFT

class diskAnalyzer: 
    def __init__(self):
        self.readingBlock = MftReader.sectorReader()

        # Information which are in MBR is hold in arrays.
        self.information1 = []
        self.information2 = []
        self.information3 = []
        self.information4 = []

    # execution of the analzing
    def execution(self):
        self.readMBR()

    # reading and analyzing master boot record
    def readMBR(self):
        self.sectorData = self.readingBlock.openSource('0')

    # If there is no MBR on NTFS
        if ("".join(self.sectorData[0:4]) == "eb52904e"):
            print("NTFS formatted drive!")
            NTFSanalyzer = analyzingMFT.MFTanalyzer()
            NTFSanalyzer.NTFSbootSector('0')
            
    # If disk includes MBR:
        # MBT includes 4 partition information.
        # These information start at offset 0xBE, and their size are 16 bytes
        
        # 5th byte of the information entries indicates type of the partition
        #e.g.: 0x07 -> NTFS, 0x0B -> FAT32 partition, or logical drive etc.
        elif ("".join(self.sectorData[0:4]) != "eb52904e"):
            self.partition1 = int("1BE", 16)
            self.partition2 = int("1BE", 16)+16
            self.partition3 = int("1BE", 16)+32
            self.partition4 = int("1BE", 16)+48

            # 1st element of the MBR info array is the type of the partition.
            self.information1.append(self.sectorData[self.partition1+4])
            print("Type of the partition 1:", self.information1[0])
            self.information2.append(self.sectorData[self.partition2+4])
            print("Type of the partition 2:",self.information2[0])
            self.information3.append(self.sectorData[self.partition3+4])
            print("Type of the partition 3:",self.information3[0])
            self.information4.append(self.sectorData[self.partition4+4])
            print("Type of the partition 4:",self.information4[0])
            print("***\t\t***\n")

            # Information about 1st partition, if there is such partition
            if int(self.information1[0]) != 0:
                if int(self.information1[0]) == 7:
                    print("NTFS formatted drive!")

                    # This information indicates whether partitionis bootable or not. 
                    # It is 2nd element of the MBR info array.
                    self.information1.append(self.sectorData[self.partition1+1])
                    print("Partition bootable or not:", self.information1[1])
                    
                    # This information indicates the logical block addressing of start sector.
                    #It is measured in blocks. Block size is generally 512 bytes.
                    #It is 3th element of the MBR info array.
                    self.information1.append((self.sectorData[self.partition1+11]) + 
                                             (self.sectorData[self.partition1+10]) + 
                                             (self.sectorData[self.partition1+9])  + 
                                             (self.sectorData[self.partition1+8])  )
                    print("The logical block of the partition:",self.information1[2])
                    print("\n\n")
                    NTFSanalyzer = analyzingMFT.MFTanalyzer()
                    NTFSanalyzer.NTFSbootSector(self.information1[2])


                else:
                    print("Drive format type which is {} is not defined".format(self.sectorData[self.partition1 + 4]))
                    print("To check format type: https://technet.microsoft.com/en-us/library/cc976786.aspx")
                    print("\n\n")
            
            # Information about 2nd partition, if there is such partition
            if(int(self.information2[0])) != 0:
                if(int(self.information2[0])) == 7:
                    print("NTFS formatted drive!")

                    # This information indicates whether partitionis bootable or not. 
                    # It is 2nd element of the MBR info array.
                    self.information2.append(self.sectorData[self.partition2+1])
                    print("Partition bootable or not:", self.information2[1])
                    
                    # This information indicates the logical block addressing of start sector.
                    #It is measured in blocks. Block size is generally 512 bytes.
                    #It is 3th element of the MBR info array.
                    self.information2.append( (self.sectorData[self.partition2+11]) + 
                                            (self.sectorData[self.partition2+10]) + 
                                            (self.sectorData[self.partition2+9])  + 
                                            (self.sectorData[self.partition2+8])  )
                    print("The logical block of the partition:",self.information2[2])
                    print("\n\n")

                else:
                    print("Drive format type which is {} is not defined".format(self.sectorData[self.partition2 + 4]))
                    print("To check format type: https://technet.microsoft.com/en-us/library/cc976786.aspx")
                    print("\n\n")

            
            # Information about 3th partition, if there is such partition
            if int(self.information3[0]) != 0:
                if int(self.information3[0]) == 7:
                    print("NTFS formatted drive!")
                
                    # This information indicates whether partitionis bootable or not. 
                    # It is 2nd element of the MBR info array.
                    self.information3.append(self.sectorData[self.partition3+1])
                    print("Partition bootable or not:", self.information3[1])
                    
                    # This information indicates the logical block addressing of start sector.
                    #It is measured in blocks. Block size is generally 512 bytes.
                    #It is 3th element of the MBR info array.
                    self.information3.append((self.sectorData[self.partition3+11]) + 
                                            (self.sectorData[self.partition3+10]) + 
                                            (self.sectorData[self.partition3+9])  + 
                                            (self.sectorData[self.partition3+8])  )
                    print("The logical block of the partition:",self.information3[2])
                    print("\n\n")

                else:
                    print("Drive format type which is {} is not defined".format(self.sectorData[self.partition3 + 4]))
                    print("To check format type: https://technet.microsoft.com/en-us/library/cc976786.aspx")
                    print("\n\n")
            
            # Information about 4th partition, if there is such partition
            if int(self.information4[0]) != 0:
                if int(self.information4[0]) == 7:
                    print("NTFS formatted drive!")
                
                    # This information indicates whether partitionis bootable or not. 
                    # It is 2nd element of the MBR info array.
                    self.information4.append(self.sectorData[self.partition4+1])
                    print("Partition bootable or not:", self.information4[1])
                    
                    # This information indicates the logical block addressing of start sector.
                    #It is measured in blocks. Block size is generally 512 bytes.
                    #It is 3th element of the MBR info array.
                    self.information4.append((self.sectorData[self.partition4+11]) + 
                                            (self.sectorData[self.partition4+10]) + 
                                            (self.sectorData[self.partition4+9])  + 
                                            (self.sectorData[self.partition4+8])  )
                    print("The logical block of the partition:",self.information4[2])
                    print("\n\n")

                else:
                    print("Drive format type which is {} is not defined".format(self.sectorData[self.partition4 + 4]))
                    print("To check format type: https://technet.microsoft.com/en-us/library/cc976786.aspx")
                    print("\n\n")
        

            
