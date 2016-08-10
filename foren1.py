
import os
import sys


dosya = os.open("/dev/sdi", os.O_RDONLY)
print (os.lseek(dosya, 13, 0))
veri = os.read(dosya, 512)

for i in range(0, 512):
    if(len(str(veri[i])) == 1):
        print(hex(veri[i]).split('x')[1], sep = " ", end = "    ")
    else:
        print(hex(veri[i]).split('x')[1], sep = " ", end = "   ")

    if((i+1)%8 == 0 and i != 0):
        print("")

os.close(dosya) 