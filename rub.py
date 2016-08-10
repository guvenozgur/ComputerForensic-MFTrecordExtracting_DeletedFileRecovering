import sys
import os
import recovering

rf = recovering.recoveringFile("guven")


with open("tt.JPG", "rb") as imageFile:
  f = imageFile.read()
  b = bytearray(f)

i=0
while i < len(b):
    rf.writeToFile(b[i])
    i = i + 1

rf.closeFile()