import pefile
import sys
import os
import binascii
import struct
import argparse
from random import randrange
from struct import unpack
from binascii import hexlify, a2b_uu
from datetime import datetime, timedelta, timezone


def getTimeDateStamp(filename):
    pe = pefile.PE(filename)

    #Get file header timestamp in hex
    hexTimeStamp = hex(pe.FILE_HEADER.TimeDateStamp)
    revHexTimeStamp = hexTimeStamp.strip('0x')
    revHexTimeStamp = "".join(reversed([revHexTimeStamp[i:i+2] for i in range(0, len(revHexTimeStamp), 2)]))
    print(f'[+] File Header TimeDateStamp: {hexTimeStamp}')
    
    #Dump contents of debug directory and get timestamp (probably a better way to do this...)
    imgDbgTimeStamps = []
    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        debugTimeStamp = (dbg.struct.dump()[2]) #timestamp field as string
        debugTimeStamp = debugTimeStamp[48:58] #get only the timestamp hex from string
        imgDbgTimeStamps.append(debugTimeStamp)
    imgDbgTimeStampHex = hex(int(imgDbgTimeStamps[0], 16)) #get hex of first entry
    revImgHexTimeStamp = imgDbgTimeStampHex.strip('0x')
    revImgHexTimeStamp = "".join(reversed([revImgHexTimeStamp[i:i+2] for i in range(0, len(revImgHexTimeStamp), 2)]))
    print(f'[+] Debug Dir TimeDateStamp: {imgDbgTimeStamps[0]}\n')

    return revHexTimeStamp, revImgHexTimeStamp

#Get file as hex, replace old timestamps with new
def modifyHex(filename, revHexTimeStamp, revImgHexTimeStamp, newFilename, newDateInHex):
    with open(filename, 'rb') as hexfile:
        data = hexfile.read()
        hexDump = (binascii.hexlify(data).decode())
        hexDump = hexDump.replace (revImgHexTimeStamp, newDateInHex) #debug dir timestamp
        newHexDump = hexDump.replace(revHexTimeStamp, newDateInHex) #file header timestamp
        
        #Write new timestamped bytes to new file
        newHexFile = binascii.unhexlify(newHexDump)
        newFile = open(newFilename, 'wb')
        newFile.write(newHexFile)
        newFile.close()
        
        print(f'[+] Wrote new file to {newFilename}\n')

def dateToHex():
    #get random date between two dates
    startRandomDate = datetime.strptime('1/3/2016 2:30 PM', '%m/%d/%Y %I:%M %p')
    endRandomDate = datetime.strptime('12/15/2018 2:30 PM', '%m/%d/%Y %I:%M %p')
    delta = endRandomDate - startRandomDate
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = randrange(int_delta)
    randomDate = startRandomDate + timedelta(seconds=random_second)
    randomDateUTC = randomDate.replace(tzinfo = timezone.utc)

    #new timestamp
    timeStamp = randomDateUTC.timestamp()
    dateHex = binascii.hexlify(struct.pack('<I', round(timeStamp))).decode()
    return dateHex, randomDate

if __name__=='__main__':

    parser = argparse.ArgumentParser(description='Simple program to change timestamp on programs made with Visual Studio Code and the .NET Framework. Modifies hex of incorrect date occurrances to random date in the past.')
    parser.add_argument('inputFile', help='Input file with the incorrect timestamp')
    parser.add_argument('outputFile', help='Output file name that will have a new timestamp')
    args = parser.parse_args()

    filename = args.inputFile
    newFilename = args.outputFile
    newDateInHex, newDate = dateToHex()

    revHexTimeStamp, revImgHexTimeStamp = getTimeDateStamp(filename)
    modifyHex(filename, revHexTimeStamp, revImgHexTimeStamp, newFilename, newDateInHex)
    print(f'[+] New Timestamp: {newDate} UTC')
    newTimestamp = getTimeDateStamp(newFilename)
