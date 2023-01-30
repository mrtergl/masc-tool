from __future__ import print_function

import argparse
from ctypes import Structure
from datetime import datetime
import hashlib
import time
from colorama import Style,Fore,Back
from pefile import PE
import os
import win32com.client
import binascii
import pefile

class metadata:
    def __init__(self) -> None:
         pass
    
    def find(self,name):
            for root, dirs, files in os.walk("C:\\"):
                if name in files:
                    return os.path.join(root, name)

    def crc32(self, data):
        return binascii.crc32(data)

    def CheckFile(self,path,filename):
        
        FIELD_SIZE = 16
        
        pe = pefile.PE(path)
        
       
        results = ''
        data = open(path, 'rb').read()
        fname = os.path.split(filename)[1]

        results += ('%-*s: %s\n' % (FIELD_SIZE, (Style.BRIGHT+Fore.YELLOW+'File Name'+Style.RESET_ALL), fname))
        results += ('%-*s: %s\n' % (FIELD_SIZE, Style.BRIGHT+Fore.YELLOW+'File Size'+Style.RESET_ALL, '{:,}'.format(os.path.getsize(path))))
        results += ('%-*s: %s\n' % (FIELD_SIZE, Style.BRIGHT+Fore.YELLOW+'CRC32'+Style.RESET_ALL, self.crc32(data)))
        results += ('%-*s: %s\n' % (FIELD_SIZE, Style.BRIGHT+Fore.YELLOW+'MD5'+Style.RESET_ALL, hashlib.md5(data).hexdigest()))
        results += ('%-*s: %s\n' % (FIELD_SIZE, Style.BRIGHT+Fore.YELLOW+'SHA1'+Style.RESET_ALL, hashlib.sha1(data).hexdigest()))
        results += ('%-*s: %s\n' % (FIELD_SIZE, Style.BRIGHT+Fore.YELLOW+'SHA256'+Style.RESET_ALL, hashlib.sha256(data).hexdigest()))

        section_hdr = 'PE Sections (%d)' % pe.FILE_HEADER.NumberOfSections
        section_hdr2 = '%-10s %-10s %s' % ('Name', 'Size', 'SHA256')
        results += ('%-*s: %s\n' % (FIELD_SIZE, Style.BRIGHT+Fore.YELLOW+section_hdr, section_hdr2+Style.RESET_ALL))
        for section in pe.sections:
            section_name = section.Name.strip(b'\x00').decode('utf-8')
            results += ('%-*s %-10s %-10s %s\n' % (FIELD_SIZE + 1, ' ', section_name,
                                                     '{:,}'.format(section.SizeOfRawData),
                                                     section.get_hash_sha256()))

        return results


if __name__ == '__main__':
        file = input(str("File Name: "))
        filename = 'BMW series 1 owners manual.pdf'
        parser = argparse.ArgumentParser('Metadata from executable file')
        f = metadata.find(file)
        if (f):
            print(metadata.CheckFile(f, file))