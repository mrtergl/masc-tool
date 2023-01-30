import itertools
import argparse
from logging import root
import os
from pathlib import Path
import re
from io import StringIO
from os.path import exists

from colorama import Fore, Style

class HexDump:
    def __init__(self) -> None:
        pass
    
    home = str(Path.home())
    home = home+"\Desktop"

    def find(self,name):
            for root, dirs, files in os.walk("C:\\"):
                if name in files:
                    return os.path.join(root, name)

    def hex_group_formatter(self,iterable):
        chunks = [iter(iterable)] * 4
        return '   '.join(
            ' '.join(format(x, '0>2x') for x in chunk)
            for chunk in itertools.zip_longest(*chunks, fillvalue=0))

    def ascii_group_formatter(self,iterable):
        return ''.join(
            chr(x) if 33 <= x <= 126 else ' '
            for x in iterable)

    def hex_viewer(self,filename, chunk_size=16):
        header = self.hex_group_formatter(range(chunk_size))
        yield 'ADDRESS        {:<53}       ASCII'.format(header)
        yield ''
        template = '{:0>8x}       {:<53}       {}'

        with open(filename, 'rb') as stream:
            for chunk_count in itertools.count(1):
                chunk = stream.read(chunk_size)
                if not chunk:
                    return
                yield template.format(
                    chunk_count * chunk_size,
                    self.hex_group_formatter(chunk),
                    self.ascii_group_formatter(chunk))

    def doFind(self, x, buf):
        ret = []
        for l in x.findall(buf, re.IGNORECASE | re.MULTILINE):
            print(l)
            for url in l:
                if len(url) > 8 and url not in ret:
                    ret.append(url)
        
        return ret

    def main(self,path,filename):
        filename = os.path.splitext(filename)[0]+"_HEX.txt"
        filepath = self.home+"\\"+filename
        if(exists(filepath)):
            open(filepath, "w").close()
        with open(filepath,"a") as f:
            for line in self.hex_viewer(path):
                f.write(line+"\n")
        print(Style.BRIGHT+Fore.LIGHTGREEN_EX+'\nHEX file created')
        ans=str(input(Style.BRIGHT+Fore.LIGHTGREEN_EX+'\nWould you like to open the file ? [y/n]: '+Style.RESET_ALL))
        if (ans == 'y'):
            os.system("start "+filepath)

    



            
        