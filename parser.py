#!/usr/bin/python3
'''
rewriting parser.cpp in Python3
'''
import sys, os, struct, binascii
DEFAULT_BLOCK = os.path.expanduser('~/.bitcoin/blocks/blk00000.dat')
MAGIC = {
    'bitcoin': binascii.a2b_hex('F9BEB4D9'),
}

def parse(blockfile=DEFAULT_BLOCK):
    '''
    dump out a block file
    '''
    index = 0
    magic = ''
    reversemagic = dict([[value, key] for key, value in MAGIC.items()])
    with open(blockfile, 'rb') as datainput:
        blockdata = datainput.read()  # not necessarily very efficient
    while index < len(blockdata):
        magic = blockdata[index:index + 4]
        blocksize = struct.unpack('<L', blockdata[index + 4:index + 8])[0]
        blockheader = blockdata[index + 8:index + 88]
        transactions = blockdata[index + 88:index + blocksize - 8]
        index += blocksize + 8

if __name__ == '__main__':
    parse(*sys.argv[1:])
