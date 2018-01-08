#!/usr/bin/python3
'''
rewriting parser.cpp in Python3
'''
import sys, os, struct, binascii, logging
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
DEFAULT_BLOCK = os.path.expanduser('~/.bitcoin/blocks/blk00000.dat')
MAGIC = {
    'bitcoin': binascii.a2b_hex('F9BEB4D9'),
    'dogecoin': binascii.a2b_hex('C0C0C0C0'),
    'testnet': binascii.a2b_hex('FABFB5DA'),
    'testnet3': binascii.a2b_hex('0B110907'),
    'namecoin': binascii.a2b_hex('F9BEB4FE'),
}
VARINT = {
    # struct format, offset, length
    '\xfd': ('<H', 1, 2),
    '\xfe': ('<L', 1, 4),
    '\xff': ('<Q', 1, 8),
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
        logging.debug('magic: %s', binascii.b2a_hex(magic))
        logging.info('block type: %s', reversemagic.get(magic, 'unknown'))
        logging.info('block size: %d', blocksize)
        logging.info('block header: %r', blockheader)
        logging.info('transactions (partial): %r', transactions[:80])
        count, transactions = parsetransactions(transactions)
        logging.info('transaction count: %d', count)
        logging.debug('transaction data (partial): %r', transactions[:80])

def parsetransactions(transactions):
    '''
    return parsed transaction length and transactions
    '''
    count, transactions = get_count(transactions)
    return count, transactions  # actual parsing will come later

def get_count(data):
    '''
    extract and decode VarInt count and return it with remainder of data
    '''
    packing, offset, length = VARINT.get(data[0], ('B', 0, 1))
    count = struct.unpack(packing, data[offset:offset + length])[0]
    remainder = data[offset + length:]
    return count, remainder

if __name__ == '__main__':
    parse(*sys.argv[1:])
