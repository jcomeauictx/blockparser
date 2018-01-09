#!/usr/bin/python3
'''
rewriting parser.cpp in Python3

using ideas and code from http://www.righto.com/2014/02/
 bitcoins-hard-way-using-raw-bitcoin.html,
https://bitcoin.org/en/developer-guide,
https://bitcoin.org/en/developer-reference,
and many other sources.
'''
import sys, os, struct, binascii, logging
from datetime import datetime
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
        parse_blockheader(blockheader)
        logging.info('transactions (partial): %r', transactions[:80])
        count, transactions = parse_transactions(transactions)
        logging.info('transaction count: %d', count)
        logging.debug('transaction data (partial): %r', transactions[:80])

def parse_blockheader(blockheader):
    '''
    return contents of block header
    '''
    version = struct.unpack('<L', blockheader[:4])[0]
    previous_blockhash = binascii.b2a_hex(blockheader[36:3:-1])
    merkle_root = binascii.b2a_hex(blockheader[68:35:-1])
    unix_time = datetime.fromtimestamp(
        struct.unpack('<L', blockheader[68:72])[0])
    target_nbits = blockheader[72:76]
    nonce = binascii.b2a_hex(blockheader[76:])
    if len(nonce) != 8:
        raise ValueError('Block header wrong size: %d bytes' % len(blockheader))
    logging.info('block version: %d', version)
    logging.info('previous block hash: %s', previous_blockhash)
    logging.info('merkle root: %s', merkle_root)
    logging.info('target_nbits: %r', target_nbits)
    logging.info('nonce: %s', nonce)
    return version, previous_blockhash, merkle_root, target_nbits, nonce

def parse_transactions(transactions):
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
