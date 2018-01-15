#!/usr/bin/python3 -OO
'''
rewriting parser.cpp in Python3

using ideas and code from
http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html,
http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html,
https://bitcoin.org/en/developer-guide,
https://bitcoin.org/en/developer-reference,
and many other sources.
'''
import sys, os, struct, binascii, logging, hashlib
from datetime import datetime
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)
DEFAULT_BLOCK = os.path.expanduser('~/.bitcoin/blocks/blk00000.dat')
MAGIC = {
    'bitcoin': binascii.a2b_hex('F9BEB4D9'),
    'dogecoin': binascii.a2b_hex('C0C0C0C0'),
    'testnet': binascii.a2b_hex('FABFB5DA'),
    'testnet3': binascii.a2b_hex('0B110907'),
    'namecoin': binascii.a2b_hex('F9BEB4FE'),
    'americancoin': binascii.a2b_hex('414D433A'),
}
VARINT = {
    # struct format, offset, length
    # remember in Python3 b'\xfd'[0] == 253
    0xfd: ('<H', 1, 2),
    0xfe: ('<L', 1, 4),
    0xff: ('<Q', 1, 8),
}
UNPACKER = {
    # fetch using len(bytestring)
    1: 'B',
    2: '<H',
    4: '<L',
    8: '<Q',
}

def parse(blockfile=DEFAULT_BLOCK, minblock=0, maxblock=sys.maxsize):
    '''
    dump out a block file
    '''
    index = 0
    magic = ''
    minheight, maxheight = int(minblock), int(maxblock)
    logging.debug('minheight: %d, maxheight: %d', minheight, maxheight)
    reversemagic = dict([[value, key] for key, value in MAGIC.items()])
    with open(blockfile or DEFAULT_BLOCK, 'rb') as datainput:
        blockdata = datainput.read()  # not necessarily very efficient
    logging.warning('NOTE: "height" values shown are relative to START OF FILE')
    logging.warning('NOTE: heights shown can be many blocks higher than what'
                    ' is reported in debug.log; for example, to view AMC'
                    ' block 291965 as shown in debug.log, instead request'
                    ' block 404603. this number varies node by node,'
                    ' as older nodes will have stale blocks embedded in the'
                    ' data files.')
    height = 0
    while index < len(blockdata):
        logging.debug('blockparser at index %d out of %d bytes',
                      index, len(blockdata))
        magic = blockdata[index:index + 4]
        blocksize = struct.unpack('<L', blockdata[index + 4:index + 8])[0]
        blockheader = blockdata[index + 8:index + 88]
        transactions = blockdata[index + 88:index + blocksize + 8]
        index += blocksize + 8
        if minheight <= height <= maxheight:
            logging.info('height: %d', height)
            logging.debug('magic: %s', binascii.b2a_hex(magic))
            logging.info('block type: %s', reversemagic.get(magic, 'unknown'))
            logging.info('block size: %d', blocksize)
            logging.info('block header: %r', blockheader)
            parse_blockheader(blockheader)
            logging.info('transactions (partial): %r', transactions[:80])
            count, transactions = parse_transactions(transactions)
            logging.info('transaction count: %d', count)
            logging.debug('transaction data (partial): %r', transactions[:80])
        elif height > maxheight:
            break
        else:
            logging.debug('height: %d', height)
        height += 1

def parse_blockheader(blockheader):
    '''
    return contents of block header
    '''
    version = blockheader[:4]
    previous_blockhash = blockheader[4:36]
    merkle_root = blockheader[36:68]
    unix_time = blockheader[68:72]
    target_nbits = blockheader[72:76]
    nonce = blockheader[76:]
    if len(nonce) != 4:
        raise ValueError('Nonce wrong size: %d bytes' % len(nonce))
    logging.info('block version: %s', show_long(version))
    logging.info('previous block hash: %s', show_hash(previous_blockhash))
    logging.info('merkle root: %s', show_hash(merkle_root))
    logging.info('unix time: %s', timestamp(unix_time))
    logging.info('target_nbits: %r', to_hex(target_nbits))
    logging.info('nonce: %s', to_hex(nonce))
    logging.info('block hash: %s', show_hash(get_hash(blockheader)))
    return version, previous_blockhash, merkle_root, target_nbits, nonce

def to_long(bytestring):
    '''
    for unpacking 8, 16, 32, or 64-bit number
    '''
    return struct.unpack(UNPACKER[(len(bytestring))], bytestring)[0]

def show_long(bytestring):
    '''
    for displaying 32-bit number
    '''
    number = to_long(bytestring)
    return '0x%08x (%d)' % (number, number)

def timestamp(bytestring):
    '''
    for displaying 32-bit number as UTC time
    '''
    return datetime.utcfromtimestamp(to_long(bytestring)).isoformat()

def to_hex(bytestring):
    '''
    for displaying bytes in hexadecimal
    '''
    return binascii.b2a_hex(bytestring)

def get_hash(bytestring, repeat=2):
    '''
    return sha256 hash digest of bytestring

    default is to return hash of hash; for simple hash, pass `repeat=1`
    '''
    for iteration in range(repeat):
        bytestring = hashlib.sha256(bytestring).digest()
    return bytestring

def show_hash(bytestring):
    '''
    return a sha256 hash, or any other bytestring, reversed and hexlified
    '''
    return to_hex(bytestring[::-1])

def parse_transactions(data):
    '''
    return parsed transaction length and transactions
    '''
    transactions = []
    rawcount, count, data = get_count(data)
    for index in range(count):
        transaction, data = parse_transaction(data)
        transactions.append(transaction)
    return count, data

def parse_transaction(data):
    '''
    return parsed transaction
    '''
    version = data[:4]
    raw_transaction = version
    logging.info('transaction version: %s', show_long(version))
    raw_in_count, in_count, data = get_count(data[4:])
    logging.info('number of transaction inputs: %d', in_count)
    raw_inputs, inputs, data = parse_inputs(in_count, data)
    logging.debug('length of data after parse_inputs: %d', len(data))
    raw_out_count, out_count, data = get_count(data)
    logging.info('number of transaction outputs: %d', out_count)
    raw_outputs, outputs, data = parse_outputs(out_count, data)
    logging.debug('length of data after parse_outputs: %d', len(data))
    raw_transaction += (raw_in_count + b''.join(raw_inputs) +
        raw_out_count + b''.join(raw_outputs))
    lock_time, data = data[:4], data[4:]
    raw_transaction += lock_time
    logging.info('lock time: %s', to_hex(lock_time))
    logging.debug('raw transaction (%d bytes): %s',
                  len(raw_transaction), to_hex(raw_transaction))
    logging.debug('raw transaction split: %s', [
        version, raw_in_count, inputs, raw_out_count, outputs, lock_time])
    logging.info('transaction hash: %s', show_hash(get_hash(raw_transaction)))
    return raw_transaction, data

def parse_inputs(count, data):
    '''
    return transaction inputs
    '''
    raw_inputs = []
    inputs = []
    for index in range(count):
        logging.debug('parse_inputs: len(data): %d', len(data))
        tx_input, input_split, data = parse_input(data)
        raw_inputs.append(tx_input)
        inputs.append(input_split)
    return raw_inputs, inputs, data

def parse_outputs(count, data):
    '''
    return transaction outputs
    '''
    raw_outputs = []
    outputs = []
    for index in range(count):
        tx_output, output_split, data = parse_output(data)
        raw_outputs.append(tx_output)
        outputs.append(output_split)
    return raw_outputs, outputs, data

def parse_input(data):
    '''
    parse and return a single transaction input
    '''
    logging.debug('parse_input: len(data): %d', len(data))
    previous_hash = data[:32]
    logging.info('txin previous txout hash: %s', show_hash(previous_hash))
    previous_index = data[32:36]
    raw_input = data[:36]
    logging.info('txin previous txout index: %s', show_long(previous_index))
    raw_length, script_length, data = get_count(data[36:])
    raw_input += raw_length
    logging.debug('script_length: %d', script_length)
    script, data = data[:script_length], data[script_length:]
    raw_input += script
    logging.info('txin script: %r', script)
    sequence = data[:4]
    logging.info('txin sequence number: %s', show_long(sequence))
    raw_input += sequence
    split_input = [previous_hash, previous_index, raw_length, script, sequence]
    return raw_input, split_input, data[4:]

def parse_output(data):
    '''
    parse and return a single transaction output
    '''
    raw_output = raw_amount = data[:8]
    value = to_long(raw_amount)
    logging.info('txout value: %.8f', value / 100000000)
    # script probably broken if amount is very high
    if __debug__ and value > 100000000000000:
        raise ValueError('Unusual value, is script broken?')
    raw_length, script_length, data = get_count(data[8:])
    script, data = data[:script_length], data[script_length:]
    logging.info('txout script: %r', script)
    raw_output += raw_length + script
    output = [raw_amount, raw_length, script]
    return raw_output, output, data

def get_count(data):
    r'''
    extract and decode VarInt count and return it with remainder of data

    # the following failed (got 253) before VARINT dict was corrected
    >>> get_count(b'\xfd@\x01\x04\xe3v@\x05\x99')[0]
    320
    '''
    logging.debug('get_count: next 9 data bytes: %r', data[:9])
    packing, offset, length = VARINT.get(data[0], ('B', 0, 1))
    count = struct.unpack(packing, data[offset:offset + length])[0]
    raw_count, data = data[:offset + length], data[offset + length:]
    logging.debug('length of data after get_count: %d', len(data))
    return raw_count, count, data

if __name__ == '__main__':
    parse(*sys.argv[1:])
