#!/usr/bin/python3 -OO
'''
writing parser.cpp replacement in Python3

using ideas and code from
http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html,
http://www.righto.com/2014/02/bitcoin-mining-hard-way-algorithms.html,
https://bitcoin.org/en/developer-guide,
https://bitcoin.org/en/developer-reference,
and many other sources.

it won't work the same but has the same general purpose, to present block
files in a readable format.
'''
from __future__ import division, print_function
import sys, os, struct, binascii, logging, hashlib, re, time
from datetime import datetime
from glob import glob
# some Python3 to Python2 mappings
if bytes([65]) != b'A':  # python2
    class bytes(str):
        def __new__(cls, initial=''):
            if type(initial) == list:
                joined = ''.join(map(chr, initial))
                return super(bytes, cls).__new__(cls, joined)
            else:
                return super(bytes, cls).__new__(cls, initial)
        def __repr__(self):
            return 'b' + super(bytes, self).__repr__()
        __str__ = __repr__
    bytevalue = lambda byte: ord(byte)
    bytevalues = lambda string: map(ord, string)
    byte = chr
    FileNotFoundError = IOError
else:  # python3
    bytevalue = lambda byte: byte
    bytevalues = list
    byte = lambda number: chr(number).encode('latin1')

LOGLEVEL = getattr(logging, os.getenv('LOGLEVEL', 'INFO'))
logging.getLogger().level=logging.DEBUG if __debug__ else LOGLEVEL
DEFAULT = sorted(glob(os.path.expanduser('~/.bitcoin/blocks/blk*.dat')))
MAGIC = {
    'bitcoin': binascii.a2b_hex(b'F9BEB4D9'),
    'dogecoin': binascii.a2b_hex(b'C0C0C0C0'),
    'testnet': binascii.a2b_hex(b'FABFB5DA'),
    'testnet3': binascii.a2b_hex(b'0B110907'),
    'namecoin': binascii.a2b_hex(b'F9BEB4FE'),
    'americancoin': binascii.a2b_hex(b'414D433A'),
}
VARINT = {
    # struct format, offset, length
    # remember in Python3 b'\xfd'[0] == 253
    0xfd: ('<H', 1, 2),
    0xfe: ('<L', 1, 4),
    0xff: ('<Q', 1, 8),
}
# extend VARINT for Python2:
VARINT.update(dict((chr(n), l) for n, l in VARINT.items()))

UNPACKER = {
    # fetch using len(bytestring)
    1: 'B',
    2: '<H',
    4: '<L',
    8: '<Q',
}

NULLBLOCK = b'\0' * 32  # pointed to by genesis block

def nextprefix(openfile):
    '''
    helper function for nextchunk

    tries to read block prefix from an open file
    '''
    try:
        prefix = openfile.read(8)
    except AttributeError:  # openfile is None
        prefix = b''
    return prefix

def nextchunk(blockfiles=None, minblock=0, maxblock=sys.maxsize, wait=True):
    '''
    generator that fetches and returns raw blocks out of blockfiles

    with defaults, waits forever until terminated by signal
    '''
    minheight, maxheight = int(minblock), int(maxblock)
    height = 0
    reversemagic = dict([[value, key] for key, value in MAGIC.items()])
    blockfiles = blockfiles or DEFAULT
    fileindex = 0
    currentfile = None
    done = False
    while True:
        prefix = nextprefix(currentfile)
        if prefix == b'':
            try:
                newfile = open(blockfiles[fileindex], 'rb')
                fileindex += 1
                if fileindex == len(blockfiles):
                    blockfiles.append(nextfile(blockfiles[-1]))
                currentfile = newfile
            except FileNotFoundError:
                if not wait:
                    logging.info('end of current data, not waiting')
                    done = True
                else:
                    logging.debug('waiting for %s to come online',
                                  blockfiles[fileindex])
                    time.sleep(10)
                    continue
            if done:
                raise StopIteration('No more blocks at this time')
        else:
            magic = prefix[:4]
            blocksize = struct.unpack('<L', prefix[4:])[0]
            logging.debug('yielding block of size %d', blocksize)
            yield prefix + currentfile.read(blocksize)

def nextfile(filename):
    '''
    returns "next" filename in series from numbered files e.g. blk0001.dat

    >>> nextfile('blk0001.dat')
    'blk0002.dat'
    >>> try: nextfile('blk.dat')
    ... except: pass
    >>> nextfile('00041')
    '00042'
    '''
    pattern = r'^(?P<prefix>[^0-9]*)(?P<number>[0-9]+)(?P<suffix>[^0-9]*)$'
    directory, filename = os.path.split(filename)
    try:
        match = re.compile(pattern).match(filename).groupdict()
    except AttributeError as match_failed:
        raise ValueError('No numeric pattern found in {}'.format(filename))
    newnumber = '{number:0{width}}'.format(
        number=int(match['number']) + 1,
        width=len(match['number']))
    filename = match['prefix'] + newnumber + match['suffix']
    return os.path.join(directory, filename) if directory else filename

def nextblock(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    generator that fetches and returns raw blocks out of blockfiles
    '''
    minheight, maxheight = int(minblock), int(maxblock)
    height = 0
    reversemagic = dict([[value, key] for key, value in MAGIC.items()])
    blockfiles = blockfiles or DEFAULT
    for blockfile in blockfiles:
        magic = ''
        index = 0
        logging.debug('blockfile "%s" of blockfiles %s', blockfile, blockfiles)
        with open(blockfile, 'rb') as datainput:
            blockdata = datainput.read()  # not necessarily very efficient
        logging.warning('NOTE: "height" values shown are relative'
                        ' to start of first file and may include'
                        ' orphaned blocks')
        while index < len(blockdata):
            logging.debug('blockparser at index %d out of %d bytes',
                          index, len(blockdata))
            magic = blockdata[index:index + 4]
            blocksize = struct.unpack('<L', blockdata[index + 4:index + 8])[0]
            blockheader = blockdata[index + 8:index + 88]
            transactions = blockdata[index + 88:index + blocksize + 8]
            index += blocksize + 8
            if minheight <= height <= maxheight:
                logging.debug('height: %d', height)
                logging.debug('magic: %s', binascii.b2a_hex(magic))
                logging.debug('block type: %s', reversemagic.get(
                             magic, 'unknown'))
                logging.debug('block size: %d', blocksize)
                logging.debug('block header: %r', blockheader)
                logging.debug('transactions (partial): %r', transactions[:80])
                yield (height, blockheader, transactions)
            elif height > maxheight:
                logging.debug('height %d > maxheight %d', height, maxheight)
                break  # still executes `height += 1` below!
            else:
                logging.debug('height: %d', height)
            height += 1
        logging.debug('height: %d, maxheight: %d', height, maxheight)
        if height > maxheight:
            break

def parse(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    dump out block files
    '''
    minheight, maxheight = int(minblock), int(maxblock)
    logging.debug('minheight: %d, maxheight: %d', minheight, maxheight)
    height = 0
    reversemagic = dict([[value, key] for key, value in MAGIC.items()])
    blockfiles = blockfiles or DEFAULT
    # if file was specified on commandline, make it into a list
    for blockfile in blockfiles:
        magic = ''
        index = 0
        with open(blockfile, 'rb') as datainput:
            blockdata = datainput.read()  # not necessarily very efficient
        logging.warning('NOTE: "height" values shown are relative'
                        ' to start of first file and may include'
                        ' orphaned blocks')
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
                logging.info('block type: %s', reversemagic.get(
                             magic, 'unknown'))
                logging.info('block size: %d', blocksize)
                logging.info('block header: %r', blockheader)
                parse_blockheader(blockheader)
                logging.info('transactions (partial): %r', transactions[:80])
                count, data = parse_transactions(transactions)
                logging.info('transaction count: %d', count)
                logging.debug('remaining data (partial): %r', data[:80])
            elif height > maxheight:
                logging.debug('height %d > maxheight %d', height, maxheight)
                break  # still executes `height += 1` below!
            else:
                logging.debug('height: %d', height)
            height += 1
        logging.debug('height: %d, maxheight: %d', height, maxheight)
        if height > maxheight:
            break

def parse_blockheader(blockheader):
    '''
    return contents of block header
    '''
    version = blockheader[:4]
    previous = blockheader[4:36]
    merkle_root = blockheader[36:68]
    unix_time = blockheader[68:72]
    nbits = blockheader[72:76]
    nonce = blockheader[76:]
    blockhash = get_hash(blockheader)
    if len(nonce) != 4:
        raise ValueError('Nonce wrong size: %d bytes' % len(nonce))
    logging.info('block version: %s', show_long(version))
    logging.info('previous block hash: %s', show_hash(previous))
    logging.info('merkle root: %s', show_hash(merkle_root))
    logging.info('unix time: %s', timestamp(unix_time))
    logging.info('nbits: %r', to_hex(nbits))
    logging.info('nonce: %s', to_hex(nonce))
    logging.info('block hash: %s', show_hash(blockhash))
    return version, previous, merkle_root, unix_time, nbits, nonce, blockhash

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

    the str() and .decode() stuff is necessary to get an unadorned string
    in both Python2 and Python3

    to_hex('\x01\xff')
    'ff01'
    '''
    logging.debug('to_hex bytestring: %r', bytestring)
    return str(binascii.b2a_hex(bytestring).decode('utf8'))

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
        raw_transaction, transaction, data = parse_transaction(data)
        transactions.append(raw_transaction)
    return count, data

def next_transaction(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    iterates over each transaction in every input block
    '''
    logging.debug('blockfiles: %s', blockfiles)
    blockfiles = blockfiles or DEFAULT
    blocks = nextblock(blockfiles, minblock, maxblock)
    for height, header, transactions in blocks:
        logging.debug('block header from next_transaction: %s', header)
        rawcount, count, data = get_count(transactions)
        for index in range(count):
            raw_transaction, transaction, data = parse_transaction(data)
            txhash = get_hash(raw_transaction)
            yield height, txhash, transaction

class Node(object):
    '''
    tree node
    '''
    def __init__(self, parent=None, blockhash=None, blocktime=''):
        self.parent = parent
        self.blockhash = blockhash
        self.blocktime = blocktime

    def countback(self, searchblock=NULLBLOCK):
        r'''
        return list of nodes that ends with this block

        if attempting to get "height", caller is responsible to zero-base
        the result, counting the genesis block as height 0

        >>> node = Node(None, NULLBLOCK)  # not a real node
        >>> node = Node(node, b'\0')  # height 0, genesis block
        >>> node = Node(node, b'\1')  # height 1
        >>> node = Node(node, b'\2')  # height 2
        >>> len(node.countback())
        3
        >>> len(node.countback(b'\0'))
        2
        >>> try:
        ...  node.countback(None)
        ... except AttributeError:
        ...  print('failed')
        failed
        '''
        traversed = [self]
        parent = self.parent
        while parent.blockhash != searchblock:
            #logging.debug('parent.blockhash: %s', show_hash(parent.blockhash))
            traversed.insert(0, parent)
            parent = parent.parent
        return traversed

    def __str__(self):
        return "{'Node': {'hash': '%s', 'timestamp': '%s'}}" % (
            show_hash(self.blockhash),
            self.blocktime)
    __repr__ = __str__

def reorder(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    removes orphan blocks and corrects height
    '''
    logging.debug('blockfiles: %s', blockfiles)
    blockfiles = blockfiles or DEFAULT
    blocks = nextblock(blockfiles, minblock, maxblock)
    lastnode = Node(None, NULLBLOCK)
    chains = [[lastnode]]
    logging.debug('chains: %s', chains)
    chain = 0
    for height, header, transactions in blocks:
        parsed = parse_blockheader(header)
        previous, blockhash = parsed[1], parsed[6]
        blocktime = timestamp(parsed[3])
        if previous != lastnode.blockhash:
            logging.warning('reorder at block %s',
                            Node(None, blockhash, blocktime))
            logging.debug('previous block should be: %s', show_hash(previous))
            logging.info('lastnode: %s', lastnode)
            found, count = None, 0
            try:
                logging.debug('assuming previous block in this same chain')
                nodes = lastnode.countback(previous)
                found = nodes[0].parent
                logging.info('reorder found %s %d blocks back',
                              found, len(nodes) + 1)
                chain = len(chains)
                chains.append([])
            except AttributeError:
                logging.debug('searching other chains')
                for chain in reversed(chains):
                    node = chain[-1]
                    if node.blockhash == previous:
                        logging.info('reorder found %s at end of another chain',
                                      found)
                        found = node
                        chain = chains.index(chain)
                for chain in reversed(chains):
                    found = ([node for node in chain
                              if node.blockhash == previous] + [None])[0]
                    if found is not None:
                        logging.info('reorder found %s in another chain',
                                      found)
                        chain = len(chains)
                        chains.append([])
                        break
            if found is None:
                raise ValueError('Previous block %s not found', previous)
            else:
                lastnode = found
                # sanity check on above programming
                assert_true(previous == lastnode.blockhash)
        node = Node(lastnode, blockhash, blocktime)
        chains[chain].append(node)
        logging.info('current chain: %d out of %d', chain, len(chains))
        lastnode = node
    nodes = chains[chain][-1].countback()
    logging.info('final [real] height: %d out of %d', len(nodes) - 1, height)
    print(nodes)

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
    transaction = [version, raw_in_count, inputs, raw_out_count,
                   outputs, lock_time]
    logging.debug('raw transaction split: %s', transaction)
    logging.info('transaction hash: %s', show_hash(get_hash(raw_transaction)))
    return raw_transaction, transaction, data

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
    logging.debug('first part of output: %s', to_hex(data[:256]))
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
    >>> get_count(b'\xfd@\x01\x04\xe3v@\x05\x99')[1]
    320
    >>> get_count(b'\xfdP\x01D\x87\x1c\x00\x00\x00')[1]
    336
    '''
    logging.debug('get_count: next 9 data bytes: %r', data[:9])
    packing, offset, length = VARINT.get(data[0], ('B', 0, 1))
    logging.debug('packing: %s, offset: %d, length: %d',
                  packing, offset, length)
    count = struct.unpack(packing, data[offset:offset + length])[0]
    raw_count, data = data[:offset + length], data[offset + length:]
    logging.debug('length of data after get_count: %d', len(data))
    return raw_count, count, data

def coins(transaction_amount):
    '''
    unpack satoshis quadword and divide by 100000000 to get fractional coins
    '''
    return struct.unpack('<Q', transaction_amount)[0] / 100000000

def varint_length(data):
    r'''
    create new VarInt count of raw data
    
    >>> repr(varint_length('\0' * 512)).endswith("'\\xfd\\x00\\x02'")
    True
    '''
    length = len(data)
    if length < 0xfd:
        return bytes([length])
    elif length <= 0xffff:
        return b'\xfd' + struct.pack('<H', length)
    elif length <= 0xffffffff:
        return b'\xfe' + struct.pack('<L', length)
    else:  # will throw struct.error if above quad range
        return b'\xff' + struct.pack('<Q', length)

# make sure assertions work even if optimized
try:
    assert 1 == 0  # check if running optimized
    # the above would have raised an AssertionError if not
    def assert_true(statement):
        if not statement:
            raise AssertionError
except AssertionError:
    def assert_true(statement):
        assert(statement)

if __name__ == '__main__':
    blockparse = parse
    COMMAND = os.path.splitext(os.path.split(sys.argv[0])[1])[0]
    BLOCKFILES = [sys.argv[1]] if len(sys.argv) > 1 else DEFAULT
    eval(COMMAND)(BLOCKFILES, *sys.argv[2:])
