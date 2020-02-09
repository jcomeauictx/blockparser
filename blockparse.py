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
import sys, os, struct, binascii, logging, hashlib, re, time, pprint
from datetime import datetime
from glob import glob
from collections import defaultdict
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
        def __getitem__(self, index):
            return ord(super(bytes, self).__getitem__(index))
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
MAGIC.update([[value, key] for key, value in MAGIC.items()])
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
PREFIX_LENGTH = 8  # block prefix
HEADER_LENGTH = 80  # block header
CONFIRMATIONS = 6  # confirmations before we count a block in blockchain
RAWBLOCKS = []  # storage for blocks in file order
BLOCKS = []  # storage for blocks in blockchain order
BLOCKCHAIN = {}  # blocks indexed by hash
NEXTBLOCK = defaultdict(list)  # blocks indexed by previous hash
CHAINS = {}  # main and orphan chains
STATE = {
    'phase': 'pre-initialization',
}
COMMAND = os.path.splitext(os.path.split(sys.argv[0])[1])[0]
BLOCKFILES = [sys.argv[1]] if len(sys.argv) > 1 and sys.argv[1] else DEFAULT

def nextprefix(openfile):
    '''
    helper function for nextchunk

    tries to read block prefix from an open file
    '''
    offset = openfile.tell()
    prefix = openfile.read(PREFIX_LENGTH)
    try:
        blocksize = struct.unpack('<L', prefix[4:])[0]
    except struct.error:
        blocksize = 0
    blocktype = MAGIC.get(prefix[:4], 'unknown')
    return prefix, blocktype, blocksize, offset

def nextchunk(blockfiles=None, minblock=0, maxblock=sys.maxsize, wait=True):
    '''
    generator that fetches and returns raw blocks out of blockfiles

    with defaults, waits forever until terminated by signal
    NOTE: block "height" here refers only to relative position in files

    NOTE: block files may be prefilled with zeroes. a prefix of all zeroes
    should be treated the same as a failed read.

    if an attempted read returns b'', it could mean 2 things:
    (1) that file has been closed, and a new one is being opened for output
    (2) that file is still open for more blocks
    '''
    minheight, maxheight = int(minblock), int(maxblock)
    height = 0
    blockfiles = blockfiles or DEFAULT
    fileindex = 0
    offset = None  # into current blockfile
    currentfile = None
    done = False
    while height <= maxheight:
        if currentfile is None or currentfile.closed:
            currentfile = open(blockfiles[fileindex], 'rb')
        prefix, blocktype, blocksize, offset = nextprefix(currentfile)
        logging.debug('prefix at offset 0x%x: %r', offset, prefix)
        if prefix == b'':
            if fileindex == len(blockfiles) - 1:  # on last known file
                nextblockfile = nextfile(blockfiles[-1])
                if os.path.exists(nextblockfile):
                    blockfiles.append(nextblockfile)
                    fileindex += 1
                    currentfile.close()
                    continue
            else:
                fileindex += 1
                currentfile.close()
                continue
            STATE['phase'] = 'serving'
            if not wait:
                logging.info('end of current data, not waiting')
                done = True
            else:
                logging.debug('waiting for %s to come online',
                              blockfiles[fileindex])
                time.sleep(10)
                # following 3 lines probably not necessary, but since we're
                # in a delay loop anyway, can't really hurt either.
                currentfile.close()
                currentfile = open(currentfile.name, 'rb')
                currentfile.seek(offset)
                continue
            if done:
                raise StopIteration('No more blocks at this time')
        elif not any(bytes(prefix)):  # all zeroes
            STATE['phase'] = 'serving'
            if not wait:
                logging.info('end of current data, not waiting')
                done = True
            else:
                logging.debug('waiting for %s to obtain next block',
                              blockfiles[fileindex])
                time.sleep(10)
                # close and reopen to see new content
                # why necessary? don't know. maybe bitcoind doesn't flush()
                currentfile.close()
                currentfile = open(currentfile.name, 'rb')
                currentfile.seek(offset)
                continue
            if done:
                raise StopIteration('No more blocks at this time')
        else:
            logging.debug('block of size 0x%x at height %d', blocksize, height)
            if minheight <= height <= maxheight:
                blockdata = currentfile.read(blocksize)
                blockheader = blockdata[:HEADER_LENGTH]
                yield {
                    'rawblock': prefix + blockdata,
                    'rawheight': height,
                    'file': blockfiles[fileindex],
                    'offset': offset,
                    'length': blocksize + PREFIX_LENGTH,
                    'currency': blocktype,
                }
            elif height > maxheight:
                raise StopIteration('Returned all requested blocks')
            else:
                logging.debug('discarding block at height %d', height)
                currentfile.seek(blocksize, os.SEEK_CUR)
            height += 1

def nextblock(blockfiles=None, minblock=0, maxblock=sys.maxsize, wait=True):
    '''
    return confirmed blocks in blockchain order

    uses globals BLOCKCHAIN and CHAINS
    '''
    blockfiles = blockfiles or DEFAULT
    chunks = nextchunk(blockfiles, minblock, maxblock, wait)
    previous_hash = show_hash(NULLBLOCK)
    last = -1  # last block returned
    # initialize BLOCKCHAIN and CHAINS globals
    BLOCKCHAIN[previous_hash] = {'children': [], 'hash': previous_hash}
    CHAINS.update(BLOCKCHAIN)  # all chains including main chain
    blocks = []  # main chain, in order
    for chunk in chunks:
        rawblock = chunk.pop('rawblock')[PREFIX_LENGTH:]
        block = blockheader(rawblock)
        block.update(chunk)
        block['children'] = []
        BLOCKCHAIN[block['hash']] = block
        changed = False
        if block['previous'] in BLOCKCHAIN:
            connect(block, BLOCKCHAIN)
            changed = True
        else:
            logging.debug('orphan block %s found', block['hash'])
            CHAINS[block['hash']] = block
        logging.debug('blocks found so far: %d', len(BLOCKCHAIN) - 1)
        logging.debug('chains found so far: %d', len(CHAINS))
        # consolidate chains
        for key in list(CHAINS):
            if key == show_hash(NULLBLOCK):
                continue
            elif CHAINS[key]['previous'] in BLOCKCHAIN:
                logging.debug('connecting previously orphan block %s',
                              CHAINS[key]['hash'])
                connect(CHAINS.pop(key), BLOCKCHAIN)
                changed = True
        logging.debug('chains after consolidation: %d', len(CHAINS))
        if changed:
            BLOCKS[:] = listchain(CHAINS[show_hash(NULLBLOCK)], BLOCKCHAIN)
            logging.debug('main chain length: %s', len(BLOCKS))
            # when chain has 7 blocks, block 0 has 6 confirmations
            available = len(BLOCKS) - CONFIRMATIONS - 1
            while available >= 0 and last < available:
                last += 1
                yield BLOCKS[last]

def listchain(root, blockchain):
    '''
    return blockchain as list after integrity check
    '''
    block = root
    # don't include fake null block in main chain
    blocks = [block] if 'previous' in block else []
    while block and len(block['children']):
        if blockchain[block['children'][0]]['previous'] == block['hash']:
            block = blockchain[block['children'][0]]
            blocks.append(block)
        else:
            raise ValueError('Broken chain at block %s' % block)
    return blocks

def connect(block, blocks):
    '''
    hook this block into an existing chain
    '''
    previous = blocks[block['previous']]
    if block['hash'] in previous['children']:
        logging.warning('duplicate block %s', block['hash'])
        previous['children'].remove(block['hash'])
    logging.debug('inserting block %s into %s', block, previous)
    previous['children'].insert(0, block['hash'])
    if len(previous['children']) > 1:
        logging.warning('block %s replaced %s',
                        previous['children'][0],
                        previous['children'][1])

def serve(blockfiles=None, minblock=0, maxblock=sys.maxsize, wait=True):
    '''
    first index all blocks, then run as a server, returning requested data
    '''
    blockfiles = blockfiles or DEFAULT
    logging.debug('serve: blockfiles: %s', blockfiles)
    blocks = nextblock(blockfiles, minblock, maxblock, wait)
    previous_hash = show_hash(NULLBLOCK)
    STATE['phase'] = 'indexing'
    for block in blocks:
        logging.info('block: %s', block)

def explorer(environ, start_response):
    '''
    implement a uWSGI block explorer
    '''
    start_response('200 gotcha', [('Content-type', 'text/plain')])
    return [('BLOCKS length now: %s' % len(BLOCKS)).encode('utf8')]

def nextfile(filename):
    '''
    returns "next" filename in series from numbered files e.g. blk0001.dat

    >>> nextfile('blk0001.dat')
    'blk0002.dat'
    >>> try: nextfile('blk.dat')
    ... except ValueError: pass
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

def catchup():
    '''
    try to catch up BLOCKS to RAWBLOCKS
    '''
    logging.debug('len(RAWBLOCKS): %d, len(BLOCKS): %d', len(RAWBLOCKS),
                  len(BLOCKS))
    for attempt in range(len(RAWBLOCKS) - len(BLOCKS)):
        block = BLOCKS[-1]
        previous_hash = block['hash']
        if previous_hash in NEXTBLOCK:
            following = NEXTBLOCK[previous_hash][0]
            logging.debug('appending block %s to BLOCKS', following['hash'])
            BLOCKS.append(following)
            previous_hash = following['hash']
        else:
            logging.debug('cannot find hash %s in NEXTBLOCK', previous_hash)
            break
    return previous_hash

def oldnextblock(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    generator that fetches and returns raw blocks out of blockfiles
    '''
    minheight, maxheight = int(minblock), int(maxblock)
    height = 0
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
                logging.debug('block type: %s', MAGIC.get(magic, 'unknown'))
                logging.debug('block size: %d', blocksize)
                logging.debug('block hash: %s',
                              show_hash(get_hash(blockheader)))
                logging.debug('transactions (partial): %r', transactions[:80])
                yield (height, blockheader, transactions)
            elif height > maxheight:
                logging.debug('height %d > maxheight %d', height, maxheight)
                break
            else:
                logging.debug('height: %d', height)
            height += 1
        logging.debug('height: %d, maxheight: %d', height, maxheight)
        if height > maxheight:
            break

def blockparse(blockfiles=None, minblock=0, maxblock=sys.maxsize, wait=False):
    '''
    dump out block files
    '''
    minheight, maxheight = int(minblock), int(maxblock)
    logging.debug('minheight: %d, maxheight: %d', minheight, maxheight)
    height = 0
    blockfiles = blockfiles or DEFAULT
    chunks = nextchunk(blockfiles, minblock, maxblock, wait)
    logging.warning('NOTE: "height" values shown are relative'
                    ' to start of first file and may include'
                    ' orphaned blocks')
    for chunk in chunks:
        rawblock = chunk.pop('rawblock')[PREFIX_LENGTH:]
        block = blockheader(rawblock)
        block.update(chunk)
        if minheight <= height <= maxheight:
            logging.debug('block: %s', block)
        elif height > maxheight:
            logging.debug('height %d > maxheight %d', height, maxheight)
            break
        else:
            logging.debug('height: %d', height)
        height += 1

def blockheader(block):
    '''
    return contents of block header as dict
    '''
    header = {}
    header['version'] = to_hex(block[:4])
    header['previous'] = show_hash(block[4:36])  # hash of previous block
    header['merkle_root'] = show_hash(block[36:68])
    header['unix_time'] = timestamp(block[68:72])
    header['nbits'] = to_hex(block[72:76])
    header['nonce'] = to_hex(block[76:80])
    header['hash'] = show_hash(get_hash(block[:80]))
    logging.debug('header: %s', header)
    return header

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
    #logging.debug('to_hex bytestring: %r', bytestring)
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

def get_transactions(block):
    '''
    read in block and return the raw transaction data
    '''
    with open(block['file'], 'rb') as infile:
        infile.seek(block['offset'] + HEADER_LENGTH + PREFIX_LENGTH)
        data = infile.read(block['length'] - HEADER_LENGTH - PREFIX_LENGTH)
        return data

def next_transaction(blockfiles=None, minblock=0,
        maxblock=sys.maxsize, wait=True):
    '''
    iterates over each transaction in every input block
    '''
    logging.debug('blockfiles: %s', blockfiles)
    blockfiles = blockfiles or DEFAULT
    blocks = nextblock(blockfiles, minblock, maxblock, wait)
    for block in blocks:
        transactions = get_transactions(block)
        rawcount, count, data = get_count(transactions)
        logging.debug('transaction count for block %s: %s',
                      block['rawheight'], count)
        for index in range(count):
            raw_transaction, transaction, data = parse_transaction(data)
            txhash = get_hash(raw_transaction)
            yield block['rawheight'], txhash, transaction

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
    logging.debug('calling %s with args %s', COMMAND, sys.argv[1:])
    try:
        eval(COMMAND)(BLOCKFILES, *sys.argv[2:])
    except KeyboardInterrupt:
        logging.error('KeyboardInterrupt, please wait for globals()...')
        pprint.pprint(globals(), stream=sys.stderr)
elif sys.argv and sys.argv[0] == 'uwsgi':
    logging.warning('args: %r', sys.argv)
    import uwsgi, threading
    logging.debug('uwsgi.opt: %s' % repr(uwsgi.opt))
    SERVER = threading.Thread(
        target=serve,
        name='server',
        args=(BLOCKFILES,) + tuple(*sys.argv[2:]))
    SERVER.daemon = True
    SERVER.start()
else:
    logging.error('nothing more for %s to do on import, args: %r',
                  __name__, sys.argv)
