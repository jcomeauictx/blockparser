#!/usr/bin/python3 -OO
'''
display and execute bitcoin stack scripts
'''
import sys, os, struct, logging, copy, hashlib, re
from binascii import b2a_hex, a2b_hex
# cheating for now until I can write my own
# pip install --user git+https://github.com/jcomeauictx/python-bitcoinlib.git
from bitcoin.core.key import CECKey
from blockparse import next_transaction, varint_length, show_hash, to_long
from collections import OrderedDict
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

COMMAND = os.path.splitext(os.path.split(sys.argv[0])[1])[0]

if COMMAND in ['pydoc', 'doctest']:
    DOCTESTDEBUG = logging.debug
else:
    DOCTESTDEBUG = lambda *args, **kwargs: None

# some Python3 to Python2 mappings
if bytes([65]) != b'A':  # python2
    class bytes(str):
        def __new__(cls, numberlist=''):
            return super(bytes, cls).__new__(cls, ''.join(map(chr, numberlist)))
        def __str__(self):
            return 'b' + super(bytes, self).__repr__()
    bytevalue = lambda byte: ord(byte)
    bytevalues = lambda string: map(ord, string)
    byte = chr
else:  # python3
    bytevalue = lambda byte: byte
    bytevalues = list
    byte = lambda number: chr(number).encode('latin1')

# each item in SCRIPT_OPS gives:
#  its numeric value in hexadecimal;
#  its "representation", most readable way to display the opcode;
#  the Python routine to be `exec`d in the context of the `run` routine;
#  the Python routine to be `exec`d in the context of an inactive IF-ELSE branch
SCRIPT_OPS = (
    (0x00, [
        'FALSE',
        'op_false',
        'op_nop']
    ),
)
SCRIPT_OPS += tuple(  # 0x01 through 0x4b are all implied PUSH operations
    (opcode, [
        'op_pushdata',
        'op_pushdata',
        'skip']
    )
    for opcode in range(0x01, 0x4c)
)
SCRIPT_OPS += (
    (0x4c, [
        'op_pushdata1',
        'op_pushdata1',
        'skip']
    ),
    (0x4d, [
        'op_pushdata2',
        'op_pushdata2',
        'skip']
    ),
    (0x4e, [
        'op_pushdata4',
        'op_pushdata4',
        'skip']
    ),
    (0x4f, [
        '-1',
        'op_1negate',
        'op_nop']
    ),
    (0x50, [
        'RESERVED',
        'op_reserved',
        'op_nop']
    ),
    (0x51, [
        'TRUE',
        'op_number',
        'op_nop']
    )
)
SCRIPT_OPS += tuple(  # 0x52 - 0x60 are OP_2 through OP_16
    (opcode, [
        'op_shownumber',
        'op_number',
        'op_nop'])
    for opcode in range(0x52, 0x61)
)
SCRIPT_OPS += (
    (0x61, [
        'NOP',
        'op_nop',
        'op_nop']
    ),
    (0x62, [
        'VER',
        'op_reserved',
        'op_nop']
    ),
    (0x63, [
        'IF',
        'op_if',
        'op_nop']
    ),
    (0x64, [
        'NOTIF',
        'op_notif',
        'op_nop']
    ),
    (0x65, [
        'VERIF',
        'op_reserved',
        'op_nop']
    ),
    (0x66, [
        'VERNOTIF',
        'op_reserved',
        'op_nop']
    ),
    (0x67, [
        'ELSE',
        'op_else',
        'op_notif']
    ),
    (0x68, [
        'ENDIF',
        'op_endif',
        'op_nop']
    ),
    (0x69, [
        'VERIFY',
        'op_verify',
        'op_nop']
    ),
    (0x6a, [
        'RETURN',
        'op_return',
        'op_nop']
    ),
    (0x6b, [
        'TOALTSTACK',
        'op_toaltstack',
        'op_nop']
    ),
    (0x6c, [
        'FROMALTSTACK',
        'op_fromaltstack'
        'op_nop']
    ),
    (0x6d, [
        '2DROP',
        'op_2drop',
        'op_nop']
    ),
    (0x6e, [
        '2DUP',
        'op_2dup',
        'op_nop']
    ),
    (0x6f, [
        '3DUP',
        'op_3dup',
        'op_nop']
    ),
    (0x70, [
        '2OVER',
        'op_2over',
        'op_nop']
    ),
    (0x71, [
        '2ROT',
        'op_2rot',
        'op_nop']
    ),
    (0x72, [
        '2SWAP',
        'op_2swap',
        'op_nop']
    ),
    (0x73, [
        'IFDUP',
        'op_ifdup',
        'op_nop']
    ),
    (0x74, [
        'DEPTH',
        'op_depth',
        'op_nop']
    ),
    (0x75, [
        'DROP',
        'op_drop',
        'op_nop']
    ),
    (0x76, [
        'DUP',
        'op_dup',
        'op_nop']
    ),
    (0x77, [
        'NIP',
        'op_nip',
        'op_nop']
    ),
    (0x78, [
        'OVER',
        'op_over',
        'op_nop']
    ),
    (0x79, [
        'PICK',
        'op_pick',
        'op_nop']
    ),
    (0x7a, [
        'ROLL',
        'op_roll',
        'op_nop']
    ),
    (0x7b, [
        'ROT',
        'op_rot',
        'op_nop']
    ),
    (0x7c, [
        'SWAP',
        'op_swap',
        'op_nop']
    ),
    (0x7d, [
        'TUCK',
        'op_tuck',
        'op_nop']
    ),
    (0x7e, [
        'CAT',
        'op_cat',
        'op_nop']
    ),
    (0x7f, [
        'SUBSTR',
        'op_substr',
        'op_nop']
    ),
    (0x80, [
        'LEFT',
        'op_left',
        'op_nop']
    ),
    (0x81, [
        'RIGHT',
        'op_right',
        'op_nop']
    ),
    (0x82, [
        'SIZE',
        'op_size',
        'op_nop']
    ),
    (0x83, [
        'INVERT',
        'op_invert',
        'op_nop']
    ),
    (0x84, [
        'AND',
        'op_and',
        'op_nop']
    ),
    (0x85, [
        'OR',
        'op_or',
        'op_nop']
    ),
    (0x86, [
        'XOR',
        'op_xor',
        'op_nop']
    ),
    (0x87, [
        'EQUAL',
        'op_equal',
        'op_nop']
    ),
    (0x88, [
        'EQUALVERIFY',
        'op_equalverify',
        'op_nop']
    ),
    (0x89, [
        'RESERVED1',
        'reserved',
        'op_nop']
    ),
    (0x8a, [
        'RESERVED2',
        'reserved',
        'op_nop']
    ),
    (0x8b, [
        '1ADD',
        'op_1add',
        'op_nop']
    ),
    (0x8c, [
        '1SUB',
        'op_1sub',
        'op_nop']
    ),
    (0x8d, [
        '2MUL',
        'op_2mul',
        'op_nop']
    ),
    (0x8e, [
        '2DIV',
        'op_2div',
        'op_nop']
    ),
    (0x8f, [
        'NEGATE',
        'op_negate',
        'op_nop']
    ),
    (0x90, [
        'ABS',
        'op_abs',
        'op_nop']
    ),
    (0x91, [
        'NOT',
        'op_not',
        'op_nop']
    ),
    (0x92, [
        '0NOTEQUAL',
        'op_0notequal',
        'op_nop']
    ),
    (0x93, [
        'ADD',
        'op_add',
        'op_nop']
    ),
    (0x94, [
        'SUB',
        'op_sub',
        'op_nop']
    ),
    (0x95, [
        'MUL',
        'op_mul',
        'op_nop']
    ),
    (0x96, [
        'DIV',
        'op_div',
        'op_nop']
    ),
    (0x97, [
        'MOD',
        'op_mod',
        'op_nop']
    ),
    (0x98, [
        'LSHIFT',
        'op_lshift',
        'op_nop']
    ),
    (0x99, [
        'RSHIFT',
        'op_rshift',
        'op_nop']
    ),
    (0x9a, [
        'BOOLAND',
        'op_booland',
        'op_nop']
    ),
    (0x9b, [
        'BOOLOR',
        'op_boolor',
        'op_nop']
    ),
    (0x9c, [
        'NUMEQUAL',
        'op_numequal',
        'op_nop']
    ),
    (0x9d, [
        'NUMEQUALVERIFY',
        'op_numequalverify',
        'op_nop']
    ),
    (0x9e, [
        'NUMNOTEQUAL',
        'op_numnotequal',
        'op_nop']
    ),
    (0x9f, [
        'LESSTHAN',
        'op_lessthan',
        'op_nop']
    ),
    (0xa0, [
        'GREATERTHAN',
        'op_greaterthan',
        'op_nop']
    ),
    (0xa1, [
        'LESSTHANOREQUAL',
        'op_lessthanorequal',
        'op_nop']
    ),
    (0xa2, [
        'GREATERTHANOREQUAL',
        'op_greaterthanorequal',
        'op_nop']
    ),
    (0xa3, [
        'MIN',
        'op_min',
        'op_nop']
    ),
    (0xa4, [
        'MAX',
        'op_max',
        'op_nop']
    ),
    (0xa5, [
        'WITHIN',
        'op_within',
        'op_nop']
    ),
    (0xa6, [
        'RIPEMD160',
        'op_ripemd160',
        'op_nop']
    ),
    (0xa7, [
        'SHA1',
        'op_sha1',
        'op_nop']
    ),
    (0xa8, [
        'SHA256',
        'op_sha256',
        'op_nop']
    ),
    (0xa9, [
        'HASH160',
        'op_hash160',
        'op_nop']
    ),
    (0xaa, [
        'HASH256',
        'op_hash256',
        'op_nop']
    ),
    (0xab, [
        'CODESEPARATOR',
        'op_codeseparator',
        'op_codeseparator']
    ),
    (0xac, [
        'CHECKSIG',
        'op_checksig',
        'op_nop']
    ),
    (0xad, [
        'CHECKSIGVERIFY',
        'op_checksigverify',
        'op_nop']
    ),
    (0xae, [
        'CHECKMULTISIG',
        'op_checkmultisig',
        'op_nop']
    ),
    (0xaf, [
        'CHECKMULTISIGVERIFY',
        'checkmultisigverify',
        'op_nop']
    ),
    (0xb0, [
        'NOP1',
        'op_nop',
        'op_nop']
    ),
    (0xb1, [
        'CHECKLOCKTIMEVERIFY',
        'op_checklocktimeverify',
        'op_nop']
    ),
    (0xb2, [
        'CHECKSEQUENCEVERIFY',
        'op_checksequenceverify',
        'op_nop']
    ),
)
SCRIPT_OPS += tuple(  # 0xb3 - 0xb9 are NOP_4 through NOP_10
    (opcode, [
        'NOP%d' % (opcode - 0xaf),
        'op_nop',
        'op_nop'])
    for opcode in range(0xb3, 0xba)
)

LOOKUP = dict([[value[0], key] for key, value in dict(SCRIPT_OPS).items()
              if re.compile('^-?[A-Z0-9]+$').match(value[0])])
DISABLED = [  # add all opcodes disabled in bitcoin-core
# make sure to list both by number and chr (for python2)
    0x83, 0x84, 0x85, 0x86
]
logging.debug('DISABLED: %s', DISABLED)
COINBASE = b'\0' * 32  # previous_tx hash all nulls indicates coinbase tx
BASE58DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
FIRST = (
    # first transaction made on blockchain other than coinbase rewards
    # from block 170, see https://en.bitcoin.it/wiki/OP_CHECKSIG
    [b'\x01\x00\x00\x00', b'\x01', [  # inputs
        [b'\xc9\x97\xa5\xe5n\x10A\x02\xfa \x9cj\x85-\xd9\x06`\xa2\x0b-\x9c5$#'
         b'\xed\xce%\x85\x7f\xcd7\x04', b'\x00\x00\x00\x00', b'H',
         b'G0D\x02 NE\xe1i2\xb8\xafQIa\xa1\xd3\xa1\xa2_\xdf?Ow2\xe9\xd6$\xc6'
         b'\xc6\x15H\xab_\xb8\xcdA\x02 \x18\x15"\xec\x8e\xca\x07\xdeH`\xa4\xac'
         b'\xdd\x12\x90\x9d\x83\x1c\xc5l\xbb\xacF"\x08"!\xa8v\x8d\x1d\t\x01',
         b'\xff\xff\xff\xff']
        ], b'\x02', [  # outputs
        [b'\x00\xca\x9a;\x00\x00\x00\x00', b'C',
         b'A\x04\xae\x1ab\xfe\t\xc5\xf5\x1b\x13\x90_\x07\xf0k\x99\xa2\xf7\x15'
         b'\x9b"%\xf3t\xcd7\x8dq0/\xa2\x84\x14\xe7\xaa\xb3s\x97\xf5T\xa7\xdf_'
         b'\x14,!\xc1\xb70;\x8a\x06&\xf1\xba\xde\xd5\xc7*pO~l\xd8L\xac'],
        [b'\x00(k\xee\x00\x00\x00\x00', b'C',
         b'A\x04\x11\xdb\x93\xe1\xdc\xdb\x8a\x01kI\x84\x0f\x8cS\xbc\x1e\xb6'
         b'\x8a8.\x97\xb1H.\xca\xd7\xb1H\xa6\x90\x9a\\\xb2\xe0\xea\xdd\xfb'
         b'\x84\xcc\xf9tDd\xf8.\x16\x0b\xfa\x9b\x8bd\xf9\xd4\xc0?\x99\x9b\x86C'
         b'\xf6V\xb4\x12\xa3\xac']
        ], b'\x00\x00\x00\x00'
    ],
    # previous transaction (in block 9)
    [b'\x01\x00\x00\x00', b'\x01', [  # inputs
        [b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
         b'\x00\x00', b'\xff\xff\xff\xff', b'\x07',
         b'\x04\xff\xff\x00\x1d\x014', b'\xff\xff\xff\xff']
        ], b'\x01', [  # outputs
        [b'\x00\xf2\x05*\x01\x00\x00\x00', b'C',
         b'A\x04\x11\xdb\x93\xe1\xdc\xdb\x8a\x01kI\x84\x0f\x8cS\xbc\x1e\xb6'
         b'\x8a8.\x97\xb1H.\xca\xd7\xb1H\xa6\x90\x9a\\\xb2\xe0\xea\xdd\xfb'
         b'\x84\xcc\xf9tDd\xf8.\x16\x0b\xfa\x9b\x8bd\xf9\xd4\xc0?\x99\x9b'
         b'\x86C\xf6V\xb4\x12\xa3\xac']
        ], b'\x00\x00\x00\x00'
    ]
)
PIZZA = (  # pizza transaction from block 57044
    [b'\x01\x00\x00\x00', b'\x01', [  # inputs
        [b'\x8d\xd4\xf5\xfb\xd5\xe9\x80\xfc\x02\xf3\\l\xe1E\x93[\x11\xe2\x84'
         b'`[\xf5\x99\xa1<mA]\xb5]\x07\xa1', b'\x00\x00\x00\x00',
         b'\x8b', b'H0E\x02!\x00\x99\x08\x14L\xa6S\x9e\tQ+\x92\x95\xc8\xa2pP'
         b'\xd4x\xfb\xb9o\x8a\xdd\xbc=\x07UD\xdcA2\x87\x02 \x1a\xa5(\xbe+\x90'
         b'}1m-\xa0h\xdd\x9e\xb1\xe22C\xd9~DMY)\r/\xdd\xf2Ri\xee\x0e\x01A\x04'
         b'.\x93\x0f9\xbab\xc6SN\xe9\x8e\xd2\x0c\xa9\x89Y\xd3J\xa9\xe0W\xcd'
         b'\xa0\x1c\xfdB,k\xab6g\xb7d&R\x93\x82\xc2?B\xb9\xb0\x8dx2\xd4\xfe'
         b'\xe1\xd6\xb47\xa8RnYf|\xe9\xc4\xe9\xdc\xeb\xca\xbb',
         b'\xff\xff\xff\xff']
    ], b'\x02', [  # outputs
        [b'\x00q\x9a\x81\x86\x00\x00\x00', b'\x19',
         b"v\xa9\x14\xdf\x1b\xd4\x9al\x9e4\xdf\xa8c\x1f,T\xcf9\x98`'P\x1b\x88"
         b'\xac'],
        [b'\x00\x9f\nSb\x00\x00\x00', b'C',
         b'A\x04\xcd^\x97&\xe6\xaf\xea\xe3W\xb1\x80k\xe2ZL=8\x11wX5\xd25A~'
         b'\xa7F\xb7\xdb\x9e\xea\xb3<\xf0\x16t\xb9D\xc6Ea\xce3\x88\xfa\x1a'
         b'\xbd\x0f\xa8\x8b\x06\xc4L\xe8\x1e"4\xaap\xfeW\x8dE]\xac']
        ], b'\x00\x00\x00\x00'
    ],
    # previous transaction (in block 57043)
    # too many inputs, just showing outputs
    [b'\x01\x00\x00\x00', b'\x00', [
    ], b'\x01', [  # single output
        [b'\x00\x10\xa5\xd4\xe8\x00\x00\x00', b'\x19',
         b"v\xa9\x14F\xaf?\xb4\x81\x83\x7f\xad\xbbB\x17'\xf9\x95\x9c-2\xa3"
         b'h)\x88\xac']
        ], b'\x00\x00\x00\x00'
    ]
) 

class TransactionInvalidError(ValueError):
    pass

class ReservedWordError(ValueError):
    pass

def script_compile(script):
    r'''
    compiles Script source into bytestring

    NOTE that if you're submitting script from the command-line, any numbers
    will be seen as strings and you are unlikely to get the expected result.

    from https://en.bitcoin.it/wiki/Script:

    When used as numbers, byte vectors are interpreted as little-endian
    variable-length integers with the most significant bit determining the
    sign of the integer. Thus 0x81 represents -1. 0x80 is another
    representation of zero (so called negative 0). Positive 0 is
    represented by a null-length vector.

    Arithmetic inputs are limited to signed 32-bit integers, but may
    overflow their output.

    >>> test = ['FALSE']
    >>> parse(script_compile(test), display=False)[1] == test
    True
    >>> test = ['DUP', 'HASH160', b'\xa0' * 20, 'EQUALVERIFY', 'CHECKSIG']
    >>> logging.debug('test: %s', test)
    >>> compiled = script_compile(test)
    >>> logging.debug('compiled: %r', compiled)
    >>> check = parse(compiled, display=False)[1]
    >>> logging.debug('check: %s', check)
    >>> test == check
    True
    '''
    compiled = b''
    for word in script:
        if word in LOOKUP:
            compiled += bytes([LOOKUP[word]])
            continue
        elif type(word) == str:
            try:
                word = a2b_hex(word)
            except TypeError:
                logging.warning('%r is not hex, assuming already bytes', word)
                pass
        elif type(word) == int:
            if word in [0, 1, -1]:  # there's a word for that
                compiled += script_compile([['FALSE', 'TRUE', '-1'][word]])
                continue
            elif word in range(2, 16 + 1):
                compiled += bytes([word + 0x50])
                continue
            elif abs(word) <= 127:
                word = struct.pack('B', word | [0, 0x80][word < 0])
            elif abs(word) <= 32767:
                word = struct.pack('<H', word | [0, 0x8000][word < 0])
            else:  # let's not bother with 3-byte representations
                word = struct.pack('<L', word | [0, 0x80000000][word < 0])
        # by now, word is assumed to be a bytestring
        if len(word) <= 75:
            compiled += bytes([len(word)]) + word
        elif len(word) <= 0xff:
            compiled += b'\x4c' + struct.pack('B', len(word)) + word
        elif len(word) <= 0xffff:
            compiled += b'\x4d' + struct.pack('<H', len(word)) + word
        else:
            compiled += b'\x4e' + struct.pack('<L', len(word)) + word
    return compiled

def parse(scriptbinary, display=True):
    '''
    breaks down binary script into something readable (to a FORTHer)

    returns same-sized list of opcodes parsed from script
    '''
    stack = []
    kwargs = {}
    opcodes = dict(SCRIPT_OPS)
    #logging.debug('opcodes: %s', opcodes)
    kwargs['script'] = script = bytevalues(scriptbinary)
    parsed = [None] * len(script)
    while script:
        parsed[-len(script)] = script[0]
        kwargs['opcode'] = opcode = script.pop(0)
        operation = opcodes.get(opcode, None)
        logging.debug('opcode: 0x%x, operation: %r', opcode, operation)
        if operation is None:
            stack.append(hex(opcode) + " (not yet implemented)")
        else:
            display_op = operation[0]
            logging.debug('running 0x%x, %s', opcode, display_op)
            if display_op in LOOKUP:
                stack.append(display_op)
            else:
                globals()[display_op](stack, **kwargs)
    if display:
        for index in range(len(stack)):
            print(stack[index])
        print('-----')
    return parsed, stack

def run(scriptbinary, txnew, txindex, parsed, stack=None):
    '''
    executes scripts the same way (hopefully) as bitcoin-core would

    showing stack at end of each operation

    >>> script = script_compile([1, 2, 3, 'ADD', 'ADD'])
    >>> logging.info('script: %r', script)
    >>> stack = []
    >>> run(script, None, None, None, stack)
    >>> number(stack.pop())
    6
    '''
    stack = [] if stack is None else stack  # continues using existing stack
    logging.debug('stack at start of run: %s', stack)
    kwargs = {'scriptbinary': scriptbinary, 'txnew': txnew,
              'txindex': txindex, 'parsed': parsed}
    kwargs['altstack'] = []
    kwargs['mark'] = [0]  # append a mark for every OP_CODESEPARATOR found
    opcodes = dict(SCRIPT_OPS)
    logging.debug('parameters: %s', kwargs)
    kwargs['script'] = script = bytevalues(scriptbinary)
    kwargs['reference'] = list(script)  # make a copy
    kwargs['ifstack'] = []  # internal stack for each script

    for opcode in DISABLED:
        opcodes.pop(opcode)
    try:
        while script:
            kwargs['opcode'] = opcode = script.pop(0)
            operation = opcodes.get(opcode, None)
            if operation is None:
                logging.error('fatal error in %s, offset %s', txnew, txindex)
                raise NotImplementedError('No such opcode %x' % opcode)
            else:
                if kwargs['ifstack'] and not kwargs['ifstack'][-1]:
                    run_op = operation[2]
                else:
                    run_op = operation[1]
                logging.info('running operation 0x%x, %s', opcode, run_op)
                globals()[run_op](stack, **kwargs)
            logging.info('script: %r, stack: %s', script, stack)
    except (TransactionInvalidError, ReservedWordError) as failed:
        logging.error('script failed or otherwise invalid: %s', failed)
        logging.info('stack: %s', stack)
        stack.append(None)
    logging.debug('run leaves stack at: %s', stack)

def base58decode(address):
    '''
    simple base58 decoder

    based on //github.com/jgarzik/python-bitcoinlib/blob/master/
     bitcoin/base58.py
    '''
    result = 0
    for digit in address:
        result = (result * 58) + BASE58DIGITS.index(digit)
    logging.debug('result: %s', result)
    try:
        decoded = result.to_bytes((result.bit_length() + 7) // 8, 'big')
    except AttributeError:  # must be Python2
        hexed = '%x' % result
        decoded = ('0' * (len(hexed) % 2) + hexed).decode('hex')
    padding = b'\0' * (len(address) - len(address.lstrip(BASE58DIGITS[0])))
    return padding + decoded

def base58encode(bytestring):
    '''
    simple base58 encoder

    based on //github.com/jgarzik/python-bitcoinlib/blob/master/
     bitcoin/base58.py
    '''
    encoded = ''
    cleaned = bytestring.lstrip(b'\0')
    string = b2a_hex(bytestring)
    number = int(string, 16)
    while number:
        number, remainder = divmod(number, 58)
        encoded += BASE58DIGITS[remainder]
    padding = BASE58DIGITS[0] * (len(bytestring) - len(cleaned))
    return padding + encoded[::-1]

def addr_to_hash(address, check_validity=True):
    r'''
    convert address back to its hash160

    >>> str(b2a_hex(addr_to_hash(
    ...  '3BTChqkFai51wFwrHSVdvSW9cPXifrJ7jC')).decode('utf8'))
    '6b146f137e7e8aa661b3515ac8856cbce061a3f2'
    '''
    binary = base58decode(address)
    logging.debug('binary: %r', binary)
    intermediate, checksum = binary[:-4], binary[-4:]
    if check_validity:
        check = op_hash256(stack=[intermediate])[:4]
        if check != checksum:
            logging.error('%r != %r', check, checksum)
            raise ValueError('Invalid address %s' % address)
        if intermediate[0] not in b'\x00\x05':
            logging.warning('%s not a bitcoin mainnet address', address)
    return intermediate[1:]

def hash_to_addr(hash160, padding=b'\0'):
    '''
    convert address hash to its base58 form

    >>> hash_to_addr(
    ...  a2b_hex('6b146f137e7e8aa661b3515ac8856cbce061a3f2'), b'\x05')
    '3BTChqkFai51wFwrHSVdvSW9cPXifrJ7jC'
    '''
    intermediate = padding + hash160
    checksum = op_hash256(stack=[intermediate])[:4]
    logging.debug('hash_to_addr adding checksum %r', checksum)
    return base58encode(intermediate + checksum)

def pubkey_to_hash(pubkey):
    '''
    hash160 a pubkey

    there can be no reverse to this procedure, unlike hash_to_addr

    >>> pubkey = ('043946a3002f7e56bad8f134f9b34282906a1ff5c54d9a60'
    ...           'd47ef691c453bf5e1706d314b474399f6dab5088cf0c9ac2'
    ...           '8543c6f13b66aef3e1ff80d5e14111f7be')
    >>> hashed = pubkey_to_hash(a2b_hex(pubkey))
    >>> hash_to_addr(hashed)
    '1Q7f2rL2irjpvsKVys5W2cmKJYss82rNCy'
    '''
    return op_hash160(stack=[pubkey])

# the following are the actual script operations, called from `run` routine.
# they all have the same parameter list

def op_nop(stack=None, **kwargs):
    '''
    handles all no-ops
    '''
    pass

def skip(stack=None, **kwargs):
    '''
    for use in an unused conditional branch; drops data instead of pushing it

    (not a real script operation)
    '''
    trash = []
    opcode = kwargs['opcode']
    if opcode < 0x4c:
        op_pushdata(trash, **kwargs)
    else:
        function = [op_pushdata1, op_pushdata2, op_pushdata4][opcode - 0x4c]
        function(trash, **kwargs)

def op_false(stack=None, **kwargs):
    '''
    pushes a zero-length bytestring that indicates False
    '''
    stack.append(b'')

def op_pushdata(stack=None, **kwargs):
    '''
    handles all the data-pushing operations 0x1 - 0x4b

    see the `Constants` section of https://en.bitcoin.it/wiki/Script
    '''
    logging.debug('kwargs: %s', kwargs)
    script = kwargs['script']
    opcode = kwargs['opcode']
    stack.append(bytes(script[:opcode]))
    script[:opcode] = []

def op_pushdata1(stack=None, **kwargs):
    '''
    pushes up to 255 bytes of data according to next byte in script
    '''
    count = kwargs['script'].pop(0)
    op_pushdata(stack, opcode=count, script=kwargs['script'])

def op_pushdata2(stack=None, **kwargs):
    '''
    pushes up to 65535 bytes of data according to next 2 bytes in script
    '''
    count = kwargs['script'].pop(0)
    count += 0x100 * kwargs['script'].pop(0)
    op_pushdata(stack, opcode=count, script=kwargs['script'])

def op_pushdata4(stack=None, **kwargs):
    script = kwargs['script']
    count = script.pop(0)
    count += 0x100 + script.pop(0)
    count += 0x10000 + script.pop(0)
    count += 0x1000000 + script.pop(0)
    op_pushdata(stack, opcode=count, script=script)

def op_1negate(stack=None, **kwargs):
    '''
    push -1 onto the stack
    '''
    stack.append(b'\x81')

def op_number(stack=None, **kwargs):
    '''
    push number from 1 ('TRUE') to 16 onto the stack
    '''
    stack.append(bytes([kwargs['opcode'] - 0x50]))

def op_shownumber(stack=None, **kwargs):
    '''
    like op_number, but unpack it for display of script
    '''
    op_number(stack, **kwargs)
    stack.append(number(stack.pop()))

def op_reserved(stack=None, **kwargs):
    '''
    reserved opcodes
    '''
    raise ReservedWordError('Reserved opcode 0x%x' % kwargs['opcode'])

def op_if(stack=None, **kwargs):
    '''
    begin an IF-ELSE-ENDIF block
    '''
    kwargs['ifstack'].append(bool(stack.pop()))

def op_notif(stack=None, **kwargs):
    '''
    begin a NOTIF-ELSE-ENDIF block
    '''
    kwargs['ifstack'].append(not bool(stack.pop()))

def op_else(stack=None, **kwargs):
    '''
    perform following action only if preceding IF or IFNOT did not
    '''
    ifstack = kwargs['ifstack']
    ifstack[-1] = None if ifstack[-1] in [True, None] else True

def op_endif(stack=None, **kwargs):
    '''
    end an IF or NOTIF block
    '''
    kwargs['ifstack'].pop()

def op_verify(stack=None, **kwargs):
    '''
    raise Exception if top of stack isn't a Boolean "true"
    '''
    if not stack.pop():
        raise TransactionInvalidError('VERIFY failed')

def op_return(stack=None, **kwargs):
    '''
    used to mark the script as unspendable and optionally append data
    '''
    raise TransactionInvalidError('RETURN')

def op_toaltstack(stack=None, **kwargs):
    '''
    moves top of stack to top of altstack
    '''
    kwargs['altstack'].append(stack.pop())

def op_fromaltstack(stack=None, **kwargs):
    '''
    moves top of altstack to top of stack
    '''
    stack.append(altstack.pop())

def op_2drop(stack=None, **kwargs):
    '''
    drop top 2 items from stack
    '''
    stack[-2:] = []

def op_2dup(stack=None, **kwargs):
    '''
    duplicate top 2 stack items

    >>> stack = [None, 1, 2]
    >>> op_2dup(stack=stack)
    >>> stack
    [None, 1, 2, 1, 2]
    '''
    stack.extend(stack[-2:])

def op_3dup(stack=None, **kwargs):
    '''
    duplicate top 3 stack items
    '''
    stack.extend(stack[-3:])

def op_2over(stack=None, **kwargs):
    '''
    copies the pair of items two spaces back in the stack to the front
    '''
    stack.extend(stack[-4:-2])

def op_2rot(stack=None, **kwargs):
    '''
    the fifth and sixth items back are moved to the top of the stack

    >>> stack = [1, 2, 3, 4, 5, 6]
    >>> op_2rot(stack=stack)
    >>> stack
    [3, 4, 5, 6, 1, 2]
    '''
    stack.extend(stack[-6:-4])
    stack[-8:-6] = []

def op_2swap(stack=None, **kwargs):
    '''
    swaps the top two pairs of items

    >>> stack = [1, 2, 3, 4]
    >>> op_2swap(stack=stack)
    >>> stack
    [3, 4, 1, 2]
    '''
    stack[-2:], stack[-4:-2] = stack[-4:-2], stack[-2:]

def op_ifdup(stack=None, **kwargs):
    '''
    if the top stack value is not 0, duplicate it
    '''
    if stack[-1]:
        stack.append(stack[-1])

def op_depth(stack=None, **kwargs):
    '''
    puts the number of stack items onto the stack
    '''
    stack.append(len(stack))

def op_drop(stack=None, **kwargs):
    '''
    removes the top stack item
    '''
    stack.pop()

def op_dup(stack=None, **kwargs):
    '''
    duplicates the top stack item
    '''
    stack.append(stack[-1])

def op_nip(stack=None, **kwargs):
    '''
    removes the second-to-top stack item

    >>> stack = [1, 2, 3]
    >>> op_nip(stack=stack)
    >>> stack
    [1, 3]
    '''
    stack.pop(-2)

def op_over(stack=None, **kwargs):
    '''
    copies the second-to-top stack item to the top

    >>> stack = [1, 2, 3]
    >>> op_over(stack=stack)
    >>> stack
    [1, 2, 3, 2]
    '''
    stack.append(stack[-2])

def op_pick(stack=None, **kwargs):
    '''
    the item n back in the stack is copied to the top

    >>> stack = [1, 2, 3, 2]
    >>> op_pick(stack=stack)
    >>> stack
    [1, 2, 3, 1]
    '''
    stack.append(stack[-1 - stack.pop()])

def op_roll(stack=None, **kwargs):
    '''
    the item n back in the stack is moved to the top

    >>> stack = [1, 2, 3, 2]
    >>> op_roll(stack=stack)
    >>> stack
    [2, 3, 1]
    '''
    stack.append(stack.pop(-1 - stack.pop()))

def op_rot(stack=None, **kwargs):
    '''
    the top 3 items on the stack are rotated to the left

    >>> stack = [1, 2, 3]
    >>> op_rot(stack=stack)
    >>> stack
    [2, 3, 1]
    '''
    stack.append(stack.pop(-3))

def op_swap(stack=None, **kwargs):
    '''
    the top two items on the stack are swapped

    >>> stack = [1, 2, 3]
    >>> op_swap(stack=stack)
    >>> stack
    [1, 3, 2]
    '''
    stack.append(stack.pop(-2))

def op_tuck(stack=None, **kwargs):
    '''
    the item at the top of the stack is copied and inserted before the
    second-to-top item

    >>> stack = [1, 2, 3]
    >>> op_tuck(stack=stack)
    >>> stack
    [1, 3, 2, 3]
    '''
    stack.insert(-2, stack[-1])

def op_cat(stack=None, **kwargs):
    '''
    concatenates two strings (disabled in bitcoin-core)

    >>> stack = [b'abc', b'de']
    >>> op_cat(stack=stack)
    >>> str(stack[0].decode('utf8'))
    'abcde'
    '''
    suffix = stack.pop()
    stack[-1] += suffix

def op_substr(stack=None, **kwargs):
    '''
    returns a section of a string (disabled in bitcoin-core)

    >>> op_substr(stack=['testcase', 0, 4])
    'test'
    >>> op_substr(stack=['testcase', 4, 4])
    'case'
    '''
    length = stack.pop()
    beginning = stack.pop()
    stack[-1] = stack[-1][beginning:beginning + length]
    return stack[-1]  # for conventional caller

def op_left(stack=None, **kwargs):
    '''
    keeps only characters left of the specified point in a string
    disabled in bitcoin-core

    >>> stack = [b'this is a test', b'\4']
    >>> op_left(stack=stack)
    >>> str(stack[-1].decode('utf8'))
    'this'
    '''
    index = number(stack.pop());
    assert_true(index >= 0)
    stack[-1] = stack[-1][:index]

def op_right(stack=None, **kwargs):
    '''
    keeps only characters right of the specified point in a string
    disabled in bitcoin-core

    >>> stack = [b'this is a test', b'\4']
    >>> op_right(stack=stack)
    >>> str(stack.pop().decode('utf8'))
    ' is a test'
    '''
    index = number(stack.pop());
    assert_true(index >= 0)
    stack[-1] = stack[-1][index:]

def op_size(stack=None, **kwargs):
    r'''
    pushes the string length of the top element of the stack
    (without popping it)

    >>> stack = [b'']
    >>> op_size(stack=stack)
    >>> stack == [b'', b'']
    True
    >>> stack = [b'this is a test']
    >>> op_size(stack=stack)
    >>> stack == [b'this is a test', b'\x0e']
    True
    '''
    stack.append(bytevector(len(stack[-1])))

def op_invert(stack=None, **kwargs):
    '''
    flips all of the bits in the input (disabled in bitcoin-core)
    '''
    top = number(stack.pop())
    stack.append(bytevector(~top))

def op_and(stack=None, **kwargs):
    '''
    boolean AND between each bit in the inputs (disabled in bitcoin-core)
    '''
    operands = (number(stack.pop()), number(stack.pop()))
    stack.append(bytevector(operands[0] & operands[1]))

def op_or(stack=None, **kwargs):
    '''
    boolean OR between each bit in the inputs (disabled in bitcoin-core)
    '''
    operands = (number(stack.pop()), number(stack.pop()))
    stack.append(bytevector(operands[0] | operands[1]))

def op_xor(stack=None, **kwargs):
    '''
    boolean XOR between each bit in the inputs (disabled in bitcoin-core)
    '''
    operands = (number(stack.pop()), number(stack.pop()))
    stack.append(bytevector(operands[0] ^ operands[1]))

def op_equal(stack=None, **kwargs):
    r'''
    returns 1 if the inputs are exactly equal, 0 otherwise

    >>> stack = [b'', b'\x80']
    >>> op_equal(stack=stack)
    >>> number(stack.pop())
    1
    '''
    operands = (number(stack.pop()), number(stack.pop()))
    stack.append(bytevector(operands[0] == operands[1]))

def op_equalverify(stack=None, **kwargs):
    '''
    same as op_equal, but runs op_verify afterward
    '''
    op_equal(stack=stack)
    op_verify(stack=stack)

# arithmetic inputs are limited to signed 32-bit integers,
# but may overflow their output.

# if any input value for any of these arithmetic commands is longer
# than 4 bytes, the script must abort and fail. if any opcode marked
# as disabled is present in a script - it must also abort and fail.

def op_1add(stack=None, **kwargs):
    '''
    1 is added to the input
    '''
    stack.append(b'\1')
    op_add(stack=stack)

def op_1sub(stack=None, **kwargs):
    '''
    1 is subtracted from the input
    '''
    stack.append(b'\x81')
    op_add(stack=stack)

def op_2mul(stack=None, **kwargs):
    r'''
    the input is multiplied by 2 (disabled in bitcoin-core)

    >>> stack = [b'\x03']
    >>> op_2mul(stack=stack)
    >>> number(stack.pop())
    6
    '''
    stack.append(bytevector(number(stack.pop()) * 2))

def op_2div(stack=None, **kwargs):
    r'''
    the input is divided by 2 (disabled in bitcoin-core)

    >>> stack = [b'\x03']
    >>> op_2div(stack=stack)
    >>> number(stack.pop())
    1
    '''
    stack.append(bytevector(number(stack.pop()) // 2))

def op_negate(stack=None, **kwargs):
    r'''
    the sign of the input is flipped

    >>> stack = [b'\x03']
    >>> op_negate(stack=stack)
    >>> number(stack.pop())
    -3
    '''
    stack.append(bytevector(-number(stack.pop())))

def op_abs(stack=None, **kwargs):
    '''
    the input is made positive
    '''
    stack.append(bytevector(abs(number(stack.pop))))

def op_not(stack=None, **kwargs):
    '''
    if the input is 0 or 1, it is flipped. otherwise the output will be 0.
    '''
    state = number(stack.pop())
    stack.append(bytevector(not state) if state in [0, 1] else b'')

def op_0notequal(stack=None, **kwargs):
    '''
    returns 0 if the input is 0. 1 otherwise.
    '''
    argument = number(stack.pop())
    stack.append(bytevector(bool(argument)))

def op_add(stack=None, **kwargs):
    '''
    add top two numbers on stack
    '''
    stack.append(bytevector(number(stack.pop()) + number(stack.pop())))

def op_sub(stack=None, **kwargs):
    '''
    for top two stack items [a, b], a - b
    '''
    stack.append(bytevector(-number(stack.pop()) + number(stack.pop())))

def op_mul(stack=None, **kwargs):
    '''
    product of top 2 stack items (disabled in bitcoin-core)
    '''
    stack.append(bytevector(number(stack.pop()) * number(stack.pop())))

def op_div(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b] return a // b (disabled in bitcoin-core)
    '''
    divisor = number(stack.pop())
    stack.append(bytevector(number(stack.pop()) // divisor))

def op_mod(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b] return a % b (disabled in bitcoin-core)
    '''
    divisor = number(stack.pop())
    stack.append(bytevector(number(stack.pop()) % divisor))

def op_lshift(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b] return a << b, preserving sign
    (disabled in bitcoin-core)
    '''
    amount = number(stack.pop())
    stack.append(bytevector(number(stack.pop()) << amount))

def op_rshift(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b] return a >> b preserving sign
    (disabled in bitcoin-core)
    '''
    amount = number(stack.pop())
    stack.append(bytevector(number(stack.pop()) >> amount))

def op_booland(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: if both a and b are not 0, return 1, else 0
    '''
    stack.append(bytevector(number(stack.pop()) and number(stack.pop())))

def op_boolor(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: if a or b is not 0, return 1, else 0
    '''
    stack.append(bytevector(number(stack.pop()) or number(stack.pop())))

def op_numequal(stack=None, **kwargs):
    '''
    returns 1 if numbers are equal, else 0
    '''
    stack.append(bytevector(number(stack.pop()) == number(stack.pop())))

def op_numequalverify(stack=None, **kwargs):
    '''
    same as op_numequal but runs op_verify afterward
    '''
    op_numequal(stack=stack)
    op_verify(stack=stack)

def op_numnotequal(stack=None, **kwargs):
    '''
    return 1 if numbers are not equal, else 0
    '''
    stack.append(bytevector(number(stack.pop()) != number(stack.pop())))

def op_lessthan(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: return 1 if a < b, else 0

    because b is popped first, we compare using > instead of <
    '''
    stack.append(bytevector(number(stack.pop()) > number(stack.pop())))

def op_greaterthen(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: return 1 if a > b, else 0

    because b is popped first, we use the opposite check
    '''
    stack.append(bytevector(number(stack.pop()) < number(stack.pop())))

def op_lessthanorequal(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: return 1 if a <= b, else 0

    because b is popped first, we use the opposite check
    '''
    stack.append(bytevector(number(stack.pop()) >= number(stack.pop())))

def op_greaterthanorequal(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: return 1 if a >= b, else 0

    because b is popped first, we use the opposite check
    '''
    stack.append(bytevector(number(stack.pop()) <= number(stack.pop())))

def op_min(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: return the smaller
    '''
    stack.append(bytevector(min(number(stack.pop()), number(stack.pop()))))

def op_max(stack=None, **kwargs):
    '''
    for top 2 stack items [a, b]: return the greater
    '''
    stack.append(bytevector(max(number(stack.pop()), number(stack.pop()))))

def op_within(stack=None, **kwargs):
    r'''
    for top 3 stack items [x, min, max]: return 1 if x is within the
    specified range (left-inclusive), else 0

    >>> stack = [-1, 0, 4]
    >>> op_within(stack=stack)
    >>> stack == [b'']
    True
    >>> stack = [0, 0, 4]
    >>> op_within(stack=stack)
    >>> stack == [b'\x01']
    True
    '''
    range_x = list(reversed([number(stack.pop()), number(stack.pop())]))
    x = number(stack.pop())
    logging.debug('checking if %d in range %s', x, range_x)
    stack.append(bytevector(range_x[0] <= x < range_x[1]))

def op_ripemd160(stack=None, **kwargs):
    '''
    RIPEMD160 hash of data at top of stack
    '''
    data = stack.pop()
    ripemd160 = hashlib.new('ripemd160')
    stack.append(ripemd160.update(data).digest())
    return stack[-1]  # for conventional caller

def op_sha1(stack=None, **kwargs):
    '''
    sha1 hash digest
    '''
    data = stack.pop()
    stack.append(hashlib.sha1(data).digest())
    return stack[-1]  # for conventional caller

def op_sha256(stack=None, **kwargs):
    '''
    sha256 single hash digest
    '''
    data = stack.pop()
    stack.append(hashlib.sha256(data).digest())
    return stack[-1]  # for conventional caller

def op_hash160(stack=None, **kwargs):
    '''
    input is hashed twice: first with SHA-256 and then with RIPEMD-160
    '''
    data = stack.pop()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(data).digest())
    stack.append(ripemd160.digest())
    return stack[-1]  # for conventional caller

def op_hash256(stack=None, **kwargs):
    '''
    sha256d hash, which is the hash of a hash
    '''
    data = stack.pop()
    stack.append(hashlib.sha256(hashlib.sha256(data).digest()).digest())
    return stack[-1]  # for conventional caller

def op_codeseparator(stack=None, **kwargs):
    '''
    signature checking words only match signatures to the data after
    the most recently-executed OP_CODESEPARATOR
    '''
    kwargs['mark'].append(len(kwargs['reference']) - len(kwargs['script']) - 1)

def op_checksig(stack=None, **kwargs):
    '''
    run OP_CHECKSIG in context of `run` subroutine

    see https://bitcoin.stackexchange.com/a/32308/3758 and
    http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
    '''
    reference = kwargs['reference']
    txnew = kwargs['txnew']
    txindex = kwargs['txindex']
    mark = kwargs['mark']
    parsed = kwargs['parsed']
    logging.debug('op_checksig stack: %s, reference: %s, mark: %s',
                  stack, reference, mark)
    pubkey = stack.pop()
    signature = bytevalues(stack.pop())
    subscript = reference[mark[-1]:]
    checker = list(parsed[mark[-1]:])  # checking for OP_CODESEPARATORs
    # remove OP_CODESEPARATORs in subscript
    # only safe way to do this is to work backwards using positive indices
    for offset in range(len(checker) - 1, 0, -1):
        if checker[offset] == 0xab:  # OP_CODESEPARATOR
            checker.pop(offset)
            subscript.pop(offset)
    hashtype = signature.pop()
    hashtype_code = struct.pack('<L', hashtype)
    txcopy = copy.deepcopy(txnew)
    for input in txcopy[2]:
        input[2] = b'\0'
        input[3] = b''
    try:
        logging.debug('replacing input script %d with subscript', txindex)
        txcopy[2][txindex][2] = varint_length(subscript)
        txcopy[2][txindex][3] = bytes(subscript)
    except TypeError:
        logging.error('txcopy: %r, txcopy[2]: %r, txcopy[2][0]: %r',
                      txcopy, txcopy[2], txcopy[2][0])
        raise
    serialized = tx_serialize(txcopy) + hashtype_code
    logging.debug('serialized with hashtype_code: %r', serialized)
    hashed = op_hash256(stack=[serialized])
    logging.debug('signature: %r, pubkey: %r', bytes(signature), pubkey)
    key = CECKey()
    key.set_pubkey(pubkey)
    stack.append(key.verify(hashed, bytes(signature)))
    return stack[-1]  # for conventional caller

def op_checksigverify(stack=None, **kwargs):
    '''
    OP_CHECKSIG followed by OP_VERIFY
    '''
    op_checksig(stack=stack, **kwargs)
    op_verify(stack=stack)

def op_checkmultisig(stack=None, **kwargs):
    '''
    compares the first signature against each public key until it finds
    an ECDSA match. Starting with the subsequent public key, it compares
    the second signature against each remaining public key until it finds
    an ECDSA match. The process is repeated until all signatures have
    been checked or not enough public keys remain to produce a successful
    result. All signatures need to match a public key. Because public
    keys are not checked again if they fail any signature comparison,
    signatures must be placed in the scriptSig using the same order
    as their corresponding public keys were placed in the scriptPubKey
    or redeemScript. If all signatures are valid, 1 is returned,
    0 otherwise. Due to a bug, one extra unused value is removed
    from the stack.
    '''
    raise NotImplementedError('op_checkmultisig')

def op_checkmultisigverify(stack=None, **kwargs):
    '''
    OP_CHECKMULTISIG followed by OP_VERIFY
    '''
    op_checkmultisig(stack=stack, **kwargs)
    op_verify(stack=stack)

def op_checklocktimeverify(stack=None, **kwargs):
    '''
    marks transaction as invalid if the top stack item is greater than
    the transaction's nLockTime field, otherwise script evaluation
    continues as though an OP_NOP was executed. Transaction is als
    o invalid if 1. the stack is empty; or 2. the top stack item is
    negative; or 3. the top stack item is greater than or equal to
    500000000 while the transaction's nLockTime field is less than
    500000000, or vice versa; or 4. the input's nSequence field is
    equal to 0xffffffff. The precise semantics are described in BIP 0065
    '''
    raise NotImplementedError('op_checklocktimeverify')

def op_checksequenceverify(stack=None, **kwargs):
    '''
    marks transaction as invalid if the relative lock time of the input
    (enforced by BIP 0068 with nSequence) is not equal to or longer
    than the value of the top stack item. The precise semantics are
    described in BIP 0112
    '''
    raise NotImplementedError('op_checksequenceverify')

# end of script ops
# now some helper functions for the script ops

def bytevector(number):
    '''
    convert integer to a byte vector according to Script rules

    let struct.pack throw exception if it doesn't fit
    '''
    if not number:
        return b''
    vector = struct.pack('<L', abs(number)).rstrip(b'\0')
    if ord(vector[-1:]) & 0x80:
        vector += b'\0'
    if number < 0:
        vector = vector[:-1] + struct.pack('B', ord(vector[-1:]) | 0x80)
    if len(vector) > 4:
        raise ValueError('%d is too large for Script numbers' % number)
    return vector

def number(bytestring):
    r'''
    treat bytestring as a number according to Script rules

    also accepts integers as they are, for testing purposes

    >>> number(b'\x80')
    0
    >>> number(b'')
    0
    >>> number(b'\xe8\x83')
    -1000
    >>> number(3)
    3
    '''
    try:
        msbs = ord(bytestring[-1:])
        sign, msbs = bool(msbs & 0x80), msbs & 0x7f
        DOCTESTDEBUG('sign: %s, msbs: %s', sign, msbs)
        bytestring = bytestring[:-1] + struct.pack('B', msbs) + b'\0\0\0'
        DOCTESTDEBUG('bytestring: %r', bytestring)
        return [1, -1][sign] * struct.unpack('<L', bytestring[:4])[0]
    except TypeError:
        try:
            return int(bytestring)
        except ValueError:  # assuming b''
            return 0

def tx_serialize(transaction):
    '''
    optimized `serialize` for this particular representation of transaction

    >>> transaction = PIZZA[0]
    >>> check = copy.deepcopy(transaction)
    >>> serialized = tx_serialize(transaction)
    >>> check == transaction
    True
    '''
    copied = list(transaction)
    copied[2] = b''.join([b''.join(item) for item in copied[2]])
    copied[4] = b''.join([b''.join(item) for item in copied[4]])
    return b''.join(copied)

# and now some routines for testing and analyzing blockchains

def test_checksig(current_tx, txin_index, previous_tx):
    r'''
    display and run scripts in given transactions to test OP_CHECKSIG

    >>> test_checksig(PIZZA[0], 0, PIZZA[1])
    b'0E\x02!\x00\x99\x08\x14L\xa6S\x9e\tQ+\x92\x95\xc8\xa2pP\xd4x\xfb\xb9o\x8a\xdd\xbc=\x07UD\xdcA2\x87\x02 \x1a\xa5(\xbe+\x90}1m-\xa0h\xdd\x9e\xb1\xe22C\xd9~DMY)\r/\xdd\xf2Ri\xee\x0e\x01'
    b'\x04.\x93\x0f9\xbab\xc6SN\xe9\x8e\xd2\x0c\xa9\x89Y\xd3J\xa9\xe0W\xcd\xa0\x1c\xfdB,k\xab6g\xb7d&R\x93\x82\xc2?B\xb9\xb0\x8dx2\xd4\xfe\xe1\xd6\xb47\xa8RnYf|\xe9\xc4\xe9\xdc\xeb\xca\xbb'
    -----
    DUP
    HASH160
    b"F\xaf?\xb4\x81\x83\x7f\xad\xbbB\x17'\xf9\x95\x9c-2\xa3h)"
    EQUALVERIFY
    CHECKSIG
    -----
    '''
    stack = []
    logging.debug('parsing and displaying current txin script...')
    txin = current_tx[2][txin_index]
    logging.debug('txin: %s', txin)
    logging.debug('previous tx hash: %s', show_hash(txin[0]))
    txout_index = struct.unpack('<L', txin[1])[0]
    txin_script = txin[3]
    parsed, readable = parse(txin_script)
    logging.debug('running txin script %s', readable)
    run(txin_script, current_tx, txin_index, parsed, stack)
    logging.debug('stack after running txin script: %s', stack)
    logging.debug('parsing and displaying previous txout script...')
    txout = previous_tx[4]
    txout_script = txout[txout_index][2]
    parsed, readable = parse(txout_script)
    logging.debug('stack before running txout script: %s', stack)
    logging.debug('running txout script %s', readable)
    run(txout_script, current_tx, txin_index, parsed, stack)
    result = bool(stack.pop())
    logging.info('transaction result: %s', ['fail', 'pass'][result])

def unusual(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    look through all output scripts to find unusual patterns, print them out
    '''
    lastheight = 0
    p2pk, p2pkh, unusual = 0, 0, 0
    blockfiles = [blockfiles] if blockfiles else None
    transactions = next_transaction(blockfiles, minblock, maxblock)
    for height, tx_hash, transaction in transactions:
        if height != lastheight:
            logging.info('height: %d', height)
            lastheight = height
        for txindex in range(len(transaction[4])):
            txout = transaction[4][txindex]
            logging.debug('txout: %s', txout)
            txout_script = txout[2]
            amount = to_long(txout[0])
            parsed, readable = parse(txout_script, display=False)
            logging.debug(readable)
            if len(readable) == 2:
                if readable[-1] == 'CHECKSIG' and len(readable[0]) == 65:
                    p2pk += 1
                    continue
            elif len(readable) == 5:
                addr_hash = readable.pop(2)
                if (readable == ['DUP', 'HASH160', 'EQUALVERIFY', 'CHECKSIG']
                        and len(addr_hash) == 20):
                    p2pkh += 1
                    continue
                else:
                    readable.insert(2, addr_hash)
            unusual += 1
            logging.info('scripts: P2PK: %d, P2PKH: %d, unusual: %d',
                         p2pk, p2pkh, unusual)
            print('%s' % {'unusual': {
                  'output': '%s:%d' % (show_hash(tx_hash).decode(), txindex),
                  'height': height,
                  'value': amount,
                  'script': readable}})

def testall(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    keep testing every script in blockchain until one fails
    '''
    lastheight = 0
    blockfiles = [blockfiles] if blockfiles else None
    transactions = next_transaction(blockfiles, minblock, maxblock)
    spendcount, count = 0, 0
    cache = OrderedDict()
    for height, tx_hash, transaction in transactions:
        cache[tx_hash] = transaction
        if height != lastheight:
            logging.info('height: %d', height)
            lastheight = height
        for txindex in range(len(transaction[2])):
            txin = transaction[2][txindex]
            stack = []
            txin_script = txin[3]
            parsed, readable = parse(txin_script, display=False)
            run(txin_script, transaction, txindex, parsed, stack)
            logging.debug('checking result on stack: %s', stack)
            result = bool(stack and stack[-1])
            logging.info('%d scripts executed successfully', count)
            if result is None:
                raise(TransactionInvalidError('input script failed'))
            elif not result:
                logging.info('input script %s was programmed to fail', readable)
            count += 1
            previous_hash = txin[0]
            if previous_hash != COINBASE:
                logging.debug('non-coinbase transaction')
                txout_index = struct.unpack('<L', txin[1])[0]
                tx = silent_search(blockfiles, previous_hash, cache)
                txout_script = tx[4][txout_index][2]
                parsed, readable = parse(txout_script, display=False)
                # still using stack from above txin_script
                run(txout_script, transaction, txindex,
                            parsed, stack)
                result = bool(stack.pop())
                logging.info('%d scripts executed successfully', count)
                logging.info('%d of those were spends', spendcount)
                if result is None:
                    raise(TransactionInvalidError('output script failed'))
                elif not result:
                    logging.info('output script %s was programmed to fail',
                                 readable)
                count += 1
                spendcount += 1
                break  # out of inner loop
    logging.info('final tally:')
    logging.info('%d scripts executed successfully', count)
    logging.info('%d of those were spends', spendcount)

def silent_search(blockfiles, search_hash, cache=None, maxlength=sys.maxsize):
    '''
    returns transaction out of cache if present

    otherwise runs a "silent" search of blockfiles and adds it to the cache
    '''
    if search_hash in cache:
        logging.debug('cache hit: %s', search_hash)
        return cache[search_hash]
    else:
        logging.debug('cache miss, searching for %s', search_hash)
        tx_search = next_transaction(blockfiles)
        for ignored, found_hash, tx in tx_search:
            logging.debug('comparing %r and %r', search_hash, found_hash)
            if search_hash == found_hash:
                logging.debug('found previous tx: %r', tx)
                cache[search_hash] = tx
                if len(cache) > maxlength:
                    cache.pop(list(cache.keys())[0])
                return tx

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
    # default operation is to test OP_CHECKSIG
    command, args = (sys.argv + [None])[1], sys.argv[2:]
    # some commands expect a list
    if command and (command in ['script_compile'] or command.startswith('op_')):
        print(globals()[command]([bytes(s, 'utf8') for s in args]))
    elif command in globals() and callable(globals()[command]):
        print(globals()[command](*args))
    else:  # assuming `command` is actually a blockfile name
        for transactions in (PIZZA, FIRST):
            test_checksig(transactions[0], 0, transactions[1])
        testall(command, *args)
