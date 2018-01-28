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
        'stack.append(stack.pop(-2))',
        'pass']
    ),
    (0x7d, [
        'TUCK',
        'stack.insert(-2, stack[-1])',
        'pass']
    ),
    (0x7e, [
        'CAT',
        '_ = stack.pop(); stack[-1] += _',
        'pass']
    ),
    (0x7f, [
        'SUBSTR',
        'substr(**globals())',
        'pass']
    ),
    (0x80, [
        'LEFT',
        '_ = stack.pop(); stack[-1] = stack[-1][:_]',
        'pass']
    ),
    (0x81, [
        'RIGHT',
        '_ = stack.pop(); stack[-1] = stack[-1][:-_]',
        'pass']
    ),
    (0x82, [
        'SIZE',
        'stack.append(len(stack[-1]))',
        'pass']
    ),
    (0x83, [
        'INVERT',
        'stack[-1] = ~stack[-1]',
        'pass']
    ),
    (0x84, [
        'AND',
        'stack.append(stack.pop() & stack.pop())',
        'pass']
    ),
    (0x85, [
        'OR',
        'stack.append(stack.pop() | stack.pop())',
        'pass']
    ),
    (0x86, [
        'XOR',
        'stack.append(stack.pop() ^ stack.pop())',
        'pass']
    ),
    (0x87, [
        'EQUAL',
        'stack.append(stack.pop() == stack.pop())',
        'pass']
    ),
    (0x88, [
        'EQUALVERIFY',
        ('if stack.pop() != stack.pop():'
         " raise(TransactionInvalidError('failed EQUALVERIFY'))"),
        'pass']
    ),
    (0x89, [
        'RESERVED1',
        "raise(ReservedWordError('reserved opcode 0x89'))",
        'pass'],
    ),
    (0x8a, [
        'RESERVED2',
        "raise(ReservedWordError('reserved opcode 0x8a'))",
        'pass']
    ),
    (0x8b, [
        '1ADD',
        'stack[-1] += 1',
        'pass']
    ),
    (0x8c, [
        '1SUB',
        'stack[-1] -= 1',
        'pass']
    ),
    (0x8d, [
        '2MUL',
        'stack[-1] *= 2',
        'pass']
    ),
    (0x8e, [
        '2DIV',
        'stack[-1] //= 2',
        'pass']
    ),
    (0x8f, [
        'NEGATE',
        'stack[-1] = -stack[-1]',
        'pass']
    ),
    (0x90, [
        'ABS',
        'stack[-1] = abs(stack[-1])',
        'pass']
    ),
    (0x91, [
        'NOT',
        'stack[-1] = not stack[-1]',
        'pass']
    ),
    (0x92, [
        '0NOTEQUAL',
        'stack[-1] = bool(stack[-1])',
        'pass']
    ),
    (0x93, [
        'ADD',
        'op_add',
        'op_nop']
    ),
    (0x94, [
        'SUB',
        'stack.append(-stack.pop() + stack.pop())',
        'pass']
    ),
    (0x95, [
        'MUL',
        '_ = stack.pop(); stack[-1] *= _',
        'pass']
    ),
    (0x96, [
        'DIV',
        '_ = stack.pop(); stack[-1] //= _',
        'pass']
    ),
    (0x97, [
        'MOD',
        '_ = stack.pop(); stack[-1] %= _',
        'pass']
    ),
    (0x98, [
        'LSHIFT',
        '_ = stack.pop(); stack[-1] <<= _',
        'pass']
    ),
    (0x99, [
        'RSHIFT',
        '_ = stack.pop(); stack[-1] >>= _',
        'pass']
    ),
    (0x9a, [
        'BOOLAND',
        '_ = stack.pop(); stack[-1] = stack[-1] and _',
        'pass']
    ),
    (0x9b, [
        'BOOLOR',
        '_ = stack.pop(); stack[-1] = stack[-1] or _',
        'pass']
    ),
    # FIXME: all numeric ops need to treat byte vectors correctly as numbers
    (0x9c, [
        'NUMEQUAL',
        'stack.append(stack.pop() == stack.pop())',
        'pass']
    ),
    (0x9d, [
        'NUMEQUALVERIFY',
        'stack.append(stack.pop() == stack.pop()); verify(**globals())',
        'pass']
    ),
    (0x9e, [
        'NUMNOTEQUAL',
        'stack.append(stack.pop() != stack.pop())',
        'pass']
    ),
    (0x9f, [
        'LESSTHAN',
        'stack.append(stack.pop() > stack.pop())',
        'pass']
    ),
    (0xa0, [
        'GREATERTHAN',
        'stack.append(stack.pop() < stack.pop())',
        'pass']
    ),
    (0xa1, [
        'LESSTHANOREQUAL',
        'stack.append(stack.pop() >= stack.pop())',
        'pass']
    ),
    (0xa2, [
        'GREATERTHANOREQUAL',
        'stack.append(stack.pop() <= stack.pop())',
        'pass']
    ),
    (0xa3, [
        'MIN',
        'stack.append(min(stack.pop(), stack.pop()))',
        'pass']
    ),
    (0xa4, [
        'MAX',
        'stack.append(max(stack.pop(), stack.pop()))',
        'pass']
    ),
    (0xa5, [
        'WITHIN',
        '_max = stack.pop(); _min = stack.pop();'
        'stack.append(_min <= stack.pop() <= _max)',
        'pass']
    ),
    (0xa6, [
        'RIPEMD160',
        'ripemd160(**globals())',
        'pass']
    ),
    (0xa7, [
        'SHA1',
        'sha1(**globals())',
        'pass']
    ),
    (0xa8, [
        'SHA256',
        'sha256(**globals())',
        'pass']
    ),
    (0xa9, [
        'HASH160',
        'hash160(**globals())',
        'pass']
    ),
    (0xaa, [
        'HASH256',
        'hash256(**globals())',
        'pass']
    ),
    (0xab, [
        'CODESEPARATOR',
        'mark.append(len(reference) - len(script) - 1)',
        'mark.append(len(reference) - len(script) - 1)']
    ),
    (0xac, [
        'CHECKSIG',
        'checksig(**globals())',
        'pass']
    ),
    (0xad, [
        'CHECKSIGVERIFY',
        'checksig(**globals()); verify(**globals())',
        'pass']
    ),
    (0xae, [
        'CHECKMULTISIG',
        'checkmultisig(**globals())',
        'pass']
    ),
    (0xaf, [
        'CHECKMULTISIGVERIFY',
        'checkmultisig(**globals()); verify(**globals())',
        'pass']
    ),
    (0xb0, [
        'NOP1',
        'pass',
        'pass']
    ),
    (0xb1, [
        'CHECKLOCKTIMEVERIFY',
        'checklocktimeverify(**globals())',
        'pass']
    ),
    (0xb2, [
        'CHECKSEQUENCEVERIFY',
        'checksequenceverify(**globals())',
        'pass']
    ),
)
SCRIPT_OPS += tuple(  # 0xb3 - 0xb9 are NOP_4 through NOP_10
    (opcode, [
        'NOP%d' % (opcode - 0xaf),
        'pass',
        'pass'])
    for opcode in range(0xb3, 0xba)
)

LOOKUP = dict([[value[0], key] for key, value in dict(SCRIPT_OPS).items()
              if re.compile('^-?[A-Z0-9]+$').match(value[0])])
DISABLED = [  # add all opcodes disabled in Bitcoin core
#    0x83, 0x84, 0x85, 0x86
]
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
            word = a2b_hex(word)
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
    opcodes = dict(SCRIPT_OPS)
    script = list(scriptbinary)  # gives list of numbers (`ord`s)
    parsed = [None] * len(script)
    while script:
        parsed[-len(script)] = script[0]
        opcode = script.pop(0)
        operation = opcodes.get(opcode, None)
        logging.debug('opcode: %r, operation: %r', opcode, operation)
        if operation is None:
            stack.append(hex(opcode) + " (not yet implemented)")
        else:
            display_op = operation[0]
            logging.debug('running 0x%x, %s', opcode, display_op)
            if display_op in LOOKUP:
                stack.append(display_op)
            else:
                globals()[display_op](opcode, stack, script)
    if display:
        for index in range(len(stack)):
            print(stack[index])
        print('-----')
    return parsed, stack

def run(scriptbinary, txnew, txindex, parsed, stack=None):
    '''
    executes scripts the same way (hopefully) as Bitcoin Core would

    showing stack at end of each operation

    >>> script = script_compile([1, 2, 3, 'ADD', 'ADD'])
    >>> logging.info('script: %r', script)
    >>> stack = []
    >>> run(script, None, None, None, stack)
    >>> number(stack.pop())
    6
    '''
    stack = stack if stack is not None else []  # continues using existing stack
    logging.debug('stack at start of run: %s', stack)
    kwargs = {}
    kwargs['altstack'] = []
    kwargs['mark'] = [0]  # append a mark for every OP_CODESEPARATOR found
    opcodes = dict(SCRIPT_OPS)
    script = list(scriptbinary)  # gives list of numbers (`ord`s)
    kwargs['reference'] = list(script)  # make a copy
    kwargs['ifstack'] = []  # internal stack for each script

    for opcode in DISABLED:
        opcodes.pop(opcode)
    try:
        while script:
            opcode = script.pop(0)
            operation = opcodes.get(opcode, None)
            if operation is None:
                logging.error('fatal error in %s, offset %d', txnew, txindex)
                raise NotImplementedError('no such opcode 0x%x' % opcode)
            else:
                if kwargs['ifstack'] and not kwargs['ifstack'][-1]:
                    run_op = operation[2]
                else:
                    run_op = operation[1]
                logging.info('running operation 0x%x, %s', opcode, run_op)
                globals()[run_op](opcode, stack, script, **kwargs)
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
    decoded = result.to_bytes((result.bit_length() + 7) // 8, 'big')
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

    >>> addr_to_hash('3BTChqkFai51wFwrHSVdvSW9cPXifrJ7jC')
    b'k\x14o\x13~~\x8a\xa6a\xb3QZ\xc8\x85l\xbc\xe0a\xa3\xf2'
    '''
    binary = base58decode(address)
    logging.debug('binary: %r', binary)
    intermediate, checksum = binary[:-4], binary[-4:]
    if check_validity:
        check = hash256(stack=[intermediate])[:4]
        if check != checksum:
            logging.error('%r != %r', check, checksum)
            raise ValueError('Invalid address %s' % address)
        if intermediate[0] not in b'\x00\x05':
            logging.warning('%s not a Bitcoin mainnet address', address)
    return intermediate[1:]

def hash_to_addr(hash160, padding=b'\0'):
    '''
    convert address hash to its base58 form

    >>> hash_to_addr(
    ...  bytes.fromhex('6b146f137e7e8aa661b3515ac8856cbce061a3f2'), b'\x05')
    '3BTChqkFai51wFwrHSVdvSW9cPXifrJ7jC'
    '''
    intermediate = padding + hash160
    checksum = hash256(stack=[intermediate])[:4]
    logging.debug('hash_to_addr adding checksum %r', checksum)
    return base58encode(intermediate + checksum)

def pubkey_to_hash(pubkey):
    '''
    hash160 a pubkey

    there can be no reverse to this procedure, unlike hash_to_addr

    >>> pubkey = ('043946a3002f7e56bad8f134f9b34282906a1ff5c54d9a60'
    ...           'd47ef691c453bf5e1706d314b474399f6dab5088cf0c9ac2'
    ...           '8543c6f13b66aef3e1ff80d5e14111f7be')
    >>> hashed = pubkey_to_hash(bytes.fromhex(pubkey))
    >>> hash_to_addr(hashed)
    '1Q7f2rL2irjpvsKVys5W2cmKJYss82rNCy'
    '''
    return hash160([pubkey])

# the following are the actual script operations, called from `run` routine.
# they all have the same parameter list

def op_verify(opcode=None, stack=None, script=None, **kwargs):
    '''
    raise Exception if top of stack isn't a Boolean "true"
    '''
    if not stack.pop():
        raise TransactionInvalidError('VERIFY failed')

def substr(stack=None, **ignored):
    '''
    substring of given string, given start and length

    >>> substr(stack=['testcase', 0, 4])
    'test'
    >>> substr(stack=['testcase', 4, 4])
    'case'
    '''
    length = stack.pop()
    beginning = stack.pop()
    stack[-1] = stack[-1][beginning:beginning + length]
    return stack[-1]  # for conventional caller

def hash256(stack=None, hashlib=hashlib, **ignored):
    '''
    sha256d hash, which is the hash of a hash
    '''
    data = stack.pop()
    stack.append(hashlib.sha256(hashlib.sha256(data).digest()).digest())
    return stack[-1]  # for conventional caller

def sha256(stack=None, hashlib=hashlib, **ignored):
    '''
    sha256 single hash digest
    '''
    data = stack.pop()
    stack.append(hashlib.sha256(data).digest())
    return stack[-1]  # for conventional caller

def ripemd160(stack=None, hashlib=hashlib, **ignored):
    '''
    RIPEMD160 hash of data at top of stack
    '''
    data = stack.pop()
    ripemd160 = hashlib.new('ripemd160')
    stack.append(ripemd160.update(data).digest())
    return stack[-1]  # for conventional caller

def hash160(stack=None, hashlib=hashlib, **ignored):
    '''
    input is hashed twice: first with SHA-256 and then with RIPEMD-160
    '''
    data = stack.pop()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(data).digest())
    stack.append(ripemd160.digest())
    return stack[-1]  # for conventional caller

def checksig(stack=None, reference=None, mark=None, parsed=None,
             txnew=None, txindex=None, **ignored):
    '''
    run OP_CHECKSIG in context of `run` subroutine

    see https://bitcoin.stackexchange.com/a/32308/3758 and
    http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
    '''
    logging.debug('checksig stack: %s, reference: %s, mark: %s',
                  stack, reference, mark)
    pubkey = stack.pop()
    signature = list(stack.pop())
    subscript = reference[mark[-1]:]
    checker = list(parsed[mark[-1]:])  # for checking for OP_CODESEPARATORs
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
    logging.debug('serialized with hashtype_code: %s', serialized)
    hashed = hash256(stack=[serialized])
    logging.debug('signature: %r, pubkey: %r', bytes(signature), pubkey)
    key = CECKey()
    key.set_pubkey(pubkey)
    stack.append(key.verify(hashed, bytes(signature)))
    return stack[-1]  # for conventional caller

def op_nop(opcode=None, stack=None, script=None, **kwargs):
    '''
    handles all no-ops
    '''
    pass

def skip(opcode=None, stack=None, script=None, **kwargs):
    '''
    for use in an unused conditional branch; drops data instead of pushing it
    '''
    trash = []
    if opcode < 0x4c:
        op_pushdata(opcode, trash, script, **kwargs)
    else:
        function = [op_pushdata1, op_pushdata2, op_pushdata4][opcode - 0x4c]
        function(opcode, trash, script, **kwargs)

def op_false(opcode=None, stack=None, script=None, **kwargs):
    '''
    pushes a zero-length bytestring that indicates False
    '''
    stack.append(b'')

def op_pushdata(opcode=None, stack=None, script=None, **kwargs):
    '''
    handles all the data-pushing operations 0x1 - 0x4b

    see the `Constants` section of https://en.bitcoin.it/wiki/Script
    '''
    stack.append(bytes(script.pop(0) for i in range(opcode)))

def op_pushdata1(opcode=None, stack=None, script=None, **kwargs):
    '''
    pushes up to 255 bytes of data according to next byte in script
    '''
    count = script.pop(0)
    op_pushdata(count, stack, script, **kwargs)

def op_pushdata2(opcode=None, stack=None, script=None, **kwargs):
    '''
    pushes up to 65535 bytes of data according to next 2 bytes in script
    '''
    count = script.pop(0)
    count += 0x100 * script.pop(0)
    op_pushdata(count, stack, script, **kwargs)

def op_pushdata4(opcode=None, stack=None, script=None, **kwargs):
    count = script.pop(0)
    count += 0x100 + script.pop(0)
    count += 0x10000 + script.pop(0)
    count += 0x1000000 + script.pop(0)
    op_pushdata(count, stack, script, **kwargs)

def op_1negate(opcode=None, stack=None, script=None, **kwargs):
    '''
    push -1 onto the stack
    '''
    stack.append(b'\x81')

def op_number(opcode=None, stack=None, script=None, **kwargs):
    '''
    push number from 1 ('TRUE') to 16 onto the stack
    '''
    stack.append(bytes([opcode - 0x50]))

def op_shownumber(opcode=None, stack=None, script=None, **kwargs):
    '''
    like op_number, but unpack it for display of script
    '''
    op_number(opcode, stack, script, **kwargs)
    stack.append(number(stack.pop()))

def op_reserved(opcode=None, stack=None, script=None, **kwargs):
    '''
    reserved opcodes
    '''
    raise ReservedWordError('Reserved opcode 0x%x' % opcode)

def op_if(opcode=None, stack=None, script=None, **kwargs):
    '''
    begin an IF-ELSE-ENDIF block
    '''
    kwargs['ifstack'].append(bool(stack.pop()))

def op_notif(opcode=None, stack=None, script=None, **kwargs):
    '''
    begin a NOTIF-ELSE-ENDIF block
    '''
    kwargs['ifstack'].append(not bool(stack.pop()))

def op_else(opcode=None, stack=None, script=None, **kwargs):
    '''
    perform following action only if preceding IF or IFNOT did not
    '''
    ifstack = kwargs['ifstack']
    ifstack[-1] = None if ifstack[-1] in [True, None] else True

def op_endif(opcode=None, stack=None, script=None, **kwargs):
    '''
    end an IF or NOTIF block
    '''
    kwargs['ifstack'].pop()

def op_return(opcode=None, stack=None, script=None, **kwargs):
    '''
    used to mark the script as unspendable and optionally append data
    '''
    raise TransactionInvalidError('RETURN')

def op_toaltstack(opcode=None, stack=None, script=None, **kwargs):
    '''
    moves top of stack to top of altstack
    '''
    kwargs['altstack'].append(stack.pop())

def op_fromaltstack(opcode=None, stack=None, script=None, **kwargs):
    '''
    moves top of altstack to top of stack
    '''
    stack.append(altstack.pop())

def op_2drop(opcode=None, stack=None, script=None, **kwargs):
    '''
    drop top 2 items from stack
    '''
    stack[-2:] = []

def op_2dup(opcode=None, stack=None, script=None, **kwargs):
    '''
    duplicate top 2 stack items

    >>> stack = [None, 1, 2]
    >>> op_2dup(stack=stack)
    >>> stack
    [None, 1, 2, 1, 2]
    '''
    stack.extend(stack[-2:])

def op_3dup(opcode=None, stack=None, script=None, **kwargs):
    '''
    duplicate top 3 stack items
    '''
    stack.extend(stack[-3:])

def op_2over(opcode=None, stack=None, script=None, **kwargs):
    '''
    copies the pair of items two spaces back in the stack to the front
    '''
    stack.extend(stack[-4:-2])

def op_2rot(opcode=None, stack=None, script=None, **kwargs):
    '''
    the fifth and sixth items back are moved to the top of the stack

    >>> stack = [1, 2, 3, 4, 5, 6]
    >>> op_2rot(stack=stack)
    >>> stack
    [3, 4, 5, 6, 1, 2]
    '''
    stack.extend(stack[-6:-4])
    stack[-8:-6] = []

def op_2swap(opcode=None, stack=None, script=None, **kwargs):
    '''
    swaps the top two pairs of items

    >>> stack = [1, 2, 3, 4]
    >>> op_2swap(stack=stack)
    >>> stack
    [3, 4, 1, 2]
    '''
    stack[-2:], stack[-4:-2] = stack[-4:-2], stack[-2:]

def op_ifdup(opcode=None, stack=None, script=None, **kwargs):
    '''
    if the top stack value is not 0, duplicate it
    '''
    if stack[-1]:
        stack.append(stack[-1])

def op_depth(opcode=None, stack=None, script=None, **kwargs):
    '''
    puts the number of stack items onto the stack
    '''
    stack.push(len(stack))

def op_drop(opcode=None, stack=None, script=None, **kwargs):
    '''
    removes the top stack item
    '''
    stack.pop()

def op_dup(opcode=None, stack=None, script=None, **kwargs):
    '''
    duplicates the top stack item
    '''
    stack.push(stack[-1])

def op_nip(opcode=None, stack=None, script=None, **kwargs):
    '''
    removes the second-to-top stack item

    >>> stack = [1, 2, 3]
    >>> op_nip(stack=stack)
    >>> stack
    [1, 3]
    '''
    stack.pop(-2)

def op_over(opcode=None, stack=None, script=None, **kwargs):
    '''
    copies the second-to-top stack item to the top

    >>> stack = [1, 2, 3]
    >>> op_over(stack=stack)
    >>> stack
    [1, 2, 3, 2]
    '''
    stack.append(stack[-2])

def op_pick(opcode=None, stack=None, script=None, **kwargs):
    '''
    the item n back in the stack is copied to the top

    >>> stack = [1, 2, 3, 2]
    >>> op_pick(stack=stack)
    >>> stack
    [1, 2, 3, 1]
    '''
    stack.append(stack[-1 - stack.pop()])

def op_roll(opcode=None, stack=None, script=None, **kwargs):
    '''
    the item n back in the stack is moved to the top

    >>> stack = [1, 2, 3, 2]
    >>> op_roll(stack=stack)
    >>> stack
    [2, 3, 1]
    '''
    stack.append(stack.pop(-1 - stack.pop()))

def op_rot(opcode=None, stack=None, script=None, **kwargs):
    '''
    the top 3 items on the stack are rotated to the left

    >>> stack = [1, 2, 3]
    >>> op_rot(stack=stack)
    >>> stack
    [2, 3, 1]
    '''
    stack.append(stack.pop(-3))

def op_add(opcode=None, stack=None, script=None, **kwargs):
    '''
    add top two numbers on stack and push the sum
    '''
    stack.append(bytevector(number(stack.pop()) + number(stack.pop())))

# end of script ops
# now some helper functions for the script ops

def bytevector(number):
    '''
    convert integer to a byte vector according to Script rules

    let struct.pack throw exception if it doesn't fit
    '''
    vector = struct.pack('<L', abs(number)).rstrip(b'\0')
    if vector[-1] & 0x80:
        vector += b'\0'
    if number < 0:
        vector = vector[:-1] + bytes([vector[-1] | 0x80])
    if len(vector) > 4:
        raise ValueError('%d is too large for Script numbers' % number)
    return vector

def number(bytestring):
    '''
    treat bytestring as a number according to Script rules
    '''
    msbs = bytestring[-1]
    sign, msbs = bool(msbs & 0x80), msbs & 0x7f
    bytestring = bytestring[:-1] + bytes([msbs, 0, 0, 0])
    return [1, -1][sign] * struct.unpack('<L', bytestring[:4])[0]

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

def test_checksig(current_tx, txin_index, previous_tx):
    '''
    display and run scripts in given transactions to test OP_CHECKSIG
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
    stack = run(txin_script, current_tx, txin_index, parsed, stack)
    logging.debug('stack after running txin script: %s', stack)
    logging.debug('parsing and displaying previous txout script...')
    txout = previous_tx[4]
    txout_script = txout[txout_index][2]
    parsed, readable = parse(txout_script)
    logging.debug('stack before running txout script: %s', stack)
    logging.debug('running txout script %s', readable)
    stack = run(txout_script, current_tx, txin_index, parsed, stack)
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
            stack = run(txin_script, transaction, txindex, parsed, stack)
            result = bool(stack and stack[-1])
            logging.info('%d scripts executed successfully', count)
            if result is None:
                raise(TransactionInvalidError('input script failed'))
            else:
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
                stack = run(txout_script, transaction, txindex,
                            parsed, stack)
                result = bool(stack.pop())
                logging.info('%d scripts executed successfully', count)
                logging.info('%d of those were spends', spendcount)
                if result is None:
                    raise(TransactionInvalidError('output script failed'))
                else:
                    logging.info('output script %s was programmed to fail',
                                 readable)
                count += 1
                spendcount += 1
                break  # out of inner loop

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

if __name__ == '__main__':
    # default operation is to test OP_CHECKSIG
    command, args = (sys.argv + [None])[1], sys.argv[2:]
    # some commands expect a list
    if command in ['script_compile', 'hash160']:
        print(globals()[command]([bytes(s, 'utf8') for s in args]))
    elif command in globals() and callable(globals()[command]):
        print(globals()[command](*args))
    else:  # assuming `command` is actually a blockfile name
        for transactions in (PIZZA, FIRST):
            test_checksig(transactions[0], 0, transactions[1])
        testall(command, *args)
