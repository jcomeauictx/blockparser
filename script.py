#!/usr/bin/python3 -OO
'''
display and execute bitcoin stack scripts
'''
import sys, os, struct, logging, copy, hashlib
from binascii import b2a_hex, a2b_hex
# cheating for now until I can write my own
# pip install --user git+https://github.com/jcomeauictx/python-bitcoinlib.git
from bitcoin.core.key import CECKey
from blockparse import next_transaction
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

# each item in SCRIPT_OPS gives:
#  its numeric value in hexadecimal;
#  its "representation", most readable way to display the script;
#  the Python code to be `exec`d in the context of the `run` routine;
#  the Python code to be `exec`d in the context of an inactive IF-ELSE branch;
SCRIPT_OPS = (
    (0x00, [
        "stack.append('FALSE')",
        "stack.append(b'')",
        'pass']
    ),
)
SCRIPT_OPS += tuple(  # 0x01 through 0x4b are all implied PUSH operations
    (opcode, [
        'stack.append(b2a_hex(bytes([script.pop(0) for i in range(opcode)])))',
        'stack.append(bytes([script.pop(0) for i in range(opcode)]))',
        '[script.pop(0) for i in range(opcode)]']
    )
    for opcode in range(0x01, 0x4c)
)
SCRIPT_OPS += (
    (0x4c, [
        ('count = script.pop(0);'
         'stack.append(b2a_hex(bytes([script.pop(0) for i in range(count)])))'),
        ('count = script.pop(0);'
         'stack.append(bytes([script.pop(0) for i in range(count)]))'),
        ('count = script.pop(0);'
         '[script.pop(0) for i in range(count)]')]
    ),
    (0x4d, [
        ("count = struct.unpack('<H', bytes("
         '[script.pop(0) for i in range(2)]));'
         'stack.append(b2a_hex(bytes([script.pop(0) for i in range(count)])))'),
        ("count = struct.unpack('<H', bytes("
         '[script.pop(0) for i in range(2)]));'
         'stack.append(bytes([script.pop(0) for i in range(count)]))'),
        ("count = struct.unpack('<H', bytes("
         '[script.pop(0) for i in range(2)]));'
         '[script.pop(0) for i in range(count)]')]
    ),
    (0x4e, [
        ("count = struct.unpack('<L', bytes("
         '[script.pop(0) for i in range(4)]));'
         'stack.append(b2a_hex(bytes([script.pop(0) for i in range(count)])))'),
        ("count = struct.unpack('<L', bytes("
         '[script.pop(0) for i in range(4)]));'
         'stack.append(bytes([script.pop(0) for i in range(count)]))'),
        ("count = struct.unpack('<L', bytes("
         '[script.pop(0) for i in range(4)]));'
         '[script.pop(0) for i in range(count)]')]
    ),
    (0x4f, [
        'stack.append(-1)',
        'stack.append(-1)',
        'pass']
    ),
    (0x50, [
        "stack.append('RESERVED')",
        "raise ReservedWordError('reserved opcode 0x50')",
        'pass']
    ),
    (0x51, [
        "stack.append('TRUE')",
        'stack.append(1)',
        'pass']
    )
)
SCRIPT_OPS += tuple(  # 0x52 - 0x60 are OP_2 through OP_16
    (opcode, [
        'stack.append(opcode - 0x50)',
        'stack.append(opcode - 0x50)',
        'pass'])
    for opcode in range(0x52, 0x60)
)
SCRIPT_OPS += (
    (0x61, [
        "stack.append('NOP')",
        'pass',
        'pass']
    ),
    (0x62, [
        "stack.append('VER')",
        "raise ReservedWordError('reserved opcode 0x62')",
        'pass']
    ),
    (0x63, [
        "stack.append('IF')",
        "raise NotImplementedError('OP_IF not yet implemented')",
        'pass']
    ),
    (0x64, [
        "stack.append('NOTIF')",
        "raise NotImplementedError('OP_NOTIF not yet implemented')",
        'pass']
    ),
    (0x65, [
        "stack.append('VERIF')",
        "raise ReservedWordError('reserved opcode 0x65')",
        'pass']
    ),
    (0x66, [
        "stack.append('VERNOTIF')",
        "raise ReservedWordError('reserved opcode 0x66')",
        'pass']
    ),
    (0x67, [
        "stack.append('ELSE')",
        "raise NotImplementedError('OP_ELSE not yet implemented')",
        'pass']
    ),
    (0x68, [
        "stack.append('ENDIF')",
        "raise NotImplementedError('OP_ENDIF not yet implemented')",
        'pass']
    ),
    (0x69, [
        "stack.append('VERIFY')",
        "if not stack.pop(): raise TransactionInvalidError('VERIFY failed')",
        'pass']
    ),
    (0x6a, [
        "stack.append('RETURN')",
        "raise TransactionInvalidError('RETURN')",
        'pass']
    ),
    (0x6b, [
        "stack.append('TOALTSTACK')",
        'alstack.append(stack.pop()',
        'pass']
    ),
    (0x6c, [
        "stack.append('FROMALTSTACK')",
        'stack.append(altstack.pop()',
        'pass']
    ),
    (0x6d, [
        "stack.append('2DROP')",
        'stack[-2:] = []',
        'pass']
    ),
    (0x6e, [
        "stack.append('2DUP')",
        'stack.extend(stack[-2:])',
        'pass']
    ),
    (0x6f, [
        "stack.append('3DUP')",
        'stack.extend(stack[-3:])',
        'pass']
    ),
    (0x70, [
        "stack.append('2OVER')",
        'stack.extend(stack[-4:-2])',
        'pass']
    ),
    (0x71, [
        "stack.append('2ROT')",
        'stack.extend(stack[-6:-4]); stack[-8:-6] = []',
        'pass']
    ),
    (0x72, [
        "stack.append('2SWAP')",
        '_ = stack[-2:], stack[-4:-2] = stack[-4:-2], stack[-2:]',
        'pass']
    ),
    (0x73, [
        "stack.append('IFDUP')",
        'if stack[-1]: stack.append(stack[-1])',
        'pass']
    ),
    (0x74, [
        "stack.append('DEPTH')",
        'stack.append(len(stack))',
        'pass']
    ),
    (0x75, [
        "stack.append('DROP')",
        'stack.pop()',
        'pass']
    ),
    (0x76, [
        "stack.append('DUP')",
        'stack.append(stack[-1])',
        'pass']
    ),
    (0x77, [
        "stack.append('NIP')",
        'stack.pop(-2)',
        'pass']
    ),
    (0x78, [
        "stack.append('OVER')",
        'stack.append(stack[-2])',
        'pass']
    ),
    (0x79, [
        "stack.append('PICK')",
        'stack.append(stack[-1 - stack.pop())]',
        'pass']
    ),
    (0x7a, [
        "stack.append('ROLL')",
        'stack.append(stack.pop(stack[-1 - stack.pop()]))',
        'pass']
    ),
    (0x7b, [
        "stack.append('ROT')",
        'stack.append(stack.pop(-3))',
        'pass']
    ),
    (0x7c, [
        "stack.append('SWAP')",
        'stack.append(stack.pop(-2))',
        'pass']
    ),
    (0x7d, [
        "stack.append('TUCK')",
        'stack.insert(-2, stack[-1])',
        'pass']
    ),
    (0x80, [
        "stack.append('LEFT')",
        'stack.append(stack.pop(-2)[:stack.pop()])',
        'pass']
    ),
    (0x81, [
        "stack.append('RIGHT')",
        'stack.append(stack.pop(-2)[stack.pop() - 1:])',
        'pass']
    ),
    (0x82, [
        "stack.append('SIZE')",
        'stack.append(len(stack[-1]))',
        'pass']
    ),
    (0x83, [
        "stack.append('INVERT')",
        'stack[-1] = ~stack[-1]',
        'pass']
    ),
    (0x84, [
        "stack.append('AND')",
        'stack.append(stack.pop() & stack.pop())',
        'pass']
    ),
    (0x85, [
        "stack.append('OR')",
        'stack.append(stack.pop() | stack.pop())',
        'pass']
    ),
    (0x86, [
        "stack.append('XOR')",
        'stack.append(stack.pop() ^ stack.pop())',
        'pass']
    ),
    (0x87, [
        "stack.append('EQUAL')",
        'stack.append(stack.pop() == stack.pop())',
        'pass']
    ),
    (0x88, [
        "stack.append('EQUALVERIFY')",
        ('if stack.pop() != stack.pop():'
         " raise(TransactionInvalidError('failed EQUALVERIFY'))"),
        'pass']
    ),
    (0x89, [
        "stack.append('RESERVED1')",
        "raise(ReservedWordError('reserved opcode 0x89'))",
        'pass'],
    ),
    (0x8a, [
        "stack.append('RESERVED2')",
        "raise(ReservedWordError('reserved opcode 0x8a'))",
        'pass']
    ),
    (0x8b, [
        "stack.append('1ADD')",
        'stack[-1] += 1',
        'pass']
    ),
    (0x8c, [
        "stack.append('1SUB')",
        'stack[-1] -= 1',
        'pass']
    ),
    (0x8d, [
        "stack.append('2MUL')",
        'stack[-1] *= 2',
        'pass']
    ),
    (0x8e, [
        "stack.append('2DIV')",
        'stack[-1] //= 2',
        'pass']
    ),
    (0x8f, [
        "stack.append('NEGATE')",
        'stack[-1] = -stack[-1]',
        'pass']
    ),
    (0x90, [
        "stack.append('ABS')",
        'stack[-1] = abs(stack[-1])',
        'pass']
    ),
    (0x91, [
        "stack.append('NOT')",
        'stack[-1] = not stack[-1]',
        'pass']
    ),
    (0x92, [
        "stack.append('0NOTEQUAL')",
        'stack[-1] = bool(stack[-1])',
        'pass']
    ),
    (0x93, [
        "stack.append('ADD')",
        'stack.append(stack.pop() + stack.pop())',
        'pass']
    ),
    (0x94, [
        "stack.append('SUB')",
        'stack.append(-stack.pop() + stack.pop())',
        'pass']
    ),
    (0x95, [
        "stack.append('MUL')",
        '_ = stack.pop(0); stack[-1] *= _',
        'pass']
    ),
    (0x96, [
        "stack.append('DIV')",
        '_ = stack.pop(0); stack[-1] //= _',
        'pass']
    ),
    (0x97, [
        "stack.append('MOD')",
        '_ = stack.pop(0); stack[-1] %= _',
        'pass']
    ),
    (0x98, [
        "stack.append('LSHIFT')",
        '_ = stack.pop(0); stack[-1] <<= _',
        'pass']
    ),
    (0x99, [
        "stack.append('RSHIFT')",
        '_ = stack.pop(0); stack[-1] >>= _',
        'pass']
    ),
    (0x9a, [
        "stack.append('BOOLAND')",
        '_ = stack.pop(0); stack[-1] = stack[-1] and _',
        'pass']
    ),
    (0x9b, [
        "stack.append('BOOLOR')",
        '_ = stack.pop(0); stack[-1] = stack[-1] or _',
        'pass']
    ),
    (0x9c, [
        "stack.append('NUMEQUAL')",
        'stack.append(stack.pop(0) == stack.pop(0))',
        'pass']
    ),
    (0xa9, [
        "stack.append('HASH160')",
        'hash160(**globals())',
        'pass']
    ),
    (0xaa, [
        "stack.append('HASH256')",
        'hash256(**glboals())',
        'pass']
    ),
    (0xab, [
        "stack.append('CODESEPARATOR')",
        'mark.append(len(reference) - len(script) - 1)',
        'mark.append(len(reference) - len(script) - 1)']
    ),
    (0xac, [
        "stack.append('CHECKSIG')",
        'checksig(**globals())',
        'pass']
    ),
)
DISABLED = [  # add all opcodes disabled in Bitcoin core
#    0x83, 0x84, 0x85, 0x86
]
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
            logging.debug('`exec`ing 0x%x, %s', opcode, display_op)
            exec(display_op, {**globals(), **locals()})
    if display:
        while stack:
            print(stack.pop(0))
        print('-----')
    return parsed

def run(scriptbinary, txnew, parsed, stack=None, checksig_prep=False):
    '''
    executes scripts the same way (hopefully) as Bitcoin Core would

    showing stack at end of each operation

    if instead checksig_prep is True, only returns copy of script with
    OP_CODESEPARATORs removed; does not run anything
    '''
    stack = stack or []  # you can pass in a stack from previous script
    logging.debug('stack at start of run: %s', stack)
    altstack = []
    mark = [0]  # append a mark for every OP_CODESEPARATOR found
    opcodes = dict(SCRIPT_OPS)
    for opcode in DISABLED:
        opcodes.pop(opcode)
    try:
        script = list(scriptbinary)  # gives list of numbers (`ord`s)
        reference = list(script)  # make a copy
        ifstack = []  # internal stack for each script
        while script:
            opcode = script.pop(0)
            operation = opcodes.get(opcode, None)
            if operation is None:
                raise NotImplementedError('no such opcode 0x%x' % opcode)
            else:
                if ifstack and not ifstack[-1]:
                    run_op = operation[2]
                else:
                    run_op = operation[1]
                logging.info('`exec`ing operation 0x%x, %s', opcode, run_op)
                exec(run_op, {**globals(), **locals()})
            logging.info('script: %r, stack: %s', script, stack)
    except (TransactionInvalidError, ReservedWordError) as failed:
        logging.error('script failed or otherwise invalid: %s', failed)
        logging.info('stack: %s', stack)
        stack.append(False)
    logging.debug('run leaves stack at: %s', stack)
    # need to actually pass the stack back to caller...
    # problem with using `exec` is that it has its own environment
    return stack

# following subroutines are for use from `exec` calls from stack language,
# hence the odd parameters
def hash256(stack=None, hashlib=None, **ignored):
    '''
    sha256d hash, which is the hash of a hash
    '''
    data = stack.pop()
    stack.append(hashlib.sha256(hashlib.sha256(data).digest()).digest())
    return stack[-1]  # for conventional caller

def hash160(stack=None, hashlib=None, **ignored):
    '''
    input is hashed twice: first with SHA-256 and then with RIPEMD-160
    '''
    data = stack.pop()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(data).digest())
    stack.append(ripemd160.digest())
    return stack[-1]  # for conventional caller

def checksig(stack=None, reference=None, mark=None, parsed=None,
             txnew=None, **ignored):
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
    for input in txcopy[2][1:]:
        input[2] = b'\0'
        input.pop(3)
    try:
        txcopy[2][0][2] = bytes([len(subscript)])  # FIXME: assumes single byte
        txcopy[2][0][3] = bytes(subscript)
    except TypeError:
        logging.error('txcopy: %r, txcopy[2]: %r, txcopy[2][0]: %r',
                      txcopy, txcopy[2], txcopy[2][0])
        raise
    serialized = serialize(txcopy) + hashtype_code
    logging.debug('serialized with hashtype_code: %s', serialized)
    hashed = hash256(stack=[serialized], hashlib=hashlib)
    logging.debug('signature: %r, pubkey: %r', bytes(signature), pubkey)
    key = CECKey()
    key.set_pubkey(pubkey)
    stack.append(key.verify(hashed, bytes(signature)))
    return stack[-1]  # for conventional caller

def serialize(lists):
    '''
    convert multi-level list to bytestring
    '''
    serialized = b''
    for item in lists:
        logging.debug('item: %s', item)
        if type(item) == list:
            serialized += serialize(item)
        else:
            logging.debug('assuming %s is bytes', item)
            serialized += item
    logging.debug('serialized: %s', b2a_hex(serialized))
    return serialized

def test_checksig(current_tx, txin_index, previous_tx):
    '''
    display and run scripts in given transactions to test OP_CHECKSIG
    '''
    stack = []
    logging.debug('parsing and displaying current txin script...')
    txin = current_tx[2][txin_index]
    logging.debug('txin: %s', txin)
    logging.debug('previous tx hash: %s', b2a_hex(txin[0]))
    txout_index = struct.unpack('<L', txin[1])[0]
    txin_script = txin[3]
    parsed = parse(txin_script)
    logging.debug('running txin script...')
    stack = run(txin_script, current_tx, parsed, stack)
    logging.debug('stack after running txin script: %s', stack)
    logging.debug('parsing and displaying previous txout script...')
    txout = previous_tx[4]
    txout_script = txout[txout_index][2]
    parsed = parse(txout_script)
    logging.debug('stack before running txout script: %s', stack)
    logging.debug('running txout script %r...', txout_script)
    stack = run(txout_script, current_tx, parsed, stack)
    result = bool(stack.pop())
    logging.info('transaction result: %s', ['fail', 'pass'][result])

def testall(blockfiles=None, minblock=0, maxblock=sys.maxsize):
    '''
    keep testing every script in blockchain until one fails
    '''
    coinbase = b'\0' * 32  # previous_tx hash all nulls indicates coinbase tx
    transactions = next_transaction(blockfiles, minblock, maxblock)
    count = 0
    for hash_ignored, transaction in transactions:
        for txin in transaction[2]:
            stack = []
            txin_script = txin[3]
            parsed = parse(txin_script)
            stack = run(txin_script, transaction, parsed, stack)
            result = bool(stack and stack[-1])
            logging.info('%d scripts executed successfully', count)
            if not result:
                raise(TransactionInvalidError('script failed'))
            count += 1
            tx_hash = txin[0]
            if tx_hash != coinbase:
                logging.debug('non-coinbase transaction')
                tx_index = struct.unpack('<L', txin[1])[0]
                tx_search = next_transaction(blockfiles)
                for search_hash, tx in tx_search:
                    logging.debug('comparing %r and %r', search_hash, tx_hash)
                    if search_hash == tx_hash:
                        logging.debug('found previous tx')
                        txout_script = tx[4][tx_index][2]
                        parsed = parse(txout_script)
                        # still using stack from above txin_script
                        stack = run(txout_script, txin, parsed, stack)
                        result = bool(stack.pop())
                        logging.info('%d scripts executed successfully', count)
                        if not result:
                            raise(TransactionInvalidError('script failed'))
                        count += 1

if __name__ == '__main__':
    # default operation is to test OP_CHECKSIG
    for transactions in (PIZZA, FIRST):
        test_checksig(transactions[0], 0, transactions[1])
    testall(*sys.argv[1:])
