#!/usr/bin/python3
'''
display and execute bitcoin stack scripts
'''
import sys, os, struct, logging, copy, hashlib
from binascii import b2a_hex, a2b_hex
from bitcoin import ecdsa_verify  # cheating for now until I can write my own
# pip install --user git+https://github.com/jcomeauictx/pybitcointools.git
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
        "if not stack.pop(-1): raise TransactionInvalidError('VERIFY failed')",
        'pass']
    ),
    (0x6a, [
        "stack.append('RETURN')",
        "raise TransactionInvalidError('RETURN')",
        'pass']
    ),
    (0x6b, [
        "stack.append('TOALTSTACK')",
        'alstack.append(stack.pop(-1)',
        'pass']
    ),
    (0x6c, [
        "stack.append('FROMALTSTACK')",
        'stack.append(altstack.pop(-1)',
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
        'stack.pop(-1)',
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
        'stack.append(stack[-1 - stack.pop(-1))]',
        'pass']
    ),
    (0x7a, [
        "stack.append('ROLL')",
        'stack.append(stack.pop(stack[-1 - stack.pop(-1)]))',
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
        'stack.append(stack.pop(-2)[:stack.pop(-1)])',
        'pass']
    ),
    (0x81, [
        "stack.append('RIGHT')",
        'stack.append(stack.pop(-2)[stack.pop(-1) - 1:])',
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
        'stack.append(stack.pop(-1) & stack.pop(-1))',
        'pass']
    ),
    (0x85, [
        "stack.append('OR')",
        'stack.append(stack.pop(-1) | stack.pop(-1))',
        'pass']
    ),
    (0x86, [
        "stack.append('XOR')",
        'stack.append(stack.pop(-1) ^ stack.pop(-1))',
        'pass']
    ),
    (0x87, [
        "stack.append('EQUAL')",
        'stack.append(stack.pop(-1) == stack.pop(-1))',
        'pass']
    ),
    (0x88, [
        "stack.append('EQUALVERIFY')",
        ('if stack.pop(-1) != stack.pop(-1):'
         " raise(TransactionInvalidError('failed EQUALVERIFY')"),
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
        'stack.append(stack.pop(-1) + stack.pop(-1))',
        'pass']
    ),
    (0x94, [
        "stack.append('SUB')",
        'stack.append(-stack.pop(-1) + stack.pop(-1))',
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
    (0xab, [
        "stack.append('CODESEPARATOR')",
        'mark.append(len(reference) - len(script) - 1)',
        'mark.append(len(reference) - len(script) - 1)']
    ),
    (0xac, [
        "stack.append('CHECKSIG')",
        "logging.debug('stack: %s', stack); checksig(stack=stack)",
        'pass']
    ),
)
DISABLED = [  # add all opcodes disabled in Bitcoin core
#    0x83, 0x84, 0x85, 0x86
]
TEST_CHECKSIG = (
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

class InvalidTransactionError(ValueError):
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
    except (InvalidTransactionError, ReservedWordError):
        logging.error('script failed or otherwise invalid')
        logging.info('stack: %s', stack)
        stack[:] = []  # empty stack
    logging.debug('run leaves stack at: %s', stack)
    # need to actually pass the stack back to caller...
    # problem with using `exec` is that it has its own environment
    return stack

def hash256(data):
    '''
    sha256d hash, which is the hash of a hash
    '''
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def checksig(stack=None, reference=None, mark=None):
    '''
    run OP_CHECKSIG in context of `run` subroutine
    '''
    logging.debug('checksig stack: %s, reference: %s, mark: %s',
                  stack, reference, mark)
    pubkey = stack.pop(-1)
    signature = stack.pop(-1)
    subscript = reference[mark[-1]:]
    checker = list(parsed[mark[-1]:])  # for checking for OP_CODESEPARATORs
    # remove OP_CODESEPARATORs in subscript
    # only safe way to do this is to work backwards using positive indices
    for offset in range(len(checker) - 1, 0, -1):
        if checker[offset] == 0xab:  # OP_CODESEPARATOR
            checker.pop(offset)
            subscript.pop(offset)
    hashtype = signature.pop(-1)
    hastype_code = struct.pack('<L', hashtype)
    txcopy = copy.deepcopy(txnew)
    for input in txcopy[2][1:]:
        input[2] = b'\0'
        input.pop(3)
    txcopy[2][0][2] = bytes([len(subscript)])
    txcopy[2][0][3] = subscript
    serialized = serialize(txcopy) + hashtype_code
    hashed = hash256(serialized)
    stack.push(ecdsa_verify(hashed, signature, pubkey))

def serialize(lists):
    '''
    convert multi-level list to bytestring
    '''
    return b''.join([item for sublist in lists for item in sublist])

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
    result = bool(stack.pop(-1))
    logging.debug('transaction result: %s', ['fail', 'pass'][result])

if __name__ == '__main__':
    # default operation is to test OP_CHECKSIG
    test_checksig(TEST_CHECKSIG[0], 0, TEST_CHECKSIG[1])
