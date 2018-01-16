#!/usr/bin/python3
'''
display and execute bitcoin stack scripts
'''
import sys, os, struct, logging
from binascii import b2a_hex, a2b_hex
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
        'VER',
        "raise ReservedWordError('reserved opcode 0x62')",
        'pass']
    ),
    (0x63, [
        'IF',
        "raise NotImplementedError('OP_IF not yet implemented')",
        'pass']
    ),
    (0x64, [
        'NOTIF',
        "raise NotImplementedError('OP_NOTIF not yet implemented')",
        'pass']
    ),
    (0x65, [
        'VERIF',
        "raise ReservedWordError('reserved opcode 0x65')",
        'pass']
    ),
    (0x66, [
        'VERNOTIF',
        "raise ReservedWordError('reserved opcode 0x66')",
        'pass']
    ),
    (0x67, [
        'ELSE',
        "raise NotImplementedError('OP_ELSE not yet implemented')",
        'pass']
    ),
    (0x68, [
        'ENDIF',
        "raise NotImplementedError('OP_ENDIF not yet implemented')",
        'pass']
    ),
    (0x69, [
        'VERIFY',
        "if not stack.pop(-1): raise TransactionInvalidError('VERIFY failed')",
        'pass']
    ),
    (0x6a, [
        'RETURN',
        "raise TransactionInvalidError('RETURN')",
        'pass']
    ),
    (0x6b, [
        'TOALTSTACK',
        'alstack.append(stack.pop(-1)',
        'pass']
    ),
    (0x6c, [
        'FROMALTSTACK',
        'stack.append(altstack.pop(-1)',
        'pass']
    ),
    (0x6d, [
        '2DROP',
        'stack[-2:] = []',
        'pass']
    ),
    (0x6e, [
        '2DUP',
        'stack.extend(stack[-2:])',
        'pass']
    ),
    (0x6f, [
        '3DUP',
        'stack.extend(stack[-3:])',
        'pass']
    ),
    (0x70, [
        '2OVER',
        'stack.extend(stack[-4:-2])',
        'pass']
    ),
    (0x71, [
        '2ROT',
        'stack.extend(stack[-6:-4]); stack[-8:-6] = []',
        'pass']
    ),
    (0x76, [
        "stack.append('DUP')",
        'stack.append(stack[-1])',
        'pass']
    ),
    (0xac, [
        "stack.append('CHECKSIG')",
        'stack.pop(-1); stack[-1] = 1',  # FIXME: simulating success for now
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
    parsed = []
    opcodes = dict(SCRIPT_OPS)
    script = list(scriptbinary)  # gives list of numbers (`ord`s)
    while script:
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

def run(scriptbinary, parsed, stack=None, checksig_prep=False):
    '''
    executes scripts the same way (hopefully) as Bitcoin Core would

    showing stack at end of each operation

    if instead checksig_prep is True, only returns copy of script with
    OP_CODESEPARATORs removed; does not run anything
    '''
    stack = stack or []  # you can pass in a stack from previous script
    logging.debug('stack at start of run: %s', stack)
    altstack = []
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
    stack = run(txin_script, parsed, stack)
    logging.debug('stack after running txin script: %s', stack)
    logging.debug('parsing and displaying previous txout script...')
    txout = previous_tx[4]
    txout_script = txout[txout_index][2]
    parsed = parse(txout_script)
    logging.debug('stack before running txout script: %s', stack)
    logging.debug('running txout script %r...', txout_script)
    stack = run(txout_script, parsed, stack)
    result = bool(stack.pop(-1))
    logging.debug('transaction result: %s', ['fail', 'pass'][result])

if __name__ == '__main__':
    # default operation is to test OP_CHECKSIG
    test_checksig(TEST_CHECKSIG[0], 0, TEST_CHECKSIG[1])
