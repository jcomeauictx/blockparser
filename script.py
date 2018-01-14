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
#  the Python code to be `exec`d in the context of the `run` routine
SCRIPT_OPS = tuple(  # 0x01 through 0x4b are all implied PUSH operations
    (n,
        ['stack.append(b2a_hex(bytes([script.pop(0) for i in range(opcode)])))',
         'stack.append(bytes([script.pop(0) for i in range(opcode)]))'])
    for n in range(0x01, 0x4c)
)
SCRIPT_OPS += (
    (0x00, [
        "stack.append('OP_FALSE')",
        'stack.append(0)']
    ),
    (0x4c, [
        "stack.append('OP_PUSHDATA1')",
        ('count = script.pop(0);'
         'stack.append(bytes[script.pop(0) for i in range(count)])')],
    ),
    (0x76, [
        "stack.append('OP_DUP')",
        'stack.append(stack[-1])'],
    ),
    (0xac, [
        "stack.append('OP_CHECKSIG')",
        'stack.pop(-1); stack[-1] = 1'],  # FIXME: simulating success for now
    ),
)
TESTSCRIPT = (  # from Satoshi's genesis block coinbase output
        b"A\x04g\x8a\xfd\xb0\xfeUH'\x19g\xf1\xa6q0\xb7\x10\\\xd6\xa8"
        b"(\xe09\t\xa6yb\xe0\xea\x1fa\xde\xb6I\xf6\xbc?L\xef8\xc4\xf3"
        b"U\x04\xe5\x1e\xc1\x12\xde\\8M\xf7\xba\x0b\x8dW\x8aLp+k\xf1\x1d_\xac"
)

def display(scriptbinary):
    '''
    breaks down binary script into something readable (to a FORTHer)
    '''
    stack = []
    opcodes = dict(SCRIPT_OPS)
    script = list(scriptbinary)  # gives list of numbers (`ord`s)
    while script:
        opcode = script.pop(0)
        operation = opcodes.get(opcode, None)
        if operation is None:
            stack.append(hex(opcode) + "(not yet implemented)")
        else:
            display_op = operation[0]
            logging.debug('`exec`ing operation 0x%x, %s', opcode, display_op)
            exec(display_op, {**globals(), **locals()})
    while stack:
        print(stack.pop(0))

def run(scriptbinary):
    '''
    executes script the same way (hopefully) as Bitcoin Core would

    showing stack at end of each operation
    '''
    stack = []
    opstack = []
    opcodes = dict(SCRIPT_OPS)
    script = list(scriptbinary)  # gives list of numbers (`ord`s)
    while script:
        opcode = script.pop(0)
        operation = opcodes.get(opcode, None)
        if operation is None:
            opstack.append("raise(NotImplementedError("
                           "'unrecognized opcode 0x%x')" % opcode)
        else:
            opstack.append(operation[1])
    while opstack:
        exec(opstack.pop(0), {**globals(), **locals()})
        logging.info('stack: %s', stack)

if __name__ == '__main__':
    SCRIPT = binascii.a2b_hex(sys.argv[1]) if len(sys.argv) > 1 else TESTSCRIPT
    display(SCRIPT)
    run(SCRIPT)
