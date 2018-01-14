#!/usr/bin/python3
'''
display and execute bitcoin stack scripts
'''
SCRIPT_OPS = tuple(
    (n, ('(PUSH(%d))' % n,
    'stack.push(bytes(script[:%d])); script[:%d]=[]' % (n, n)))
    for n in range(0x01, 0x4c))
SCRIPT_OPS += (
    (0x00, ('OP_FALSE', 'stack.push(0)')),
    (0x4c, ('OP_PUSHDATA1', 'stack.push(program.eat(1))')),
    (0x76, ('OP_DUP', 'stack.push(stack[-1])')),
)
