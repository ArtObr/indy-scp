from pathlib import Path
from typing import NamedTuple

from eth_utils import (
    decode_hex,
    encode_hex
)

from scp.abc import AtomicDatabaseAPI
from scp.db.atomic import AtomicDB
from scp.db.backends.level import LevelDB
from scp.db.chain import ChainDB

from scp.tools.factories.transaction import (
    new_transaction
)
from scp.vm.base import VM
from scp.vm.opcode_values import CALLDATALOADFUNCTION, EQ, PUSH1, JUMPI, JUMPDEST, RETURN, SSTORE, PUSH32, PUSH4, SLOAD, \
    MSTORE
from scp.vm.state import VMState

contract_OOP_code = \
    '''
    contract GetSetContract {
        string value = "Initial ";
        
        function getValue() returns(string) {
            return value;
        }
        
        function setValue(string value) public {
            value = value;
        }
    }
    '''

contract_code = bytes([
    CALLDATALOADFUNCTION,
    PUSH1,  # jump to constructor
    0x0,
    EQ,
    PUSH1,
    0x1C,  # dest of constuctor
    JUMPI,
    CALLDATALOADFUNCTION,
    PUSH4,  # jump to getValue()
    *'2096'.encode(),
    EQ,
    PUSH1,
    0x42,  # dest of getValue
    JUMPI,
    CALLDATALOADFUNCTION,
    PUSH4,  # jump to setValue(string)
    *'93a0'.encode(),
    EQ,
    PUSH1,
    0x41,  # dest of setValue(string)
    JUMPI,
    RETURN,
    JUMPDEST,  # 26 constuctor code
    PUSH32,
    *'Hello World'.encode().rjust(32, b'\x00'),
    PUSH1,
    0x0,
    SSTORE,
    RETURN,
    JUMPDEST,  # 66 getValue code
    PUSH1,
    0x0,
    SLOAD,
    PUSH1,
    0x0,
    MSTORE,
    PUSH1,
    0x20,
    PUSH1,
    0x0,
    RETURN
])

call_get_value_code = bytes([*'2096'.encode()])


def create_test_txn(data, sender, to):
    Txn = NamedTuple('txn',
                     (('data', bytes),
                      ('sender', bytes),
                      ('to', bytes)))
    return Txn(data, sender, to)


def test_apply_transaction():
    vm = VM()
    recipient = b''
    amount = 0
    from_ = b''
    tx = create_test_txn(contract_code, from_, recipient)
    computation = vm.apply_transaction(tx)

    recipient = b'+\xea/ _\n\x1b6t\xc8\xd1\xd7\xae\xe6\xb1q"\xa2\xf7:'
    tx = create_test_txn(call_get_value_code, from_, recipient)
    computation = vm.apply_transaction(tx)
    assert computation.output.decode('utf-8').lstrip('\0') == 'Hello World'
