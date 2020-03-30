import copy
from typing import Dict

from eth_utils.toolz import merge

from scp import constants
from scp.abc import OpcodeAPI
from scp.vm import mnemonics
from scp.vm import opcode_values
from scp.vm.logic import (
    call,
)

from scp.vm.forks.frontier.opcodes import FRONTIER_OPCODES


NEW_OPCODES = {
    opcode_values.DELEGATECALL: call.DelegateCall.configure(
        __name__='opcode:DELEGATECALL',
        mnemonic=mnemonics.DELEGATECALL,
        gas_cost=constants.GAS_CALL,
    )(),
}


HOMESTEAD_OPCODES: Dict[int, OpcodeAPI] = merge(
    copy.deepcopy(FRONTIER_OPCODES),
    NEW_OPCODES
)
