from pathlib import Path

import pytest

from eth_utils import (
    decode_hex,
    ValidationError,
)

from scp import constants
from scp.abc import AtomicDatabaseAPI, ConsensusContextAPI
from scp.db.backends.level import LevelDB
from scp.db.chain import ChainDB

from scp.tools.factories.transaction import (
    new_transaction
)
from scp.vm.chain_context import ChainContext
from scp.vm.forks import HomesteadVM


class ConsensusContext(ConsensusContextAPI):
    def __init__(self, db: AtomicDatabaseAPI):
        self.db = db


def test_apply_transaction():
    db = LevelDB(Path('/home/alice/dev/level_db'))
    vm = HomesteadVM(None, ChainDB(db), ChainContext(None), ConsensusContext(db))
    recipient = b'1' * 20
    amount = 0
    from_ = ''
    # tx = new_transaction(vm, from_, recipient, amount, b'', data=decode_hex('6d4c'))
    tx = new_transaction(vm, from_, recipient, amount, b'', data=b'ce6d4')
    receipt, computation = vm.apply_transaction(vm.get_header(), tx)
    a = 10
