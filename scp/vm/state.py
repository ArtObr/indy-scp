import contextlib
from typing import (
    Iterator,
    Tuple,
    Type,
)
from uuid import UUID

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
)
from eth_utils import (
    ExtendedDebugLogger,
    get_extended_debug_logger, encode_hex,
)
from eth_utils.toolz import nth

from scp._utils.address import generate_contract_address
from scp._utils.datatypes import (
    Configurable,
)
from scp.abc import (
    AtomicDatabaseAPI,
    ComputationAPI,
    MessageAPI,
    SignedTransactionAPI,
    StateAPI,
    TransactionExecutorAPI,
)
from scp.constants import (
    MAX_PREV_HEADER_DEPTH, CREATE_CONTRACT_ADDRESS,
)
from scp.exceptions import ContractCreationCollision
from scp.vm.computation import BaseComputation
from scp.vm.message import Message
from scp.vm.transaction import HomesteadUnsignedTransaction


class VMTransactionExecutor(TransactionExecutorAPI):
    def __init__(self, vm_state: StateAPI) -> None:
        self.vm_state = vm_state

    def __call__(self, transaction: SignedTransactionAPI) -> ComputationAPI:
        self.validate_transaction(transaction)
        message = self.build_evm_message(transaction)
        computation = self.build_computation(message, transaction)
        finalized_computation = self.finalize_computation(transaction, computation)
        return finalized_computation

    def validate_transaction(self, transaction: SignedTransactionAPI) -> None:

        # Validate the transaction
        transaction.validate()
        self.vm_state.validate_transaction(transaction)

    def build_evm_message(self, transaction: SignedTransactionAPI) -> MessageAPI:

        # Increment Nonce
        # self.vm_state.increment_nonce(transaction.sender)

        if transaction.to == CREATE_CONTRACT_ADDRESS:
            contract_address = generate_contract_address(
                transaction.sender,
                # self.vm_state.get_nonce(transaction.sender) - 1,
                1
            )
            data = b''
            code = transaction.data
            self.vm_state.set_code(contract_address, transaction.data)
        else:
            contract_address = None
            data = transaction.data
            code = self.vm_state.get_code(transaction.to)

        message = Message(
            gas=1,
            to=transaction.to,
            sender=transaction.sender,
            value=transaction.value,
            data=data,
            code=code,
            create_address=contract_address,
        )
        return message

    def build_computation(self,
                          message: MessageAPI,
                          transaction: SignedTransactionAPI) -> ComputationAPI:
        if message.is_create:
            is_collision = self.vm_state.has_code_or_nonce(
                message.storage_address
            )

            if is_collision:
                # The address of the newly created contract has *somehow* collided
                # with an existing contract address.
                computation = self.vm_state.get_computation(message)
                computation.error = ContractCreationCollision(
                    f"Address collision while creating contract: "
                    f"{encode_hex(message.storage_address)}"
                )
                self.vm_state.logger.debug2(
                    "Address collision while creating contract: %s",
                    encode_hex(message.storage_address),
                )
            else:
                computation = self.vm_state.get_computation(
                    message
                ).apply_create_message()
        else:
            computation = self.vm_state.get_computation(
                message).apply_message()

        return computation

    def finalize_computation(self,
                             transaction: SignedTransactionAPI,
                             computation: ComputationAPI) -> ComputationAPI:

        return computation


class VMState(Configurable, StateAPI):
    #
    # Set from __init__
    #
    __slots__ = ['_db', 'execution_context', '_account_db']

    computation_class: Type[ComputationAPI] = BaseComputation
    transaction_executor_class: Type[TransactionExecutorAPI] = VMTransactionExecutor

    def __init__(
            self,
            db: AtomicDatabaseAPI) -> None:
        self._db = db
        self._account_db = {

        }
        self._account_storage = {
            b'+\xea/ _\n\x1b6t\xc8\xd1\xd7\xae\xe6\xb1q"\xa2\xf7:': {
            }
        }

    def apply_transaction(self, transaction: SignedTransactionAPI) -> ComputationAPI:
        executor = self.get_transaction_executor()
        return executor(transaction)

    def validate_transaction(self, transaction: SignedTransactionAPI) -> None:
        pass

    #
    # Logging
    #
    @property
    def logger(self) -> ExtendedDebugLogger:
        return get_extended_debug_logger(f'eth.vm.state.{self.__class__.__name__}')

    #
    # Block Object Properties (in opcodes)
    #

    @property
    def coinbase(self) -> Address:
        return self.execution_context.coinbase

    @property
    def timestamp(self) -> int:
        return self.execution_context.timestamp

    @property
    def block_number(self) -> BlockNumber:
        return self.execution_context.block_number

    @property
    def difficulty(self) -> int:
        return self.execution_context.difficulty

    @property
    def gas_limit(self) -> int:
        return self.execution_context.gas_limit

    #
    # Access to account db
    #

    @property
    def state_root(self) -> Hash32:
        return self._account_db.state_root

    def make_state_root(self) -> Hash32:
        return self._account_db.make_state_root()

    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        storage = self._account_storage.get(address)
        return storage.get(slot)

    def set_storage(self, address: Address, slot: int, value: int) -> None:
        storage = self._account_storage.get(address)
        storage[slot] = value

    def delete_storage(self, address: Address) -> None:
        self._account_db.delete_storage(address)

    def delete_account(self, address: Address) -> None:
        self._account_db.delete_account(address)

    def get_balance(self, address: Address) -> int:
        return self._account_db.get_balance(address)

    def set_balance(self, address: Address, balance: int) -> None:
        self._account_db.set_balance(address, balance)

    def delta_balance(self, address: Address, delta: int) -> None:
        self.set_balance(address, self.get_balance(address) + delta)

    def get_nonce(self, address: Address) -> int:
        return self._account_db.get_nonce(address)

    def set_nonce(self, address: Address, nonce: int) -> None:
        self._account_db.set_nonce(address, nonce)

    def increment_nonce(self, address: Address) -> None:
        self._account_db.increment_nonce(address)

    def get_code(self, address: Address) -> bytes:
        return self._account_db.get(address)

    def set_code(self, address: Address, code: bytes) -> None:
        self._account_db[address] = code

    def get_code_hash(self, address: Address) -> Hash32:
        return self._account_db.get_code_hash(address)

    def delete_code(self, address: Address) -> None:
        self._account_db.delete_code(address)

    def has_code_or_nonce(self, address: Address) -> bool:
        # return self._account_db.account_has_code_or_nonce(address)
        return False

    def account_exists(self, address: Address) -> bool:
        return self._account_db.account_exists(address)

    def touch_account(self, address: Address) -> None:
        self._account_db.touch_account(address)

    def account_is_empty(self, address: Address) -> bool:
        return self._account_db.account_is_empty(address)

    #
    # Access self._chaindb
    #
    def snapshot(self) -> Tuple[Hash32, UUID]:
        return self.state_root, self._account_db.record()

    def revert(self, snapshot: Tuple[Hash32, UUID]) -> None:
        state_root, account_snapshot = snapshot

        # first revert the database state root.
        self._account_db.state_root = state_root
        # now roll the underlying database back
        self._account_db.discard(account_snapshot)

    def commit(self, snapshot: Tuple[Hash32, UUID]) -> None:
        _, account_snapshot = snapshot
        self._account_db.commit(account_snapshot)

    def lock_changes(self) -> None:
        self._account_db.lock_changes()

    def persist(self) -> None:
        self._account_db.persist()

    #
    # Access self.prev_hashes (Read-only)
    #
    def get_ancestor_hash(self, block_number: int) -> Hash32:
        ancestor_depth = self.block_number - block_number - 1
        is_ancestor_depth_out_of_range = (
                ancestor_depth >= MAX_PREV_HEADER_DEPTH or
                ancestor_depth < 0 or
                block_number < 0
        )
        if is_ancestor_depth_out_of_range:
            return Hash32(b'')

        try:
            return nth(ancestor_depth, self.execution_context.prev_hashes)
        except StopIteration:
            # Ancestor with specified depth not present
            return Hash32(b'')

    #
    # Computation
    #
    def get_computation(self,
                        message: MessageAPI) -> ComputationAPI:
        if self.computation_class is None:
            raise AttributeError("No `computation_class` has been set for this State")
        else:
            computation = self.computation_class(self, message)
        return computation

    #
    # Execution
    #
    def get_transaction_executor(self) -> TransactionExecutorAPI:
        return self.transaction_executor_class(self)

    @classmethod
    def create_unsigned_transaction(cls,
                                    *,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    data: bytes) -> 'HomesteadUnsignedTransaction':
        return HomesteadUnsignedTransaction(nonce, gas_price, gas, to, value, data)
