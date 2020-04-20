import logging
from typing import (
    Any,
    ClassVar,
    Iterable,
    Sequence,
    Tuple,
    Type,
)

from eth_typing import (
    Address,
    Hash32,
)
from eth_utils import (
    ValidationError,
)

from scp._utils.datatypes import (
    Configurable,
)
from scp.abc import (
    AtomicDatabaseAPI,
    BlockHeaderAPI,
    ChainContextAPI,
    ComputationAPI,
    ReceiptAPI,
    SignedTransactionAPI,
    StateAPI,
    UnsignedTransactionAPI,
    VirtualMachineAPI,
)
from scp.vm.interrupt import (
    EVMMissingData,
)
from scp.vm.message import (
    Message,
)
from scp.vm.state import VMState


class VM(Configurable, VirtualMachineAPI):
    extra_data_max_bytes: ClassVar[int] = 32
    fork: str = None  # noqa: E701  # flake8 bug that's fixed in 3.6.0+
    _state_class: Type[StateAPI] = VMState

    _state = None
    _block = None

    cls_logger = logging.getLogger('eth.vm.base.VM')

    def __init__(self) -> None:
        pass

    @property
    def state(self) -> StateAPI:
        if self._state is None:
            self._state = self.build_state()
        return self._state

    @classmethod
    def build_state(self) -> StateAPI:
        return self._state_class()

    #
    # Execution
    #
    def apply_transaction(self, transaction) -> ComputationAPI:

        computation = self.state.apply_transaction(transaction)

        return computation

    def execute_bytecode(self,
                         origin: Address,
                         gas_price: int,
                         gas: int,
                         to: Address,
                         sender: Address,
                         value: int,
                         data: bytes,
                         code: bytes,
                         code_address: Address = None,
                         ) -> ComputationAPI:
        if origin is None:
            origin = sender

        # Construct a message
        message = Message(
            gas=gas,
            to=to,
            sender=sender,
            value=value,
            data=data,
            code=code,
            code_address=code_address,
        )

        # Construction a tx context
        transaction_context = self.state.get_transaction_context_class()(
            gas_price=gas_price,
            origin=origin,
        )

        # Execute it in the VM
        return self.state.get_computation(message, transaction_context).apply_computation(
            self.state,
            message,
            transaction_context,
        )

    def apply_all_transactions(
            self,
            transactions: Sequence[SignedTransactionAPI],
            base_header: BlockHeaderAPI
    ) -> Tuple[BlockHeaderAPI, Tuple[ReceiptAPI, ...], Tuple[ComputationAPI, ...]]:
        if base_header.block_number != self.get_header().block_number:
            raise ValidationError(
                f"This VM instance must only work on block #{self.get_header().block_number}, "
                f"but the target header has block #{base_header.block_number}"
            )

        receipts = []
        computations = []
        previous_header = base_header
        result_header = base_header

        for transaction in transactions:
            try:
                snapshot = self.state.snapshot()
                receipt, computation = self.apply_transaction(
                    previous_header,
                    transaction,
                )
            except EVMMissingData as exc:
                self.state.revert(snapshot)
                raise

            result_header = self.add_receipt_to_header(previous_header, receipt)
            previous_header = result_header
            receipts.append(receipt)
            computations.append(computation)

        receipts_tuple = tuple(receipts)
        computations_tuple = tuple(computations)

        return result_header, receipts_tuple, computations_tuple

    #
    # Transactions
    #
    def create_transaction(self, *args: Any, **kwargs: Any) -> SignedTransactionAPI:
        return self.get_transaction_class()(*args, **kwargs)

    @classmethod
    def create_unsigned_transaction(cls,
                                    *,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    data: bytes) -> UnsignedTransactionAPI:
        return cls.get_transaction_class().create_unsigned_transaction(
            nonce=nonce,
            gas_price=gas_price,
            gas=gas,
            to=to,
            value=value,
            data=data
        )
