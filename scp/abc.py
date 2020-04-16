from abc import (
    ABC,
    abstractmethod
)
from typing import (
    Any,
    Callable,
    ClassVar,
    ContextManager,
    Dict,
    Iterable,
    Iterator,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    NamedTuple)
from uuid import UUID

import rlp

from eth_bloom import BloomFilter

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
)

from eth_utils import ExtendedDebugLogger

from eth_keys.datatypes import PrivateKey

from scp.constants import (
    BLANK_ROOT_HASH,
)
from scp.exceptions import VMError
from scp.typing import (
    BytesOrView,
    JournalDBCheckpoint,
    AccountState,
    HeaderParams,
    VMConfiguration,
)

T = TypeVar('T')


class MiningHeaderAPI(rlp.Serializable, ABC):
    """
    A class to define a block header without ``mix_hash`` and ``nonce`` which can act as a
    temporary representation during mining before the block header is sealed.
    """
    parent_hash: Hash32
    uncles_hash: Hash32
    coinbase: Address
    state_root: Hash32
    transaction_root: Hash32
    receipt_root: Hash32
    bloom: int
    difficulty: int
    block_number: BlockNumber
    gas_limit: int
    gas_used: int
    timestamp: int
    extra_data: bytes


class BlockHeaderAPI(MiningHeaderAPI):
    """
    A class derived from :class:`~eth.abc.MiningHeaderAPI` to define a block header after it is
    sealed.
    """
    mix_hash: Hash32
    nonce: bytes


class LogAPI(rlp.Serializable, ABC):
    """
    A class to define a written log.
    """
    address: Address
    topics: Sequence[int]
    data: bytes

    @property
    @abstractmethod
    def bloomables(self) -> Tuple[bytes, ...]:
        ...


class ReceiptAPI(rlp.Serializable, ABC):
    """
    A class to define a receipt to capture the outcome of a transaction.
    """
    state_root: bytes
    gas_used: int
    bloom: int
    logs: Sequence[LogAPI]

    @property
    @abstractmethod
    def bloom_filter(self) -> BloomFilter:
        ...


class BaseTransactionAPI(ABC):
    """
    A class to define all common methods of a transaction.
    """

    @abstractmethod
    def validate(self) -> None:
        """
        Hook called during instantiation to ensure that all transaction
        parameters pass validation rules.
        """
        ...

    @property
    @abstractmethod
    def intrinsic_gas(self) -> int:
        """
        Convenience property for the return value of `get_intrinsic_gas`
        """
        ...

    @abstractmethod
    def get_intrinsic_gas(self) -> int:
        """
        Return the intrinsic gas for the transaction which is defined as the amount of gas that
        is needed before any code runs.
        """
        ...

    @abstractmethod
    def gas_used_by(self, computation: 'ComputationAPI') -> int:
        """
        Return the gas used by the given computation. In Frontier,
        for example, this is sum of the intrinsic cost and the gas used
        during computation.
        """
        ...

    # @abstractmethod
    # def copy(self: T, **overrides: Any) -> T:
    #     """
    #     Return a copy of the transaction.
    #     """
    #     ...


class TransactionFieldsAPI(ABC):
    """
    A class to define all common transaction fields.
    """
    nonce: int
    gas_price: int
    gas: int
    to: Address
    value: int
    data: bytes
    v: int
    r: int
    s: int

    @property
    @abstractmethod
    def hash(self) -> bytes:
        ...


class UnsignedTransactionAPI(rlp.Serializable, BaseTransactionAPI):
    """
    A class representing a transaction before it is signed.
    """
    nonce: int
    gas_price: int
    gas: int
    to: Address
    value: int
    data: bytes

    #
    # API that must be implemented by all Transaction subclasses.
    #
    @abstractmethod
    def as_signed_transaction(self, private_key: PrivateKey) -> 'SignedTransactionAPI':
        """
        Return a version of this transaction which has been signed using the
        provided `private_key`
        """
        ...


class SignedTransactionAPI(rlp.Serializable, BaseTransactionAPI, TransactionFieldsAPI):
    """
    A class representing a transaction that was signed with a private key.
    """

    @classmethod
    @abstractmethod
    def from_base_transaction(cls, transaction: 'SignedTransactionAPI') -> 'SignedTransactionAPI':
        """
        Create a signed transaction from a base transaction.
        """
        ...

    @property
    @abstractmethod
    def sender(self) -> Address:
        """
        Convenience and performance property for the return value of `get_sender`
        """
        ...

    # +-------------------------------------------------------------+
    # | API that must be implemented by all Transaction subclasses. |
    # +-------------------------------------------------------------+

    #
    # Validation
    #
    @abstractmethod
    def validate(self) -> None:
        """
        Hook called during instantiation to ensure that all transaction
        parameters pass validation rules.
        """

        ...

    #
    # Signature and Sender
    #
    @property
    @abstractmethod
    def is_signature_valid(self) -> bool:
        """
        Return ``True`` if the signature is valid, otherwise ``False``.
        """
        ...

    @abstractmethod
    def check_signature_validity(self) -> None:
        """
        Check if the signature is valid. Raise a ``ValidationError`` if the signature
        is invalid.
        """
        ...

    @abstractmethod
    def get_sender(self) -> Address:
        """
        Get the 20-byte address which sent this transaction.

        This can be a slow operation. ``transaction.sender`` is always preferred.
        """
        ...

    #
    # Conversion to and creation of unsigned transactions.
    #
    @abstractmethod
    def get_message_for_signing(self) -> bytes:
        """
        Return the bytestring that should be signed in order to create a signed transactions
        """
        ...

    @classmethod
    @abstractmethod
    def create_unsigned_transaction(cls,
                                    *,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    data: bytes) -> UnsignedTransactionAPI:
        """
        Create an unsigned transaction.
        """
        ...


class BlockAPI(rlp.Serializable, ABC):
    """
    A class to define a block.
    """
    transaction_class: Type[SignedTransactionAPI] = None

    @classmethod
    @abstractmethod
    def get_transaction_class(cls) -> Type[SignedTransactionAPI]:
        """
        Return the transaction class that is valid for the block.
        """
        ...

    @classmethod
    @abstractmethod
    def from_header(cls, header: BlockHeaderAPI, chaindb: 'ChainDatabaseAPI') -> 'BlockAPI':
        """
        Instantiate a block from the given ``header`` and the ``chaindb``.
        """
        ...

    @property
    @abstractmethod
    def hash(self) -> Hash32:
        """
        Return the hash of the block.
        """
        ...

    @property
    @abstractmethod
    def number(self) -> BlockNumber:
        """
        Return the number of the block.
        """
        ...

    @property
    @abstractmethod
    def is_genesis(self) -> bool:
        """
        Return ``True`` if this block represents the genesis block of the chain,
        otherwise ``False``.
        """
        ...


class BlockImportResult(NamedTuple):
    imported_block: BlockAPI
    new_canonical_blocks: Tuple[BlockAPI, ...]
    old_canonical_blocks: Tuple[BlockAPI, ...]


class SchemaAPI(ABC):
    """
    A class representing a database schema that maps values to lookup keys.
    """

    @staticmethod
    @abstractmethod
    def make_canonical_head_hash_lookup_key() -> bytes:
        """
        Return the lookup key to retrieve the canonical head from the database.
        """
        ...

    @staticmethod
    @abstractmethod
    def make_block_number_to_hash_lookup_key(block_number: BlockNumber) -> bytes:
        """
        Return the lookup key to retrieve a block hash from a block number.
        """
        ...

    @staticmethod
    @abstractmethod
    def make_block_hash_to_score_lookup_key(block_hash: Hash32) -> bytes:
        """
        Return the lookup key to retrieve the score from a block hash.
        """
        ...

    @staticmethod
    @abstractmethod
    def make_transaction_hash_to_block_lookup_key(transaction_hash: Hash32) -> bytes:
        """
        Return the lookup key to retrieve a transaction key from a transaction hash.
        """
        ...


class DatabaseAPI(MutableMapping[bytes, bytes], ABC):
    """
    A class representing a database.
    """

    @abstractmethod
    def set(self, key: bytes, value: bytes) -> None:
        """
        Assign the ``value`` to the ``key``.
        """
        ...

    @abstractmethod
    def exists(self, key: bytes) -> bool:
        """
        Return ``True`` if the ``key`` exists in the database, otherwise ``False``.
        """
        ...

    @abstractmethod
    def delete(self, key: bytes) -> None:
        """
        Delete the given ``key`` from the database.
        """
        ...


class AtomicWriteBatchAPI(DatabaseAPI):
    """
    The readable/writeable object returned by an atomic database when we start building
    a batch of writes to commit.

    Reads to this database will observe writes written during batching,
    but the writes will not actually persist until this object is committed.
    """
    pass


class AtomicDatabaseAPI(DatabaseAPI):
    """
    Like ``BatchDB``, but immediately write out changes if they are
    not in an ``atomic_batch()`` context.
    """

    @abstractmethod
    def atomic_batch(self) -> ContextManager[AtomicWriteBatchAPI]:
        """
        Return a :class:`~typing.ContextManager` to write an atomic batch to the database.
        """
        ...


class HeaderDatabaseAPI(ABC):
    """
    A class representing a database for block headers.
    """
    db: AtomicDatabaseAPI

    @abstractmethod
    def __init__(self, db: AtomicDatabaseAPI) -> None:
        """
        Instantiate the database from an :class:`~eth.abc.AtomicDatabaseAPI`.
        """
        ...

    #
    # Canonical Chain API
    #
    @abstractmethod
    def get_canonical_block_hash(self, block_number: BlockNumber) -> Hash32:
        """
        Return the block hash for the canonical block at the given number.

        Raise ``BlockNotFound`` if there's no block header with the given number in the
        canonical chain.
        """
        ...

    @abstractmethod
    def get_canonical_block_header_by_number(self, block_number: BlockNumber) -> BlockHeaderAPI:
        """
        Return the block header with the given number in the canonical chain.

        Raise ``HeaderNotFound`` if there's no block header with the given number in the
        canonical chain.
        """
        ...

    @abstractmethod
    def get_canonical_head(self) -> BlockHeaderAPI:
        """
        Return the current block header at the head of the chain.
        """
        ...

    #
    # Header API
    #
    @abstractmethod
    def get_block_header_by_hash(self, block_hash: Hash32) -> BlockHeaderAPI:
        """
        Return the block header for the given ``block_hash``.
        Raise ``HeaderNotFound`` if no header with the given ``block_hash`` exists in the database.
        """
        ...

    @abstractmethod
    def get_score(self, block_hash: Hash32) -> int:
        """
        Return the score for the given ``block_hash``.
        """
        ...

    @abstractmethod
    def header_exists(self, block_hash: Hash32) -> bool:
        """
        Return ``True`` if the ``block_hash`` exists in the database, otherwise ``False``.
        """
        ...

    @abstractmethod
    def persist_checkpoint_header(self, header: BlockHeaderAPI, score: int) -> None:
        """
        Persist a checkpoint header with a trusted score. Persisting the checkpoint header
        automatically sets it as the new canonical head.
        """
        ...

    @abstractmethod
    def persist_header(self,
                       header: BlockHeaderAPI
                       ) -> Tuple[Tuple[BlockHeaderAPI, ...], Tuple[BlockHeaderAPI, ...]]:
        """
        Persist the ``header`` in the database.
        Return two iterable of headers, the first containing the new canonical header,
        the second containing the old canonical headers
        """
        ...

    @abstractmethod
    def persist_header_chain(self,
                             headers: Sequence[BlockHeaderAPI],
                             genesis_parent_hash: Hash32 = None,
                             ) -> Tuple[Tuple[BlockHeaderAPI, ...], Tuple[BlockHeaderAPI, ...]]:
        """
        Persist a chain of headers in the database.
        Return two iterable of headers, the first containing the new canonical headers,
        the second containing the old canonical headers

        :param genesis_parent_hash: *optional* parent hash of the block that is treated as genesis.
            Providing a ``genesis_parent_hash`` allows storage of headers that aren't (yet)
            connected back to the true genesis header.

        """
        ...


class GasMeterAPI(ABC):
    """
    A class to define a gas meter.
    """
    gas_refunded: int
    gas_remaining: int

    #
    # Write API
    #
    @abstractmethod
    def consume_gas(self, amount: int, reason: str) -> None:
        """
        Consume ``amount`` of gas for a defined ``reason``.
        """
        ...

    @abstractmethod
    def return_gas(self, amount: int) -> None:
        """
        Return ``amount`` of gas.
        """
        ...

    @abstractmethod
    def refund_gas(self, amount: int) -> None:
        """
        Refund ``amount`` of gas.
        """
        ...


class MessageAPI(ABC):
    """
    A message for VM computation.
    """
    code: bytes
    _code_address: Address
    create_address: Address
    data: BytesOrView
    depth: int
    gas: int
    is_static: bool
    sender: Address
    should_transfer_value: bool
    _storage_address: Address
    to: Address
    value: int

    __slots__ = [
        'code',
        '_code_address',
        'create_address',
        'data',
        'depth',
        'gas',
        'is_static',
        'sender',
        'should_transfer_value',
        '_storage_address'
        'to',
        'value',
    ]

    @property
    @abstractmethod
    def code_address(self) -> Address:
        ...

    @property
    @abstractmethod
    def storage_address(self) -> Address:
        ...

    @property
    @abstractmethod
    def is_create(self) -> bool:
        ...

    @property
    @abstractmethod
    def data_as_bytes(self) -> bytes:
        ...


class OpcodeAPI(ABC):
    """
    A class representing an opcode.
    """
    mnemonic: str

    @abstractmethod
    def __call__(self, computation: 'ComputationAPI') -> None:
        """
        Execute the logic of the opcode.
        """
        ...

    @classmethod
    @abstractmethod
    def as_opcode(cls: Type[T],
                  logic_fn: Callable[['ComputationAPI'], None],
                  mnemonic: str,
                  gas_cost: int) -> Type[T]:
        """
        Class factory method for turning vanilla functions into Opcode classes.
        """
        ...

    @abstractmethod
    def __copy__(self) -> 'OpcodeAPI':
        """
        Return a copy of the opcode.
        """
        ...

    @abstractmethod
    def __deepcopy__(self, memo: Any) -> 'OpcodeAPI':
        """
        Return a deep copy of the opcode.
        """
        ...


class ChainContextAPI(ABC):
    """
    Immutable chain context information that remains constant over the VM execution.
    """

    @abstractmethod
    def __init__(self, chain_id: Optional[int]) -> None:
        """
        Initialize the chain context with the given ``chain_id``.
        """
        ...

    @property
    @abstractmethod
    def chain_id(self) -> int:
        """
        Return the chain id of the chain context.
        """
        ...


class MemoryAPI(ABC):
    """
    A class representing the memory of the :class:`~eth.abc.VirtualMachineAPI`.
    """

    @abstractmethod
    def extend(self, start_position: int, size: int) -> None:
        """
        Extend the memory from the given ``start_position`` to the provided ``size``.
        """
        ...

    @abstractmethod
    def __len__(self) -> int:
        """
        Return the length of the memory.
        """
        ...

    @abstractmethod
    def write(self, start_position: int, size: int, value: bytes) -> None:
        """
        Write `value` into memory.
        """
        ...

    @abstractmethod
    def read(self, start_position: int, size: int) -> memoryview:
        """
        Return a view into the memory
        """
        ...

    @abstractmethod
    def read_bytes(self, start_position: int, size: int) -> bytes:
        """
        Read a value from memory and return a fresh bytes instance
        """
        ...


class StackAPI(ABC):
    """
    A class representing the stack of the :class:`~eth.abc.VirtualMachineAPI`.
    """

    @abstractmethod
    def push_int(self, value: int) -> None:
        """
        Push an integer item onto the stack.
        """
        ...

    @abstractmethod
    def push_bytes(self, value: bytes) -> None:
        """
        Push a bytes item onto the stack.
        """
        ...

    @abstractmethod
    def pop1_bytes(self) -> bytes:
        """
        Pop and return a bytes element from the stack.

        Raise `eth.exceptions.InsufficientStack` if the stack was empty.
        """
        ...

    @abstractmethod
    def pop1_int(self) -> int:
        """
        Pop and return an integer from the stack.

        Raise `eth.exceptions.InsufficientStack` if the stack was empty.
        """
        ...

    @abstractmethod
    def pop1_any(self) -> Union[int, bytes]:
        """
        Pop and return an element from the stack.
        The type of each element will be int or bytes, depending on whether it was
        pushed with push_bytes or push_int.

        Raise `eth.exceptions.InsufficientStack` if the stack was empty.
        """
        ...

    @abstractmethod
    def pop_any(self, num_items: int) -> Tuple[Union[int, bytes], ...]:
        """
        Pop and return a tuple of items of length ``num_items`` from the stack.
        The type of each element will be int or bytes, depending on whether it was
        pushed with stack_push_bytes or stack_push_int.

        Raise `eth.exceptions.InsufficientStack` if there are not enough items on
        the stack.

        Items are ordered with the top of the stack as the first item in the tuple.
        """
        ...

    @abstractmethod
    def pop_ints(self, num_items: int) -> Tuple[int, ...]:
        """
        Pop and return a tuple of integers of length ``num_items`` from the stack.

        Raise `eth.exceptions.InsufficientStack` if there are not enough items on
        the stack.

        Items are ordered with the top of the stack as the first item in the tuple.
        """
        ...

    @abstractmethod
    def pop_bytes(self, num_items: int) -> Tuple[bytes, ...]:
        """
        Pop and return a tuple of bytes of length ``num_items`` from the stack.

        Raise `eth.exceptions.InsufficientStack` if there are not enough items on
        the stack.

        Items are ordered with the top of the stack as the first item in the tuple.
        """
        ...

    @abstractmethod
    def swap(self, position: int) -> None:
        """
        Perform a SWAP operation on the stack.
        """
        ...

    @abstractmethod
    def dup(self, position: int) -> None:
        """
        Perform a DUP operation on the stack.
        """
        ...


class CodeStreamAPI(ABC):
    """
    A class representing a stream of EVM code.
    """
    program_counter: int

    @abstractmethod
    def read(self, size: int) -> bytes:
        """
        Read and return the code from the current position of the cursor up to ``size``.
        """
        ...

    @abstractmethod
    def __len__(self) -> int:
        """
        Return the length of the code stream.
        """
        ...

    @abstractmethod
    def __getitem__(self, index: int) -> int:
        """
        Return the ordinal value of the byte at the given ``index``.
        """
        ...

    @abstractmethod
    def __iter__(self) -> Iterator[int]:
        """
        Iterate over all ordinal values of the bytes of the code stream.
        """
        ...

    @abstractmethod
    def peek(self) -> int:
        """
        Return the ordinal value of the byte at the current program counter.
        """
        ...

    @abstractmethod
    def seek(self, program_counter: int) -> ContextManager['CodeStreamAPI']:
        """
        Return a :class:`~typing.ContextManager` with the program counter
        set to ``program_counter``.
        """
        ...

    @abstractmethod
    def is_valid_opcode(self, position: int) -> bool:
        """
        Return ``True`` if a valid opcode exists at ``position``.
        """
        ...


class StackManipulationAPI(ABC):
    @abstractmethod
    def stack_pop_ints(self, num_items: int) -> Tuple[int, ...]:
        """
        Pop the last ``num_items`` from the stack, returning a tuple of their ordinal values.
        """
        ...

    @abstractmethod
    def stack_pop_bytes(self, num_items: int) -> Tuple[bytes, ...]:
        """
        Pop the last ``num_items`` from the stack, returning a tuple of bytes.
        """
        ...

    @abstractmethod
    def stack_pop_any(self, num_items: int) -> Tuple[Union[int, bytes], ...]:
        """
        Pop the last ``num_items`` from the stack, returning a tuple with potentially mixed values
        of bytes or ordinal values of bytes.
        """
        ...

    @abstractmethod
    def stack_pop1_int(self) -> int:
        """
        Pop one item from the stack and return the ordinal value of the represented bytes.
        """
        ...

    @abstractmethod
    def stack_pop1_bytes(self) -> bytes:
        """
        Pop one item from the stack and return the value as ``bytes``.
        """
        ...

    @abstractmethod
    def stack_pop1_any(self) -> Union[int, bytes]:
        """
        Pop one item from the stack and return the value either as byte or the ordinal value of
        a byte.
        """
        ...

    @abstractmethod
    def stack_push_int(self, value: int) -> None:
        """
        Push ``value`` on the stack which must be a 256 bit integer.
        """
        ...

    @abstractmethod
    def stack_push_bytes(self, value: bytes) -> None:
        """
        Push ``value`` on the stack which must be a 32 byte string.
        """
        ...


class ComputationAPI(ContextManager['ComputationAPI'], StackManipulationAPI):
    """
    The base class for all execution computations.
    """
    msg: MessageAPI
    logger: ExtendedDebugLogger
    code: CodeStreamAPI
    opcodes: Dict[int, OpcodeAPI] = None
    state: 'StateAPI'
    return_data: bytes

    @abstractmethod
    def __init__(self,
                 state: 'StateAPI',
                 message: MessageAPI) -> None:
        """
        Instantiate the computation.
        """
        ...

    #
    # Convenience
    #
    @property
    @abstractmethod
    def is_origin_computation(self) -> bool:
        """
        Return ``True`` if this computation is the outermost computation at ``depth == 0``.
        """
        ...

    #
    # Error handling
    #
    @property
    @abstractmethod
    def is_success(self) -> bool:
        """
        Return ``True`` if the computation did not result in an error.
        """
        ...

    @property
    @abstractmethod
    def is_error(self) -> bool:
        """
        Return ``True`` if the computation resulted in an error.
        """
        ...

    @property
    @abstractmethod
    def error(self) -> VMError:
        """
        Return the :class:`~eth.exceptions.VMError` of the computation.
        Raise ``AttributeError`` if no error exists.
        """
        ...

    @error.setter
    def error(self, value: VMError) -> None:
        """
        Set an :class:`~eth.exceptions.VMError` for the computation.
        """
        # See: https://github.com/python/mypy/issues/4165
        # Since we can't also decorate this with abstract method we want to be
        # sure that the setter doesn't actually get used as a noop.
        raise NotImplementedError

    @abstractmethod
    def raise_if_error(self) -> None:
        """
        If there was an error during computation, raise it as an exception immediately.

        :raise VMError:
        """
        ...

    @property
    @abstractmethod
    def should_burn_gas(self) -> bool:
        """
        Return ``True`` if the remaining gas should be burned.
        """
        ...

    @property
    @abstractmethod
    def should_return_gas(self) -> bool:
        """
        Return ``True`` if the remaining gas should be returned.
        """
        ...

    @property
    @abstractmethod
    def should_erase_return_data(self) -> bool:
        """
        Return ``True`` if the return data should be zerod out due to an error.
        """
        ...

    #
    # Memory Management
    #
    @abstractmethod
    def extend_memory(self, start_position: int, size: int) -> None:
        """
        Extend the size of the memory to be at minimum ``start_position + size``
        bytes in length.  Raise `eth.exceptions.OutOfGas` if there is not enough
        gas to pay for extending the memory.
        """
        ...

    @abstractmethod
    def memory_write(self, start_position: int, size: int, value: bytes) -> None:
        """
        Write ``value`` to memory at ``start_position``. Require that ``len(value) == size``.
        """
        ...

    @abstractmethod
    def memory_read(self, start_position: int, size: int) -> memoryview:
        """
        Read and return a view of ``size`` bytes from memory starting at ``start_position``.
        """
        ...

    @abstractmethod
    def memory_read_bytes(self, start_position: int, size: int) -> bytes:
        """
        Read and return ``size`` bytes from memory starting at ``start_position``.
        """
        ...

    #
    # Gas Consumption
    #

    @abstractmethod
    def consume_gas(self, amount: int, reason: str) -> None:
        """
        Consume ``amount`` of gas from the remaining gas.
        Raise `eth.exceptions.OutOfGas` if there is not enough gas remaining.
        """
        ...

    @abstractmethod
    def return_gas(self, amount: int) -> None:
        """
        Return ``amount`` of gas to the available gas pool.
        """
        ...

    @abstractmethod
    def refund_gas(self, amount: int) -> None:
        """
        Add ``amount`` of gas to the pool of gas marked to be refunded.
        """
        ...

    @abstractmethod
    def get_gas_refund(self) -> int:
        """
        Return the number of refunded gas.
        """
        ...

    @abstractmethod
    def get_gas_used(self) -> int:
        """
        Return the number of used gas.
        """
        ...

    @abstractmethod
    def get_gas_remaining(self) -> int:
        """
        Return the number of remaining gas.
        """
        ...

    #
    # Stack management
    #
    @abstractmethod
    def stack_swap(self, position: int) -> None:
        """
        Swap the item on the top of the stack with the item at ``position``.
        """
        ...

    @abstractmethod
    def stack_dup(self, position: int) -> None:
        """
        Duplicate the stack item at ``position`` and pushes it onto the stack.
        """
        ...

    #
    # Computation result
    #
    @property
    @abstractmethod
    def output(self) -> bytes:
        """
        Get the return value of the computation.
        """
        ...

    @output.setter
    def output(self, value: bytes) -> None:
        """
        Set the return value of the computation.
        """
        # See: https://github.com/python/mypy/issues/4165
        # Since we can't also decorate this with abstract method we want to be
        # sure that the setter doesn't actually get used as a noop.
        raise NotImplementedError

    #
    # Runtime operations
    #
    @abstractmethod
    def prepare_child_message(self,
                              gas: int,
                              to: Address,
                              value: int,
                              data: BytesOrView,
                              code: bytes,
                              **kwargs: Any) -> MessageAPI:
        """
        Helper method for creating a child computation.
        """
        ...

    @abstractmethod
    def apply_child_computation(self, child_msg: MessageAPI) -> 'ComputationAPI':
        """
        Apply the vm message ``child_msg`` as a child computation.
        """
        ...

    @abstractmethod
    def generate_child_computation(self, child_msg: MessageAPI) -> 'ComputationAPI':
        """
        Generate a child computation from the given ``child_msg``.
        """
        ...

    @abstractmethod
    def add_child_computation(self, child_computation: 'ComputationAPI') -> None:
        """
        Add the given ``child_computation``.
        """
        ...

    #
    # Account management
    #
    @abstractmethod
    def register_account_for_deletion(self, beneficiary: Address) -> None:
        """
        Register the address of ``beneficiary`` for deletion.
        """
        ...

    @abstractmethod
    def get_accounts_for_deletion(self) -> Tuple[Tuple[Address, Address], ...]:
        """
        Return a tuple of addresses that are registered for deletion.
        """
        ...

    #
    # EVM logging
    #
    @abstractmethod
    def add_log_entry(self, account: Address, topics: Tuple[int, ...], data: bytes) -> None:
        """
        Add a log entry.
        """
        ...

    @abstractmethod
    def get_raw_log_entries(self) -> Tuple[Tuple[int, bytes, Tuple[int, ...], bytes], ...]:
        """
        Return a tuple of raw log entries.
        """
        ...

    @abstractmethod
    def get_log_entries(self) -> Tuple[Tuple[bytes, Tuple[int, ...], bytes], ...]:
        """
        Return the log entries for this computation and its children.

        They are sorted in the same order they were emitted during the transaction processing, and
        include the sequential counter as the first element of the tuple representing every entry.
        """
        ...

    #
    # State Transition
    #
    @abstractmethod
    def apply_message(self) -> 'ComputationAPI':
        """
        Execution of a VM message.
        """
        ...

    @abstractmethod
    def apply_create_message(self) -> 'ComputationAPI':
        """
        Execution of a VM message to create a new contract.
        """
        ...

    @classmethod
    @abstractmethod
    def apply_computation(cls,
                          state: 'StateAPI',
                          message: MessageAPI) -> 'ComputationAPI':
        """
        Perform the computation that would be triggered by the VM message.
        """
        ...

    #
    # Opcode API
    #
    @property
    @abstractmethod
    def precompiles(self) -> Dict[Address, Callable[['ComputationAPI'], None]]:
        """
        Return a dictionary where the keys are the addresses of precompiles and the values are
        the precompile functions.
        """
        ...

    @abstractmethod
    def get_opcode_fn(self, opcode: int) -> OpcodeAPI:
        """
        Return the function for the given ``opcode``.
        """
        ...


class TransactionExecutorAPI(ABC):
    """
    A class providing APIs to execute transactions on VM state.
    """

    @abstractmethod
    def __init__(self, vm_state: 'StateAPI') -> None:
        """
        Initialize the executor from the given ``vm_state``.
        """
        ...

    @abstractmethod
    def __call__(self, transaction: SignedTransactionAPI) -> 'ComputationAPI':
        """
        Execute the ``transaction`` and return a :class:`eth.abc.ComputationAPI`.
        """
        ...

    @abstractmethod
    def validate_transaction(self, transaction: SignedTransactionAPI) -> None:
        """
        Validate the given ``transaction``.
        Raise a ``ValidationError`` if the transaction is invalid.
        """
        ...

    @abstractmethod
    def build_evm_message(self, transaction: SignedTransactionAPI) -> MessageAPI:
        """
        Build and return a :class:`~eth.abc.MessageAPI` from the given ``transaction``.
        """
        ...

    @abstractmethod
    def build_computation(self,
                          message: MessageAPI,
                          transaction: SignedTransactionAPI) -> 'ComputationAPI':
        """
        Apply the ``message`` to the VM and use the given ``transaction`` to
        retrieve the context from.
        """

        ...

    @abstractmethod
    def finalize_computation(self,
                             transaction: SignedTransactionAPI,
                             computation: 'ComputationAPI') -> 'ComputationAPI':
        """
        Finalize the ``transaction``.
        """
        ...


class ConfigurableAPI(ABC):
    """
    A class providing inline subclassing.
    """

    @classmethod
    @abstractmethod
    def configure(cls: Type[T],
                  __name__: str = None,
                  **overrides: Any) -> Type[T]:
        ...


class StateAPI(ConfigurableAPI):
    """
    The base class that encapsulates all of the various moving parts related to
    the state of the VM during execution.
    Each :class:`~eth.abc.VirtualMachineAPI` must be configured with a subclass of the
    :class:`~eth.abc.StateAPI`.

      .. note::

        Each :class:`~eth.abc.StateAPI` class must be configured with:

        - ``computation_class``: The :class:`~eth.abc.ComputationAPI` class for
          vm execution.
        - ``transaction_context_class``: The :class:`~eth.abc.TransactionContextAPI`
          class for vm execution.
    """
    #
    # Set from __init__
    #

    computation_class: Type[ComputationAPI]
    transaction_executor_class: Type[TransactionExecutorAPI] = None

    @abstractmethod
    def __init__(
            self,
            db: AtomicDatabaseAPI) -> None:
        """
        Initialize the state.
        """
        ...

    #
    # Block Object Properties (in opcodes)
    #
    @property
    @abstractmethod
    def coinbase(self) -> Address:
        """
        Return the current ``coinbase`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def timestamp(self) -> int:
        """
        Return the current ``timestamp`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def block_number(self) -> BlockNumber:
        """
        Return the current ``block_number`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def difficulty(self) -> int:
        """
        Return the current ``difficulty`` from the current :attr:`~execution_context`
        """
        ...

    @property
    @abstractmethod
    def gas_limit(self) -> int:
        """
        Return the current ``gas_limit`` from the current :attr:`~transaction_context`
        """
        ...

    @abstractmethod
    def get_storage(self, address: Address, slot: int, from_journal: bool = True) -> int:
        """
        Return the storage at ``slot`` for ``address``.
        """
        ...

    @abstractmethod
    def set_storage(self, address: Address, slot: int, value: int) -> None:
        """
        Write ``value`` to the given ``slot`` at ``address``.
        """
        ...

    @abstractmethod
    def delete_storage(self, address: Address) -> None:
        """
        Delete the storage at ``address``
        """
        ...

    @abstractmethod
    def delete_account(self, address: Address) -> None:
        """
        Delete the account at the given ``address``.
        """
        ...

    @abstractmethod
    def get_balance(self, address: Address) -> int:
        """
        Return the balance for the account at ``address``.
        """
        ...

    @abstractmethod
    def set_balance(self, address: Address, balance: int) -> None:
        """
        Set ``balance`` to the balance at ``address``.
        """
        ...

    @abstractmethod
    def delta_balance(self, address: Address, delta: int) -> None:
        """
        Apply ``delta`` to the balance at ``address``.
        """
        ...

    @abstractmethod
    def get_nonce(self, address: Address) -> int:
        """
        Return the nonce at ``address``.
        """
        ...

    @abstractmethod
    def set_nonce(self, address: Address, nonce: int) -> None:
        """
        Set ``nonce`` as the new nonce at ``address``.
        """
        ...

    @abstractmethod
    def increment_nonce(self, address: Address) -> None:
        """
        Increment the nonce at ``address``.
        """
        ...

    @abstractmethod
    def get_code(self, address: Address) -> bytes:
        """
        Return the code at ``address``.
        """
        ...

    @abstractmethod
    def set_code(self, address: Address, code: bytes) -> None:
        """
        Set ``code`` as the new code at ``address``.
        """
        ...

    @abstractmethod
    def get_code_hash(self, address: Address) -> Hash32:
        """
        Return the hash of the code at ``address``.
        """
        ...

    @abstractmethod
    def delete_code(self, address: Address) -> None:
        """
        Delete the code at ``address``.
        """
        ...

    @abstractmethod
    def has_code_or_nonce(self, address: Address) -> bool:
        """
        Return ``True`` if either a nonce or code exists at the given ``address``.
        """
        ...

    @abstractmethod
    def account_exists(self, address: Address) -> bool:
        """
        Return ``True`` if an account exists at ``address``.
        """
        ...

    @abstractmethod
    def touch_account(self, address: Address) -> None:
        """
        Touch the account at the given ``address``.
        """
        ...

    @abstractmethod
    def account_is_empty(self, address: Address) -> bool:
        """
        Return ``True`` if the account at ``address`` is empty, otherwise ``False``.
        """
        ...

    #
    # Access self._chaindb
    #
    @abstractmethod
    def snapshot(self) -> Tuple[Hash32, UUID]:
        """
        Perform a full snapshot of the current state.

        Snapshots are a combination of the :attr:`~state_root` at the time of the
        snapshot and the checkpoint from the journaled DB.
        """
        ...

    @abstractmethod
    def revert(self, snapshot: Tuple[Hash32, UUID]) -> None:
        """
        Revert the VM to the state at the snapshot
        """
        ...

    @abstractmethod
    def commit(self, snapshot: Tuple[Hash32, UUID]) -> None:
        """
        Commit the journal to the point where the snapshot was taken.  This
        merges in any changes that were recorded since the snapshot.
        """
        ...

    @abstractmethod
    def lock_changes(self) -> None:
        """
        Locks in all changes to state, typically just as a transaction starts.

        This is used, for example, to look up the storage value from the start
        of the transaction, when calculating gas costs in EIP-2200: net gas metering.
        """
        ...

    @abstractmethod
    def persist(self) -> None:
        """
        Persist the current state to the database.
        """
        ...

    #
    # Access self.prev_hashes (Read-only)
    #
    @abstractmethod
    def get_ancestor_hash(self, block_number: BlockNumber) -> Hash32:
        """
        Return the hash for the ancestor block with number ``block_number``.
        Return the empty bytestring ``b''`` if the block number is outside of the
        range of available block numbers (typically the last 255 blocks).
        """
        ...

    #
    # Computation
    #
    @abstractmethod
    def get_computation(self,
                        message: MessageAPI) -> ComputationAPI:
        """
        Return a computation instance for the given `message` and `transaction_context`
        """
        ...

    #
    # Execution
    #
    @abstractmethod
    def apply_transaction(self, transaction: SignedTransactionAPI) -> ComputationAPI:
        """
        Apply transaction to the vm state

        :param transaction: the transaction to apply
        :return: the computation
        """
        ...

    @abstractmethod
    def get_transaction_executor(self) -> TransactionExecutorAPI:
        """
        Return the transaction executor.
        """
        ...

    @abstractmethod
    def validate_transaction(self, transaction: SignedTransactionAPI) -> None:
        """
        Validate the given ``transaction``.
        """
        ...


class VirtualMachineAPI(ConfigurableAPI):
    """
    The :class:`~eth.abc.VirtualMachineAPI` class represents the Chain rules for a
    specific protocol definition such as the Frontier or Homestead network.

      .. note::

        Each :class:`~eth.abc.VirtualMachineAPI` class must be configured with:

        - ``block_class``: The :class:`~eth.abc.BlockAPI` class for blocks in this VM ruleset.
        - ``_state_class``: The :class:`~eth.abc.StateAPI` class used by this VM for execution.
    """

    fork: str  # noqa: E701  # flake8 bug that's fixed in 3.6.0+
    extra_data_max_bytes: ClassVar[int]

    @abstractmethod
    def __init__(self) -> None:
        """
        Initialize the virtual machine.
        """
        ...

    @property
    @abstractmethod
    def state(self) -> StateAPI:
        """
        Return the current state.
        """
        ...

    @abstractmethod
    def build_state(self,
                    db: AtomicDatabaseAPI,
                    header: BlockHeaderAPI,
                    chain_context: ChainContextAPI,
                    previous_hashes: Iterable[Hash32] = (),
                    ) -> StateAPI:
        """
        You probably want `VM().state` instead of this.

        Occasionally, you want to build custom state against a particular header and DB,
        even if you don't have the VM initialized. This is a convenience method to do that.
        """
        ...

    #
    # Execution
    #
    @abstractmethod
    def apply_transaction(self,
                          header: BlockHeaderAPI,
                          transaction: SignedTransactionAPI
                          ) -> ComputationAPI:
        """
        Apply the transaction to the current block. This is a wrapper around
        :func:`~eth.vm.state.State.apply_transaction` with some extra orchestration logic.

        :param header: header of the block before application
        :param transaction: to apply
        """
        ...

    @abstractmethod
    def execute_bytecode(self,
                         origin: Address,
                         gas_price: int,
                         gas: int,
                         to: Address,
                         sender: Address,
                         value: int,
                         data: bytes,
                         code: bytes,
                         code_address: Address = None) -> ComputationAPI:
        """
        Execute raw bytecode in the context of the current state of
        the virtual machine.
        """
        ...

    @abstractmethod
    def apply_all_transactions(
            self,
            transactions: Sequence[SignedTransactionAPI],
            base_header: BlockHeaderAPI
    ) -> Tuple[BlockHeaderAPI, Tuple[ReceiptAPI, ...], Tuple[ComputationAPI, ...]]:
        """
        Determine the results of applying all transactions to the base header.
        This does *not* update the current block or header of the VM.

        :param transactions: an iterable of all transactions to apply
        :param base_header: the starting header to apply transactions to
        :return: the final header, the receipts of each transaction, and the computations
        """
        ...
