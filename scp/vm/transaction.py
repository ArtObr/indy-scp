from eth_keys.datatypes import PrivateKey
from eth_typing import Address
from eth_utils import ValidationError
from rlp.sedes import big_endian_int, binary

from scp._utils.transactions import create_transaction_signature, validate_transaction_signature, \
    extract_transaction_sender
from scp.abc import UnsignedTransactionAPI, SignedTransactionAPI
from scp.constants import CREATE_CONTRACT_ADDRESS
from scp.rlp.sedes import address
from scp.rlp.transactions import BaseTransactionMethods, BASE_TRANSACTION_FIELDS, BaseTransactionFields
from scp.tools import rlp
from scp.validation import validate_uint256, validate_is_integer, validate_canonical_address, validate_is_bytes, \
    validate_lt_secpk1n, validate_gte, validate_lte, validate_lt_secpk1n2


class BaseUnsignedTransaction(BaseTransactionMethods, UnsignedTransactionAPI):
    fields = [
        ('nonce', big_endian_int),
        ('gas_price', big_endian_int),
        ('gas', big_endian_int),
        ('to', address),
        ('value', big_endian_int),
        ('data', binary),
    ]


class BaseTransaction(BaseTransactionFields, BaseTransactionMethods, SignedTransactionAPI):  # noqa: E501
    # this is duplicated to make the rlp library happy, otherwise it complains
    # about no fields being defined but inheriting from multiple `Serializable`
    # bases.
    fields = BASE_TRANSACTION_FIELDS

    @classmethod
    def from_base_transaction(cls, transaction):
        return rlp.decode(rlp.encode(transaction), sedes=cls)

    def sender(self) -> Address:
        return self.get_sender()

    # +-------------------------------------------------------------+
    # | API that must be implemented by all Transaction subclasses. |
    # +-------------------------------------------------------------+

    #
    # Validation
    #
    def validate(self) -> None:
        if self.gas < self.intrinsic_gas:
            raise ValidationError("Insufficient gas")
        self.check_signature_validity()

    #
    # Signature and Sender
    #
    @property
    def is_signature_valid(self) -> bool:
        try:
            self.check_signature_validity()
        except ValidationError:
            return False
        else:
            return True


class FrontierTransaction(BaseTransaction):

    @property
    def v_min(self) -> int:
        return 27

    @property
    def v_max(self) -> int:
        return 28

    def validate(self) -> None:
        validate_uint256(self.nonce, title="Transaction.nonce")
        validate_uint256(self.gas_price, title="Transaction.gas_price")
        validate_uint256(self.gas, title="Transaction.gas")
        if self.to != CREATE_CONTRACT_ADDRESS:
            validate_canonical_address(self.to, title="Transaction.to")
        validate_uint256(self.value, title="Transaction.value")
        validate_is_bytes(self.data, title="Transaction.data")

        validate_uint256(self.v, title="Transaction.v")
        validate_uint256(self.r, title="Transaction.r")
        validate_uint256(self.s, title="Transaction.s")

        validate_lt_secpk1n(self.r, title="Transaction.r")
        validate_gte(self.r, minimum=1, title="Transaction.r")
        validate_lt_secpk1n(self.s, title="Transaction.s")
        validate_gte(self.s, minimum=1, title="Transaction.s")

        validate_gte(self.v, minimum=self.v_min, title="Transaction.v")
        validate_lte(self.v, maximum=self.v_max, title="Transaction.v")

        super().validate()

    def check_signature_validity(self) -> None:
        validate_transaction_signature(self)

    def get_sender(self) -> Address:
        return extract_transaction_sender(self)

    # def get_intrinsic_gas(self) -> int:
    #     return frontier_get_intrinsic_gas(self)

    def get_message_for_signing(self) -> bytes:
        return rlp.encode(FrontierUnsignedTransaction(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas=self.gas,
            to=self.to,
            value=self.value,
            data=self.data,
        ))

    @classmethod
    def create_unsigned_transaction(cls,
                                    *,
                                    nonce: int,
                                    gas_price: int,
                                    gas: int,
                                    to: Address,
                                    value: int,
                                    data: bytes) -> 'FrontierUnsignedTransaction':
        return FrontierUnsignedTransaction(nonce, gas_price, gas, to, value, data)


class FrontierUnsignedTransaction(BaseUnsignedTransaction):

    def validate(self) -> None:
        validate_uint256(self.nonce, title="Transaction.nonce")
        validate_is_integer(self.gas_price, title="Transaction.gas_price")
        validate_uint256(self.gas, title="Transaction.gas")
        if self.to != CREATE_CONTRACT_ADDRESS:
            validate_canonical_address(self.to, title="Transaction.to")
        validate_uint256(self.value, title="Transaction.value")
        validate_is_bytes(self.data, title="Transaction.data")
        super().validate()

    def as_signed_transaction(self, private_key: PrivateKey):
        v, r, s = create_transaction_signature(self, private_key)
        return FrontierTransaction(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas=self.gas,
            to=self.to,
            value=self.value,
            data=self.data,
            v=v,
            r=r,
            s=s,
        )

    # def get_intrinsic_gas(self) -> int:
    #     return frontier_get_intrinsic_gas(self)


class HomesteadTransaction(FrontierTransaction):
    def validate(self) -> None:
        super().validate()
        validate_lt_secpk1n2(self.s, title="Transaction.s")

    # def get_intrinsic_gas(self) -> int:
    #     return homestead_get_intrinsic_gas(self)

    def get_message_for_signing(self) -> bytes:
        return rlp.encode(HomesteadUnsignedTransaction(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas=self.gas,
            to=self.to,
            value=self.value,
            data=self.data,
        ))

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


class HomesteadUnsignedTransaction(FrontierUnsignedTransaction):
    def as_signed_transaction(self, private_key: PrivateKey) -> HomesteadTransaction:
        v, r, s = create_transaction_signature(self, private_key)
        return HomesteadTransaction(
            nonce=self.nonce,
            gas_price=self.gas_price,
            gas=self.gas,
            to=self.to,
            value=self.value,
            data=self.data,
            v=v,
            r=r,
            s=s,
        )

    def get_intrinsic_gas(self) -> int:
        pass
