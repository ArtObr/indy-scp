from typing import NamedTuple

from eth_utils import (
    encode_hex,
)

from scp import constants
from scp.abc import ComputationAPI


def sstore(computation: ComputationAPI) -> None:
    slot, value = computation.stack_pop_ints(2)

    computation.state.set_storage(
        address=computation.msg.storage_address,
        slot=slot,
        value=value,
    )


def sload(computation: ComputationAPI) -> None:
    slot = computation.stack_pop1_int()

    value = computation.state.get_storage(
        address=computation.msg.storage_address,
        slot=slot,
    )
    computation.stack_push_int(value)


class NetSStoreGasSchedule(NamedTuple):
    base: int  # the gas cost when nothing changes (eg~ dirty->dirty, clean->clean, etc)
    create: int  # a brand new value, where none previously existed, aka init or set
    update: int  # a change to a value when the value was previously unchanged, aka clean, reset
    remove_refund: int  # the refund for removing a value, aka: clear_refund


def net_sstore(gas_schedule: NetSStoreGasSchedule, computation: ComputationAPI) -> None:
    slot, value = computation.stack_pop_ints(2)

    current_value = computation.state.get_storage(
        address=computation.msg.storage_address,
        slot=slot,
    )

    original_value = computation.state.get_storage(
        address=computation.msg.storage_address,
        slot=slot,
        from_journal=False
    )

    gas_refund = 0

    if current_value == value:
        gas_cost = gas_schedule.base
    else:
        if original_value == current_value:
            if original_value == 0:
                gas_cost = gas_schedule.create
            else:
                gas_cost = gas_schedule.update

                if value == 0:
                    gas_refund += gas_schedule.remove_refund
        else:
            gas_cost = gas_schedule.base

            if original_value != 0:
                if current_value == 0:
                    gas_refund -= gas_schedule.remove_refund
                if value == 0:
                    gas_refund += gas_schedule.remove_refund

            if original_value == value:
                if original_value == 0:
                    gas_refund += (gas_schedule.create - gas_schedule.base)
                else:
                    gas_refund += (gas_schedule.update - gas_schedule.base)

    computation.consume_gas(
        gas_cost,
        reason=(
            f"SSTORE: {encode_hex(computation.msg.storage_address)}"
            f"[{slot}] -> {value} (current: {current_value} / original: {original_value})"
        )
    )

    if gas_refund:
        computation.refund_gas(gas_refund)

    computation.state.set_storage(
        address=computation.msg.storage_address,
        slot=slot,
        value=value,
    )
