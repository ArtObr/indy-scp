from typing import NamedTuple

from eth_utils import decode_hex

from indy_node.server.request_handlers.action_req_handlers.utils import generate_action_result
from plenum.common.txn_util import get_request_data

from indy_common.authorize.auth_actions import AuthActionAdd
from indy_common.authorize.auth_request_validator import WriteRequestValidator
from plenum.server.database_manager import DatabaseManager

from plenum.server.request_handlers.handler_interfaces.action_request_handler import ActionRequestHandler
from plenum.common.request import Request
from scp.indy_constants import CONTRACT_LEDGER_ID, CONTRACT_INVOKE
from scp.vm.base import VM


class ContractRequestHandler(ActionRequestHandler):
    def __init__(self, database_manager: DatabaseManager,
                 write_req_validator: WriteRequestValidator,
                 virtual_machine: VM
                 ):
        super().__init__(database_manager, CONTRACT_INVOKE, CONTRACT_LEDGER_ID)
        self.write_req_validator = write_req_validator
        self.virtual_machine = virtual_machine

    def static_validation(self, request: Request):
        pass

    def dynamic_validation(self, request: Request):
        self._validate_request_type(request)
        self.write_req_validator.validate(request,
                                          [AuthActionAdd(txn_type=CONTRACT_INVOKE,
                                                         field='*',
                                                         value='*')])

    def process_action(self, request: Request):
        self._validate_request_type(request)
        identifier, req_id, operation = get_request_data(request)
        Txn = NamedTuple('txn',
                         (('data', bytes),
                          ('sender', bytes),
                          ('to', bytes)))
        txn = Txn(decode_hex(operation['contract_code']), identifier, operation['contract_dest'])
        computation = self.virtual_machine.apply_transaction(txn)

        result = generate_action_result(request)
        # result[DATA] = self.info_tool.info
        return result
