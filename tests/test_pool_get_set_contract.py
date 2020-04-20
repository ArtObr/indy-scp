import json

import pytest
from eth_utils import encode_hex
from plenum.test.helper import sdk_get_and_check_replies

from indy_common.constants import ENDORSER_STRING

from plenum.common.exceptions import RequestRejectedException

from plenum.test.pool_transactions.helper import sdk_add_new_nym, sdk_sign_and_send_prepared_request

from scp.indy_constants import CONTRACT_INVOKE
from tests.test_get_set_contract import contract_code


def send_contract_txn(looper, creators_wallet, sdk_pool_handle, code, contract_dest):
    wh, _ = creators_wallet

    request = json.dumps({
        'identifier': creators_wallet[1],
        'reqId': 999999999,
        'protocolVersion': 2,
        'operation': {
            'type': CONTRACT_INVOKE,
            'contract_code': encode_hex(code),
            'contract_dest': contract_dest,
        }
    })

    request_couple = sdk_sign_and_send_prepared_request(looper, creators_wallet,
                                                        sdk_pool_handle, request)

    reply = sdk_get_and_check_replies(looper, [request_couple])
    return reply

def testStewardCreatesAEndorser(helpers, looper, sdk_pool_handle, sdk_wallet_steward):
    sdk_add_new_nym(looper, sdk_pool_handle, sdk_wallet_steward, role=ENDORSER_STRING)

    send_contract_txn(looper, sdk_wallet_steward, sdk_pool_handle, contract_code, '')
