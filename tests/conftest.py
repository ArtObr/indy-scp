import json

from plenum.client.wallet import Wallet
from plenum.common.constants import STEWARD, TARGET_NYM, TRUSTEE_STRING, VERKEY
from plenum.common.txn_util import get_seq_no
from sovtoken.util import \
    update_token_wallet_with_result
from sovtoken.constants import RESULT
from sovtoken.test.wallet import TokenWallet
from plenum.test.conftest import get_data_for_role, get_payload_data
from sovtoken.test.helper import send_get_utxo, send_xfer
from sovtoken.test.helpers import form_helpers, libloader
from indy_common.test.conftest import tconf as _tconf
from indy_node.test.conftest import *
from indy.did import create_and_store_my_did
from indy.ledger import build_nym_request, sign_and_submit_request

from scp.main import integrate_plugin_in_node

total_mint = 100
seller_gets = 40


# def build_wallets_from_data(name_seeds, looper, pool_name):
def build_wallets_from_data(name_seeds):
    wallets = []
    for name, seed in name_seeds:
        # wallet_handle = looper.loop.run_until_complete(
        #     _gen_wallet_handler(pool_name, name))
        # looper.loop.run_until_complete(
        #     create_and_store_my_did(wallet_handle,
        #                             json.dumps({'seed': seed})))
        # wallets.append(wallet_handle)
        w = Wallet(name)
        w.addIdentifier(seed=seed.encode())
        wallets.append(w)
    return wallets


@pytest.fixture(scope="module")
def tconf(_tconf):
    oldMax3PCBatchSize = _tconf.Max3PCBatchSize
    oldMax3PCBatchWait = _tconf.Max3PCBatchWait
    _tconf.Max3PCBatchSize = 1000
    _tconf.Max3PCBatchWait = 1
    yield _tconf
    _tconf.Max3PCBatchSize = oldMax3PCBatchSize
    _tconf.Max3PCBatchWait = oldMax3PCBatchWait


@pytest.fixture(scope="module")
def SF_token_wallet():
    return TokenWallet('SF_MASTER')


@pytest.fixture(scope="module")
def SF_address(SF_token_wallet):
    seed = 'sf000000000000000000000000000000'.encode()
    SF_token_wallet.add_new_address(seed=seed)
    return next(iter(SF_token_wallet.addresses.keys()))


@pytest.fixture(scope="module")
def seller_token_wallet():
    return TokenWallet('SELLER')


@pytest.fixture(scope="module")
def seller_address(seller_token_wallet):
    # Token selling/buying platform's address
    seed = 'se000000000000000000000000000000'.encode()
    seller_token_wallet.add_new_address(seed=seed)
    return next(iter(seller_token_wallet.addresses.keys()))


@pytest.fixture(scope="module")
def trustee_wallets(trustee_data, looper, sdk_pool_data):
    return build_wallets_from_data(trustee_data)


@pytest.fixture(scope="module")
def steward_wallets(poolTxnData):
    steward_data = get_data_for_role(poolTxnData, STEWARD)
    return build_wallets_from_data(steward_data)


@pytest.fixture(scope="module")
def sdk_trustees(looper, sdk_wallet_handle, trustee_data):
    trustees = []
    for _, trustee_seed in trustee_data:
        did_future = create_and_store_my_did(sdk_wallet_handle, json.dumps({"seed": trustee_seed}))
        did, _ = looper.loop.run_until_complete(did_future)
        trustees.append(did)
    return trustees


@pytest.fixture(scope="module")
def sdk_wallet_trustee(sdk_wallet_handle, sdk_trustees):
    return sdk_wallet_handle, sdk_trustees[0]


@pytest.fixture(scope="module")
def sdk_stewards(looper, sdk_wallet_handle, poolTxnData):
    stewards = []
    pool_txn_stewards_data = get_data_for_role(poolTxnData, STEWARD)
    for _, steward_seed in pool_txn_stewards_data:
        did_future = create_and_store_my_did(sdk_wallet_handle, json.dumps({"seed": steward_seed}))
        did, _ = looper.loop.run_until_complete(did_future)
        stewards.append(did)
    return stewards


@pytest.fixture(scope="module")
def sdk_wallet_steward(sdk_wallet_handle, sdk_stewards):
    return sdk_wallet_handle, sdk_stewards[0]


@pytest.fixture(scope="module")
def nodeSetWithIntegratedContractPlugin(do_post_node_creation, tconf, nodeSet):
    return nodeSet


@pytest.fixture(scope='module')
def helpers(
        nodeSetWithIntegratedContractPlugin,
        looper,
        sdk_pool_handle,
        trustee_wallets,
        steward_wallets,
        sdk_wallet_client,
        sdk_wallet_handle,
        sdk_trustees,
        sdk_stewards
):
    return form_helpers(
        nodeSetWithIntegratedContractPlugin,
        looper,
        sdk_pool_handle,
        trustee_wallets,
        steward_wallets,
        sdk_wallet_client,
        (sdk_wallet_handle, sdk_stewards[0]),
        sdk_wallet_handle,
        sdk_trustees,
        sdk_stewards
    )


@pytest.fixture(scope="module")
def do_post_node_creation():
    # Integrate plugin into each node.
    def _post_node_creation(node):
        integrate_plugin_in_node(node)

    return _post_node_creation
