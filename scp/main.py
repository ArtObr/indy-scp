from scp.indy_constants import CONTRACT_LEDGER_ID
from scp.vm.forks import HomesteadVM
from state.pruning_state import PruningState

from storage.helper import initKeyValueStorage

from plenum.common.ledger import Ledger

from ledger.compact_merkle_tree import CompactMerkleTree
from plenum.common.constants import KeyValueStorageType


def integrate_plugin_in_node(node):
    update_config(node)
    init_storages(node)
    init_virtual_machine(node)
    register_req_handlers(node)
    register_batch_handlers(node)
    return node


def update_config(node):
    config = node.config
    config.contractTransactionsFile = 'contract_transactions'
    config.contractStateStorage = KeyValueStorageType.Rocksdb
    config.contractStateDbName = 'contract_state'


def init_storages(node):
    # Token ledger and state init
    if CONTRACT_LEDGER_ID not in node.ledger_ids:
        node.ledger_ids.append(CONTRACT_LEDGER_ID)
    token_state = init_contract_state(node)
    token_ledger = init_contract_ledger(node)
    node.db_manager.register_new_database(CONTRACT_LEDGER_ID,
                                          token_ledger,
                                          token_state)
    init_token_database(node)


def init_virtual_machine(node):
    node.virtual_machine = HomesteadVM()


def init_contract_ledger(node):
    return Ledger(CompactMerkleTree(hashStore=node.getHashStore('sovtoken')),
                  dataDir=node.dataLocation,
                  fileName=node.config.tokenTransactionsFile,
                  ensureDurability=node.config.EnsureLedgerDurability)


def init_contract_state(node):
    return PruningState(
        initKeyValueStorage(
            node.config.tokenStateStorage,
            node.dataLocation,
            node.config.tokenStateDbName,
            db_config=node.config.db_state_config)
    )


def init_token_database(node):
    node.ledgerManager.addLedger(CONTRACT_LEDGER_ID,
                                 node.db_manager.get_ledger(CONTRACT_LEDGER_ID),
                                 postTxnAddedToLedgerClbk=node.postTxnFromCatchupAddedToLedger)
    node.on_new_ledger_added(CONTRACT_LEDGER_ID)


def register_req_handlers(node):
    node.write_manager.register_req_handler(XferHandler(node.db_manager,
                                                        node.write_req_validator))
    node.write_manager.register_req_handler_with_version(XferHandler100(node.db_manager,
                                                                        node.write_req_validator),
                                                         "1.0.0")
    node.write_manager.register_req_handler(MintHandler(node.db_manager,
                                                        node.write_req_validator))
    node.read_manager.register_req_handler(GetUtxoHandler(node.db_manager, node.config.MSG_LEN_LIMIT))


def register_batch_handlers(node):
    node.write_manager.register_batch_handler(UTXOBatchHandler(node.db_manager), add_to_begin=True)
    node.write_manager.register_batch_handler(TokenBatchHandler(node.db_manager), add_to_begin=True)
    node.write_manager.register_batch_handler(node.write_manager.node_reg_handler,
                                              ledger_id=TOKEN_LEDGER_ID)
    node.write_manager.register_batch_handler(node.write_manager.primary_reg_handler,
                                              ledger_id=TOKEN_LEDGER_ID)
    node.write_manager.register_batch_handler(node.write_manager.audit_b_handler,
                                              ledger_id=TOKEN_LEDGER_ID)
