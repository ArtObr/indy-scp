
from plenum.server.batch_handlers.batch_request_handler import BatchRequestHandler
from plenum.server.database_manager import DatabaseManager
from scp.indy_constants import CONTRACT_LEDGER_ID


class ContractBatchHandler(BatchRequestHandler):

    def __init__(self, database_manager: DatabaseManager):
        super().__init__(database_manager, CONTRACT_LEDGER_ID)

    def post_batch_applied(self, three_pc_batch, prev_handler_result=None):
        pass

    def post_batch_rejected(self, ledger_id, prev_handler_result=None):
        pass
