from typing import Any, Union

from scp.abc import SignedTransactionAPI, UnsignedTransactionAPI
from scp._utils.spoof import SpoofAttributes


class SpoofTransaction(SpoofAttributes):
    def __init__(self,
                 transaction: Union[SignedTransactionAPI, UnsignedTransactionAPI],
                 **overrides: Any) -> None:
        super().__init__(transaction, **overrides)
