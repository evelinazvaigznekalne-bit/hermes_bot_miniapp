"""Telegram Hermes Bot Mini App - read-only wallet/asset inspection.

Security model
--------------
* The backend NEVER receives, requests, or stores seed phrases or private keys.
* Ownership is proven with a nonce/challenge + EIP-191 ``personal_sign``
  signature. Only the recovered PUBLIC address is used downstream.
* All chain access is read-only. No transactions are ever built or broadcast.
"""

__version__ = "1.0.0"
