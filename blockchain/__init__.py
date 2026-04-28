"""
Blockchain Interaction Module — Phase 3.

Provides a Python interface to the deployed TransactionContract smart
contract on Ganache (or any EVM-compatible network).

Module Structure:
    contract.py  —  ContractInterface wrapping web3.py calls into
                    Pythonic methods for funding wallets, submitting
                    and approving/rejecting transactions, querying
                    records, and streaming contract events.

Quick Start:
    from web3 import Web3
    from blockchain.contract import ContractInterface

    w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:7545"))
    ci = ContractInterface.from_deployment_file(w3)  # reads deployment.json
    balance = ci.get_balance("0xabc...")
"""
