from web3 import Web3

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))

print("Connected:", w3.is_connected())
print("Accounts and balances:")
for acc in w3.eth.accounts:
    balance = w3.eth.get_balance(acc)
    print(f"  {acc} → {w3.from_wei(balance, 'ether')} ETH")