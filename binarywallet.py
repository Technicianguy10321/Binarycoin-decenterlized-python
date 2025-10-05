#!/usr/bin/env python3
"""
BinaryCoin Wallet CLI
- Automatic wallet creation
- Password encryption
- Transaction fees (1–30 BC)
- Validates balance before sending
- Waits for confirmation after mining
"""

import os, json, base64, secrets, time
from getpass import getpass
import requests
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

NODE_URL = "https://1e5ccc8960e8f7effb78c57f4661e861.serveo.net"
WALLET_FILE = "binarywallet.dat"
SALT = b"binarycoin_salt"
KDF_ITERS = 390_000

# --------------------------
# Wallet Encryption
# --------------------------
def derive_fernet_key(password: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def save_wallet(wallet, password):
    key = derive_fernet_key(password)
    f = Fernet(key)
    encrypted = f.encrypt(json.dumps(wallet).encode())
    with open(WALLET_FILE, "wb") as wf:
        wf.write(encrypted)

def load_wallet(password):
    if not os.path.exists(WALLET_FILE):
        return None
    with open(WALLET_FILE,"rb") as f:
        data = f.read()
    key = derive_fernet_key(password)
    fernet = Fernet(key)
    try:
        decrypted = fernet.decrypt(data).decode()
        wallet = json.loads(decrypted)
        if "address" not in wallet:
            return None
        return wallet
    except:
        return None

# --------------------------
# Wallet Functions
# --------------------------
def get_balance(address):
    try:
        r = requests.get(f"{NODE_URL}/balance/{address}")
        return r.json().get("balance",0)
    except:
        return None

def send_binarycoin(wallet):
    recipient = input("Recipient address: ").strip()
    try:
        amount = float(input("Amount to send: ").strip())
        if amount <=0:
            print("Invalid amount.")
            return
    except:
        print("Invalid amount.")
        return

    print("Choose transaction fee (higher fee = faster confirmation):")
    print("1) 1 BC  2) 5 BC  3)10 BC  4)20 BC  5)30 BC")
    choice = input("Fee option [1-5]: ").strip()
    fee_map = {"1":1,"2":5,"3":10,"4":20,"5":30}
    fee = fee_map.get(choice,1)

    # Check balance before sending
    balance = get_balance(wallet["address"])
    total_needed = amount + fee
    if balance is None:
        print("Failed to connect to node.")
        return
    if balance < total_needed:
        print(f"Insufficient balance. Your balance: {balance} BC, needed: {total_needed} BC")
        return

    tx = {"from": wallet["address"], "to": recipient, "amount": amount, "fee": fee}
    try:
        r = requests.post(f"{NODE_URL}/transactions", json=tx)
        resp = r.json()
        if "error" in resp:
            print(f"Transaction rejected: {resp['error']}")
            return
        print("Transaction submitted successfully. Waiting for confirmation...")

        # Poll node until transaction appears in mined blocks
        confirmed = False
        while not confirmed:
            r2 = requests.get(f"{NODE_URL}/miner_records/{wallet['address']}")
            blocks = r2.json()
            for blk in blocks:
                for t in blk["transactions"]:
                    if t["from"]==wallet["address"] and t["to"]==recipient and t["amount"]==amount and t["fee"]==fee:
                        confirmed = True
                        print(f"Transaction confirmed in block #{blk['index']}")
                        break
                if confirmed:
                    break
            if not confirmed:
                print("Waiting for block to be mined...")
                time.sleep(3)
    except Exception as e:
        print(f"Failed to send transaction: {e}")

# --------------------------
# CLI
# --------------------------
def main():
    if not os.path.exists(WALLET_FILE):
        print("No wallet found. Creating new wallet...")
        wallet_address = secrets.token_hex(16)  # 32-character random hex
        while True:
            pw1 = getpass("Enter new wallet password: ")
            pw2 = getpass("Repeat password: ")
            if pw1 != pw2:
                print("Passwords do not match.")
            else:
                break
        wallet = {"address": wallet_address}
        save_wallet(wallet,pw1)
        print(f"Wallet created successfully! Address: {wallet_address}")
    else:
        while True:
            pw = getpass("Enter wallet password: ")
            wallet = load_wallet(pw)
            if not wallet:
                print("Invalid password or corrupted wallet. Try again.")
            else:
                break
        print(f"Wallet loaded. Address: {wallet['address']}")

    while True:
        print("\n--- BinaryCoin Wallet ---")
        print("1) Show Balance")
        print("2) Send BinaryCoin")
        print("3) Exit")
        choice = input("Choose [1-3]: ").strip()
        if choice=="1":
            balance = get_balance(wallet["address"])
            if balance is None:
                print("Failed to connect to node.")
            else:
                print(f"Balance: {balance} BC")
        elif choice=="2":
            send_binarycoin(wallet)
        elif choice=="3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__=="__main__":
    main()
