#!/usr/bin/env python3
"""
BinaryCoin CLI Miner
- Local CPU mining
- Node mining (submit blocks to your node)
"""

import requests, hashlib, time, json

# --------------------------
# Configuration
# --------------------------
NODE_URL = "https://1e5ccc8960e8f7effb78c57f4661e861.serveo.net"  # Replace with your node IP or localhost
DIFFICULTY = 5  # Should match node
BLOCK_REWARD = 10  # Should match node

# --------------------------
# Block Class (for local mining)
# --------------------------
class Block:
    def __init__(self, index, timestamp, previous_hash, transactions, miner, nonce):
        self.index = index
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.transactions = transactions
        self.miner = miner
        self.nonce = nonce
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "miner": self.miner,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

# --------------------------
# Get last block from node
# --------------------------
def get_last_block():
    try:
        r = requests.get(f"{NODE_URL}/chain")
        data = r.json()
        length = data["length"]
        # Get full last block info from miner_records or chain endpoint
        return length - 1  # We'll use index only for local mining
    except:
        print("Failed to get last block from node.")
        return 0

# --------------------------
# Local Mining
# --------------------------
def local_mine(miner_address):
    last_index = get_last_block()
    previous_hash = "0"*64  # default for genesis
    try:
        r = requests.get(f"{NODE_URL}/miner_records/{miner_address}")
        blocks = r.json()
        if blocks:
            previous_hash = blocks[-1]["hash"]
    except:
        pass

    print("Starting local mining (Ctrl+C to stop)...")
    nonce = 0
    while True:
        transactions = [{"from":"Network","to":miner_address,"amount":BLOCK_REWARD,"fee":0}]
        blk = Block(last_index + 1, time.time(), previous_hash, transactions, miner_address, nonce)
        if blk.hash.startswith("0"*DIFFICULTY):
            print(f"Block mined locally! Index: {blk.index}, Nonce: {blk.nonce}, Hash: {blk.hash}")
            # Try to submit to node
            try:
                r = requests.post(f"{NODE_URL}/mine", json={"address": miner_address})
                result = r.json()
                print("Submit block result:", result)
            except Exception as e:
                print("Failed to submit block:", e)
            nonce = 0
            previous_hash = blk.hash
            last_index += 1
        else:
            nonce += 1

# --------------------------
# Node Mining (let node do the mining)
# --------------------------
def node_mine(miner_address):
    print("Starting node mining (Ctrl+C to stop)...")
    try:
        while True:
            r = requests.post(f"{NODE_URL}/mine", json={"address": miner_address})
            blk = r.json()
            print(f"--- New Block Mined by Node ---")
            print(f"Block #{blk['index']}")
            print(f"Timestamp: {time.ctime(blk['timestamp'])}")
            print(f"Nonce: {blk['nonce']}")
            print(f"Previous Hash: {blk['previous_hash']}")
            print(f"Current Hash: {blk['hash']}")
            print("Transactions:")
            for tx in blk['transactions']:
                print(f"  From: {tx['from']}, To: {tx['to']}, Amount: {tx['amount']}, Fee: {tx['fee']}")
            print("-------------------------\n")
    except KeyboardInterrupt:
        print("Node mining stopped by user.")

# --------------------------
# CLI
# --------------------------
def main():
    miner_address = input("Enter your miner wallet address: ").strip()
    while True:
        print("\n--- BinaryCoin CLI Miner ---")
        print("1) Local Mining (CPU)")
        print("2) Node Mining (submit to node)")
        print("3) Exit")
        choice = input("Choose [1-3]: ").strip()
        if choice=="1":
            local_mine(miner_address)
        elif choice=="2":
            node_mine(miner_address)
        elif choice=="3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__=="__main__":
    main()
