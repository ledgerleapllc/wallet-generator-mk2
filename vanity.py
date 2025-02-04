import os
import sys
import json
import hashlib
import base58
import ecdsa
import time
import signal
import multiprocessing
from bip32utils import BIP32Key
from mnemonic import Mnemonic
from solders.keypair import Keypair
from datetime import datetime

# 🔧 CONFIGURATION: Use 75% of available CPU cores
CPU_USAGE_RATIO = 0.75  # Adjust this for different CPU usage levels

# Ensure 32-byte (256-bit) private key
def get_random_secret_key():
    return os.urandom(32)

# Generate Bitcoin Wallet (BIP-44)
def generate_bitcoin_wallet(seed_bytes):
    HARDENED_OFFSET = 0x80000000
    root_key = BIP32Key.fromEntropy(seed_bytes)
    account_key = root_key.ChildKey(44 + HARDENED_OFFSET) \
                          .ChildKey(0 + HARDENED_OFFSET) \
                          .ChildKey(0 + HARDENED_OFFSET)
    receive_key = account_key.ChildKey(0).ChildKey(0)
    return {
        "root_key": root_key.ExtendedKey(),
        "address": receive_key.Address(),
        "public_key": receive_key.PublicKey().hex(),
        "private_key_wif": receive_key.WalletImportFormat(),
    }

# Generate Ethereum Wallet
def generate_ethereum_wallet(secret_key):
    eth_pubkey = ecdsa.SigningKey.from_string(secret_key, curve=ecdsa.SECP256k1).verifying_key
    eth_pubkey_bytes = b"\x04" + eth_pubkey.to_string()
    eth_address = hashlib.sha3_256(eth_pubkey_bytes).digest()[-20:].hex()
    return {
        "address": "0x" + eth_address,
        "public_key": eth_pubkey_bytes.hex(),
    }

# Generate Solana Wallet
def generate_solana_wallet(secret_key):
    solana_keypair = Keypair.from_seed(secret_key)
    solana_pubkey = str(solana_keypair.pubkey())
    solana_privkey = base58.b58encode(solana_keypair.secret()).decode()
    return {
        "address": solana_pubkey,
        "private_key_base58": solana_privkey,
    }

# Worker function for vanity search
def search_vanity(worker_id, search_prefix, tested_count, result_queue):
    try:
        while True:
            secret_key = get_random_secret_key()
            mnemonic = Mnemonic("english").to_mnemonic(secret_key)
            seed_bytes = Mnemonic("english").to_seed(mnemonic)

            bitcoin_wallet = generate_bitcoin_wallet(seed_bytes)
            ethereum_wallet = generate_ethereum_wallet(secret_key)
            solana_wallet = generate_solana_wallet(secret_key)

            wallet_data = {
                "secret_key_hex": secret_key.hex(),
                "mnemonic": mnemonic,
                "bitcoin": bitcoin_wallet,
                "ethereum": ethereum_wallet,
                "solana": solana_wallet
            }

            # Check if any address starts with the search prefix (ignoring case)
            for wallet_type, wallet in zip(["bitcoin", "ethereum", "solana"], [bitcoin_wallet, ethereum_wallet, solana_wallet]):
                address_to_check = wallet["address"]

                # Special case: Ignore "0x" prefix for Ethereum addresses
                if wallet_type == "ethereum":
                    address_to_check = address_to_check[2:]

                if address_to_check.lower().startswith(search_prefix):
                    result_queue.put(wallet_data)  # Send result to main process
                    return

            # Update shared counter
            with tested_count.get_lock():
                tested_count.value += 1

    except KeyboardInterrupt:
        return  # Allow graceful exit

# Function to display real-time progress
def display_progress(start_time, tested_count, stop_event):
    try:
        while not stop_event.is_set():
            time.sleep(1)  # Update every second
            elapsed_seconds = (datetime.now() - start_time).total_seconds()
            rate = tested_count.value / elapsed_seconds if elapsed_seconds > 0 else 0

            sys.stdout.write(f"\r[Running: {int(elapsed_seconds // 3600):02}:{int((elapsed_seconds // 60) % 60):02}:{int(elapsed_seconds % 60):02} | Tested: {tested_count.value:,} wallets | Rate: {rate:.1f} wallets/sec] Searching... ")
            sys.stdout.flush()
    except KeyboardInterrupt:
        return  # Allow graceful exit

# Main function with multiprocessing
def main():
    if len(sys.argv) < 2:
        print("Usage: python vanity.py <prefix>")
        sys.exit(1)

    search_prefix = sys.argv[1].lower()  # Ensure case insensitivity
    available_cores = max(1, int(multiprocessing.cpu_count() * CPU_USAGE_RATIO))
    print(f"Searching for a vanity address starting with: '{search_prefix}' using {available_cores} CPU cores.")

    start_time = datetime.now()
    result_queue = multiprocessing.Queue()
    tested_count = multiprocessing.Value("i", 0)  # Shared counter across all workers
    stop_event = multiprocessing.Event()  # Stop flag for clean exit

    processes = []

    # Start multiple worker processes
    for i in range(available_cores):
        p = multiprocessing.Process(target=search_vanity, args=(i, search_prefix, tested_count, result_queue))
        processes.append(p)
        p.start()

    # Start a separate process for real-time progress display
    progress_process = multiprocessing.Process(target=display_progress, args=(start_time, tested_count, stop_event))
    progress_process.daemon = True
    progress_process.start()

    try:
        # Wait for a match
        wallet_data = result_queue.get()

        # Stop all processes
        stop_event.set()
        for p in processes:
            p.terminate()
        progress_process.terminate()

        print("\nMatch found!")
        print(json.dumps(wallet_data, indent=4))

        # Save to JSON file
        with open("wallet-mk2.json", "w") as f:
            json.dump(wallet_data, f, indent=4)

        print("\nSaved as 'wallet-mk2.json'.")

    except KeyboardInterrupt:
        print("\nProcess interrupted. Cleaning up...")
        stop_event.set()

        # Terminate all worker processes
        for p in processes:
            p.terminate()
        progress_process.terminate()

        sys.exit(0)

if __name__ == "__main__":
    main()
