import os
import sys
import json
import hashlib
import base58
import ecdsa
from bip32utils import BIP32Key
from mnemonic import Mnemonic
from solders.keypair import Keypair

# Ensure 32-byte (256-bit) private key
def get_secret_key(input_hex=None):
    if input_hex:
        key_bytes = bytes.fromhex(input_hex.ljust(64, '0'))[:32]  # Pad or truncate
    else:
        key_bytes = os.urandom(32)  # Generate random 256-bit key
    return key_bytes

# Read CLI argument if provided
input_hex = sys.argv[1] if len(sys.argv) > 1 else None
secret_key = get_secret_key(input_hex)

# Generate Mnemonic and Seed for Bitcoin
mnemo = Mnemonic("english")
mnemonic_phrase = mnemo.to_mnemonic(secret_key)
seed_bytes = mnemo.to_seed(mnemonic_phrase)

# Bitcoin Wallet (BIP-44)
HARDENED_OFFSET = 0x80000000
root_key = BIP32Key.fromEntropy(seed_bytes)
account_key = root_key.ChildKey(44 + HARDENED_OFFSET) \
                      .ChildKey(0 + HARDENED_OFFSET) \
                      .ChildKey(0 + HARDENED_OFFSET)
receive_key = account_key.ChildKey(0).ChildKey(0)
btc_address = receive_key.Address()
btc_pubkey = receive_key.PublicKey().hex()
btc_privkey = receive_key.WalletImportFormat()

# Ethereum Wallet
eth_pubkey = ecdsa.SigningKey.from_string(secret_key, curve=ecdsa.SECP256k1).verifying_key
eth_pubkey_bytes = b"\x04" + eth_pubkey.to_string()
eth_address = hashlib.sha3_256(eth_pubkey_bytes).digest()[-20:].hex()
eth_address = "0x" + eth_address

# Solana Wallet
solana_keypair = Keypair.from_seed(secret_key)
solana_pubkey = str(solana_keypair.pubkey())
solana_privkey = base58.b58encode(solana_keypair.secret()).decode()

# Output JSON Structure
wallet_data = {
    "secret_key_hex": secret_key.hex(),
    "mnemonic": mnemonic_phrase,
    "bitcoin": {
        "root_key": root_key.ExtendedKey(),
        "address": btc_address,
        "public_key": btc_pubkey,
        "private_key_wif": btc_privkey
    },
    "ethereum": {
        "address": eth_address,
        "public_key": eth_pubkey_bytes.hex()
    },
    "solana": {
        "address": solana_pubkey,
        "private_key_base58": solana_privkey
    }
}

# Save to JSON File
with open("wallet-mk2.json", "w") as f:
    json.dump(wallet_data, f, indent=4)

# Print JSON to stdout
print(json.dumps(wallet_data, indent=4))
