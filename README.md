# Wallet Generator

This Python script generates Bitcoin, Ethereum, and Solana wallets from a single 256-bit secret key.

## Features
- Generate wallets from a **random secret key** or a **user-supplied secret key**.
- Supports **Bitcoin (BIP-44)**, **Ethereum**, and **Solana** wallets.
- Outputs structured **JSON** with addresses, public keys, and private keys.

## Installation
Clone the repo and install dependencies:

```sh
git clone https://github.com/yourusername/wallet-generator.git
cd wallet-generator
pip install -r requirements.txt
python wallet-generator.py
```

## Usage

### Generate wallets with a random key:
```sh
python wallet_generator.py
```

### Generate wallets from a custom secret key:
```sh
python wallet_generator.py f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0987654321
```

### Example Output
```json
{
    "secret_key_hex": "f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0987654321...",
    "mnemonic": "abandon ability able about above absent absorb abstract absurd...",
    "bitcoin": {
        "address": "1J6PYEzr4CUoGbnXrELyHszoTSz3wCsCaj",
        "public_key": "04a34d7f1b...",
        "private_key_wif": "L4mEi6sA..."
    },
    "ethereum": {
        "address": "0x4b85f5a2...",
        "public_key": "04cd3f1c...",
        "private_key_hex": "f9a8b7c6..."
    },
    "solana": {
        "address": "5Z4XpLsH...",
        "public_key": "5Z4XpLsH...",
        "private_key_base58": "4B3yf3k..."
    }
}
```

### Generate vanity wallets
Included is a vanity address generator. Matches both ethereum prefixes and solana prefixes. Uses multicore parallel processing. Default CPU usage caps at 75%, modified by adjusting **CPU_USAGE_RATIO** at the top of **vanity.py**.

```
python vanity.py <your_prefix>
```
