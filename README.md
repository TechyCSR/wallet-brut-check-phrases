# fast-bip39-gen

A high-performance, parallel Rust toolkit for generating valid BIP-39 mnemonic seed phrases, deriving multi-chain hierarchical deterministic (HD) wallet addresses (EVM, Bitcoin SegWit, Solana), and querying live balances via batched RPCs.

---

## Features

- **Zero-Waste Parallel BIP-39 Generation:** Generates valid 12-word and 24-word phrases using OS CSPRNG entropy with exact checksum calculations across all available CPU threads (millions of phrases/sec).
- **Multi-Chain Derivation (BIP-32 / BIP-44 / SLIP-0010):**
  - **Ethereum / EVM:** `m/44'/60'/0'/0/0` with Keccak-256 and EIP-55 checksumming.
  - **Bitcoin Native SegWit:** `m/84'/0'/0'/0/0` (Bech32 `bc1q...`).
  - **Solana:** `m/44'/501'/0'/0'` (SLIP-0010 on Ed25519) + Sollet legacy paths (`m/44'/501'/0'`).
- **Parallel Derivation to CSV:** Rayon-powered batch derivation capable of deriving thousands of multi-chain addresses per second.
- **High-Throughput Batch RPC Queries:**
  - Queries **100 Solana accounts per single JSON-RPC call** via `getMultipleAccounts`.
  - Built-in rate limiting and exponential backoff retry logic.
- **Multi-Account Discovery:** Scan multiple account indices (`--accounts <N>`) and derivation paths for a given phrase.

---

## Installation & Build

Make sure you have [Rust & Cargo](https://rustup.rs/) installed:

```bash
cargo build --release
```

The compiled binary will be placed at `./target/release/fast-bip39-gen`.

---

## CLI Usage

### 1. Generate BIP-39 Phrases

```bash
# Generate 10,000 valid phrases (saved to clean_valid_phrases.txt)
./target/release/fast-bip39-gen -s 10000

# Generate only 12-word phrases
./target/release/fast-bip39-gen -m 12 -s 5000 -o 12_word_phrases.txt

# Generate only 24-word phrases
./target/release/fast-bip39-gen -m 24 -s 5000 -o 24_word_phrases.txt
```

### 2. Derive Multi-Chain Addresses to CSV

```bash
./target/release/fast-bip39-gen --derive --input clean_valid_phrases.txt --csv-output derived_wallets.csv
```

### 3. Check Live Balances for an Entire Phrase File

```bash
# Scan live balances for clean_valid_phrases.txt
./target/release/fast-bip39-gen --check-file clean_valid_phrases.txt

# Scan with custom RPC and query delay
./target/release/fast-bip39-gen --check-file clean_valid_phrases.txt --solana-rpc "https://api.mainnet-beta.solana.com" --delay-ms 50
```

### 4. Check Single Phrase with Multi-Account Discovery

```bash
./target/release/fast-bip39-gen --check-phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" --accounts 5
```

---

## One-Line Generate & Check Pipeline

To generate a new batch of phrases and immediately scan their balances in a single command:

```bash
./target/release/fast-bip39-gen -s 1000 -o batch.txt && ./target/release/fast-bip39-gen --check-file batch.txt
```

---

## License

This project is licensed under the [MIT License](LICENSE).
