use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rayon::prelude::*;
use sha2::Sha512;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::str::FromStr;
use std::thread::sleep;
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Keccak};

type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone)]
pub struct DerivedWallets {
    pub phrase: String,
    pub eth_address: String,
    pub btc_address: String,
    pub sol_address: String,
}

/// Derive standard EVM, Bitcoin Native SegWit, and Solana addresses from a mnemonic phrase
pub fn derive_all_addresses(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    phrase: &str,
) -> Result<DerivedWallets, Box<dyn std::error::Error + Send + Sync>> {
    let mnemonic = Mnemonic::parse_normalized(phrase)?;
    let seed = mnemonic.to_seed("");

    // 1. BIP-32 Master key for secp256k1 (ETH & BTC)
    let master = Xpriv::new_master(Network::Bitcoin, &seed)?;

    // --- Ethereum / EVM: m/44'/60'/0'/0/0 ---
    let eth_path = DerivationPath::from_str("m/44'/60'/0'/0/0")?;
    let eth_child = master.derive_priv(secp, &eth_path)?;
    let eth_secp_pub = eth_child.to_priv().public_key(secp);
    let uncompressed = eth_secp_pub.inner.serialize_uncompressed(); // 65 bytes (0x04 + 64 bytes pubkey)

    let mut keccak = Keccak::v256();
    keccak.update(&uncompressed[1..65]);
    let mut eth_hash = [0u8; 32];
    keccak.finalize(&mut eth_hash);
    let eth_address = to_eip55_checksum(&eth_hash[12..32]);

    // --- Bitcoin Native SegWit (Bech32): m/84'/0'/0'/0/0 ---
    let btc_path = DerivationPath::from_str("m/84'/0'/0'/0/0")?;
    let btc_child = master.derive_priv(secp, &btc_path)?;
    let btc_pubkey = btc_child.to_priv().public_key(secp);
    let compressed = CompressedPublicKey(btc_pubkey.inner);
    let btc_address = Address::p2wpkh(&compressed, Network::Bitcoin).to_string();

    // --- Solana: m/44'/501'/0'/0' (SLIP-0010 on Ed25519) ---
    let sol_address = derive_solana_address(&seed)?;

    Ok(DerivedWallets {
        phrase: phrase.to_string(),
        eth_address,
        btc_address,
        sol_address,
    })
}

/// EIP-55 checksum encoding for Ethereum addresses
fn to_eip55_checksum(address_bytes: &[u8]) -> String {
    let hex_chars: &[u8; 16] = b"0123456789abcdef";
    let mut lower = String::with_capacity(40);
    for &b in address_bytes {
        lower.push(hex_chars[(b >> 4) as usize] as char);
        lower.push(hex_chars[(b & 0x0f) as usize] as char);
    }

    let mut keccak = Keccak::v256();
    keccak.update(lower.as_bytes());
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");
    for (i, ch) in lower.chars().enumerate() {
        let hash_byte = hash[i / 2];
        let nibble = if i % 2 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };
        if nibble >= 8 {
            checksummed.push(ch.to_ascii_uppercase());
        } else {
            checksummed.push(ch);
        }
    }
    checksummed
}

/// SLIP-0010 key derivation helper for arbitrary path indices on Ed25519
fn derive_ed25519_path(seed: &[u8], path_indices: &[u32]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[0..32]);
    chain_code.copy_from_slice(&result[32..64]);

    for &index in path_indices {
        let mut data = [0u8; 37];
        data[0] = 0x00;
        data[1..33].copy_from_slice(&key);
        data[33..37].copy_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&chain_code)?;
        mac.update(&data);
        let step_res = mac.finalize().into_bytes();

        key.copy_from_slice(&step_res[0..32]);
        chain_code.copy_from_slice(&step_res[32..64]);
    }

    let signing_key = SigningKey::from_bytes(&key);
    let verifying_key = signing_key.verifying_key();
    let sol_address = bs58::encode(verifying_key.as_bytes()).into_string();

    Ok(sol_address)
}

/// Standard BIP-44 Solana path: m/44'/501'/account'/0' (Phantom, Backpack, Solflare)
pub fn derive_solana_address_indexed(seed: &[u8], account_idx: u32) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let path = [
        44u32 | 0x8000_0000,
        501u32 | 0x8000_0000,
        account_idx | 0x8000_0000,
        0u32 | 0x8000_0000,
    ];
    derive_ed25519_path(seed, &path)
}

/// Legacy Solana path: m/44'/501'/account' (Sollet, older web wallets)
pub fn derive_solana_address_legacy(seed: &[u8], account_idx: u32) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let path = [
        44u32 | 0x8000_0000,
        501u32 | 0x8000_0000,
        account_idx | 0x8000_0000,
    ];
    derive_ed25519_path(seed, &path)
}

/// SLIP-0010 key derivation for default Ed25519 (Solana path: m/44'/501'/0'/0')
fn derive_solana_address(seed: &[u8]) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    derive_solana_address_indexed(seed, 0)
}

/// Cleans and extracts the raw mnemonic phrase from lines (strips [12-WORD] or [24-WORD] prefixes)
pub fn clean_phrase(line: &str) -> String {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix("[12-WORD]") {
        rest.trim().to_string()
    } else if let Some(rest) = trimmed.strip_prefix("[24-WORD]") {
        rest.trim().to_string()
    } else {
        trimmed.to_string()
    }
}

/// Loads and cleans mnemonic phrases from a text file, respecting an optional limit
pub fn load_phrases_from_file(
    input_path: &str,
    limit: Option<usize>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let file = File::open(input_path)?;
    let reader = BufReader::new(file);

    let mut phrases = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let cleaned = clean_phrase(&line);
        if !cleaned.is_empty() {
            phrases.push(cleaned);
            if let Some(max) = limit {
                if phrases.len() >= max {
                    break;
                }
            }
        }
    }
    Ok(phrases)
}

/// Derives multi-chain addresses for a collection of phrases in parallel
pub fn derive_wallets_parallel(phrases: Vec<String>) -> Vec<DerivedWallets> {
    phrases
        .into_par_iter()
        .map_init(
            || Secp256k1::new(),
            |secp, phrase| match derive_all_addresses(secp, &phrase) {
                Ok(w) => Some(w),
                Err(e) => {
                    eprintln!("Warning: could not derive phrase '{}': {}", phrase, e);
                    None
                }
            },
        )
        .filter_map(|x| x)
        .collect()
}

/// Reads a phrase file and derives multi-chain addresses in parallel, writing to CSV
pub fn process_phrase_file_to_csv(
    input_path: &str,
    output_path: &str,
    limit: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let phrases = load_phrases_from_file(input_path, limit)?;
    let total = phrases.len();
    println!(
        "Loaded {} phrases from '{}'. Starting parallel derivation across {} threads...",
        total,
        input_path,
        rayon::current_num_threads()
    );

    let start = Instant::now();
    let results = derive_wallets_parallel(phrases);
    let elapsed = start.elapsed();
    println!(
        "Derived {} wallets in {:.2}s ({:.0} wallets/sec). Writing CSV to '{}'...",
        results.len(),
        elapsed.as_secs_f64(),
        results.len() as f64 / elapsed.as_secs_f64(),
        output_path
    );

    // Write to CSV
    let mut writer = csv::WriterBuilder::new().from_path(output_path)?;
    writer.write_record(&["phrase", "eth_address", "btc_address", "sol_address"])?;

    for w in &results {
        writer.write_record(&[&w.phrase, &w.eth_address, &w.btc_address, &w.sol_address])?;
    }

    writer.flush()?;
    println!("Successfully saved CSV: {}", output_path);
    Ok(())
}

/// Reads a phrase file, derives addresses, and scans live balances across Solana RPC in high-speed batches
pub fn check_file_balances(
    input_path: &str,
    rpc_url: &str,
    limit: Option<usize>,
    hits_output: &str,
    delay_ms: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let phrases = load_phrases_from_file(input_path, limit)?;
    let total_phrases = phrases.len();
    if total_phrases == 0 {
        println!("No phrases found in '{}'", input_path);
        return Ok(());
    }

    println!("=== Phrase File Wallet & Balance Scanner ===");
    println!("File:       {}", input_path);
    println!("Phrases:    {}", total_phrases);
    println!("Solana RPC: {}", rpc_url);
    println!("Hits File:  {}", hits_output);
    println!();

    println!("Deriving multi-chain addresses across {} CPU threads...", rayon::current_num_threads());
    let d_start = Instant::now();
    let wallets = derive_wallets_parallel(phrases);
    let d_elapsed = d_start.elapsed().as_secs_f64();
    println!(
        "Derived {} wallets in {:.2}s ({:.0} wallets/sec).\n",
        wallets.len(),
        d_elapsed,
        wallets.len() as f64 / d_elapsed
    );

    println!("Querying live Solana balances via batch RPC (100 addresses/request)...");
    let batch_size = 100;
    let chunks: Vec<&[DerivedWallets]> = wallets.chunks(batch_size).collect();
    let total_chunks = chunks.len();

    let mut checked_wallets = 0;
    let mut hits_found = 0;
    let scan_start = Instant::now();

    for (chunk_idx, chunk) in chunks.into_iter().enumerate() {
        let addresses: Vec<&str> = chunk.iter().map(|w| w.sol_address.as_str()).collect();

        match crate::rpc::get_multiple_solana_balances_chunk(rpc_url, &addresses) {
            Ok(balances) => {
                for (w, balance) in chunk.iter().zip(balances.iter().copied()) {
                    if balance > 0.0 {
                        hits_found += 1;
                        println!(
                            "\n\n======================================================\n\
                             >>> [FOUND FUNDED WALLET!] <<<\n\
                             Phrase:      {}\n\
                             ETH:         {}\n\
                             BTC:         {}\n\
                             SOL:         {}\n\
                             SOL Balance: {:.9} SOL\n\
                             ======================================================\n",
                            w.phrase, w.eth_address, w.btc_address, w.sol_address, balance
                        );

                        if let Ok(mut hits_file) = OpenOptions::new().create(true).append(true).open(hits_output) {
                            let _ = writeln!(
                                hits_file,
                                "Phrase: {}\nETH: {}\nBTC: {}\nSOL: {}\nSOL Balance: {:.9} SOL\n---",
                                w.phrase, w.eth_address, w.btc_address, w.sol_address, balance
                            );
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("\nWarning: Failed batch {}/{}: {}", chunk_idx + 1, total_chunks, e);
            }
        }

        checked_wallets += chunk.len();
        let elapsed = scan_start.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 { checked_wallets as f64 / elapsed } else { 0.0 };
        let pct = (checked_wallets as f64 / wallets.len() as f64) * 100.0;

        print!(
            "\rProgress: {:>6} / {} ({:>5.1}%) | Funded Hits: {:>3} | Speed: {:>5.0} wallets/sec",
            checked_wallets,
            wallets.len(),
            pct,
            hits_found,
            rate
        );
        let _ = std::io::stdout().flush();

        if delay_ms > 0 && chunk_idx + 1 < total_chunks {
            sleep(Duration::from_millis(delay_ms));
        }
    }

    println!();
    let total_elapsed = scan_start.elapsed().as_secs_f64();
    println!("\n=== Balance Check Finished ===");
    println!("Total Wallets Checked: {}", checked_wallets);
    println!("Funded Wallets Found:  {}", hits_found);
    println!("Time Elapsed:          {:.2}s", total_elapsed);
    if hits_found > 0 {
        println!("All funded wallet details saved to: {}", hits_output);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_phrase_derivation() {
        let secp = Secp256k1::new();
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallets = derive_all_addresses(&secp, phrase).unwrap();

        assert_eq!(wallets.eth_address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
        assert_eq!(wallets.btc_address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(wallets.sol_address, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
    }

    #[test]
    fn test_clean_phrase() {
        assert_eq!(
            clean_phrase("[12-WORD] test phrase one two three"),
            "test phrase one two three"
        );
        assert_eq!(
            clean_phrase("[24-WORD]   hello world   "),
            "hello world"
        );
        assert_eq!(
            clean_phrase("plain phrase test"),
            "plain phrase test"
        );
    }
}
