mod derive;
mod rpc;

use bip39::Language;
use clap::Parser;
use rand::rngs::SmallRng;
use rand::{RngCore, SeedableRng};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(about = "Ultra-Fast Parallel 12 & 24 Word Valid BIP-39 Generator")]
struct Args {
    /// Total valid phrases to generate (e.g., 10000000 for 10M, 1000000000 for 1B)
    #[arg(short, long, default_value_t = 10_000_000)]
    count: u64,

    /// Mode: "12", "24", or "both"
    #[arg(short, long, default_value = "both")]
    mode: String,

    /// Number of phrases to save to disk (prevents filling up your SSD with terabytes of text)
    #[arg(short, long, default_value_t = 10_000)]
    save_limit: usize,

    /// Output file path for saved phrases
    #[arg(short, long, default_value = "clean_valid_phrases.txt")]
    output: String,

    /// Run address derivation on an input phrase file and export to CSV
    #[arg(long)]
    derive: bool,

    /// Input phrase file for address derivation
    #[arg(long, default_value = "clean_valid_phrases.txt")]
    input: String,

    /// Output CSV file for derived addresses (phrase, eth_address, btc_address, sol_address)
    #[arg(long, default_value = "derived_wallets.csv")]
    csv_output: String,

    /// Optional limit on the number of phrases to derive or check
    #[arg(long)]
    derive_limit: Option<usize>,

    /// Check the derived address and live balance for a single user-provided phrase
    #[arg(long)]
    check_phrase: Option<String>,

    /// Check derived addresses and live balances for an entire phrase file (e.g. clean_valid_phrases.txt)
    #[arg(long, num_args = 0..=1, default_missing_value = "clean_valid_phrases.txt")]
    check_file: Option<String>,

    /// Check live balances when used with --derive or --input
    #[arg(long)]
    check_balance: bool,

    /// Output file for saving details of any discovered wallets with non-zero balance
    #[arg(long, default_value = "funded_wallets.txt")]
    hits_output: String,

    /// Delay in milliseconds between RPC batch queries (prevents rate limits, default: 50ms)
    #[arg(long, default_value_t = 50)]
    delay_ms: u64,

    /// Number of account indices to derive and check per phrase (default: 1)
    #[arg(long, default_value_t = 1)]
    accounts: u32,

    /// Solana RPC endpoint (default: https://api.mainnet-beta.solana.com)
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    solana_rpc: String,
}

/// Exact Trezor `to_mnemonic` 128-bit (12-word) implementation with zero invalid waste
#[inline(always)]
fn generate_valid_12(rng: &mut SmallRng, wordlist: &[&'static str; 2048]) -> [&'static str; 12] {
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);

    let hash = Sha256::digest(entropy);
    let checksum_byte = hash[0]; // First 4 bits used for 12-word checksum

    // Pack 16 bytes (128 bits) + 1 byte (top 4 bits checksum) into a single bit buffer
    let mut bits = [0u8; 17];
    bits[..16].copy_from_slice(&entropy);
    bits[16] = checksum_byte;

    let mut words = [""; 12];
    for i in 0..12 {
        let bit_index = i * 11;
        let byte_idx = bit_index / 8;
        let bit_offset = bit_index % 8;

        let chunk = ((bits[byte_idx] as u32) << 16)
            | ((bits[byte_idx + 1] as u32) << 8)
            | (if byte_idx + 2 < 17 { bits[byte_idx + 2] as u32 } else { 0 });

        let word_idx = ((chunk >> (24 - 11 - bit_offset)) & 0x7FF) as usize;
        words[i] = wordlist[word_idx];
    }
    words
}

/// Exact Trezor `to_mnemonic` 256-bit (24-word) implementation with zero invalid waste
#[inline(always)]
fn generate_valid_24(rng: &mut SmallRng, wordlist: &[&'static str; 2048]) -> [&'static str; 24] {
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);

    let hash = Sha256::digest(entropy);
    let checksum_byte = hash[0]; // All 8 bits used for 24-word checksum

    let mut bits = [0u8; 33];
    bits[..32].copy_from_slice(&entropy);
    bits[32] = checksum_byte;

    let mut words = [""; 24];
    for i in 0..24 {
        let bit_index = i * 11;
        let byte_idx = bit_index / 8;
        let bit_offset = bit_index % 8;

        let chunk = ((bits[byte_idx] as u32) << 16)
            | ((bits[byte_idx + 1] as u32) << 8)
            | (if byte_idx + 2 < 33 { bits[byte_idx + 2] as u32 } else { 0 });

        let word_idx = ((chunk >> (24 - 11 - bit_offset)) & 0x7FF) as usize;
        words[i] = wordlist[word_idx];
    }
    words
}

fn main() {
    let args = Args::parse();

    if let Some(phrase) = &args.check_phrase {
        println!("=== Single Phrase Wallet Check ===");
        let cleaned = derive::clean_phrase(phrase);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        match derive::derive_all_addresses(&secp, &cleaned) {
            Ok(wallets) => {
                println!("Phrase:  {}", wallets.phrase);
                println!("ETH:     {}", wallets.eth_address);
                println!("BTC:     {}", wallets.btc_address);
                println!("SOL:     {}", wallets.sol_address);
                println!("\nQuerying Solana RPC ({}) for balance...", args.solana_rpc);
                match rpc::get_solana_balance(&args.solana_rpc, &wallets.sol_address) {
                    Ok(bal) => println!("Account 0 (BIP-44 m/44'/501'/0'/0') SOL: {:.9} SOL", bal),
                    Err(e) => eprintln!("Error querying Solana balance: {}", e),
                }

                if args.accounts > 1 {
                    println!("\n--- Checking Additional Accounts (Total {} accounts) ---", args.accounts);
                    if let Ok(mnemonic) = bip39::Mnemonic::parse_normalized(&cleaned) {
                        let seed = mnemonic.to_seed("");
                        for i in 1..args.accounts {
                            if let Ok(sol_addr) = derive::derive_solana_address_indexed(&seed, i) {
                                match rpc::get_solana_balance(&args.solana_rpc, &sol_addr) {
                                    Ok(bal) => println!("Account {} (BIP-44 m/44'/501'/{i}'/0'): {} => {:.9} SOL", i, sol_addr, bal),
                                    Err(e) => eprintln!("Account {}: Error: {}", i, e),
                                }
                            }
                        }
                        println!("\n--- Sollet / Legacy Derivation Paths (m/44'/501'/i') ---");
                        for i in 0..args.accounts {
                            if let Ok(sol_addr) = derive::derive_solana_address_legacy(&seed, i) {
                                match rpc::get_solana_balance(&args.solana_rpc, &sol_addr) {
                                    Ok(bal) => println!("Sollet Account {} (m/44'/501'/{i}'): {} => {:.9} SOL", i, sol_addr, bal),
                                    Err(e) => eprintln!("Sollet Account {}: Error: {}", i, e),
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Invalid phrase: {}", e),
        }
        return;
    }

    if let Some(phrase_file) = &args.check_file {
        if let Err(e) = derive::check_file_balances(
            phrase_file,
            &args.solana_rpc,
            args.derive_limit,
            &args.hits_output,
            args.delay_ms,
        ) {
            eprintln!("Error checking phrase file: {}", e);
            std::process::exit(1);
        }
        return;
    }

    if args.check_balance {
        if let Err(e) = derive::check_file_balances(
            &args.input,
            &args.solana_rpc,
            args.derive_limit,
            &args.hits_output,
            args.delay_ms,
        ) {
            eprintln!("Error checking balances: {}", e);
            std::process::exit(1);
        }
        return;
    }

    if args.derive {
        println!("=== BIP-39 Multi-Chain Address Deriver ===");
        if let Err(e) = derive::process_phrase_file_to_csv(&args.input, &args.csv_output, args.derive_limit) {
            eprintln!("Error during derivation: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let wordlist = Language::English.word_list();

    let file = File::create(&args.output).expect("Unable to create output file");
    let writer = Mutex::new(BufWriter::new(file));
    let saved_count = AtomicU64::new(0);
    let total_generated = AtomicU64::new(0);

    let batch_size: u64 = 1_000_000;
    let start = Instant::now();

    println!(
        "Launching on {} CPU threads | Target: {} valid phrases | Mode: {}",
        rayon::current_num_threads(),
        args.count,
        args.mode
    );

    let mut completed: u64 = 0;
    while completed < args.count {
        let current_batch = std::cmp::min(batch_size, args.count - completed);

        (0..current_batch).into_par_iter().for_each_init(
            || SmallRng::from_entropy(), // Seeded from local OS CSPRNG (never public/flagged)
            |rng, i| {
                let gen_24 = match args.mode.as_str() {
                    "12" => false,
                    "24" => true,
                    _ => i % 2 == 0, // "both" alternates 12-word and 24-word
                };

                if gen_24 {
                    let words = generate_valid_24(rng, wordlist);
                    if (saved_count.load(Ordering::Relaxed) as usize) < args.save_limit {
                        let prev = saved_count.fetch_add(1, Ordering::Relaxed) as usize;
                        if prev < args.save_limit {
                            let phrase = words.join(" ");
                            let mut w = writer.lock().unwrap();
                            let _ = writeln!(w, "[24-WORD] {}", phrase);
                        }
                    }
                } else {
                    let words = generate_valid_12(rng, wordlist);
                    
                    if (saved_count.load(Ordering::Relaxed) as usize) < args.save_limit {
                        let prev = saved_count.fetch_add(1, Ordering::Relaxed) as usize;
                        if prev < args.save_limit {
                            let phrase = words.join(" ");
                            let mut w = writer.lock().unwrap();
                            let _ = writeln!(w, "[12-WORD] {}", phrase);
                        }
                    }
                }
            },
        );

        completed += current_batch;
        total_generated.store(completed, Ordering::Relaxed);
        let elapsed = start.elapsed().as_secs_f64();
        let rate = completed as f64 / elapsed;

        println!(
            "Generated: {:>12} / {} (100% Valid) | Speed: {:>10.0} phrases/sec | Elapsed: {:.2}s",
            completed, args.count, rate, elapsed
        );
    }

    writer.lock().unwrap().flush().unwrap();
    println!(
        "\nDone! Saved {} clean, unflagged 12 & 24 word phrases to '{}'",
        std::cmp::min(args.count as usize, args.save_limit),
        args.output
    );
}