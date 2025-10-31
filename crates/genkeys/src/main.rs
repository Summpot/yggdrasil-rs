#![forbid(unsafe_code)]

use anyhow::Result;
use clap::Parser;
use ed25519_dalek::SigningKey;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use yggdrasil_core::Address;

#[derive(Parser)]
#[command(name = "genkeys")]
#[command(about = "Generate optimized Yggdrasil keys", long_about = None)]
struct Cli {
    /// Number of threads to use (default: CPU cores)
    #[arg(short, long)]
    threads: Option<usize>,

    /// Target number of leading 1 bits in address (higher = better)
    #[arg(short, long)]
    target: Option<u8>,

    /// Continue searching for better keys indefinitely
    #[arg(short, long)]
    continuous: bool,
}

struct KeyResult {
    private_key: [u8; 32],
    public_key: [u8; 32],
    address: String,
    leading_ones: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let num_threads = cli.threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    });
    let target = cli.target.unwrap_or(16); // Default target: 16 leading 1s

    println!("Yggdrasil Key Generator");
    println!("Threads: {}", num_threads);
    println!("Target: {} leading 1 bits", target);
    println!();

    let best_ones = Arc::new(AtomicU64::new(0));
    let total_attempts = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Start worker threads
    let mut handles = vec![];
    for _ in 0..num_threads {
        let best_ones = Arc::clone(&best_ones);
        let total_attempts = Arc::clone(&total_attempts);
        let running = Arc::clone(&running);

        let handle = thread::spawn(move || {
            let mut local_attempts = 0u64;

            loop {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                // Generate keys
                let mut secret = [0u8; 32];
                getrandom::fill(&mut secret).expect("Failed to generate random bytes");
                let signing_key = SigningKey::from_bytes(&secret);
                let public_key = signing_key.verifying_key();

                // Calculate address
                let address = Address::from_public_key(&public_key);
                let ones = count_leading_ones(&address);

                local_attempts += 1;

                // Check if it's the best
                let current_best = best_ones.load(Ordering::Relaxed);
                if ones > current_best as u8 {
                    best_ones.store(ones as u64, Ordering::Relaxed);

                    // Print result
                    let result = KeyResult {
                        private_key: secret,
                        public_key: public_key.to_bytes(),
                        address: address.to_string(),
                        leading_ones: ones,
                    };
                    print_result(&result, local_attempts);

                    if ones >= target {
                        running.store(false, Ordering::Relaxed);
                        break;
                    }
                }

                // Periodically update total attempts
                if local_attempts.is_multiple_of(10000) {
                    total_attempts.fetch_add(10000, Ordering::Relaxed);
                }
            }

            total_attempts.fetch_add(local_attempts % 10000, Ordering::Relaxed);
        });

        handles.push(handle);
    }

    // 监控线程
    let total_attempts_monitor = Arc::clone(&total_attempts);
    let running_monitor = Arc::clone(&running);
    let monitor = thread::spawn(move || {
        let start = Instant::now();
        loop {
            thread::sleep(Duration::from_secs(5));
            if !running_monitor.load(Ordering::Relaxed) {
                break;
            }

            let attempts = total_attempts_monitor.load(Ordering::Relaxed);
            let elapsed = start.elapsed().as_secs_f64();
            let rate = attempts as f64 / elapsed;
            eprintln!("Attempts: {} | Rate: {:.0} keys/sec", attempts, rate);
        }
    });

    // 等待完成
    if !cli.continuous {
        for handle in handles {
            handle.join().unwrap();
        }
        running.store(false, Ordering::Relaxed);
        monitor.join().unwrap();
    } else {
        // 持续模式：等待 Ctrl+C
        ctrlc::set_handler(move || {
            running.store(false, Ordering::Relaxed);
        })
        .expect("Error setting Ctrl-C handler");

        for handle in handles {
            handle.join().unwrap();
        }
        monitor.join().unwrap();
    }

    println!();
    println!("Key generation complete!");
    println!("Total attempts: {}", total_attempts.load(Ordering::Relaxed));

    Ok(())
}

fn count_leading_ones(address: &Address) -> u8 {
    let bytes = address.as_bytes();
    let mut count = 0u8;

    for byte in bytes {
        let leading = byte.leading_ones() as u8;
        count += leading;
        if leading < 8 {
            break;
        }
    }

    count
}

fn print_result(result: &KeyResult, attempts: u64) {
    println!("Found better key after {} attempts!", attempts);
    println!("Leading 1 bits: {}", result.leading_ones);
    println!("Address: {}", result.address);
    println!("Private key: {}", hex::encode(result.private_key));
    println!("Public key:  {}", hex::encode(result.public_key));
    println!();
}
