use avail_fri::{
    core::{FriBiniusPCS, B128},
    encoding::BytesEncoder,
    eval_utils::{derive_evaluation_point, derive_seed_from_inputs, eval_claim_to_bytes},
    FriParamsVersion,
};
use avail_rust::{avail_rust_core::rpc::blob::submit_blob, prelude::*};
use clap::Parser;
use rayon::ThreadPoolBuilder;
use sp_crypto_hashing::keccak_256;
use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, Semaphore},
    task::JoinSet,
};

/// Babe epoch randomness
pub struct BabeRandomness;
impl StorageValue for BabeRandomness {
    type VALUE = [u8; 32];

    const PALLET_NAME: &str = "Babe";
    const STORAGE_NAME: &str = "Randomness";
}

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(name = "da-spammer", about = "Sustained DA load generator for Avail")]
struct Args {
    /// One of: alice,bob,charlie,dave,eve,ferdie,one,two
    #[arg(long, value_parser = validate_account)]
    account: String,

    /// Payload size in MiB [1..=64]
    #[arg(long, default_value_t = 32)]
    size_mb: usize,

    /// Blobs per batch
    #[arg(long, default_value_t = 50)]
    count: usize,

    /// Single character to repeat for the blob. Default: first char of `--account`
    #[arg(long)]
    ch: Option<char>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    endpoint: String,

    /// Precompute worker threads for commitment generation
    #[arg(long)]
    precompute_workers: Option<usize>,

    /// Max concurrent submit tasks
    #[arg(long, default_value_t = 4)]
    in_flight: usize,

    /// Prepared-blob queue capacity
    #[arg(long, default_value_t = 16)]
    queue_cap: usize,

    /// Max retries for a failed submit
    #[arg(long, default_value_t = 3)]
    max_retries: u32,

    /// Initial retry backoff (milliseconds)
    #[arg(long, default_value_t = 250)]
    retry_base_ms: u64,

    /// Optional send rate cap (transactions per second)
    #[arg(long)]
    tps: Option<f64>,
}

#[derive(Debug)]
struct PreparedBlob {
    index: usize,
    blob: Vec<u8>,
    hash: H256,
    commitment: Vec<u8>,
    seed: [u8; 32],
    claim: [u8; 16],
}

#[derive(Default)]
struct BatchStats {
    ok: AtomicUsize,
    failed: AtomicUsize,
    retries: AtomicUsize,
    bytes_ok: AtomicU64,
    submit_ms_ok: AtomicU64,
}

struct SubmitResult {
    index: usize,
    nonce: u32,
    blob_len: usize,
    attempts: u32,
    elapsed: Duration,
    err: Option<String>,
}

fn validate_account(s: &str) -> Result<String, String> {
    let s = s.to_lowercase();
    match s.as_str() {
        "alice" | "bob" | "charlie" | "dave" | "eve" | "ferdie" | "one" | "two" => Ok(s),
        _ => Err("must be one of: alice,bob,charlie,dave,eve,ferdie,one,two".into()),
    }
}

fn keypair_for(account: &str) -> Keypair {
    match account {
        "alice" => alice(),
        "bob" => bob(),
        "charlie" => charlie(),
        "dave" => dave(),
        "eve" => eve(),
        "ferdie" => ferdie(),
        "one" => one(),
        "two" => two(),
        _ => panic!("invalid account"),
    }
}

fn precompute_blob(
    index: usize,
    byte: u8,
    len_bytes: usize,
    babe_randomness: [u8; 32],
) -> Result<PreparedBlob, String> {
    let mut blob = vec![byte; len_bytes];
    if len_bytes >= 8 {
        blob[..8].copy_from_slice(&(index as u64).to_le_bytes());
    } else {
        blob[0] = blob[0].wrapping_add((index % 255) as u8);
    }

    let blob_hash = H256::from(keccak_256(&blob));

    let encoder = BytesEncoder::<B128>::new();
    let packed = encoder
        .bytes_to_packed_mle(&blob)
        .map_err(|e| format!("encode error: {e}"))?;

    let cfg = FriParamsVersion::V0.to_config(packed.total_n_vars);
    let pcs = FriBiniusPCS::new(cfg);
    let ctx = pcs
        .initialize_fri_context::<B128>(packed.packed_mle.log_len())
        .map_err(|e| format!("init fri context error: {e}"))?;

    let commit_output = pcs
        .commit(&packed.packed_mle, &ctx)
        .map_err(|e| format!("commit error: {e}"))?;

    let eval_point_seed = derive_seed_from_inputs(&babe_randomness, &blob_hash.0);
    let eval_point = derive_evaluation_point(eval_point_seed, packed.total_n_vars);

    let eval_claim = pcs
        .calculate_evaluation_claim(&packed.packed_values, &eval_point)
        .map_err(|e| format!("evaluation claim error: {e}"))?;

    let eval_claim_bytes: [u8; 16] = eval_claim_to_bytes(eval_claim)
        .try_into()
        .map_err(|_| "invalid claim byte length".to_string())?;

    Ok(PreparedBlob {
        index,
        blob,
        hash: blob_hash,
        commitment: commit_output.commitment.to_vec(),
        seed: eval_point_seed,
        claim: eval_claim_bytes,
    })
}

fn is_nonce_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    lower.contains("stale")
        || lower.contains("future")
        || lower.contains("invalid transaction")
        || lower.contains("bad proof")
        || lower.contains("priority is too low")
        || lower.contains("already imported")
}

fn is_already_imported(msg: &str) -> bool {
    msg.to_lowercase().contains("already imported")
}

async fn submit_with_retry(
    client: Arc<Client>,
    signer: Arc<Keypair>,
    prepared: PreparedBlob,
    mut nonce: u32,
    app_id: u32,
    max_retries: u32,
    retry_base_ms: u64,
) -> SubmitResult {
    let started = Instant::now();
    let mut attempts: u32 = 0;

    loop {
        attempts += 1;

        let unsigned = client.tx().data_availability().submit_blob_metadata(
            app_id,
            prepared.hash,
            prepared.blob.len() as u64,
            prepared.commitment.clone(),
            Some(prepared.seed),
            Some(prepared.claim),
        );

        let tx_bytes = match unsigned
            .sign(&signer, Options::default().app_id(app_id).nonce(nonce))
            .await
        {
            Ok(v) => v.encode(),
            Err(err) => {
                if attempts > max_retries {
                    return SubmitResult {
                        index: prepared.index,
                        nonce,
                        blob_len: prepared.blob.len(),
                        attempts,
                        elapsed: started.elapsed(),
                        err: Some(format!("sign error: {err}")),
                    };
                }
                let shift = (attempts - 1).min(16);
                let backoff = retry_base_ms.saturating_mul(1_u64 << shift);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                continue;
            }
        };

        match submit_blob(&client.rpc_client, &tx_bytes, &prepared.blob).await {
            Ok(_) => {
                return SubmitResult {
                    index: prepared.index,
                    nonce,
                    blob_len: prepared.blob.len(),
                    attempts,
                    elapsed: started.elapsed(),
                    err: None,
                }
            }
            Err(err) => {
                let err_s = err.to_string();
                if is_already_imported(&err_s) {
                    return SubmitResult {
                        index: prepared.index,
                        nonce,
                        blob_len: prepared.blob.len(),
                        attempts,
                        elapsed: started.elapsed(),
                        err: None,
                    };
                }

                if attempts > max_retries {
                    return SubmitResult {
                        index: prepared.index,
                        nonce,
                        blob_len: prepared.blob.len(),
                        attempts,
                        elapsed: started.elapsed(),
                        err: Some(err_s),
                    };
                }

                if is_nonce_error(&err_s) {
                    match client.chain().account_nonce(signer.account_id()).await {
                        Ok(fresh_nonce) => nonce = fresh_nonce,
                        Err(refresh_err) => eprintln!("failed to refresh nonce: {refresh_err}"),
                    }
                }

                let shift = (attempts - 1).min(16);
                let backoff = retry_base_ms.saturating_mul(1_u64 << shift);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if !(1..=64).contains(&args.size_mb) {
        return Err("--size-mb must be within 1..=64".into());
    }
    if args.count == 0 {
        return Err("--count must be > 0".into());
    }
    if args.in_flight == 0 {
        return Err("--in-flight must be > 0".into());
    }
    if args.queue_cap == 0 {
        return Err("--queue-cap must be > 0".into());
    }

    let threads = args
        .precompute_workers
        .unwrap_or_else(|| std::cmp::max(2, num_cpus::get() / 2));

    ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .expect("failed to init rayon");

    ctrlc::set_handler(|| {
        println!("\nCtrl-C received, shutting down...");
        RUNNING.store(false, Ordering::SeqCst);
    })
    .expect("failed setting Ctrl-C handler");

    let len_bytes = args.size_mb * 1024 * 1024;

    println!("========== Avail DA Spammer ==========");
    println!("Endpoint          : {}", args.endpoint);
    println!("Account           : {}", args.account);
    println!(
        "Blob size         : {} MiB ({} bytes)",
        args.size_mb, len_bytes
    );
    println!("Batch size        : {} blobs", args.count);
    println!("Precompute threads: {}", threads);
    println!("Submit in-flight  : {}", args.in_flight);
    println!("Queue cap         : {}", args.queue_cap);
    println!("Retries           : {}", args.max_retries);
    if let Some(tps) = args.tps {
        println!("TPS cap           : {:.2}", tps);
    } else {
        println!("TPS cap           : unlimited");
    }

    let client = Arc::new(Client::new(&args.endpoint).await?);
    let signer = Arc::new(keypair_for(&args.account));

    let byte = args
        .ch
        .unwrap_or_else(|| args.account.chars().next().unwrap()) as u8;

    let account_id = signer.account_id();
    let mut next_nonce = client.chain().account_nonce(account_id.clone()).await?;
    println!("AccountId         : {account_id}");
    println!("Start nonce       : {next_nonce}\n");

    let mut current_epoch_randomness: Option<[u8; 32]> = None;

    while RUNNING.load(Ordering::SeqCst) {
        let epoch_randomness: [u8; 32] = BabeRandomness::fetch(&client.rpc_client, None)
            .await?
            .expect("epoch randomness must exist");

        if current_epoch_randomness.as_ref() != Some(&epoch_randomness) {
            println!("New BABE epoch detected");
            current_epoch_randomness = Some(epoch_randomness);
        }

        let batch_started = Instant::now();
        let stats = Arc::new(BatchStats::default());
        let submit_gate = Arc::new(Semaphore::new(args.in_flight));

        let (prepared_tx, mut prepared_rx) =
            mpsc::channel::<Result<PreparedBlob, String>>(args.queue_cap);
        let mut precompute_set = JoinSet::new();

        for i in 0..args.count {
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }

            let tx = prepared_tx.clone();
            let randomness = epoch_randomness;
            precompute_set.spawn(async move {
                let out = tokio::task::spawn_blocking(move || {
                    precompute_blob(i, byte, len_bytes, randomness)
                })
                .await
                .map_err(|e| format!("precompute task join error: {e}"))?;
                let _ = tx.send(out).await;
                Ok::<(), String>(())
            });
        }
        drop(prepared_tx);

        let mut submit_set = JoinSet::new();
        let mut dispatched = 0usize;
        let mut next_dispatch_at = Instant::now();

        while let Some(prepared_result) = prepared_rx.recv().await {
            if !RUNNING.load(Ordering::SeqCst) {
                break;
            }

            match prepared_result {
                Ok(prepared) => {
                    if let Some(tps) = args.tps {
                        if tps > 0.0 {
                            let interval = Duration::from_secs_f64(1.0 / tps);
                            let now = Instant::now();
                            if now < next_dispatch_at {
                                tokio::time::sleep(next_dispatch_at - now).await;
                            }
                            next_dispatch_at =
                                std::cmp::max(Instant::now(), next_dispatch_at) + interval;
                        }
                    }

                    let permit = submit_gate.clone().acquire_owned().await?;
                    let my_nonce = next_nonce;
                    next_nonce = next_nonce.saturating_add(1);
                    dispatched += 1;

                    let app_id = (prepared.index % 5) as u32;
                    let local_client = Arc::clone(&client);
                    let local_signer = Arc::clone(&signer);
                    let local_stats = Arc::clone(&stats);
                    let max_retries = args.max_retries;
                    let retry_base_ms = args.retry_base_ms;

                    submit_set.spawn(async move {
                        let _permit = permit;
                        let result = submit_with_retry(
                            local_client,
                            local_signer,
                            prepared,
                            my_nonce,
                            app_id,
                            max_retries,
                            retry_base_ms,
                        )
                        .await;

                        if result.attempts > 1 {
                            local_stats
                                .retries
                                .fetch_add((result.attempts - 1) as usize, Ordering::Relaxed);
                        }

                        match &result.err {
                            None => {
                                local_stats.ok.fetch_add(1, Ordering::Relaxed);
                                local_stats
                                    .bytes_ok
                                    .fetch_add(result.blob_len as u64, Ordering::Relaxed);
                                local_stats.submit_ms_ok.fetch_add(
                                    result.elapsed.as_millis() as u64,
                                    Ordering::Relaxed,
                                );
                            }
                            Some(_) => {
                                local_stats.failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }

                        result
                    });
                }
                Err(err) => {
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    eprintln!("precompute error: {err}");
                }
            }
        }

        while let Some(res) = precompute_set.join_next().await {
            if let Err(err) = res {
                eprintln!("precompute join error: {err}");
                stats.failed.fetch_add(1, Ordering::Relaxed);
            }
        }

        while let Some(res) = submit_set.join_next().await {
            match res {
                Ok(r) => {
                    if let Some(err) = r.err {
                        eprintln!(
                            "  x idx={} nonce={} size={}B attempts={} err={}",
                            r.index, r.nonce, r.blob_len, r.attempts, err
                        );
                    } else {
                        println!(
                            "  ok idx={} nonce={} size={}B attempts={} elapsed={:.2?}",
                            r.index, r.nonce, r.blob_len, r.attempts, r.elapsed
                        );
                    }
                }
                Err(err) => {
                    stats.failed.fetch_add(1, Ordering::Relaxed);
                    eprintln!("submit join error: {err}");
                }
            }
        }

        let elapsed = batch_started.elapsed();
        let ok = stats.ok.load(Ordering::Relaxed);
        let failed = stats.failed.load(Ordering::Relaxed);
        let retries = stats.retries.load(Ordering::Relaxed);
        let bytes_ok = stats.bytes_ok.load(Ordering::Relaxed);
        let submit_ms_ok = stats.submit_ms_ok.load(Ordering::Relaxed);

        let mbps = if elapsed.is_zero() {
            0.0
        } else {
            (bytes_ok as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64()
        };
        let tps = if elapsed.is_zero() {
            0.0
        } else {
            ok as f64 / elapsed.as_secs_f64()
        };
        let avg_submit = if ok == 0 {
            0.0
        } else {
            submit_ms_ok as f64 / ok as f64
        };

        if failed > 0 {
            match client.chain().account_nonce(account_id.clone()).await {
                Ok(chain_nonce) if chain_nonce > next_nonce => next_nonce = chain_nonce,
                Ok(_) => {}
                Err(err) => eprintln!("failed to refresh nonce after errors: {err}"),
            }
        }

        println!("\n==== Batch Summary ====");
        println!("dispatched      : {}", dispatched);
        println!("success         : {}", ok);
        println!("failed          : {}", failed);
        println!("retries         : {}", retries);
        println!("duration        : {:.2?}", elapsed);
        println!("throughput tps  : {:.2}", tps);
        println!("throughput MiB/s: {:.2}", mbps);
        println!("avg submit ms   : {:.2}", avg_submit);
        println!("next nonce      : {}", next_nonce);
        println!("=======================\n");
    }

    println!("Spammer exited cleanly");
    Ok(())
}
