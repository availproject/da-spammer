use avail_fri::{
    core::{FriBiniusPCS, B128},
    encoding::BytesEncoder,
    eval_utils::{derive_evaluation_point, derive_seed_from_inputs, eval_claim_to_bytes},
    FriParamsVersion,
};
use avail_rust::codec::Encode;
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
use tokio::{sync::Semaphore, task::JoinSet};

/// Babe epoch randomness
pub struct BabeRandomness;
impl StorageValue for BabeRandomness {
    type VALUE = [u8; 32];

    const PALLET_NAME: &str = "Babe";
    const STORAGE_NAME: &str = "Randomness";
}

static RUNNING: AtomicBool = AtomicBool::new(true);

#[derive(Parser, Debug)]
#[command(
    name = "da-sybil-spammer",
    about = "Generate accounts, batch fund, and submit blobs round-robin"
)]
struct Args {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    endpoint: String,

    /// Funder account to pay transfers; one of: alice,bob,charlie,dave,eve,ferdie,one,two
    #[arg(long, default_value = "alice", value_parser = validate_account)]
    funder: String,

    /// Number of deterministic ephemeral accounts to derive
    #[arg(long, default_value_t = 100)]
    accounts: usize,

    /// Amount to send to each account, in whole AVAIL
    #[arg(long, default_value_t = 10)]
    fund_each: u128,

    /// Transfer calls per `utility.batch_all`
    #[arg(long, default_value_t = 100)]
    batch_size: usize,

    /// Payload size in MiB [1..=64]
    #[arg(long, default_value_t = 32)]
    size_mb: usize,

    /// Total blob submissions
    #[arg(long, default_value_t = 1000)]
    loops: usize,

    /// Max in-flight submissions
    #[arg(long, default_value_t = 50)]
    in_flight: usize,

    /// Optional send rate cap (tx/sec)
    #[arg(long)]
    tps: Option<f64>,

    /// Max retries for a failed submit
    #[arg(long, default_value_t = 3)]
    max_retries: u32,

    /// Initial retry backoff (milliseconds)
    #[arg(long, default_value_t = 250)]
    retry_base_ms: u64,

    /// Optional fixed blob fill character
    #[arg(long)]
    ch: Option<char>,

    /// Wait after funding before spamming
    #[arg(long, default_value_t = 1500)]
    funding_settle_ms: u64,

    /// Precompute worker threads
    #[arg(long)]
    precompute_workers: Option<usize>,
}

#[derive(Default)]
struct Stats {
    ok: AtomicUsize,
    failed: AtomicUsize,
    retries: AtomicUsize,
    bytes_ok: AtomicU64,
    submit_ms_ok: AtomicU64,
}

#[derive(Debug)]
struct SubmitResult {
    index: usize,
    account_idx: usize,
    nonce: u32,
    blob_len: usize,
    attempts: u32,
    elapsed: Duration,
    err: Option<String>,
}

#[derive(Debug)]
struct PreparedBlob {
    blob: Vec<u8>,
    hash: H256,
    commitment: Vec<u8>,
    seed: [u8; 32],
    claim: [u8; 16],
}

fn validate_account(s: &str) -> Result<String, String> {
    let s = s.to_lowercase();
    match s.as_str() {
        "alice" | "bob" | "charlie" | "dave" | "eve" | "ferdie" | "one" | "two" => Ok(s),
        _ => Err("must be one of: alice,bob,charlie,dave,eve,ferdie,one,two".into()),
    }
}

fn dev_keypair(name: &str) -> Keypair {
    match name {
        "alice" => alice(),
        "bob" => bob(),
        "charlie" => charlie(),
        "dave" => dave(),
        "eve" => eve(),
        "ferdie" => ferdie(),
        "one" => one(),
        "two" => two(),
        _ => unreachable!("validated"),
    }
}

fn derive_sybil_keypair(i: usize) -> Result<Keypair, String> {
    let suri = format!("//da-spammer/{i}");
    let secret_uri: SecretUri = suri
        .parse()
        .map_err(|e| format!("failed to parse secret URI {suri}: {e:?}"))?;
    Keypair::from_uri(&secret_uri).map_err(|e| format!("failed to derive keypair for {suri}: {e}"))
}

fn precompute_blob(
    byte: u8,
    len_bytes: usize,
    unique_nonce: u64,
    babe_randomness: [u8; 32],
) -> Result<PreparedBlob, String> {
    let mut blob = vec![byte; len_bytes];
    if len_bytes >= 8 {
        blob[..8].copy_from_slice(&unique_nonce.to_le_bytes());
    } else {
        blob[0] = blob[0].wrapping_add((unique_nonce % 255) as u8);
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
}

fn is_already_imported(msg: &str) -> bool {
    msg.to_lowercase().contains("already imported")
}

async fn submit_with_retry(
    client: Arc<Client>,
    signer: Arc<Keypair>,
    account_id: AccountId,
    app_id: u32,
    prepared: PreparedBlob,
    mut nonce: u32,
    max_retries: u32,
    retry_base_ms: u64,
) -> (SubmitResult, u32) {
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
                    return (
                        SubmitResult {
                            index: 0,
                            account_idx: 0,
                            nonce,
                            blob_len: prepared.blob.len(),
                            attempts,
                            elapsed: started.elapsed(),
                            err: Some(format!("sign error: {err}")),
                        },
                        nonce,
                    );
                }
                let shift = (attempts - 1).min(16);
                let backoff = retry_base_ms.saturating_mul(1_u64 << shift);
                tokio::time::sleep(Duration::from_millis(backoff)).await;
                continue;
            }
        };

        match submit_blob(&client.rpc_client, &tx_bytes, &prepared.blob).await {
            Ok(_) => {
                return (
                    SubmitResult {
                        index: 0,
                        account_idx: 0,
                        nonce,
                        blob_len: prepared.blob.len(),
                        attempts,
                        elapsed: started.elapsed(),
                        err: None,
                    },
                    nonce + 1,
                )
            }
            Err(err) => {
                let err_s = err.to_string();

                if is_already_imported(&err_s) {
                    return (
                        SubmitResult {
                            index: 0,
                            account_idx: 0,
                            nonce,
                            blob_len: prepared.blob.len(),
                            attempts,
                            elapsed: started.elapsed(),
                            err: None,
                        },
                        nonce + 1,
                    );
                }

                if attempts > max_retries {
                    return (
                        SubmitResult {
                            index: 0,
                            account_idx: 0,
                            nonce,
                            blob_len: prepared.blob.len(),
                            attempts,
                            elapsed: started.elapsed(),
                            err: Some(err_s),
                        },
                        nonce,
                    );
                }

                if is_nonce_error(&err_s) {
                    if let Ok(fresh_nonce) = client.chain().account_nonce(account_id.clone()).await
                    {
                        nonce = fresh_nonce;
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
    if args.accounts == 0 {
        return Err("--accounts must be > 0".into());
    }
    if args.batch_size == 0 {
        return Err("--batch-size must be > 0".into());
    }
    if args.in_flight == 0 {
        return Err("--in-flight must be > 0".into());
    }
    if args.loops == 0 {
        return Err("--loops must be > 0".into());
    }
    let len_bytes = args.size_mb * 1024 * 1024;

    let threads = args
        .precompute_workers
        .unwrap_or_else(|| std::cmp::max(2, num_cpus::get() / 2));
    ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .expect("failed to init rayon");

    ctrlc::set_handler(|| {
        println!("\\nCtrl-C received, shutting down...");
        RUNNING.store(false, Ordering::SeqCst);
    })
    .expect("failed setting Ctrl-C handler");

    println!("========== Avail DA Sybil Spammer ==========");
    println!("Endpoint          : {}", args.endpoint);
    println!("Funder            : {}", args.funder);
    println!("Accounts          : {}", args.accounts);
    println!("Fund each         : {} AVAIL", args.fund_each);
    println!("Batch size        : {}", args.batch_size);
    println!(
        "Blob size         : {} MiB ({} bytes)",
        args.size_mb, len_bytes
    );
    println!("Loops             : {}", args.loops);
    println!("In-flight         : {}", args.in_flight);
    println!("Precompute threads: {}", threads);

    let client = Arc::new(Client::connect(&args.endpoint).await?);

    println!("Deriving {} deterministic accounts...", args.accounts);
    let mut accounts: Vec<Arc<Keypair>> = Vec::with_capacity(args.accounts);
    for i in 0..args.accounts {
        let kp = derive_sybil_keypair(i)?;
        accounts.push(Arc::new(kp));
    }
    println!("Derived {} accounts", accounts.len());
    println!(
        "Sample account #0 : {}",
        accounts[0].public_key().to_account_id()
    );

    let amount_units = args.fund_each.saturating_mul(constants::ONE_AVAIL);
    let funder = dev_keypair(&args.funder);
    let funder_account_id = funder.public_key().to_account_id();
    let mut funder_nonce: u32 = client.chain().account_nonce(funder_account_id).await?;

    println!(
        "Funding {} accounts using batch_all (nonce starts at {})...",
        accounts.len(),
        funder_nonce
    );

    for (chunk_idx, chunk) in accounts.chunks(args.batch_size).enumerate() {
        let mut calls = Vec::with_capacity(chunk.len());
        for kp in chunk {
            let transfer = client
                .tx()
                .balances()
                .transfer_keep_alive(kp.public_key().to_account_id(), amount_units)?;
            calls.push(transfer);
        }

        let batch = client.tx().utility().batch_all(calls);
        batch
            .submit(&funder, Options::default().nonce(funder_nonce))
            .await?;

        println!(
            "  funded batch #{} with {} transfers (nonce={})",
            chunk_idx,
            chunk.len(),
            funder_nonce
        );
        funder_nonce += 1;
    }

    if args.funding_settle_ms > 0 {
        println!(
            "Waiting {} ms for funding settlement...",
            args.funding_settle_ms
        );
        tokio::time::sleep(Duration::from_millis(args.funding_settle_ms)).await;
    }

    println!("Fetching starting nonces for all sybil accounts...");
    let mut account_nonces = Vec::with_capacity(accounts.len());
    for kp in &accounts {
        let n: u32 = client
            .chain()
            .account_nonce(kp.public_key().to_account_id())
            .await?;
        account_nonces.push(Arc::new(tokio::sync::Mutex::new(n)));
    }
    println!("Nonces loaded");

    let stats = Arc::new(Stats::default());
    let gate = Arc::new(Semaphore::new(args.in_flight));
    let mut submit_set = JoinSet::new();
    let mut next_dispatch_at = Instant::now();

    let mut babe_randomness = BabeRandomness::fetch(&client.rpc_client, None)
        .await?
        .expect("epoch randomness must exist");
    let mut randomness_last_update = Instant::now();

    for i in 0..args.loops {
        if !RUNNING.load(Ordering::SeqCst) {
            break;
        }

        if randomness_last_update.elapsed() >= Duration::from_secs(30) {
            babe_randomness = BabeRandomness::fetch(&client.rpc_client, None)
                .await?
                .expect("epoch randomness must exist");
            randomness_last_update = Instant::now();
        }

        if let Some(tps) = args.tps {
            if tps > 0.0 {
                let interval = Duration::from_secs_f64(1.0 / tps);
                let now = Instant::now();
                if now < next_dispatch_at {
                    tokio::time::sleep(next_dispatch_at - now).await;
                }
                next_dispatch_at = std::cmp::max(Instant::now(), next_dispatch_at) + interval;
            }
        }

        let permit = gate.clone().acquire_owned().await?;
        let account_idx = i % accounts.len();

        let signer = Arc::clone(&accounts[account_idx]);
        let account_id = signer.public_key().to_account_id();
        let nonce_lock = Arc::clone(&account_nonces[account_idx]);
        let client_ref = Arc::clone(&client);
        let stats_ref = Arc::clone(&stats);

        let byte = args
            .ch
            .unwrap_or_else(|| (b'a' + (account_idx as u8 % 26)) as char) as u8;

        let unique_nonce = i as u64;
        let max_retries = args.max_retries;
        let retry_base_ms = args.retry_base_ms;
        let app_id = (i % 5) as u32;

        submit_set.spawn(async move {
            let _permit = permit;

            let starting_nonce = {
                let mut guard = nonce_lock.lock().await;
                let n = *guard;
                *guard = guard.saturating_add(1);
                n
            };

            let prepared = match tokio::task::spawn_blocking(move || {
                precompute_blob(byte, len_bytes, unique_nonce, babe_randomness)
            })
            .await
            {
                Ok(Ok(prepared)) => prepared,
                Ok(Err(err)) => {
                    stats_ref.failed.fetch_add(1, Ordering::Relaxed);
                    return SubmitResult {
                        index: i,
                        account_idx,
                        nonce: starting_nonce,
                        blob_len: len_bytes,
                        attempts: 0,
                        elapsed: Duration::ZERO,
                        err: Some(format!("precompute error: {err}")),
                    };
                }
                Err(err) => {
                    stats_ref.failed.fetch_add(1, Ordering::Relaxed);
                    return SubmitResult {
                        index: i,
                        account_idx,
                        nonce: starting_nonce,
                        blob_len: len_bytes,
                        attempts: 0,
                        elapsed: Duration::ZERO,
                        err: Some(format!("precompute join error: {err}")),
                    };
                }
            };

            let (mut result, next_nonce_hint) = submit_with_retry(
                client_ref,
                signer,
                account_id,
                app_id,
                prepared,
                starting_nonce,
                max_retries,
                retry_base_ms,
            )
            .await;

            result.index = i;
            result.account_idx = account_idx;

            if result.attempts > 1 {
                stats_ref
                    .retries
                    .fetch_add((result.attempts - 1) as usize, Ordering::Relaxed);
            }

            if result.err.is_none() {
                stats_ref.ok.fetch_add(1, Ordering::Relaxed);
                stats_ref
                    .bytes_ok
                    .fetch_add(result.blob_len as u64, Ordering::Relaxed);
                stats_ref
                    .submit_ms_ok
                    .fetch_add(result.elapsed.as_millis() as u64, Ordering::Relaxed);
            } else {
                stats_ref.failed.fetch_add(1, Ordering::Relaxed);
            }

            {
                let mut guard = nonce_lock.lock().await;
                if next_nonce_hint > *guard {
                    *guard = next_nonce_hint;
                }
            }

            result
        });
    }

    while let Some(res) = submit_set.join_next().await {
        match res {
            Ok(r) => {
                if let Some(err) = r.err {
                    eprintln!(
                        "  x tx={} acct#{} nonce={} attempts={} err={}",
                        r.index, r.account_idx, r.nonce, r.attempts, err
                    );
                } else {
                    println!(
                        "  ok tx={} acct#{} nonce={} size={}B attempts={} elapsed={:.2?}",
                        r.index, r.account_idx, r.nonce, r.blob_len, r.attempts, r.elapsed
                    );
                }
            }
            Err(err) => {
                stats.failed.fetch_add(1, Ordering::Relaxed);
                eprintln!("submit task join error: {err}");
            }
        }
    }

    let ok = stats.ok.load(Ordering::Relaxed);
    let failed = stats.failed.load(Ordering::Relaxed);
    let retries = stats.retries.load(Ordering::Relaxed);
    let bytes_ok = stats.bytes_ok.load(Ordering::Relaxed);
    let submit_ms_ok = stats.submit_ms_ok.load(Ordering::Relaxed);

    let total = if let Some(tps) = args.tps {
        if tps > 0.0 {
            Duration::from_secs_f64((ok + failed) as f64 / tps)
        } else {
            Duration::ZERO
        }
    } else {
        Duration::ZERO
    };

    let avg_submit_ms = if ok == 0 {
        0.0
    } else {
        submit_ms_ok as f64 / ok as f64
    };

    println!("\\n==== Final Summary ====");
    println!("success         : {}", ok);
    println!("failed          : {}", failed);
    println!("retries         : {}", retries);
    println!("bytes submitted : {}", bytes_ok);
    println!("avg submit ms   : {:.2}", avg_submit_ms);
    if !total.is_zero() {
        println!("scheduled runtime: {:.2?}", total);
    }
    println!("=======================");

    Ok(())
}
