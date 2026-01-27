use avail_fri::{
    core::{FriBiniusPCS, B128},
    encoding::BytesEncoder,
    eval_utils::{derive_evaluation_point, derive_seed_from_inputs, eval_claim_to_bytes},
    FriParamsVersion,
};
use avail_rust::{avail_rust_core::rpc::blob::submit_blob, prelude::*};
use clap::Parser;
use sp_crypto_hashing::keccak_256;
use std::error::Error;

pub struct BabeRandomness;
impl StorageValue for BabeRandomness {
    type VALUE = [u8; 32];

    const PALLET_NAME: &str = "Babe";
    const STORAGE_NAME: &str = "Randomness";
}

/// Simple CLI for spamming blobs + metadata to an Avail node.
#[derive(Parser, Debug)]
#[command(name = "da-spammer", about = "Submit blobs + metadata to Avail")]
struct Args {
    /// One of: alice,bob,charlie,dave,eve,ferdie,one,two
    #[arg(long, value_parser = validate_account)]
    account: String,

    /// Payload size in MiB [1..=64] (default: 32)
    #[arg(long, default_value_t = 32)]
    size_mb: usize,

    /// Number of transactions [1..=100] (default: 50)
    #[arg(long, default_value_t = 50)]
    count: usize,

    /// Single character to repeat for the blob. Default: first char of `--account`
    #[arg(long)]
    ch: Option<char>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:9944")]
    endpoint: String,
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
        _ => unreachable!("validated above"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if !(1..=64).contains(&args.size_mb) {
        panic!("--size-mb must be within 1..=64");
    }
    if !(1..=100).contains(&args.count) {
        panic!("--count must be within 1..=100");
    }
    if let Some(ch) = args.ch {
        if ch.len_utf8() != 1 {
            panic!("--ch must be a single ASCII character");
        }
    }

    let len_bytes = args.size_mb * 1024 * 1024;

    println!("========== Avail DA Spammer ==========");
    println!("Endpoint : {}", args.endpoint);
    println!("Account  : {}", args.account);
    println!("Size     : {} MiB ({} bytes)", args.size_mb, len_bytes);
    println!("Count    : {}", args.count);

    let client = Client::new(&args.endpoint).await?;
    let signer = keypair_for(&args.account);

    let default_ch = args.account.chars().next().unwrap();
    let ch = args.ch.unwrap_or(default_ch);
    let byte = ch as u8;

    let account_id = signer.account_id();
    let mut nonce = client.chain().account_nonce(account_id.clone()).await?;
    println!("AccountId: {account_id}");
    println!("Start nonce: {nonce}");

    // Precompute blobs & commitments
    println!("---- Precomputing {} blobs & commitments ...", args.count);
    let mut prepared: Vec<(Vec<u8>, H256, Vec<u8>, Option<[u8; 32]>, Option<[u8; 16]>)> =
        Vec::with_capacity(args.count);
    for i in 0..args.count {
        let this_len = len_bytes - i;
        let blob = vec![byte; this_len];
        let blob_hash = H256::from(keccak_256(&blob));
        let params_version = FriParamsVersion(0);
        // Encode bytes → multilinear extension over B128
        let encoder = BytesEncoder::<B128>::new();
        let packed = encoder
            .bytes_to_packed_mle(&blob)
            .expect("Failed to encode blob to packed MLE");

        let n_vars = packed.total_n_vars;

        // Map version + n_vars → concrete FriParamsConfig
        let cfg = params_version.to_config(n_vars);

        // Build PCS + FRI context
        let pcs = FriBiniusPCS::new(cfg);
        let ctx = pcs
            .initialize_fri_context::<B128>(packed.packed_mle.log_len())
            .expect("Failed to initialize FRI context");

        // Commit to the blob MLE: returns a 32-byte digest in `commitment`
        let commit_output = pcs
            .commit(&packed.packed_mle, &ctx)
            .expect("Failed to commit to blob MLE");
        let commitments = commit_output.commitment;
        // fetch current epoch randomness from the chain & use it to derive eval point seed
        let rpc_client = &client.rpc_client;
        let babe_randomness = BabeRandomness::fetch(&rpc_client, None)
            .await?
            .expect("Babe Randomness should be available for every epoch except genesis era");
        let eval_point_seed = derive_seed_from_inputs(&babe_randomness, &blob_hash.0);
        let eval_point = derive_evaluation_point(eval_point_seed, n_vars);
        let eval_claim = pcs
            .calculate_evaluation_claim(&packed.packed_values, &eval_point)
            .expect("Failed to calculate evaluation claim");
        let eval_cliam_bytes = eval_claim_to_bytes(eval_claim);
        // use our prepared blob (same content) to keep prints identical to before
        println!(
            "  [{}] blob_len={}B  hash={:?}  commitments_len={}",
            i,
            blob.len(),
            blob_hash,
            commitments.len()
        );
        prepared.push((
            blob,
            blob_hash,
            commitments,
            Some(eval_point_seed),
            Some(eval_cliam_bytes),
        ));
    }
    println!("✓ Precompute done");

    println!("---- Submitting {} blobs ...", prepared.len());
    for (i, (blob, hash, commitments, eval_point_seed, eval_claim)) in
        prepared.into_iter().enumerate()
    {
        let app_id = (i % 5) as u32;
        let options = Options::default().app_id(app_id).nonce(nonce);

        let unsigned = client.tx().data_availability().submit_blob_metadata(
            app_id,
            hash,
            blob.len() as u64,
            commitments,
            eval_point_seed,
            eval_claim,
        );

        let tx_bytes = unsigned.sign(&signer, options).await.unwrap().encode();

        println!(
            "  → [{}] nonce={} app_id={} tx_bytes={}B ...",
            i,
            nonce,
            app_id,
            tx_bytes.len()
        );

        match submit_blob(&client.rpc_client, &tx_bytes, &blob).await {
            Ok(_) => println!("    ✓ [{}] submitted", i),
            Err(e) => eprintln!("    ✗ [{}] error: {e}", i),
        }

        nonce += 1;
    }

    println!("✅ Finished. Submitted {} transactions.", args.count);
    Ok(())
}
