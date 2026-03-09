# DA Spammer

Two Rust CLIs to stress-test data availability on an [Avail](https://www.availproject.org/) node:

- `da-spammer`: single-account spammer with bounded precompute pipeline, retry/backoff, nonce refresh, and throughput metrics.
- `da-sybil-spammer`: multi-account spammer that deterministically derives many accounts, batch-funds them, and submits blobs round-robin with bounded concurrency.

## Build

```bash
cargo build --release
```

Artifacts:
- `./target/release/da-spammer`
- `./target/release/da-sybil-spammer`

## `da-spammer` (single account)

### What it does
- Uses one dev account (`alice|bob|charlie|dave|eve|ferdie|one|two`)
- Streams blob precompute via a bounded queue instead of materializing a full batch in memory
- Submits with bounded in-flight concurrency
- Retries failed submissions with exponential backoff
- Refreshes nonce on nonce-related RPC errors
- Prints batch-level success/failure/retry/TPS/MiB/s metrics

### Flags
- `--account <alice|bob|charlie|dave|eve|ferdie|one|two>` required
- `--endpoint <url>` default: `http://127.0.0.1:9944`
- `--size-mb <1..64>` default: `32`
- `--count <n>` default: `50`
- `--ch <char>` optional blob fill character
- `--precompute-workers <n>` default: half CPU cores, min 2
- `--in-flight <n>` default: `4`
- `--queue-cap <n>` default: `16`
- `--max-retries <n>` default: `3`
- `--retry-base-ms <ms>` default: `250`
- `--tps <float>` optional dispatch rate cap

### Example
```bash
./target/release/da-spammer \
  --account alice \
  --size-mb 16 \
  --count 200 \
  --in-flight 12 \
  --queue-cap 64 \
  --max-retries 5 \
  --retry-base-ms 200 \
  --tps 150 \
  --endpoint http://127.0.0.1:9944
```

## `da-sybil-spammer` (multi account)

### What it does
- Derives `--accounts` deterministic sybil keypairs from `//da-spammer/<index>`
- Funds all derived accounts from a dev funder using `utility.batch_all(balances.transfer_keep_alive(...))`
- Runs `--loops` blob submissions in round-robin over all accounts
- Uses bounded in-flight concurrency
- Retries with backoff and refreshes account nonce on nonce-related errors
- Logs per-tx outcomes and final aggregate metrics

### Flags
- `--endpoint <url>` default: `http://127.0.0.1:9944`
- `--funder <alice|bob|charlie|dave|eve|ferdie|one|two>` default: `alice`
- `--accounts <n>` default: `100`
- `--fund-each <avail>` default: `10`
- `--batch-size <n>` default: `100`
- `--size-mb <1..64>` default: `32`
- `--loops <n>` default: `1000`
- `--in-flight <n>` default: `50`
- `--tps <float>` optional dispatch rate cap
- `--max-retries <n>` default: `3`
- `--retry-base-ms <ms>` default: `250`
- `--ch <char>` optional fixed blob fill character
- `--funding-settle-ms <ms>` default: `1500`
- `--precompute-workers <n>` default: half CPU cores, min 2

### Example
```bash
./target/release/da-sybil-spammer \
  --endpoint http://127.0.0.1:9944 \
  --funder alice \
  --accounts 500 \
  --fund-each 5 \
  --batch-size 100 \
  --size-mb 8 \
  --loops 20000 \
  --in-flight 100 \
  --tps 400 \
  --max-retries 5 \
  --retry-base-ms 200
```

## Notes
- `--fund-each` is interpreted in whole AVAIL and multiplied by runtime `ONE_AVAIL`.
- High `--in-flight`, `--count`, `--accounts`, and `--size-mb` values can overload RPC, mempool, or node memory; scale gradually.
- Deterministic sybil accounts are reproducible across runs due to `//da-spammer/<index>` derivation.

## License

MIT
