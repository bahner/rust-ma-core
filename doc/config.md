# Configuration and identity keys

The `config` feature in `ma-core` provides two closely related types that
together represent a running 間 endpoint: `Config` holds the runtime
parameters (addresses, log levels, cache TTLs), and `SecretBundle` holds the
four cryptographic keys that define the endpoint's identity. You almost always
need both.

On native targets, `Config` knows how to read itself from a YAML file, merge
in values from environment variables and CLI arguments, and write itself back
to disk. On wasm, it serializes and deserializes as plain YAML text; storage
is your responsibility. `SecretBundle` follows the same split: native targets
can save and load an encrypted binary file; wasm targets get encrypt/decrypt
functions and delegate persistence to IndexedDB. See
[wasm.md](wasm.md) for the browser-specific story.

## The four keys in SecretBundle

Every 間 endpoint has exactly one `SecretBundle`. It contains four standard
32-byte keys, each with a distinct role:

**`iroh_secret_key`** is the seed for the iroh QUIC transport keypair. iroh
derives an Ed25519 signing key and an X25519 key exchange key from this seed
internally. This determines the endpoint's network address on the iroh
overlay. If you change this key, other endpoints can no longer find you at the
same address.

**`ipns_secret_key`** roots the `did:ma:` identity. The IPNS public key
derived from this seed, encoded in base58, becomes the `<ipns-id>` part of
`did:ma:<ipns-id>`. This is the long-term stable identifier for the endpoint.
If you change this key, you get a new DID and all previous associations (inbox
messages, alias entries pointing to the old DID) are orphaned.

**`did_signing_key`** is the Ed25519 key used to sign DID documents and
outgoing messages. It appears in the DID document as the `#sign` verification
method. Recipients use it to verify the `proof` field of your DID document and
the `signature` field of messages you send.

**`did_encryption_key`** is the X25519 key used for message encryption. It
appears in the DID document as the `#enc` key agreement method. Senders use
it to encrypt `Envelope` payloads so that only you can decrypt them.

All four fields are `[u8; 32]` and are zeroed from memory when the struct is
 dropped, courtesy of the `zeroize` crate.

## Generating a fresh identity

```rust,ignore
use ma_core::config::SecretBundle;

let bundle = SecretBundle::generate();
println!("new DID will be: did:ma:{}", bundle.ipns_id()?);
```

`SecretBundle::generate()` calls the OS CSPRNG for each of the four keys. The
`created_at` field is set to the current UTC time and never changed — it is a
creation timestamp for the identity, not a lease.

For unattended deployment there is a shortcut: `Config::gen_headless` generates
a fresh bundle and config together and writes them to the XDG paths in one
call. See the native daemon section below.

## Building a DID document

Once you have a bundle, `build_document` produces a complete signed `Document`
ready to publish. Pass a `MaExtension` carrying the `ma:`-namespace fields —
type and language are the common ones:

```rust,ignore
use ma_core::config::SecretBundle;
use ma_core::doc::MaExtension;

let bundle = SecretBundle::generate();

let ext = MaExtension::new()
    .kind("agent")   // "agent" for interactive endpoints, "runtime" for daemons
    .lang("en");     // BCP-47 language tag

let document = bundle.build_document(ext)?;

// Encode to DAG-CBOR bytes for storage in IPFS.
let cbor = document.encode()?;

// Or get the JSON representation for debugging.
let json = document.to_json()?;
println!("{}", json);
```

The resulting document includes the iroh transport service strings, the signing
verification method (`#sign`), the encryption key agreement method (`#enc`), a
`created` timestamp, and a `proof` block containing a signature over the whole
document.

## Saving and loading on native targets

The bundle is stored as an encrypted binary file. Encryption uses Argon2id for
key derivation and XChaCha20-Poly1305 for authenticated encryption. The on-disk
format is a salt, a nonce, the base64-encoded ciphertext, and the authentication
tag — all concatenated in a single file written with mode `0600`.

```rust,ignore
use ma_core::config::SecretBundle;
use std::path::Path;

let path = Path::new("/home/user/.config/myapp/myapp.bin");
let passphrase = "correct horse battery staple";

// Save — writes with mode 0600.
bundle.save(path, passphrase)?;

// Load — derives the same key from the passphrase and decrypts.
let bundle = SecretBundle::load(path, passphrase)?;
```

If the passphrase is wrong, `load` returns an error. There is no way to
distinguish a wrong passphrase from a corrupted file other than trying to
decrypt — the binary file gives no hints about its contents.

## Adding custom keys to a bundle

Daemons sometimes need additional key material alongside the four standard
keys. The bundle accommodates this with `add_key`, `generate_key`, and
`get_key`. The standard key names (`iroh`, `ipns`, `did_signing`,
`did_encryption`) are reserved; everything else is yours:

```rust,ignore
use ma_core::config::SecretBundle;

let mut bundle = SecretBundle::generate();

// Generate a fresh random 32-byte key and store it.
bundle.generate_key("plugin_signing")?;

// Or store an existing key you already have.
let my_key: [u8; 32] = derive_my_key();
bundle.add_key("session_token", my_key)?;

// Retrieve it later.
let key = bundle.get_key("plugin_signing").expect("we just added it");

// Custom keys survive save/load cycles.
bundle.save(&path, passphrase)?;
let loaded = SecretBundle::load(&path, passphrase)?;
assert_eq!(key, loaded.get_key("plugin_signing").unwrap());
```

## Config for native daemons

`Config` on native targets carries the full set of fields a daemon needs:

| Field | Default | Notes |
|-------|---------|-------|
| `slug` | `MA_DEFAULT_SLUG` | Instance name; used in file paths. CLI/env only. |
| `log_level` | `"info"` | Log level for the log file. |
| `log_level_stdout` | `"warn"` | Log level for stdout. |
| `kubo_rpc_url` | `"http://127.0.0.1:5001"` | Kubo HTTP RPC address. |
| `did_resolver_positive_ttl_secs` | 60 | Cache TTL for successful DID lookups. |
| `did_resolver_negative_ttl_secs` | 10 | Cache TTL for failed DID lookups. |
| `secret_bundle` | XDG-derived | Path to the `.bin` file. |
| `log_file` | XDG-derived | Path to the log file. |
| `extra` | empty | Free-form YAML keys not part of the core schema. |

### The slug and its env-var prefix

The slug is a short identifier used to derive default file paths. A daemon
with slug `ma` looks for its config at `~/.config/ma/ma.yaml` and its bundle
at `~/.config/ma/ma.bin`. It also sets the env-var prefix: slug `ma` means the
daemon reads `MA_MA_LOG_LEVEL`, `MA_MA_KUBO_RPC_URL`, and so on.

The slug **must never appear in the YAML config file**. The daemon needs the
slug to find the file, and would need the file to learn the slug — an
unresolvable catch-22. Set it via `--slug` on the command line or via the
`MA_SLUG` environment variable only.

### Setting up Config::from_args

Every native binary declares a compile-time constant and flattens `MaArgs`
into its `clap` parser:

```rust,ignore
use clap::Parser;
use ma_core::config::{Config, MaArgs};

// This constant sets the default slug and the compile-time env-var prefix.
const MA_DEFAULT_SLUG: &str = "myapp";

#[derive(Parser)]
struct Cli {
    #[arg(long)]
    dry_run: bool,

    #[command(flatten)]
    ma: MaArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Merges CLI flags, env vars, YAML, and built-in defaults in that order.
    let config = Config::from_args(&cli.ma, MA_DEFAULT_SLUG)?;
    config.init_logging()?;

    let bundle = config.load_secret_bundle()?;

    tracing::info!("started as did:ma:{}", bundle.ipns_id()?);
    Ok(())
}
```

With this in place a user can run `myapp --slug staging` to use a separate
config and bundle for a staging instance, or set
`MA_MYAPP_KUBO_RPC_URL=http://192.168.1.5:5001` to override the Kubo address
without editing the YAML file.

### First-time headless setup

For unattended deployment (CI, servers, containers), pass `--gen-headless-config`
on first run:

```bash
myapp --gen-headless-config
```

This generates a fresh `SecretBundle`, encrypts it with a randomly-generated
passphrase, and writes both the YAML config and the encrypted bundle to the
XDG paths with mode `0600`. The passphrase ends up in the YAML file in
cleartext — intended for headless use where the config file is protected by
OS-level permissions and the host is trusted.

### The YAML config file

Config is read from `$XDG_CONFIG_HOME/ma/<slug>.yaml`. A typical file:

```yaml
log_level: debug
log_level_stdout: info
kubo_rpc_url: http://127.0.0.1:5001
did_resolver_positive_ttl_secs: 120
did_resolver_negative_ttl_secs: 30
```

Extra keys in the file are preserved in `config.extra` when loaded, so you
can safely share the file between `ma-core`'s config and your own
application-specific settings.

All files written by `ma-core` follow the XDG Base Directory Specification:

| File | Default path |
|------|-------------|
| Config YAML | `$XDG_CONFIG_HOME/ma/<slug>.yaml` |
| Secret bundle | `$XDG_CONFIG_HOME/ma/<slug>.bin` |
| Log file | `$XDG_DATA_HOME/ma/<slug>.log` |
