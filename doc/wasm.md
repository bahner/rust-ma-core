# Using ma-core in the browser (wasm32)

`ma-core` is designed from the start to compile to `wasm32-unknown-unknown`.
This is not an afterthought — `ma-agent`, the primary browser-based 間
endpoint, is built on exactly this target, and the crate split between wasm
and native reflects real deployment requirements, not just theoretical
portability.

In practical terms: a browser tab running `ma-agent` is a full 間 identity.
It has its own keypair, its own iroh QUIC transport, and it sends and receives
messages directly over the network — no server in the middle. The only thing
it cannot do natively is talk to a Kubo daemon to publish its DID document to
IPFS/IPNS. That job is delegated to a `ma-runtime` instance running on the
user's machine. See [ipfs-publish.md](ipfs-publish.md) for how that works.

## Adding ma-core to a wasm crate

The recommended feature set for a browser endpoint mirrors what `ma-agent`
uses:

```toml
[dependencies]
ma-core = { version = "0.12", default-features = false, features = ["iroh", "config", "acl"] }
```

Turning off default features gives browser applications explicit control over
which optional APIs they compile. The three features above give you everything
a browser endpoint needs: the iroh QUIC transport, the identity and config
model, and the ACL for inbound message filtering.

You do **not** need to add `getrandom` with `js` feature to your own
`Cargo.toml`. `ma-core` declares the wasm-specific dependencies itself:

```toml
# Already in ma-core's Cargo.toml — you don't repeat this
[target.'cfg(target_arch = "wasm32")'.dependencies]
getrandom = { version = "0.2", features = ["js"] }
js-sys = "0.3"
wasm-bindgen = "0.2"
web-sys = { version = "0.3", features = ["console"] }
web-time = "1"
```

If you pull in a crate that depends on `getrandom` directly and it does not
itself enable the `js` feature, you may need to add a `[patch]` or a direct
dependency to ensure the feature is activated. This is a standard wasm
gotcha in the Rust ecosystem, not specific to `ma-core`.

## What is available on wasm

Almost everything in `ma-core` works on wasm. The things that do not are
native-only by design because they touch the filesystem or spawn OS threads
in ways that have no browser equivalent:

- The `kubo` feature and everything behind it. Kubo speaks HTTP to
  `localhost:5001`, and a browser cannot make arbitrary localhost HTTP
  requests. Use `ma-runtime` as the publishing proxy instead.
- `Config::from_args` and `MaArgs` — `clap` argument parsing has no meaning
  in a browser context. Configuration comes from IndexedDB.
- `Config::save`, `Config::gen_headless` — filesystem writes.
- `SecretBundle::load`, `SecretBundle::save` — same reason.
- `Config::init_logging()` is available on wasm but routes to `console.log`
  instead of a file. The call site is identical; the behaviour differs.

Everything else compiles and works: messaging, crypto, DID document
construction, iroh transport, ACL, and DID resolution via the IPFS gateway.

## The storage problem

On native, `ma-core` manages files in `$XDG_CONFIG_HOME/ma/`. On wasm you are
responsible for storage yourself. There are two pieces of state that must
survive across browser sessions:

**The encrypted secret bundle.** This is the user's identity — their
keypairs. `SecretBundle::encrypt(passphrase)` returns a `Vec<u8>` that you
store in IndexedDB. On the next login, you retrieve those bytes and call
`SecretBundle::decrypt(&bytes, passphrase)` to get the bundle back. The
passphrase is collected from the user at login time and never persisted.

**The config.** `Config::to_yaml_string()` returns a plain UTF-8 string. Store
it as a string entry in IndexedDB alongside the bundle bytes. Load it back
with `Config::from_yaml_str(&text)`.

A typical login sequence looks like this:

```rust,ignore
use ma_core::config::{Config, SecretBundle};

async fn login(username: &str, passphrase: &str) -> anyhow::Result<(Config, SecretBundle)> {
    // Load the raw encrypted bytes from IndexedDB.
    let encrypted_bytes = indexeddb_load_bytes(username).await?;
    let config_yaml = indexeddb_load_string(&format!("{username}.config")).await?;

    // Decrypt — this fails loudly on a wrong passphrase.
    let bundle = SecretBundle::decrypt(&encrypted_bytes, passphrase)?;
    let config = Config::from_yaml_str(&config_yaml)?;

    Ok((config, bundle))
}
```

And the first-time registration for a new identity:

```rust,ignore
use ma_core::config::{Config, SecretBundle};
use ma_core::doc::MaExtension;

async fn register(username: &str, passphrase: &str) -> anyhow::Result<()> {
    // Generate a fresh identity with four new random keypairs.
    let bundle = SecretBundle::generate();

    // Build a minimal config. You can add more fields before saving.
    let mut config = Config::default();
    config.slug = username.to_string();

    // Encrypt and persist both pieces.
    let encrypted = bundle.encrypt(passphrase)?;
    indexeddb_store_bytes(username, &encrypted).await?;
    indexeddb_store_string(
        &format!("{username}.config"),
        &config.to_yaml_string()?,
    ).await?;

    Ok(())
}
```

The passphrase must be kept in memory for the duration of the session and
discarded when the tab closes or the user logs out. Never write it to
IndexedDB, localStorage, or any other persistent store.

## Building a DID document from the bundle

Once you have a `SecretBundle` in memory, producing a DID document is a single
call. The `MaExtension` carries the `ma:`-specific fields that go into the
published document — at minimum the endpoint type and, if set, the language
preference:

```rust,ignore
use ma_core::doc::MaExtension;
use ma_core::config::SecretBundle;

fn build_my_document(bundle: &SecretBundle) -> anyhow::Result<Vec<u8>> {
    let ext = MaExtension::new()
        .kind("agent")           // this endpoint is an interactive agent
        .lang("nb");             // the user's preferred language

    let document = bundle.build_document(ext)?;

    // document.encode() gives you DAG-CBOR bytes, suitable for IPFS.
    // If you want the JSON representation for debugging, use document.to_json().
    Ok(document.encode()?)
}
```

The resulting document includes the iroh transport service endpoints so that
other identities can find and connect to you.

## Exporting and importing an identity

If a user wants to use the same identity on a different machine or in a
different browser, `BrowserIdentityExport` packages the encrypted bundle and
the config YAML into a single JSON string that the user can copy, download,
or paste:

```rust,ignore
use ma_core::config::{BrowserIdentityExport, Config, SecretBundle};

fn export_identity(config: &Config, bundle: &SecretBundle, passphrase: &str)
    -> anyhow::Result<String>
{
    let encrypted = bundle.encrypt(passphrase)?;
    let export = BrowserIdentityExport::new(
        config.to_yaml_string()?,
        &encrypted,
    );
    Ok(export.to_json_string()?)
}

fn import_identity(json: &str, passphrase: &str)
    -> anyhow::Result<(Config, SecretBundle)>
{
    let export = BrowserIdentityExport::from_json_str(json)?;
    let bundle_bytes = export.encrypted_secret_bundle_bytes()?;
    let bundle = SecretBundle::decrypt(&bundle_bytes, passphrase)?;
    let config = Config::from_yaml_str(&export.config_yaml)?;
    Ok((config, bundle))
}
```

The exported JSON is safe to transfer in plaintext — the bundle inside it is
encrypted with the user's passphrase. Someone who intercepts it still needs
the passphrase to do anything with the keys.

## Verifying the wasm build locally

Trunk (used by `ma-agent`) runs these checks automatically, but if you are
working on `ma-core` itself and want to verify that your changes do not break
the wasm target:

```bash
# The profile used by ma-agent:
cargo check --target wasm32-unknown-unknown --no-default-features --features "iroh,config,acl"
```

The one feature you must never enable on wasm is `kubo`. It will fail at
compile time because it depends on native HTTP client code that is not
available in the browser environment.
