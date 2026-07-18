# Access control

`ma-core` includes a lightweight capability-based access control system behind
the `acl` feature flag. Both `ma-runtime` and `ma-agent` use it, in slightly
different roles: the runtime uses it to decide which remote identities are
allowed to call its services, and `ma-agent` uses it client-side to filter
messages arriving in the inbox.

The ACL is intentionally simple. It maps identity principals to sets of
capability strings. At runtime you call `check_cap(acl, sender_did, cap)` and
get either an `Ok(())` (allowed) or an error (denied). The evaluation happens
on every incoming message, so it needs to be fast — and it is, because the
whole map is in memory.

## The one rule you must internalise: deny wins

The most important thing to understand is that an explicit deny always beats
any allow, including a wildcard allow. If you have a rule that says everyone
(`"*"`) can use RPC, but you also have an explicit deny for a specific DID,
that DID is denied. Full stop. You cannot override a deny with another allow
entry. The only way to re-allow a denied principal is to remove the deny entry
from the map.

There is also no implicit open default. An empty `AclMap` with no entries
denies everyone. Never treat a missing ACL file as "open" — if the file is
missing, that is a configuration error and you should refuse to start.
`ma-runtime` enforces this strictly.

When `check_cap` evaluates a request, it looks up the sender's DID in the map.
If there is a direct match and it is a deny, the request is rejected
immediately, without consulting the wildcard. If there is a direct match and
it allows the capability, the request is approved. Only if there is no direct
match does the code fall through to the wildcard `"*"` entry. If there is no
wildcard either, the request is denied.

## Capabilities

Capabilities are plain strings. The built-in ones correspond to the well-known
service protocols:

| Capability | What it guards |
|------------|----------------|
| "inbox" | Deliver messages via `/ma/inbox/0.0.1` |
| "rpc" | Send RPC calls via `/ma/rpc/0.0.1` |
| "ipfs" | Store generic content via `/ma/ipfs/0.0.1` (fire-and-forget) |
| "identity-publish" | Publish DID documents via `/ma/ipfs/0.0.1` |
| "crud" | Access the CRUD service via `/ma/crud/0.0.1` |
| "read" | Read entities, config, namespace contents |
| "create" | Create new namespaces or entities |
| "update" | Update existing entries |
| "delete" | Delete entries |
| "*" | Wildcard — grants all capabilities to this principal |

The string "*" is special: if it appears in a principal's allow set, it
grants every capability. This is not the same as the wildcard principal key
(`"*"` as a map key matching any caller) — these are two different levels of
wildcarding and they compose independently.

Custom capability strings are also valid. An entity-specific ACL might use
verb names as capabilities; a namespace ACL might use sub-namespace names.
The check is just a string comparison, so anything goes as long as both sides
agree on the string.

## Writing an ACL file

The ACL is stored and loaded as YAML. The structure is a map under an `acl:`
key, where each entry maps a principal string to either a list of capability
strings or nothing (which means deny):

```yaml
acl:
  # Open to everyone for basic messaging
  "*": [inbox, rpc]

  # Alice is an admin — she gets everything
  "did:ma:k51qzi5uqu5dh5kbbff1ucw3ksphpy3vxx4en4dbtfh90pvw4mbe5no9txndkg": ["*"]

  # Bob can use RPC but cannot publish
  "did:ma:k51qzi5uqu5dh8fbc4roh9l0bv3j8fqv7h1pgstnh0fhxlxaevf2jwezpgxpbr": [rpc, read]

  # Eve is explicitly denied. The bare key with no value means null/deny.
  # Even though "*" grants rpc above, Eve cannot use anything.
  "did:ma:k51qzi5uqu5dllwp93boolhmk2j48yxw6djr9vl3g1ptdtg1o4gqbhqq5qkxc":

  # A named group of Alice's friends all get rpc access.
  # Groups are resolved by the identity that defines them.
  "+alice.friends": [rpc]

  # Deep group paths work the same way.
  "+alice.project4.admins": ["*"]

  # An entire group can be denied.
  "+alice.enemies":
```

Save this as `acl.yaml` and pass `--acl-file acl.yaml` to `ma-runtime`.

A few things to notice in the example above. The `did:ma:k51…eve` entry has
no value — in YAML this deserialises as `null`, which the ACL layer treats as
an explicit deny. The comment makes the intent clear, but the denial works
even without it. Similarly, "+alice.enemies": with no value denies the
entire group.

## Using check_cap in your code

Add the feature to your `Cargo.toml`:

```toml
ma-core = { version = "0.10", features = ["acl"] }
```

Loading an ACL from a file and checking a capability looks like this:

```rust,ignore
use ma_core::{AclMap, check_cap, CAP_RPC, CAP_IPFS};

fn load_acl(path: &str) -> anyhow::Result<AclMap> {
    let yaml = std::fs::read_to_string(path)?;
    let value: serde_yaml::Value = serde_yaml::from_str(&yaml)?;
    let acl: AclMap = serde_yaml::from_value(value["acl"].clone())?;
    Ok(acl)
}

fn handle_incoming(acl: &AclMap, sender_did: &str, is_rpc: bool) -> anyhow::Result<()> {
    let cap = if is_rpc { CAP_RPC } else { CAP_INBOX };

    check_cap(acl, sender_did, cap)?;
    // If we reach here, the sender is allowed. Process the message.
    Ok(())
}
```

You can also build an `AclMap` directly in code without a file, which is
useful in tests or when you want to hardcode a simple policy:

```rust,ignore
use ma_core::{AclMap, CapabilityEntry, check_cap, CAP_RPC, CAP_IPFS};

let mut acl = AclMap::new();

// Allow everyone to use RPC.
acl.insert("*".to_string(), CapabilityEntry::from_caps(["rpc"]));

// Allow Alice everything.
acl.insert("did:ma:k51qzi5uqu5dh5kbbff1ucw3ksphpy3vxx4en4dbtfh90pvw4mbe5no9txndkg".to_string(), CapabilityEntry::from_caps(["*"]));

// Explicitly deny Eve, even though the wildcard above would otherwise allow her.
acl.insert("did:ma:k51qzi5uqu5dllwp93boolhmk2j48yxw6djr9vl3g1ptdtg1o4gqbhqq5qkxc".to_string(), CapabilityEntry::Deny);

assert!(check_cap(&acl, "did:ma:k51qzi5uqu5dh5kbbff1ucw3ksphpy3vxx4en4dbtfh90pvw4mbe5no9txndkg", CAP_IPFS).is_ok());
assert!(check_cap(&acl, "did:ma:k51qzi5uqu5dh8fbc4roh9l0bv3j8fqv7h1pgstnh0fhxlxaevf2jwezpgxpbr",   CAP_RPC).is_ok());
assert!(check_cap(&acl, "did:ma:k51qzi5uqu5dllwp93boolhmk2j48yxw6djr9vl3g1ptdtg1o4gqbhqq5qkxc",   CAP_RPC).is_err());  // deny wins

// Bob is allowed rpc by wildcard but not ipfs, which nobody but Alice has.
assert!(check_cap(&acl, "did:ma:k51qzi5uqu5dh8fbc4roh9l0bv3j8fqv7h1pgstnh0fhxlxaevf2jwezpgxpbr", CAP_IPFS).is_err());
```

## DID fragments are stripped automatically

When a message arrives, the `from` field in the message headers is often a
DID-URL with a fragment, such as `did:ma:k51qzi5uqu5d…#sign`. The ACL lookup
strips the fragment before checking — `normalize_principal` does this — so
your ACL entries only need the bare DID. You never write
`did:ma:k51qzi5uqu5d…#sign`: in an ACL file.

## Local fragment principals

Not every principal needs to be a full `did:ma:` identity. Local entities,
plugins, and internal components that live inside the same endpoint can be
addressed by a bare fragment identifier — a string starting with `#`. These
are local IDs in the sense that they are meaningful only within the running
endpoint, without any network-resolvable DID behind them.

A short nanoid or a human-readable label works fine:

```yaml
acl:
  "*": [inbox, rpc]

  # A locally-running plugin identified by a short random ID.
  "#nanoid123": [rpc, create]

  # A named local component.
  "#indexer": [read]
```

`normalize_principal` treats a `#`-prefixed string as already normalised and
passes it through unchanged, so `check_cap` works the same way as for full
DIDs. The calling code is responsible for constructing the right `#<id>` string
when checking access for a local component.

## Group principals

Group principals have the form `+<handle>.<path>`, where `<handle>` is the
DID handle of the identity that owns the group and `<path>` is a
dot-separated path of arbitrary depth into their group hierarchy. For example,
`+alice.project4.admins` refers to the `admins` subgroup of `project4` in
Alice's group tree.

Group membership is resolved by querying the owning identity's published
group definitions. This is the only part of the ACL that involves a network
lookup; all other evaluations are pure in-memory map lookups.

## Validating an ACL map

If you are building tooling that edits or generates ACL files, `validate_acl_map`
checks the structural correctness of a loaded map — reserved key forms,
duplicate entries, and other invariants. `is_valid_acl_key` and
`is_principal_key` let you validate individual keys before inserting them.
