//! Gossip pub/sub topic primitive.
//!
//! A [`Topic`] represents a named gossip channel identified by a BLAKE3 hash
//! of its name string. Topics deliver validated messages to an [`Inbox`].
//!
//! See the [pubsub spec](https://github.com/bahner/ma-core-spec/blob/main/pubsub.md)
//! for the full specification.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use did_ma::Message;

use crate::endpoint::DEFAULT_INBOX_CAPACITY;
use crate::inbox::Inbox;
use crate::service::{BROADCAST_TOPIC, CONTENT_TYPE_BROADCAST};

/// A 32-byte topic identifier derived from `blake3(topic_string)`.
pub type TopicId = [u8; 32];

/// Compute a [`TopicId`] from a topic name string.
///
/// ```
/// use ma_core::topic::topic_id;
///
/// let id = topic_id("/ma/broadcast/0.0.1");
/// assert_eq!(id, *blake3::hash(b"/ma/broadcast/0.0.1").as_bytes());
/// ```
pub fn topic_id(name: &str) -> TopicId {
    *blake3::hash(name.as_bytes()).as_bytes()
}

/// A gossip pub/sub topic.
///
/// Topics are identified by a BLAKE3 hash of their name string. When
/// subscribed, incoming messages are validated (§1.4) and delivered to an
/// inbox. Messages from blocked senders (§1.5) are dropped silently.
///
/// # Examples
///
/// ```
/// use ma_core::Topic;
///
/// let topic = Topic::new("/ma/broadcast/0.0.1");
/// assert_eq!(topic.name(), "/ma/broadcast/0.0.1");
/// assert!(!topic.is_subscribed());
/// ```
pub struct Topic {
    name: String,
    id: TopicId,
    inbox: Option<Inbox<Message>>,
    blocked: HashSet<String>,
}

impl Topic {
    /// Create a new topic from a protocol-style name string.
    ///
    /// The topic starts unsubscribed. Call [`subscribe`](Self::subscribe) to
    /// begin receiving messages.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let id = topic_id(&name);
        Self {
            name,
            id,
            inbox: None,
            blocked: HashSet::new(),
        }
    }

    /// Create a topic for the well-known broadcast channel.
    ///
    /// Equivalent to `Topic::new("/ma/broadcast/0.0.1")`.
    pub fn broadcast() -> Self {
        Self::new(BROADCAST_TOPIC)
    }

    /// The human-readable topic name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The BLAKE3-derived topic identifier.
    pub fn id(&self) -> &TopicId {
        &self.id
    }

    /// Whether this topic is currently subscribed (has an inbox).
    pub fn is_subscribed(&self) -> bool {
        self.inbox.is_some()
    }

    /// Subscribe with a new internal inbox using the default capacity.
    ///
    /// If already subscribed, this is a no-op.
    pub fn subscribe(&mut self) {
        if self.inbox.is_none() {
            self.inbox = Some(Inbox::new(DEFAULT_INBOX_CAPACITY));
        }
    }

    /// Subscribe with an existing inbox, so messages from multiple sources
    /// converge into a single queue.
    ///
    /// Replaces any previous inbox.
    pub fn subscribe_with(&mut self, inbox: Inbox<Message>) {
        self.inbox = Some(inbox);
    }

    /// Unsubscribe — stop receiving messages and drop the inbox.
    pub fn unsubscribe(&mut self) {
        self.inbox = None;
    }

    /// Deliver a message into this topic's inbox after validation.
    ///
    /// Returns `true` if the message was accepted, `false` if it was
    /// rejected (wrong content type, has recipient, blocked sender,
    /// expired, or not subscribed).
    pub fn deliver(&mut self, message: Message) -> bool {
        if self.inbox.is_none() {
            return false;
        }

        if !self.validate(&message) {
            return false;
        }

        let now = now_secs();
        let expires_at = if message.ttl == 0 {
            0
        } else {
            message.created_at.saturating_add(message.ttl)
        };

        // Safety: we checked inbox.is_some() above.
        self.inbox.as_mut().unwrap().push(now, expires_at, message);
        true
    }

    /// Drain all non-expired messages from the topic's inbox.
    ///
    /// Returns an empty `Vec` if not subscribed.
    pub fn drain(&mut self) -> Vec<Message> {
        match self.inbox.as_mut() {
            Some(inbox) => inbox.drain(now_secs()),
            None => Vec::new(),
        }
    }

    // ─── Sender blocking (§1.5) ─────────────────────────────────────────

    /// Block a sender DID. Messages from this sender will be dropped
    /// before any other validation.
    pub fn block(&mut self, sender_did: impl Into<String>) {
        self.blocked.insert(sender_did.into());
    }

    /// Unblock a sender DID.
    pub fn unblock(&mut self, sender_did: &str) {
        self.blocked.remove(sender_did);
    }

    /// Whether a sender DID is blocked.
    pub fn is_blocked(&self, sender_did: &str) -> bool {
        self.blocked.contains(sender_did)
    }

    // ─── Validation (§1.4) ──────────────────────────────────────────────

    /// Validate a message for topic delivery.
    ///
    /// Rules (pubsub.md §1.4):
    /// 1. Content type MUST be `application/x-ma-broadcast`.
    /// 2. The `to` field MUST be absent or empty.
    /// 3. Sender MUST NOT be blocked (§1.5 — checked first).
    /// 4. TTL — reject expired messages.
    ///
    /// Signature validation is the caller's responsibility (requires async
    /// DID document resolution).
    fn validate(&self, message: &Message) -> bool {
        // §1.5: blocked sender check first.
        if self.blocked.contains(&message.from) {
            return false;
        }

        // §1.4 rule 1: content type must be broadcast.
        if message.content_type != CONTENT_TYPE_BROADCAST {
            return false;
        }

        // §1.4 rule 2: no recipient.
        if !message.to.is_empty() {
            return false;
        }

        // §1.4 rule 4: TTL check.
        if message.ttl > 0 {
            let expires_at = message.created_at.saturating_add(message.ttl);
            if expires_at <= now_secs() {
                return false;
            }
        }

        true
    }
}

/// Current unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_ma::{Did, SigningKey};

    fn test_signing_key() -> (SigningKey, String) {
        let did = Did::new_identity("k51qzi5uqu5test").expect("did");
        let did_string = did.id();
        let signing_key = SigningKey::generate(did).expect("signing key");
        (signing_key, did_string)
    }

    fn make_broadcast(from: &str, signing_key: &SigningKey) -> Message {
        Message::new(
            from.to_string(),
            String::new(),
            CONTENT_TYPE_BROADCAST,
            b"hello world".to_vec(),
            signing_key,
        )
        .expect("broadcast message")
    }

    #[test]
    fn topic_id_is_blake3() {
        let name = "/ma/broadcast/0.0.1";
        let id = topic_id(name);
        assert_eq!(id, *blake3::hash(name.as_bytes()).as_bytes());
    }

    #[test]
    fn broadcast_topic_uses_protocol_constant() {
        let t = Topic::broadcast();
        assert_eq!(t.name(), BROADCAST_TOPIC);
    }

    #[test]
    fn subscribe_unsubscribe_lifecycle() {
        let mut t = Topic::new("test/topic/0.0.1");
        assert!(!t.is_subscribed());

        t.subscribe();
        assert!(t.is_subscribed());

        t.unsubscribe();
        assert!(!t.is_subscribed());
    }

    #[test]
    fn deliver_requires_subscription() {
        let mut t = Topic::new("test/topic/0.0.1");
        let (sk, did) = test_signing_key();
        let msg = make_broadcast(&did, &sk);
        assert!(!t.deliver(msg));
    }

    #[test]
    fn deliver_and_drain() {
        let mut t = Topic::new("test/topic/0.0.1");
        t.subscribe();
        let (sk, did) = test_signing_key();
        let msg = make_broadcast(&did, &sk);
        assert!(t.deliver(msg));
        let drained = t.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].content_type, CONTENT_TYPE_BROADCAST);
    }

    #[test]
    fn rejects_wrong_content_type() {
        let mut t = Topic::new("test/topic/0.0.1");
        t.subscribe();
        let (sk, did) = test_signing_key();
        // Use a non-broadcast content type.
        let msg = Message::new(
            did,
            String::new(),
            "application/x-ma-custom",
            b"payload".to_vec(),
            &sk,
        )
        .expect("custom message");
        assert!(!t.deliver(msg));
    }

    #[test]
    fn rejects_message_with_recipient() {
        let mut t = Topic::new("test/topic/0.0.1");
        t.subscribe();
        let (sk, did) = test_signing_key();
        // x-ma-broadcast with a recipient should be rejected by topic
        // validation even though ma-did would reject it at construction.
        // Build a valid broadcast first, then tamper with `to`.
        let mut msg = make_broadcast(&did, &sk);
        msg.to = "did:ma:someone".to_string();
        assert!(!t.deliver(msg));
    }

    #[test]
    fn blocked_sender_rejected() {
        let mut t = Topic::new("test/topic/0.0.1");
        t.subscribe();
        let (sk, did) = test_signing_key();
        t.block(did.clone());
        let msg = make_broadcast(&did, &sk);
        assert!(!t.deliver(msg));
    }

    #[test]
    fn unblock_allows_delivery() {
        let mut t = Topic::new("test/topic/0.0.1");
        t.subscribe();
        let (sk, did) = test_signing_key();
        t.block(did.clone());
        t.unblock(&did);
        let msg = make_broadcast(&did, &sk);
        assert!(t.deliver(msg));
    }

    #[test]
    fn drain_empty_when_unsubscribed() {
        let mut t = Topic::new("test/topic/0.0.1");
        assert!(t.drain().is_empty());
    }

    #[test]
    fn subscribe_with_shared_inbox() {
        let mut t = Topic::new("test/topic/0.0.1");
        let inbox = Inbox::new(128);
        t.subscribe_with(inbox);
        assert!(t.is_subscribed());
        let (sk, did) = test_signing_key();
        let msg = make_broadcast(&did, &sk);
        assert!(t.deliver(msg));
        assert_eq!(t.drain().len(), 1);
    }
}
