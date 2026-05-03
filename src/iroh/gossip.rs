//! Shared iroh-gossip helpers for the ma broadcast channel.

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::Endpoint;
use iroh_gossip::api::GossipSender;
use iroh_gossip::net::Gossip;
use iroh_gossip::proto::TopicId;

use crate::service::BROADCAST_TOPIC;

/// Derive the canonical `TopicId` for a gossip topic string using blake3.
pub fn topic_id_for(topic: &str) -> TopicId {
    TopicId::from_bytes(*blake3::hash(topic.as_bytes()).as_bytes())
}

/// Derive the canonical `TopicId` for the ma broadcast channel.
pub fn broadcast_topic_id() -> TopicId {
    topic_id_for(BROADCAST_TOPIC)
}

/// Spawn an iroh-gossip node on `endpoint` and join `topic`, bootstrapping
/// from `peers` (empty is fine for the first node in the mesh).
///
/// Returns `(Gossip, GossipSender)`. The caller is responsible for keeping
/// the `Gossip` handle alive for the lifetime of the node and for spawning a
/// receiver task if inbound messages are needed.
pub async fn join_gossip_topic(
    endpoint: Endpoint,
    topic: TopicId,
    peers: Vec<iroh::EndpointId>,
) -> Result<(Gossip, GossipSender)> {
    let gossip = Gossip::builder().spawn(endpoint);

    let topic_handle = gossip
        .subscribe_and_join(topic, peers)
        .await
        .context("iroh-gossip subscribe_and_join failed")?;

    let (sender, _receiver) = topic_handle.split();
    Ok((gossip, sender))
}

/// Join the ma broadcast channel with no bootstrap peers.
pub async fn join_broadcast_channel(endpoint: Endpoint) -> Result<(Gossip, GossipSender)> {
    join_gossip_topic(endpoint, broadcast_topic_id(), vec![]).await
}

/// Send a raw byte payload on an existing gossip sender.
pub async fn gossip_send(sender: &GossipSender, payload: Bytes) -> Result<()> {
    sender
        .broadcast(payload)
        .await
        .context("iroh-gossip broadcast failed")
}

/// Serialise `payload` as UTF-8 and send it on `sender`.
pub async fn gossip_send_text(sender: &GossipSender, payload: &str) -> Result<()> {
    gossip_send(sender, Bytes::copy_from_slice(payload.as_bytes())).await
}
