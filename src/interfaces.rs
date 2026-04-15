pub trait DidPublisher {
    type Error;

    fn publish_did_document(&self, actor_id: &str, document_json: &str) -> Result<String, Self::Error>;
}

pub trait IpfsPublisher {
    type Error;

    fn put_json(&self, value_json: &str) -> Result<String, Self::Error>;
    fn publish_name(&self, key_name: &str, cid: &str) -> Result<String, Self::Error>;
}
