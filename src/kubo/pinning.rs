//! Safe pin lifecycle management.
//!
//! [`pin_add_then_rm`] pins a new CID, then attempts to remove the old
//! pin, reporting any removal failure as metadata rather than a hard error.

use std::future::Future;

use anyhow::Result;

#[cfg(feature = "config")]
use crate::config::RemotePinConfig;

#[derive(Debug, Default, Clone)]
pub struct PinReplaceOutcome {
    pub previous_remove_error: Option<String>,
}

pub async fn pin_add_then_rm<FAdd, FRm, FutAdd, FutRm>(
    old_cid: Option<&str>,
    new_cid: &str,
    pin_name: &str,
    add_named: FAdd,
    remove_pin: FRm,
) -> Result<PinReplaceOutcome>
where
    FAdd: Fn(String, String) -> FutAdd,
    FRm: Fn(String) -> FutRm,
    FutAdd: Future<Output = Result<()>>,
    FutRm: Future<Output = Result<()>>,
{
    let Some(previous) = old_cid else {
        add_named(new_cid.to_string(), pin_name.to_string()).await?;
        return Ok(PinReplaceOutcome::default());
    };

    if previous == new_cid {
        return Ok(PinReplaceOutcome::default());
    }

    add_named(new_cid.to_string(), pin_name.to_string()).await?;

    let previous_remove_error = remove_pin(previous.to_string())
        .await
        .err()
        .map(|err| err.to_string());

    Ok(PinReplaceOutcome {
        previous_remove_error,
    })
}

#[cfg(feature = "config")]
pub async fn remote_pin_replace(
    kubo_url: &str,
    remote: &RemotePinConfig,
    old_cid: Option<&str>,
    new_cid: &str,
) -> Result<PinReplaceOutcome> {
    let add_url = kubo_url.to_string();
    let add_service = remote.service.clone();
    let rm_url = kubo_url.to_string();
    let rm_service = remote.service.clone();
    pin_add_then_rm(
        old_cid,
        new_cid,
        &remote.name,
        move |cid, name| {
            let add_url = add_url.clone();
            let add_service = add_service.clone();
            async move {
                crate::kubo::kubo::remote_pin_add_named(&add_url, &add_service, &cid, &name).await
            }
        },
        move |cid| {
            let rm_url = rm_url.clone();
            let rm_service = rm_service.clone();
            async move { crate::kubo::kubo::remote_pin_rm(&rm_url, &rm_service, &cid).await }
        },
    )
    .await
}
