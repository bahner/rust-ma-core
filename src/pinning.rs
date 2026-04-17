//! Safe pin lifecycle management.
//!
//! [`pin_update_add_rm`] pins a new CID, then attempts to unpin the old
//! one, reporting any unpin failure as metadata rather than a hard error.

use std::future::Future;

use anyhow::Result;

#[derive(Debug, Default, Clone)]
pub struct PinUpdateOutcome {
    pub previous_unpin_error: Option<String>,
}

pub async fn pin_update_add_rm<FAdd, FRm, FutAdd, FutRm>(
    old_cid: Option<&str>,
    new_cid: &str,
    pin_name: &str,
    add_named: FAdd,
    remove_pin: FRm,
) -> Result<PinUpdateOutcome>
where
    FAdd: Fn(String, String) -> FutAdd,
    FRm: Fn(String) -> FutRm,
    FutAdd: Future<Output = Result<()>>,
    FutRm: Future<Output = Result<()>>,
{
    let Some(previous) = old_cid else {
        add_named(new_cid.to_string(), pin_name.to_string()).await?;
        return Ok(PinUpdateOutcome::default());
    };

    if previous == new_cid {
        return Ok(PinUpdateOutcome::default());
    }

    add_named(new_cid.to_string(), pin_name.to_string()).await?;

    let previous_unpin_error = remove_pin(previous.to_string())
        .await
        .err()
        .map(|err| err.to_string());

    Ok(PinUpdateOutcome {
        previous_unpin_error,
    })
}
