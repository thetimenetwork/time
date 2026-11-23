//! Bitcoin-funded, account-bound, lazily claimed pro-rata issuance. Closing an
//! epoch touches one summary, never all bidders or the full account registry.
use crate::engine::ExtensionHost;
use crate::wire::SignedAction;
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const OPEN_KEY: &[u8] = b"auction/open";
pub fn epoch_key(epoch: u64) -> Vec<u8> {
    [b"auction/epoch/".as_slice(), &epoch.to_be_bytes()].concat()
}
pub fn bid_key(epoch: u64, owner: u64) -> Vec<u8> {
    [
        b"auction/bid/".as_slice(),
        &epoch.to_be_bytes(),
        &owner.to_be_bytes(),
    ]
    .concat()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    #[serde(with = "pos::decimal::u64")]
    pub epoch: u64,
    #[serde(with = "pos::decimal::u64")]
    pub total_sats: u64,
    #[serde(with = "pos::decimal::u64")]
    pub bidders: u64,
    #[serde(with = "pos::decimal::u64")]
    pub pot: u64,
    #[serde(with = "pos::decimal::u64")]
    pub paid: u64,
    #[serde(with = "pos::decimal::u64")]
    pub claims: u64,
    pub closed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bid {
    #[serde(with = "pos::decimal::u64")]
    pub owner: u64,
    #[serde(with = "pos::decimal::u64")]
    pub epoch: u64,
    #[serde(with = "pos::decimal::u64")]
    pub sats: u64,
    pub claimed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    epochs: Vec<String>,
}
fn read<T: DeserializeOwned>(host: &impl ExtensionHost, key: &[u8]) -> Result<Option<T>> {
    host.get(key)?
        .map(|raw| serde_json::from_slice(&raw).map_err(Into::into))
        .transpose()
}
fn write<T: Serialize>(host: &mut impl ExtensionHost, key: Vec<u8>, value: &T) -> Result<()> {
    host.put(key, Some(serde_json::to_vec(value)?))
}
fn open(host: &impl ExtensionHost) -> Result<Vec<u64>> {
    let row: Open = read(host, OPEN_KEY)?.ok_or_else(|| anyhow!("missing auction state"))?;
    let values = row
        .epochs
        .iter()
        .map(|v| {
            let n = v.parse::<u64>()?;
            ensure!(n.to_string() == *v, "noncanonical epoch");
            Ok(n)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        values.len() <= 48 && values.windows(2).all(|w| w[0] < w[1]),
        "invalid open auction index"
    );
    Ok(values)
}
fn save_open(host: &mut impl ExtensionHost, epochs: &[u64]) -> Result<()> {
    write(
        host,
        OPEN_KEY.to_vec(),
        &Open {
            epochs: epochs.iter().map(ToString::to_string).collect(),
        },
    )
}
pub fn initialize(host: &mut impl ExtensionHost) -> Result<()> {
    save_open(host, &[])
}
pub fn current_epoch(host: &impl ExtensionHost) -> Result<u64> {
    let period = host
        .meta()
        .config
        .auction
        .epoch_seconds
        .checked_mul(1_000_000)
        .ok_or_else(|| anyhow!("auction period overflow"))?;
    Ok(host.meta().elapsed_micros()? / period)
}
pub fn validate_target(host: &impl ExtensionHost, epoch: u64) -> Result<()> {
    let config = &host.meta().config.auction;
    let current = current_epoch(host)?;
    ensure!(
        epoch
            >= current
                .checked_add(config.bid_lead_epochs)
                .ok_or_else(|| anyhow!("epoch exhausted"))?
            && epoch
                <= current
                    .checked_add(config.max_future_epochs)
                    .ok_or_else(|| anyhow!("epoch exhausted"))?,
        "bid must target an allowed future earning epoch"
    );
    Ok(())
}
pub fn record_bid(host: &mut impl ExtensionHost, owner: u64, epoch: u64, sats: u64) -> Result<()> {
    validate_target(host, epoch)?;
    let config = &host.meta().config.auction;
    ensure!(
        (config.min_sats..=config.max_sats).contains(&sats),
        "Bitcoin bid amount outside bounds"
    );
    let _ = host.account(owner)?;
    let mut epochs = open(host)?;
    let mut summary: Epoch = read(host, &epoch_key(epoch))?.unwrap_or(Epoch {
        epoch,
        total_sats: 0,
        bidders: 0,
        pot: 0,
        paid: 0,
        claims: 0,
        closed: false,
    });
    ensure!(summary.epoch == epoch && !summary.closed, "auction closed");
    let old: Option<Bid> = read(host, &bid_key(epoch, owner))?;
    if old.is_none() {
        summary.bidders = summary
            .bidders
            .checked_add(1)
            .ok_or_else(|| anyhow!("bidder overflow"))?;
    }
    let mut bid = old.unwrap_or(Bid {
        owner,
        epoch,
        sats: 0,
        claimed: false,
    });
    ensure!(
        bid.owner == owner && bid.epoch == epoch && !bid.claimed,
        "invalid bid coordinates"
    );
    bid.sats = bid
        .sats
        .checked_add(sats)
        .ok_or_else(|| anyhow!("bid overflow"))?;
    summary.total_sats = summary
        .total_sats
        .checked_add(sats)
        .ok_or_else(|| anyhow!("epoch total overflow"))?;
    ensure!(
        summary.total_sats <= 2_100_000_000_000_000,
        "epoch exceeds Bitcoin supply"
    );
    if let Err(index) = epochs.binary_search(&epoch) {
        ensure!(epochs.len() < 48, "too many open auctions");
        epochs.insert(index, epoch);
    }
    write(host, epoch_key(epoch), &summary)?;
    write(host, bid_key(epoch, owner), &bid)?;
    save_open(host, &epochs)
}
pub fn epoch_budget(epoch: u64, period_micros: u64) -> Result<u64> {
    let start = u128::from(epoch) * u128::from(period_micros);
    let end = start + u128::from(period_micros);
    Ok(u64::try_from(end * 4 / 5 - start * 4 / 5)?)
}
pub fn begin_block(host: &mut impl ExtensionHost) -> Result<()> {
    let current = current_epoch(host)?;
    let mut epochs = open(host)?;
    let mut reserve = host.meta().auction_reserve_total;
    let period = host
        .meta()
        .config
        .auction
        .epoch_seconds
        .checked_mul(1_000_000)
        .ok_or_else(|| anyhow!("period overflow"))?;
    for epoch in epochs.iter().copied().take_while(|e| *e < current) {
        let mut row: Epoch =
            read(host, &epoch_key(epoch))?.ok_or_else(|| anyhow!("missing indexed auction"))?;
        ensure!(
            row.epoch == epoch && !row.closed && row.total_sats > 0 && row.bidders > 0,
            "invalid open auction"
        );
        row.pot = epoch_budget(epoch, period)?;
        row.closed = true;
        host.bank_debit(row.pot)?;
        reserve = reserve
            .checked_add(row.pot)
            .ok_or_else(|| anyhow!("auction reserve overflow"))?;
        write(host, epoch_key(epoch), &row)?;
    }
    epochs.retain(|e| *e >= current);
    host.set_auction_reserve(reserve)?;
    save_open(host, &epochs)
}
pub fn apply(host: &mut impl ExtensionHost, action: &SignedAction) -> Result<()> {
    ensure!(action.kind == 42, "unsupported auction action");
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Claim {
        #[serde(with = "pos::decimal::u64")]
        epoch: u64,
    }
    let claim: Claim = serde_json::from_value(action.payload.clone())?;
    let mut epoch: Epoch =
        read(host, &epoch_key(claim.epoch))?.ok_or_else(|| anyhow!("no earning epoch"))?;
    let mut bid: Bid = read(host, &bid_key(claim.epoch, action.from))?
        .ok_or_else(|| anyhow!("no account-bound Bitcoin bid"))?;
    ensure!(
        epoch.closed
            && epoch.epoch == claim.epoch
            && bid.epoch == claim.epoch
            && bid.owner == action.from
            && !bid.claimed,
        "earning is unavailable or already claimed"
    );
    ensure!(
        epoch.total_sats >= bid.sats && epoch.total_sats > 0,
        "invalid bid total"
    );
    let payout =
        u64::try_from(u128::from(epoch.pot) * u128::from(bid.sats) / u128::from(epoch.total_sats))?;
    epoch.paid = epoch
        .paid
        .checked_add(payout)
        .ok_or_else(|| anyhow!("payout overflow"))?;
    epoch.claims = epoch
        .claims
        .checked_add(1)
        .ok_or_else(|| anyhow!("claim overflow"))?;
    bid.claimed = true;
    ensure!(
        epoch.paid <= epoch.pot && epoch.claims <= epoch.bidders,
        "auction payout exceeds reserve"
    );
    let mut used = payout;
    if epoch.claims == epoch.bidders {
        let dust = epoch.pot - epoch.paid;
        host.bank_credit(dust)?;
        used = used
            .checked_add(dust)
            .ok_or_else(|| anyhow!("reserve overflow"))?;
    }
    host.set_auction_reserve(
        host.meta()
            .auction_reserve_total
            .checked_sub(used)
            .ok_or_else(|| anyhow!("reserve underflow"))?,
    )?;
    host.credit(action.from, payout)?;
    write(host, epoch_key(claim.epoch), &epoch)?;
    write(host, bid_key(claim.epoch, action.from), &bid)
}
/// Independent reserve and every bid/claim recount over a previously fully
/// authenticated immutable tree. No registry-sized in-memory accumulator.
pub fn audit(
    snapshot: &crate::store::VerifiedAudit<'_>,
    meta: &crate::engine::Meta,
) -> Result<u64> {
    use crate::engine::canonical_decode;
    let open: Open = canonical_decode(
        &snapshot
            .get(OPEN_KEY)?
            .ok_or_else(|| anyhow!("missing auction index"))?,
    )?;
    let indexed = open
        .epochs
        .iter()
        .map(|e| {
            let n = e.parse::<u64>()?;
            ensure!(n.to_string() == *e, "epoch encoding");
            Ok(n)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        indexed.len() <= 48 && indexed.windows(2).all(|w| w[0] < w[1]),
        "open epoch order/bound"
    );
    let mut reserve = 0u64;
    let mut leaves = 1u64;
    let mut open_count = 0usize;
    snapshot.for_each_prefix(b"auction/epoch/", |key, value| {
        let epoch: Epoch = canonical_decode(value)?;
        ensure!(key == epoch_key(epoch.epoch), "epoch key mismatch");
        let mut count = 0u64;
        let mut sats = 0u64;
        let mut claims = 0u64;
        let mut paid = 0u64;
        let prefix = [b"auction/bid/".as_slice(), &epoch.epoch.to_be_bytes()].concat();
        snapshot.for_each_prefix(&prefix, |key, value| {
            let bid: Bid = canonical_decode(value)?;
            ensure!(
                bid.epoch == epoch.epoch
                    && key == bid_key(bid.epoch, bid.owner)
                    && bid.sats > 0
                    && snapshot
                        .get(&crate::engine::account_key(bid.owner))?
                        .is_some(),
                "invalid bidder"
            );
            let mut btc_sats = 0u64;
            snapshot.for_each_prefix(
                &crate::bitcoin_adapter::credit_prefix(bid.epoch, bid.owner),
                |key, value| {
                    let outpoint: bitcoin_bridge::bitcoin::OutPoint = canonical_decode(value)?;
                    let receipt: bitcoin_bridge::AcceptedReceipt = canonical_decode(
                        &snapshot
                            .get(&crate::bitcoin_adapter::receipt_key(&outpoint))?
                            .ok_or_else(|| anyhow!("orphan Bitcoin credit"))?,
                    )?;
                    ensure!(
                        receipt.account == bid.owner
                            && receipt.auction_epoch == bid.epoch
                            && receipt.outpoint == outpoint
                            && key == crate::bitcoin_adapter::credit_key(&receipt),
                        "Bitcoin credit binding mismatch"
                    );
                    btc_sats = btc_sats
                        .checked_add(receipt.sats)
                        .ok_or_else(|| anyhow!("Bitcoin credit overflow"))?;
                    Ok(())
                },
            )?;
            ensure!(
                btc_sats == bid.sats,
                "bid differs from consumed Bitcoin credits"
            );
            sats = sats
                .checked_add(bid.sats)
                .ok_or_else(|| anyhow!("bid sum overflow"))?;
            count += 1;
            if bid.claimed {
                ensure!(epoch.closed && epoch.total_sats > 0, "claim on open epoch");
                claims += 1;
                paid = paid
                    .checked_add(u64::try_from(
                        u128::from(epoch.pot) * u128::from(bid.sats) / u128::from(epoch.total_sats),
                    )?)
                    .ok_or_else(|| anyhow!("paid sum overflow"))?;
            }
            leaves += 1;
            Ok(())
        })?;
        ensure!(
            sats == epoch.total_sats
                && sats > 0
                && count == epoch.bidders
                && claims == epoch.claims
                && paid == epoch.paid,
            "auction independent recount mismatch"
        );
        if epoch.closed {
            ensure!(
                !indexed.contains(&epoch.epoch)
                    && epoch.pot
                        == epoch_budget(
                            epoch.epoch,
                            meta.config.auction.epoch_seconds * 1_000_000
                        )?
                    && paid <= epoch.pot,
                "closed auction budget mismatch"
            );
            if claims < count {
                reserve = reserve
                    .checked_add(epoch.pot - paid)
                    .ok_or_else(|| anyhow!("reserve sum overflow"))?;
            }
        } else {
            ensure!(
                indexed.contains(&epoch.epoch) && epoch.pot == 0 && paid == 0 && claims == 0,
                "open auction mismatch"
            );
            open_count += 1;
        }
        leaves += 1;
        Ok(())
    })?;
    ensure!(
        reserve == meta.auction_reserve_total && open_count == indexed.len(),
        "auction reserve/index recount mismatch"
    );
    let mut actual = 0u64;
    snapshot.for_each_prefix(b"auction/", |_, _| {
        actual += 1;
        Ok(())
    })?;
    ensure!(leaves == actual, "orphan auction leaf");
    Ok(leaves)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn budget_is_exact_and_interval_independent() {
        for period in [1, 3, 1_000_000, 3_600_000_000] {
            let sum = (0..99)
                .map(|e| epoch_budget(e, period).unwrap() as u128)
                .sum::<u128>();
            assert_eq!(sum, u128::from(period) * 99 * 4 / 5);
        }
    }
}
