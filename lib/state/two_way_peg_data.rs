//! Connect and disconnect two-way peg data

use std::collections::{BTreeMap, HashMap};

use fallible_iterator::FallibleIterator;
use sneed::{RoTxn, RwTxn, db::error::Error as DbError};

use crate::parent_chain_rpc::{ParentChainRpcClient, RpcConfig};
use crate::{
    state::{
        Error, State, WITHDRAWAL_BUNDLE_FAILURE_GAP, WithdrawalBundleInfo,
        rollback::RollBack,
    },
    types::{
        AccumulatorDiff, AggregatedWithdrawal, AmountOverflowError, BlockHash,
        GetValue, InPoint, M6id, OutPoint, OutPointKey, Output, OutputContent,
        ParentChainType, PointedOutput, PointedOutputRef, SpentOutput, Swap,
        SwapId, SwapState, SwapTxId, WithdrawalBundle, WithdrawalBundleEvent,
        WithdrawalBundleStatus, hash,
        proto::mainchain::{BlockEvent, TwoWayPegData},
    },
    wallet::Wallet,
};

fn collect_withdrawal_bundle(
    state: &State,
    rotxn: &RoTxn,
    block_height: u32,
) -> Result<Option<WithdrawalBundle>, Error> {
    // Weight of a bundle with 0 outputs.
    const BUNDLE_0_WEIGHT: u64 = 504;
    // Weight of a single output.
    const OUTPUT_WEIGHT: u64 = 128;
    // Turns out to be 3121.
    const MAX_BUNDLE_OUTPUTS: usize =
        ((bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64 - BUNDLE_0_WEIGHT)
            / OUTPUT_WEIGHT) as usize;

    // Aggregate all outputs by destination.
    // destination -> (value, mainchain fee, spent_utxos)
    let mut address_to_aggregated_withdrawal = HashMap::<
        bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        AggregatedWithdrawal,
    >::new();
    let () = state
        .utxos
        .iter(rotxn)
        .map_err(DbError::from)?
        .map_err(|err| DbError::from(err).into())
        .for_each(|(outpoint_key, output)| {
            let outpoint: OutPoint = outpoint_key.into();
            if let OutputContent::Withdrawal {
                value,
                ref main_address,
                main_fee,
            } = output.content
            {
                let aggregated = address_to_aggregated_withdrawal
                    .entry(main_address.clone())
                    .or_insert(AggregatedWithdrawal {
                        spend_utxos: HashMap::new(),
                        main_address: main_address.clone(),
                        value: bitcoin::Amount::ZERO,
                        main_fee: bitcoin::Amount::ZERO,
                    });
                // Add up all values.
                aggregated.value = aggregated
                    .value
                    .checked_add(value)
                    .ok_or(AmountOverflowError)?;
                aggregated.main_fee = aggregated
                    .main_fee
                    .checked_add(main_fee)
                    .ok_or(AmountOverflowError)?;
                aggregated.spend_utxos.insert(outpoint, output);
            }
            Ok::<_, Error>(())
        })?;
    if address_to_aggregated_withdrawal.is_empty() {
        return Ok(None);
    }
    let mut aggregated_withdrawals: Vec<_> =
        address_to_aggregated_withdrawal.into_values().collect();
    aggregated_withdrawals.sort_by_key(|a| std::cmp::Reverse(a.clone()));
    let mut fee = bitcoin::Amount::ZERO;
    let mut spend_utxos = BTreeMap::<OutPoint, Output>::new();
    let mut bundle_outputs = Vec::with_capacity(MAX_BUNDLE_OUTPUTS);
    for aggregated in &aggregated_withdrawals {
        if bundle_outputs.len() > MAX_BUNDLE_OUTPUTS {
            break;
        }
        let bundle_output = bitcoin::TxOut {
            value: aggregated.value,
            script_pubkey: aggregated
                .main_address
                .assume_checked_ref()
                .script_pubkey(),
        };
        spend_utxos.extend(aggregated.spend_utxos.clone());
        bundle_outputs.push(bundle_output);
        fee += aggregated.main_fee;
    }
    let bundle =
        WithdrawalBundle::new(block_height, fee, spend_utxos, bundle_outputs)?;
    Ok(Some(bundle))
}

fn connect_withdrawal_bundle_submitted(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    event_block_hash: &bitcoin::BlockHash,
    m6id: M6id,
) -> Result<(), Error> {
    if let Some((bundle, bundle_block_height)) = state
        .pending_withdrawal_bundle
        .try_get(rwtxn, &())
        .map_err(DbError::from)?
        && bundle.compute_m6id() == m6id
    {
        assert_eq!(bundle_block_height, block_height - 1);

        // Calculate total withdrawal amount from bundle outputs
        let total_withdrawal_value: bitcoin::Amount = bundle
            .tx()
            .output
            .iter()
            .skip(2) // Skip mainchain_fee_txout and inputs_commitment_txout
            .map(|txout| txout.value)
            .sum();

        // Calculate total value being withdrawn from spend_utxos
        let total_spent_value: bitcoin::Amount = bundle
            .spend_utxos()
            .values()
            .map(|output| GetValue::get_value(&output.content))
            .sum();

        let output_count = bundle.tx().output.len().saturating_sub(2);

        tracing::info!(
            %block_height,
            %event_block_hash,
            %m6id,
            total_withdrawal_btc = %total_withdrawal_value.to_string_in(bitcoin::Denomination::Bitcoin),
            total_withdrawal_sats = %total_withdrawal_value.to_sat(),
            total_spent_btc = %total_spent_value.to_string_in(bitcoin::Denomination::Bitcoin),
            total_spent_sats = %total_spent_value.to_sat(),
            output_count = output_count,
            "Withdrawal bundle submitted to parent chain"
        );

        tracing::debug!(
            %block_height,
            %m6id,
            "Withdrawal bundle successfully submitted"
        );
        for (outpoint, spend_output) in bundle.spend_utxos() {
            let utxo_hash = hash(&PointedOutputRef {
                outpoint: *outpoint,
                output: spend_output,
            });
            accumulator_diff.remove(utxo_hash.into());
            let key = OutPointKey::from(outpoint);
            state.utxos.delete(rwtxn, &key).map_err(DbError::from)?;
            let spent_output = SpentOutput {
                output: spend_output.clone(),
                inpoint: InPoint::Withdrawal { m6id },
            };
            state
                .stxos
                .put(rwtxn, &key, &spent_output)
                .map_err(DbError::from)?;
        }
        state
            .withdrawal_bundles
            .put(
                rwtxn,
                &m6id,
                &(
                    WithdrawalBundleInfo::Known(bundle),
                    RollBack::new(
                        WithdrawalBundleStatus::Submitted,
                        block_height,
                    ),
                ),
            )
            .map_err(DbError::from)?;
        state
            .pending_withdrawal_bundle
            .delete(rwtxn, &())
            .map_err(DbError::from)?;
    } else if let Some((_bundle, bundle_status)) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)
        .map_err(DbError::from)?
    {
        // Already applied
        assert_eq!(
            bundle_status.earliest().value,
            WithdrawalBundleStatus::Submitted
        );
    } else {
        tracing::warn!(
            %event_block_hash,
            %m6id,
            "Unknown withdrawal bundle submitted"
        );
        state
            .withdrawal_bundles
            .put(
                rwtxn,
                &m6id,
                &(
                    WithdrawalBundleInfo::Unknown,
                    RollBack::new(
                        WithdrawalBundleStatus::Submitted,
                        block_height,
                    ),
                ),
            )
            .map_err(DbError::from)?;
    };
    Ok(())
}

fn connect_withdrawal_bundle_confirmed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    event_block_hash: &bitcoin::BlockHash,
    m6id: M6id,
) -> Result<(), Error> {
    let (mut bundle, mut bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)
        .map_err(DbError::from)?
        .ok_or(Error::UnknownWithdrawalBundle { m6id })?;
    if bundle_status.latest().value == WithdrawalBundleStatus::Confirmed {
        // Already applied
        return Ok(());
    }
    assert_eq!(
        bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
    );

    // Log withdrawal bundle confirmation
    match &bundle {
        WithdrawalBundleInfo::Known(bundle) => {
            let total_withdrawal_value: bitcoin::Amount = bundle
                .tx()
                .output
                .iter()
                .skip(2) // Skip mainchain_fee_txout and inputs_commitment_txout
                .map(|txout| txout.value)
                .sum();

            let output_count = bundle.tx().output.len().saturating_sub(2);

            tracing::info!(
                %block_height,
                %event_block_hash,
                %m6id,
                total_withdrawal_btc = %total_withdrawal_value.to_string_in(bitcoin::Denomination::Bitcoin),
                total_withdrawal_sats = %total_withdrawal_value.to_sat(),
                output_count = output_count,
                "Withdrawal bundle confirmed on parent chain"
            );
        }
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => {
            tracing::info!(
                %block_height,
                %event_block_hash,
                %m6id,
                "Unknown withdrawal bundle confirmed on parent chain"
            );
        }
    }
    // If an unknown bundle is confirmed, all UTXOs older than the
    // bundle submission are potentially spent.
    // This is only accepted in the case that block height is 0,
    // and so no UTXOs could possibly have been double-spent yet.
    // In this case, ALL UTXOs are considered spent.
    if !bundle.is_known() {
        if block_height == 0 {
            tracing::warn!(
                %event_block_hash,
                %m6id,
                "Unknown withdrawal bundle confirmed, marking all UTXOs as spent"
            );
            let utxos: BTreeMap<OutPoint, Output> = state
                .utxos
                .iter(rwtxn)
                .map_err(DbError::from)?
                .map(|(key, output)| Ok((key.into(), output)))
                .collect()
                .map_err(DbError::from)?;
            for (outpoint, output) in &utxos {
                let spent_output = SpentOutput {
                    output: output.clone(),
                    inpoint: InPoint::Withdrawal { m6id },
                };
                state
                    .stxos
                    .put(rwtxn, &OutPointKey::from(outpoint), &spent_output)
                    .map_err(DbError::from)?;
                let utxo_hash = hash(&PointedOutputRef {
                    outpoint: *outpoint,
                    output: &spent_output.output,
                });
                accumulator_diff.remove(utxo_hash.into());
            }
            state.utxos.clear(rwtxn).map_err(DbError::from)?;
            bundle =
                WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: utxos };
        } else {
            return Err(Error::UnknownWithdrawalBundleConfirmed {
                event_block_hash: *event_block_hash,
                m6id,
            });
        }
    }
    bundle_status
        .push(WithdrawalBundleStatus::Confirmed, block_height)
        .expect("Push confirmed status should be valid");
    state
        .withdrawal_bundles
        .put(rwtxn, &m6id, &(bundle, bundle_status))
        .map_err(DbError::from)?;
    Ok(())
}

fn connect_withdrawal_bundle_failed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    m6id: M6id,
) -> Result<(), Error> {
    let (bundle, mut bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)
        .map_err(DbError::from)?
        .ok_or_else(|| Error::UnknownWithdrawalBundle { m6id })?;
    if bundle_status.latest().value == WithdrawalBundleStatus::Failed {
        // Already applied
        return Ok(());
    }
    assert_eq!(
        bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
    );

    // Log withdrawal bundle failure
    match &bundle {
        WithdrawalBundleInfo::Known(bundle) => {
            let total_withdrawal_value: bitcoin::Amount = bundle
                .tx()
                .output
                .iter()
                .skip(2) // Skip mainchain_fee_txout and inputs_commitment_txout
                .map(|txout| txout.value)
                .sum();

            let output_count = bundle.tx().output.len().saturating_sub(2);

            tracing::warn!(
                %block_height,
                %m6id,
                total_withdrawal_btc = %total_withdrawal_value.to_string_in(bitcoin::Denomination::Bitcoin),
                total_withdrawal_sats = %total_withdrawal_value.to_sat(),
                output_count = output_count,
                "Withdrawal bundle failed on parent chain"
            );
        }
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => {
            tracing::warn!(
                %block_height,
                %m6id,
                "Unknown withdrawal bundle failed on parent chain"
            );
        }
    }

    tracing::debug!(
        %block_height,
        %m6id,
        "Handling failed withdrawal bundle");
    bundle_status
        .push(WithdrawalBundleStatus::Failed, block_height)
        .expect("Push failed status should be valid");
    match &bundle {
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => (),
        WithdrawalBundleInfo::Known(bundle) => {
            for (outpoint, output) in bundle.spend_utxos() {
                let key = OutPointKey::from(outpoint);
                state.stxos.delete(rwtxn, &key).map_err(DbError::from)?;
                state
                    .utxos
                    .put(rwtxn, &key, output)
                    .map_err(DbError::from)?;
                let utxo_hash = hash(&PointedOutput {
                    outpoint: *outpoint,
                    output: output.clone(),
                });
                accumulator_diff.insert(utxo_hash.into());
            }
            let latest_failed_m6id = if let Some(mut latest_failed_m6id) = state
                .latest_failed_withdrawal_bundle
                .try_get(rwtxn, &())
                .map_err(DbError::from)?
            {
                latest_failed_m6id
                    .push(m6id, block_height)
                    .expect("Push latest failed m6id should be valid");
                latest_failed_m6id
            } else {
                RollBack::new(m6id, block_height)
            };
            state
                .latest_failed_withdrawal_bundle
                .put(rwtxn, &(), &latest_failed_m6id)
                .map_err(DbError::from)?;
        }
    }
    state
        .withdrawal_bundles
        .put(rwtxn, &m6id, &(bundle, bundle_status))
        .map_err(DbError::from)?;
    Ok(())
}

fn connect_withdrawal_bundle_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    event_block_hash: &bitcoin::BlockHash,
    event: &WithdrawalBundleEvent,
) -> Result<(), Error> {
    match event.status {
        WithdrawalBundleStatus::Submitted => {
            connect_withdrawal_bundle_submitted(
                state,
                rwtxn,
                block_height,
                accumulator_diff,
                event_block_hash,
                event.m6id,
            )
        }
        WithdrawalBundleStatus::Confirmed => {
            connect_withdrawal_bundle_confirmed(
                state,
                rwtxn,
                block_height,
                accumulator_diff,
                event_block_hash,
                event.m6id,
            )
        }
        WithdrawalBundleStatus::Failed => connect_withdrawal_bundle_failed(
            state,
            rwtxn,
            block_height,
            accumulator_diff,
            event.m6id,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn connect_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    latest_deposit_block_hash: &mut Option<bitcoin::BlockHash>,
    latest_withdrawal_bundle_event_block_hash: &mut Option<bitcoin::BlockHash>,
    event_block_hash: bitcoin::BlockHash,
    event: &BlockEvent,
    _wallet: Option<&Wallet>,
) -> Result<(), Error> {
    match event {
        BlockEvent::Deposit(deposit) => {
            let outpoint = OutPoint::Deposit(deposit.outpoint);
            let output = &deposit.output;

            // Extract value and address for logging
            let value = output.content.get_value();
            let address = output.address;

            tracing::info!(
                %block_height,
                %event_block_hash,
                outpoint = %outpoint,
                address = %address,
                amount_btc = %value.to_string_in(bitcoin::Denomination::Bitcoin),
                amount_sats = %value.to_sat(),
                "Deposit from parent chain received"
            );

            state
                .utxos
                .put(rwtxn, &OutPointKey::from(&outpoint), output)
                .map_err(DbError::from)?;
            let utxo_hash = hash(&PointedOutputRef { outpoint, output });
            accumulator_diff.insert(utxo_hash.into());
            *latest_deposit_block_hash = Some(event_block_hash);
        }
        BlockEvent::WithdrawalBundle(withdrawal_bundle_event) => {
            let () = connect_withdrawal_bundle_event(
                state,
                rwtxn,
                block_height,
                accumulator_diff,
                &event_block_hash,
                withdrawal_bundle_event,
            )?;
            *latest_withdrawal_bundle_event_block_hash = Some(event_block_hash);
        }
    }
    Ok(())
}

/// Process coinshift transactions - update swap states based on L1 transactions
/// This should be called when connecting 2WPD to check for L1 transactions
/// that match pending swaps.
///
/// IMPORTANT: This queries the SWAP TARGET CHAIN (e.g., Signet), NOT the sidechain's
/// mainchain (e.g., Regtest). The swap target chain is specified in swap.parent_chain.
///
/// Flow:
/// 1. Get all pending swaps
/// 2. For each swap, query swap.parent_chain (e.g., Signet) for transactions
/// 3. Match transactions by: l1_recipient_address and l1_amount
/// 4. Update swap state based on found transactions and confirmations
///
/// **BMM / header chain / merkle proof:** None of these are used for swap L1
/// verification in this repo. L1 presence and confirmations are taken from the
/// configured parent chain RPC only (no BMM reports, no per–parent-chain header
/// chain for swaps, no merkle proof of L1 tx in block).
///
/// Query L1 blockchain for matching transactions and update swap.
///
/// `block_hash` and `block_height` are the sidechain block where this
/// validation occurs.
///
/// Enforces L1 transaction uniqueness: the same (parent_chain, l1_txid) must
/// not be associated with more than one swap. Uses `get_swap_by_l1_txid` before
/// accepting a new L1 tx.
#[allow(clippy::too_many_arguments)]
fn query_and_update_swap(
    state: &State,
    rwtxn: &mut RwTxn,
    rpc_config: &RpcConfig,
    swap: &mut Swap,
    l1_recipient: &str,
    l1_amount: bitcoin::Amount,
    block_hash: BlockHash,
    block_height: u32,
) -> Result<bool, Error> {
    let client = ParentChainRpcClient::new(rpc_config.clone());
    let amount_sats = l1_amount.to_sat();

    // Find transactions matching address and amount
    let matches = client
        .find_transactions_by_address_and_amount(l1_recipient, amount_sats)?;

    if matches.is_empty() {
        return Ok(false);
    }

    // Only accept transactions that are confirmed and included in a block,
    // and not older than the chain's max L1 tx age
    let max_age = swap.parent_chain.max_l1_tx_age_blocks();
    let matches: Vec<_> = matches
        .into_iter()
        .filter(|(_, tx_info)| {
            if tx_info.confirmations == 0 || tx_info.blockheight.is_none() {
                return false;
            }
            if tx_info.confirmations > max_age {
                tracing::info!(
                    swap_id = %swap.id,
                    l1_txid = %tx_info.txid,
                    confirmations = %tx_info.confirmations,
                    max_age = %max_age,
                    "Rejecting L1 tx: too old (confirmations exceed max_l1_tx_age_blocks)"
                );
                return false;
            }
            true
        })
        .collect();
    if matches.is_empty() {
        tracing::debug!(
            swap_id = %swap.id,
            "No confirmed or block-included L1 match; rejecting unconfirmed, mempool-only, or too-old tx"
        );
        return Ok(false);
    }

    // Use the first valid match (most recent transaction)
    // In a production system, you might want to handle multiple matches differently
    let (sender_address, tx_info) = &matches[0];

    // Convert txid string from parent chain RPC (RPC byte order) to SwapTxId (canonical storage)
    let l1_txid = SwapTxId::from_hex_rpc(&tx_info.txid)
        .map_err(|_| crate::parent_chain_rpc::Error::InvalidResponse)?;

    // Check if this is an update or new detection
    let zero_hash32 = [0u8; 32];
    let is_new = matches!(swap.l1_txid, SwapTxId::Hash32(h) if h == zero_hash32)
        || matches!(swap.l1_txid, SwapTxId::Hash(ref v) if v.is_empty() || v.iter().all(|&b| b == 0));

    if is_new {
        // L1 transaction uniqueness: do not accept an L1 tx already used by another swap
        if let Some(existing) =
            state.get_swap_by_l1_txid(rwtxn, &swap.parent_chain, &l1_txid)?
            && existing.id != swap.id
        {
            tracing::info!(
                swap_id = %swap.id,
                existing_swap_id = %existing.id,
                l1_txid = %tx_info.txid,
                "Rejecting L1 tx already associated with another swap"
            );
            return Ok(false);
        }

        // New L1 transaction detected
        tracing::info!(
            swap_id = %swap.id,
            l1_txid = %tx_info.txid,
            confirmations = %tx_info.confirmations,
            sender = %sender_address,
            is_open_swap = %swap.l2_recipient.is_none(),
            "Detected new L1 transaction for swap"
        );

        // Update swap with L1 transaction
        // For open swaps, we don't store the sender address here - the claimer will provide
        // their L2 address when claiming, and we'll verify they sent the L1 transaction
        swap.update_l1_txid(l1_txid);

        // Save the sidechain block reference where this validation occurred
        swap.set_l1_txid_validation_block(block_hash, block_height);

        // Update state based on confirmations
        if tx_info.confirmations >= swap.required_confirmations {
            swap.state = SwapState::ReadyToClaim;
        } else {
            swap.state = SwapState::WaitingConfirmations(
                tx_info.confirmations,
                swap.required_confirmations,
            );
        }

        Ok(true)
    } else {
        // Update confirmations for existing transaction
        let current_confirmations = match swap.state {
            SwapState::WaitingConfirmations(current, _) => current,
            _ => 0,
        };

        if tx_info.confirmations > current_confirmations {
            tracing::debug!(
                swap_id = %swap.id,
                old_confirmations = %current_confirmations,
                new_confirmations = %tx_info.confirmations,
                "Updating swap confirmations"
            );

            if tx_info.confirmations >= swap.required_confirmations {
                swap.state = SwapState::ReadyToClaim;
            } else {
                swap.state = SwapState::WaitingConfirmations(
                    tx_info.confirmations,
                    swap.required_confirmations,
                );
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn process_coinshift_transactions(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    block_hash: BlockHash,
    rpc_config_getter: Option<&dyn Fn(ParentChainType) -> Option<RpcConfig>>,
) -> Result<(), Error> {
    tracing::debug!(%block_height, "Starting to scan enforcer for coinshift transactions");

    // Get all pending swaps
    let swaps = state.load_all_swaps(rwtxn)?;
    let total_swaps_count = swaps.len();
    tracing::debug!(
        %block_height,
        swap_count = total_swaps_count,
        "Loaded swaps from state, scanning enforcer for matching transactions"
    );

    let mut pending_swaps_count = 0;
    let mut expired_swaps_count = 0;
    let mut scanned_swaps_count = 0;

    for mut swap in swaps {
        // Only process L2 → L1 swaps that are pending or waiting for confirmations
        if !matches!(
            swap.state,
            SwapState::Pending | SwapState::WaitingConfirmations(..)
        ) {
            continue;
        }

        pending_swaps_count += 1;
        let l1_amount_str = swap
            .l1_amount
            .map(|amt| amt.to_string_in(bitcoin::Denomination::Bitcoin))
            .unwrap_or_else(|| "N/A".to_string());
        let l1_amount_sats =
            swap.l1_amount.map(|amt| amt.to_sat()).unwrap_or(0);
        tracing::debug!(
            swap_id = %swap.id,
            parent_chain = ?swap.parent_chain,
            l1_recipient_address = ?swap.l1_recipient_address,
            l1_amount_btc = %l1_amount_str,
            l1_amount_sats = %l1_amount_sats,
            swap_state = ?swap.state,
            "Checking swap for matching L1 transactions"
        );

        // Check if swap has expired
        if let Some(expires_at) = swap.expires_at_height
            && block_height >= expires_at
        {
            // Unlock all outputs locked to this swap so the creator can spend them again
            let mut unlocked_count = 0u32;
            let locked_outputs: Vec<(OutPointKey, SwapId)> = state
                .locked_swap_outputs
                .iter(rwtxn)
                .map_err(DbError::from)?
                .map(|(key, sid)| Ok((key, sid)))
                .collect()?;
            for (outpoint_key, locked_swap_id) in locked_outputs {
                if locked_swap_id == swap.id {
                    let outpoint: OutPoint = outpoint_key.into();
                    state.unlock_output_from_swap(rwtxn, &outpoint)?;
                    unlocked_count += 1;
                }
            }

            tracing::info!(
                swap_id = %swap.id,
                block_height = %block_height,
                expires_at = %expires_at,
                unlocked_outputs = %unlocked_count,
                "Swap expired, unlocking outputs and marking as cancelled"
            );
            swap.state = SwapState::Cancelled;
            state.save_swap(rwtxn, &swap)?;
            expired_swaps_count += 1;
            continue;
        }

        // For L2 → L1 swaps, we need to check if the L1 transaction exists
        // on the SWAP TARGET CHAIN (swap.parent_chain), NOT the sidechain's mainchain.
        //
        // Example:
        // - Sidechain mainchain: Regtest (for deposits/withdrawals)
        // - Swap target: Signet (for coinshift transactions)
        // - We query Signet for transactions, not Regtest!
        //
        let l1_recipient_str =
            swap.l1_recipient_address.as_deref().unwrap_or("N/A");
        let l1_amount_str = swap
            .l1_amount
            .map(|amt| amt.to_string_in(bitcoin::Denomination::Bitcoin))
            .unwrap_or_else(|| "N/A".to_string());
        let l1_amount_sats =
            swap.l1_amount.map(|amt| amt.to_sat()).unwrap_or(0);
        tracing::debug!(
            swap_id = %swap.id,
            parent_chain = ?swap.parent_chain,
            l1_recipient_address = ?swap.l1_recipient_address,
            l1_amount_btc = %l1_amount_str,
            l1_amount_sats = %l1_amount_sats,
            "Scanning enforcer on {:?} for transactions to {} with amount {} BTC",
            swap.parent_chain,
            l1_recipient_str,
            l1_amount_str
        );

        // Swap L1 presence and confirmation count rely on the configured RPC for
        // the swap target chain (swap.parent_chain). If no RPC is configured here,
        // we skip L1 lookup and the swap stays Pending until RPC is set or the user
        // manually updates via update_swap_l1_txid.
        // Query L1 blockchain for matching transactions if RPC config is available.
        // URL is chosen by swap.parent_chain: we look up that chain in l1_rpc_configs.json.
        // If no RPC config exists for this chain, we skip L1 lookup and the swap stays
        // Pending until config is set or the user updates via update_swap_l1_txid.
        let l1_recipient_clone = swap.l1_recipient_address.clone();
        let l1_amount_clone = swap.l1_amount;
        let parent_chain_clone = swap.parent_chain;
        if let (Some(l1_recipient), Some(l1_amount)) =
            (l1_recipient_clone.as_deref(), l1_amount_clone)
            && let Some(get_rpc_config) = rpc_config_getter
            && let Some(rpc_config) = get_rpc_config(parent_chain_clone)
        {
            tracing::info!(
                swap_id = %swap.id,
                parent_chain = ?parent_chain_clone,
                l1_recipient = %l1_recipient,
                l1_amount_sats = %l1_amount.to_sat(),
                url = %rpc_config.url,
                "Querying L1 for swap"
            );
            match query_and_update_swap(
                state,
                rwtxn,
                &rpc_config,
                &mut swap,
                l1_recipient,
                l1_amount,
                block_hash,
                block_height,
            ) {
                Ok(updated) => {
                    if updated {
                        tracing::info!(
                            swap_id = %swap.id,
                            l1_txid = ?swap.l1_txid,
                            state = ?swap.state,
                            "Updated swap with L1 transaction"
                        );
                        state.save_swap(rwtxn, &swap)?;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        swap_id = %swap.id,
                        parent_chain = ?parent_chain_clone,
                        l1_recipient = %l1_recipient,
                        url = %rpc_config.url,
                        error = %e,
                        "Failed to query L1 for swap; swap will stay pending until RPC succeeds or l1_txid is set manually"
                    );
                }
            }
        } else if l1_recipient_clone.is_some() && l1_amount_clone.is_some() {
            tracing::debug!(
                swap_id = %swap.id,
                parent_chain = ?parent_chain_clone,
                "Skipping L1 lookup: no RPC config for this parent chain (swap stays Pending until config is set or l1_txid is set manually)"
            );
        }

        scanned_swaps_count += 1;
    }

    tracing::debug!(
        %block_height,
        total_swaps = total_swaps_count,
        pending_swaps = pending_swaps_count,
        expired_swaps = expired_swaps_count,
        scanned_swaps = scanned_swaps_count,
        "Finished scanning enforcer for coinshift transactions"
    );

    Ok(())
}

pub fn connect(
    state: &State,
    rwtxn: &mut RwTxn,
    two_way_peg_data: &TwoWayPegData,
    rpc_config_getter: Option<&dyn Fn(ParentChainType) -> Option<RpcConfig>>,
    wallet: Option<&Wallet>,
) -> Result<(), Error> {
    let block_height = state.try_get_height(rwtxn)?.ok_or(Error::NoTip)?;
    tracing::trace!(%block_height, "Connecting 2WPD...");
    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rwtxn, &())
        .map_err(DbError::from)?
        .unwrap_or_default();
    let mut accumulator_diff = AccumulatorDiff::default();
    let mut latest_deposit_block_hash = None;
    let mut latest_withdrawal_bundle_event_block_hash = None;
    for (event_block_hash, event_block_info) in &two_way_peg_data.block_info {
        for event in &event_block_info.events {
            let () = connect_event(
                state,
                rwtxn,
                block_height,
                &mut accumulator_diff,
                &mut latest_deposit_block_hash,
                &mut latest_withdrawal_bundle_event_block_hash,
                *event_block_hash,
                event,
                wallet,
            )?;
        }
    }

    // Process coinshift transactions after processing deposits/withdrawals
    let block_hash = state.try_get_tip(rwtxn)?.ok_or(Error::NoTip)?;
    process_coinshift_transactions(
        state,
        rwtxn,
        block_height,
        block_hash,
        rpc_config_getter,
    )?;
    // Handle deposits.
    if let Some(latest_deposit_block_hash) = latest_deposit_block_hash {
        let deposit_block_seq_idx = state
            .deposit_blocks
            .last(rwtxn)
            .map_err(DbError::from)?
            .map_or(0, |(seq_idx, _)| seq_idx + 1);
        state
            .deposit_blocks
            .put(
                rwtxn,
                &deposit_block_seq_idx,
                &(latest_deposit_block_hash, block_height),
            )
            .map_err(DbError::from)?;
    }
    // Handle withdrawals
    if let Some(latest_withdrawal_bundle_event_block_hash) =
        latest_withdrawal_bundle_event_block_hash
    {
        let withdrawal_bundle_event_block_seq_idx = state
            .withdrawal_bundle_event_blocks
            .last(rwtxn)
            .map_err(DbError::from)?
            .map_or(0, |(seq_idx, _)| seq_idx + 1);
        state
            .withdrawal_bundle_event_blocks
            .put(
                rwtxn,
                &withdrawal_bundle_event_block_seq_idx,
                &(latest_withdrawal_bundle_event_block_hash, block_height),
            )
            .map_err(DbError::from)?;
    }
    let last_withdrawal_bundle_failure_height = state
        .get_latest_failed_withdrawal_bundle(rwtxn)
        .map_err(DbError::from)?
        .map(|(height, _bundle)| height)
        .unwrap_or_default();
    if block_height - last_withdrawal_bundle_failure_height
        >= WITHDRAWAL_BUNDLE_FAILURE_GAP
        && state
            .pending_withdrawal_bundle
            .try_get(rwtxn, &())
            .map_err(DbError::from)?
            .is_none()
        && let Some(bundle) =
            collect_withdrawal_bundle(state, rwtxn, block_height)?
    {
        let m6id = bundle.compute_m6id();
        state
            .pending_withdrawal_bundle
            .put(rwtxn, &(), &(bundle, block_height))
            .map_err(DbError::from)?;
        tracing::trace!(
            %block_height,
            %m6id,
            "Stored pending withdrawal bundle"
        );
    }
    let () = accumulator.apply_diff(accumulator_diff)?;
    state
        .utreexo_accumulator
        .put(rwtxn, &(), &accumulator)
        .map_err(DbError::from)?;
    Ok(())
}

fn disconnect_withdrawal_bundle_submitted(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    m6id: M6id,
) -> Result<(), Error> {
    let Some((bundle, bundle_status)) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)
        .map_err(DbError::from)?
    else {
        if let Some((bundle, _)) = state
            .pending_withdrawal_bundle
            .try_get(rwtxn, &())
            .map_err(DbError::from)?
            && bundle.compute_m6id() == m6id
        {
            // Already applied
            return Ok(());
        } else {
            return Err(Error::UnknownWithdrawalBundle { m6id });
        }
    };
    let bundle_status = bundle_status.latest();
    assert_eq!(bundle_status.value, WithdrawalBundleStatus::Submitted);
    assert_eq!(bundle_status.height, block_height);
    match bundle {
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => (),
        WithdrawalBundleInfo::Known(bundle) => {
            for (outpoint, output) in bundle.spend_utxos().iter().rev() {
                if !state
                    .stxos
                    .delete(rwtxn, &OutPointKey::from(outpoint))
                    .map_err(DbError::from)?
                {
                    return Err(Error::NoStxo {
                        outpoint: *outpoint,
                    });
                };
                state
                    .utxos
                    .put(rwtxn, &OutPointKey::from(outpoint), output)
                    .map_err(DbError::from)?;
                let utxo_hash = hash(&PointedOutput {
                    outpoint: *outpoint,
                    output: output.clone(),
                });
                accumulator_diff.insert(utxo_hash.into());
            }
            state
                .pending_withdrawal_bundle
                .put(rwtxn, &(), &(bundle, bundle_status.height - 1))
                .map_err(DbError::from)?;
        }
    }
    state
        .withdrawal_bundles
        .delete(rwtxn, &m6id)
        .map_err(DbError::from)?;
    Ok(())
}

fn disconnect_withdrawal_bundle_confirmed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    m6id: M6id,
) -> Result<(), Error> {
    let (mut bundle, bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)
        .map_err(DbError::from)?
        .ok_or_else(|| Error::UnknownWithdrawalBundle { m6id })?;
    let (prev_bundle_status, latest_bundle_status) = bundle_status.pop();
    if latest_bundle_status.value == WithdrawalBundleStatus::Submitted {
        // Already applied
        return Ok(());
    }
    assert_eq!(
        latest_bundle_status.value,
        WithdrawalBundleStatus::Confirmed
    );
    assert_eq!(latest_bundle_status.height, block_height);
    let prev_bundle_status = prev_bundle_status
        .expect("Pop confirmed bundle status should be valid");
    assert_eq!(
        prev_bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
    );
    match bundle {
        WithdrawalBundleInfo::Known(_) | WithdrawalBundleInfo::Unknown => (),
        WithdrawalBundleInfo::UnknownConfirmed { spend_utxos } => {
            for (outpoint, output) in spend_utxos {
                state
                    .utxos
                    .put(rwtxn, &OutPointKey::from(&outpoint), &output)
                    .map_err(DbError::from)?;
                if !state
                    .stxos
                    .delete(rwtxn, &OutPointKey::from(&outpoint))
                    .map_err(DbError::from)?
                {
                    return Err(Error::NoStxo { outpoint });
                };
                let utxo_hash = hash(&PointedOutput { outpoint, output });
                accumulator_diff.insert(utxo_hash.into());
            }
            bundle = WithdrawalBundleInfo::Unknown;
        }
    }
    state
        .withdrawal_bundles
        .put(rwtxn, &m6id, &(bundle, prev_bundle_status))
        .map_err(DbError::from)?;
    Ok(())
}

fn disconnect_withdrawal_bundle_failed(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    m6id: M6id,
) -> Result<(), Error> {
    let (bundle, bundle_status) = state
        .withdrawal_bundles
        .try_get(rwtxn, &m6id)
        .map_err(DbError::from)?
        .ok_or_else(|| Error::UnknownWithdrawalBundle { m6id })?;
    let (prev_bundle_status, latest_bundle_status) = bundle_status.pop();
    if latest_bundle_status.value == WithdrawalBundleStatus::Submitted {
        // Already applied
        return Ok(());
    } else {
        assert_eq!(latest_bundle_status.value, WithdrawalBundleStatus::Failed);
    }
    assert_eq!(latest_bundle_status.height, block_height);
    let prev_bundle_status =
        prev_bundle_status.expect("Pop failed bundle status should be valid");
    assert_eq!(
        prev_bundle_status.latest().value,
        WithdrawalBundleStatus::Submitted
    );
    match &bundle {
        WithdrawalBundleInfo::Unknown
        | WithdrawalBundleInfo::UnknownConfirmed { .. } => (),
        WithdrawalBundleInfo::Known(bundle) => {
            for (outpoint, output) in bundle.spend_utxos().iter().rev() {
                let spent_output = SpentOutput {
                    output: output.clone(),
                    inpoint: InPoint::Withdrawal { m6id },
                };
                state
                    .stxos
                    .put(rwtxn, &OutPointKey::from(outpoint), &spent_output)
                    .map_err(DbError::from)?;
                if state
                    .utxos
                    .delete(rwtxn, &OutPointKey::from(outpoint))
                    .map_err(DbError::from)?
                {
                    return Err(Error::NoUtxo {
                        outpoint: *outpoint,
                    });
                };
                let utxo_hash = hash(&PointedOutput {
                    outpoint: *outpoint,
                    output: output.clone(),
                });
                accumulator_diff.remove(utxo_hash.into());
            }
            let (prev_latest_failed_m6id, latest_failed_m6id) = state
                .latest_failed_withdrawal_bundle
                .try_get(rwtxn, &())
                .map_err(DbError::from)?
                .expect("latest failed withdrawal bundle should exist")
                .pop();
            assert_eq!(latest_failed_m6id.value, m6id);
            assert_eq!(latest_failed_m6id.height, block_height);
            if let Some(prev_latest_failed_m6id) = prev_latest_failed_m6id {
                state
                    .latest_failed_withdrawal_bundle
                    .put(rwtxn, &(), &prev_latest_failed_m6id)
                    .map_err(DbError::from)?;
            } else {
                state
                    .latest_failed_withdrawal_bundle
                    .delete(rwtxn, &())
                    .map_err(DbError::from)?;
            }
        }
    }
    state
        .withdrawal_bundles
        .put(rwtxn, &m6id, &(bundle, prev_bundle_status))
        .map_err(DbError::from)?;
    Ok(())
}

fn disconnect_withdrawal_bundle_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    event: &WithdrawalBundleEvent,
) -> Result<(), Error> {
    match event.status {
        WithdrawalBundleStatus::Submitted => {
            disconnect_withdrawal_bundle_submitted(
                state,
                rwtxn,
                block_height,
                accumulator_diff,
                event.m6id,
            )
        }
        WithdrawalBundleStatus::Confirmed => {
            disconnect_withdrawal_bundle_confirmed(
                state,
                rwtxn,
                block_height,
                accumulator_diff,
                event.m6id,
            )
        }
        WithdrawalBundleStatus::Failed => disconnect_withdrawal_bundle_failed(
            state,
            rwtxn,
            block_height,
            accumulator_diff,
            event.m6id,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn disconnect_event(
    state: &State,
    rwtxn: &mut RwTxn,
    block_height: u32,
    accumulator_diff: &mut AccumulatorDiff,
    latest_deposit_block_hash: &mut Option<bitcoin::BlockHash>,
    latest_withdrawal_bundle_event_block_hash: &mut Option<bitcoin::BlockHash>,
    event_block_hash: bitcoin::BlockHash,
    event: &BlockEvent,
) -> Result<(), Error> {
    match event {
        BlockEvent::Deposit(deposit) => {
            let outpoint = OutPoint::Deposit(deposit.outpoint);
            let output = deposit.output.clone();
            if !state
                .utxos
                .delete(rwtxn, &OutPointKey::from(&outpoint))
                .map_err(DbError::from)?
            {
                return Err(Error::NoUtxo { outpoint });
            }
            let utxo_hash = hash(&PointedOutput { outpoint, output });
            accumulator_diff.remove(utxo_hash.into());
            *latest_deposit_block_hash = Some(event_block_hash);
        }
        BlockEvent::WithdrawalBundle(withdrawal_bundle_event) => {
            let () = disconnect_withdrawal_bundle_event(
                state,
                rwtxn,
                block_height,
                accumulator_diff,
                withdrawal_bundle_event,
            )?;
            *latest_withdrawal_bundle_event_block_hash = Some(event_block_hash);
        }
    }
    Ok(())
}

pub fn disconnect(
    state: &State,
    rwtxn: &mut RwTxn,
    two_way_peg_data: &TwoWayPegData,
) -> Result<(), Error> {
    let block_height = state
        .try_get_height(rwtxn)?
        .expect("Height should not be None");
    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rwtxn, &())
        .map_err(DbError::from)?
        .unwrap_or_default();
    let mut accumulator_diff = AccumulatorDiff::default();
    let mut latest_deposit_block_hash = None;
    let mut latest_withdrawal_bundle_event_block_hash = None;
    // Restore pending withdrawal bundle
    for (event_block_hash, event_block_info) in
        two_way_peg_data.block_info.iter().rev()
    {
        for event in event_block_info.events.iter().rev() {
            let () = disconnect_event(
                state,
                rwtxn,
                block_height,
                &mut accumulator_diff,
                &mut latest_deposit_block_hash,
                &mut latest_withdrawal_bundle_event_block_hash,
                *event_block_hash,
                event,
            )?;
        }
    }
    // Handle withdrawals
    if let Some(latest_withdrawal_bundle_event_block_hash) =
        latest_withdrawal_bundle_event_block_hash
    {
        let (
            last_withdrawal_bundle_event_block_seq_idx,
            (
                last_withdrawal_bundle_event_block_hash,
                last_withdrawal_bundle_event_block_height,
            ),
        ) = state
            .withdrawal_bundle_event_blocks
            .last(rwtxn)
            .map_err(DbError::from)?
            .ok_or(Error::NoWithdrawalBundleEventBlock)?;
        assert_eq!(
            latest_withdrawal_bundle_event_block_hash,
            last_withdrawal_bundle_event_block_hash
        );
        assert_eq!(block_height - 1, last_withdrawal_bundle_event_block_height);
        if !state
            .deposit_blocks
            .delete(rwtxn, &last_withdrawal_bundle_event_block_seq_idx)
            .map_err(DbError::from)?
        {
            return Err(Error::NoWithdrawalBundleEventBlock);
        };
    }
    let last_withdrawal_bundle_failure_height = state
        .get_latest_failed_withdrawal_bundle(rwtxn)
        .map_err(DbError::from)?
        .map(|(height, _bundle)| height)
        .unwrap_or_default();
    if block_height - last_withdrawal_bundle_failure_height
        > WITHDRAWAL_BUNDLE_FAILURE_GAP
        && let Some((_bundle, bundle_height)) = state
            .pending_withdrawal_bundle
            .try_get(rwtxn, &())
            .map_err(DbError::from)?
        && bundle_height == block_height - 1
    {
        state
            .pending_withdrawal_bundle
            .delete(rwtxn, &())
            .map_err(DbError::from)?;
    }
    // Handle deposits.
    if let Some(latest_deposit_block_hash) = latest_deposit_block_hash {
        let (
            last_deposit_block_seq_idx,
            (last_deposit_block_hash, last_deposit_block_height),
        ) = state
            .deposit_blocks
            .last(rwtxn)
            .map_err(DbError::from)?
            .ok_or(Error::NoDepositBlock)?;
        assert_eq!(latest_deposit_block_hash, last_deposit_block_hash);
        assert_eq!(block_height - 1, last_deposit_block_height);
        if !state
            .deposit_blocks
            .delete(rwtxn, &last_deposit_block_seq_idx)
            .map_err(DbError::from)?
        {
            return Err(Error::NoDepositBlock);
        };
    }
    let () = accumulator.apply_diff(accumulator_diff)?;
    state
        .utreexo_accumulator
        .put(rwtxn, &(), &accumulator)
        .map_err(DbError::from)?;
    Ok(())
}

#[cfg(test)]
fn poc_fresh_env() -> sneed::Env {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let n = CTR.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let path = std::env::temp_dir()
        .join(format!("coinshift_w2_twpd_poc_{pid}_{n}"));
    let remove_res = std::fs::remove_dir_all(&path);
    drop(remove_res);
    std::fs::create_dir_all(&path).unwrap();
    let mut opts = heed::EnvOpenOptions::new();
    opts.map_size(512 * 1024 * 1024).max_dbs(State::NUM_DBS);
    unsafe { sneed::Env::open(&opts, &path) }.unwrap()
}

/// collect_withdrawal_bundle off-by-one. The loop checks
/// `len() > MAX_BUNDLE_OUTPUTS` BEFORE pushing, so it accepts MAX_BUNDLE_OUTPUTS+1
/// outputs and then WithdrawalBundle::new rejects the bundle as BundleTooHeavy,
/// which propagates as an error instead of selecting a valid subset.
#[cfg(test)]
mod bug_bundle_output_limit {
    use super::*;
    use crate::types::{Address, OutPoint, Output, OutputContent, Txid};
    use bitcoin::hashes::Hash as _;

    // Keep in sync with the constant inside collect_withdrawal_bundle.
    const BUNDLE_0_WEIGHT: u64 = 504;
    const OUTPUT_WEIGHT: u64 = 128;
    const MAX_BUNDLE_OUTPUTS: usize =
        ((bitcoin::policy::MAX_STANDARD_TX_WEIGHT as u64 - BUNDLE_0_WEIGHT)
            / OUTPUT_WEIGHT) as usize;

    fn unique_main_address(
        i: u32,
    ) -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
        let mut h = [0u8; 20];
        h[..4].copy_from_slice(&i.to_le_bytes());
        let spk = bitcoin::ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::from_byte_array(h),
        );
        bitcoin::Address::from_script(&spk, bitcoin::Network::Regtest)
            .unwrap()
            .as_unchecked()
            .clone()
    }

    #[test]
    fn off_by_one_allows_max_plus_one_then_errors_bundle_too_heavy() {
        let env = poc_fresh_env();
        let state = State::new(&env).unwrap();

        let total = MAX_BUNDLE_OUTPUTS + 1;
        {
            let mut rwtxn = env.write_txn().unwrap();
            for i in 0..total as u32 {
                let outpoint = OutPoint::Regular {
                    txid: Txid::from({
                        let mut b = [0u8; 32];
                        b[..4].copy_from_slice(&i.to_le_bytes());
                        b
                    }),
                    vout: 0,
                };
                let output = Output {
                    address: Address([0u8; 20]),
                    content: OutputContent::Withdrawal {
                        value: bitcoin::Amount::from_sat(10_000),
                        main_fee: bitcoin::Amount::from_sat(1_000),
                        main_address: unique_main_address(i),
                    },
                };
                state
                    .utxos
                    .put(&mut rwtxn, &(&outpoint).into(), &output)
                    .unwrap();
            }
            rwtxn.commit().unwrap();
        }

        let rotxn = env.read_txn().unwrap();
        let result = collect_withdrawal_bundle(&state, &rotxn, 1);

        // The off-by-one: the loop guard `len() > MAX` runs before push, so the
        // collector accepts MAX_BUNDLE_OUTPUTS + 1 outputs. A correct collector
        // would cap at MAX_BUNDLE_OUTPUTS. We prove that the produced bundle
        // contains MAX+1 withdrawal outputs (2 header outputs + MAX+1).
        let bundle = result
            .expect("bundle build should succeed for small outputs")
            .expect("eligible withdrawals should produce Some(bundle)");
        let withdrawal_outputs = bundle.tx().output.len() - 2; // minus fee + commitment
        assert_eq!(
            withdrawal_outputs,
            MAX_BUNDLE_OUTPUTS + 1,
            "off-by-one: collector should have pushed exactly MAX_BUNDLE_OUTPUTS+1 outputs"
        );
        assert!(
            withdrawal_outputs > MAX_BUNDLE_OUTPUTS,
            "collector exceeded the documented MAX_BUNDLE_OUTPUTS cap"
        );
        println!(
            "proven: collect_withdrawal_bundle included {withdrawal_outputs} withdrawal outputs (= MAX_BUNDLE_OUTPUTS+1 = {}), one past the cap, because the `len() > MAX` guard runs before push",
            MAX_BUNDLE_OUTPUTS + 1
        );
    }
}

/// disconnect_withdrawal_bundle_failed uses the inverted delete check
/// `if utxos.delete(..)? { return Err(NoUtxo) }`. delete() returns true on a
/// SUCCESSFUL delete, so a normal disconnect over an existing live UTXO errors
/// NoUtxo even though the delete succeeded.
#[cfg(test)]
mod bug_bundle_disconnect_inverted_check {
    use super::*;
    use crate::state::rollback::RollBack;
    use crate::types::{
        AccumulatorDiff, Address, OutPoint, Output, OutputContent, Txid,
        WithdrawalBundle, WithdrawalBundleStatus,
    };
    use bitcoin::hashes::Hash as _;

    #[test]
    fn successful_delete_is_misreported_as_no_utxo() {
        let env = poc_fresh_env();
        let state = State::new(&env).unwrap();

        let block_height = 5u32;

        let spent_outpoint = OutPoint::Regular {
            txid: Txid::from([0x42; 32]),
            vout: 0,
        };
        let spent_output = Output {
            address: Address([0x07; 20]),
            content: OutputContent::Value(bitcoin::Amount::from_sat(50_000)),
        };

        let mut spend_utxos = std::collections::BTreeMap::new();
        spend_utxos.insert(spent_outpoint, spent_output.clone());
        let main_spk = bitcoin::ScriptBuf::new_p2wpkh(
            &bitcoin::WPubkeyHash::from_byte_array([0x09; 20]),
        );
        let main_addr =
            bitcoin::Address::from_script(&main_spk, bitcoin::Network::Regtest)
                .unwrap();
        let bundle_output = bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(49_000),
            script_pubkey: main_addr.script_pubkey(),
        };
        let bundle = WithdrawalBundle::new(
            block_height,
            bitcoin::Amount::from_sat(1_000),
            spend_utxos,
            vec![bundle_output],
        )
        .unwrap();
        let m6id = bundle.compute_m6id();

        {
            let mut rwtxn = env.write_txn().unwrap();

            state
                .utxos
                .put(&mut rwtxn, &(&spent_outpoint).into(), &spent_output)
                .unwrap();

            let mut status = RollBack::new(
                WithdrawalBundleStatus::Submitted,
                block_height,
            );
            status
                .push(WithdrawalBundleStatus::Failed, block_height)
                .unwrap();
            state
                .withdrawal_bundles
                .put(
                    &mut rwtxn,
                    &m6id,
                    &(WithdrawalBundleInfo::Known(bundle), status),
                )
                .unwrap();

            state
                .latest_failed_withdrawal_bundle
                .put(&mut rwtxn, &(), &RollBack::new(m6id, block_height))
                .unwrap();
            rwtxn.commit().unwrap();
        }

        let mut rwtxn = env.write_txn().unwrap();
        let mut diff = AccumulatorDiff::default();
        let result = disconnect_withdrawal_bundle_failed(
            &state,
            &mut rwtxn,
            block_height,
            &mut diff,
            m6id,
        );

        let is_no_utxo = matches!(result, Err(Error::NoUtxo { .. }));
        assert!(
            is_no_utxo,
            "inverted delete check should report NoUtxo on a successful delete, got {result:?}"
        );
        println!(
            "proven: disconnect_withdrawal_bundle_failed returned NoUtxo even though the live UTXO existed and was deleted successfully (inverted `if delete()? {{ return Err(NoUtxo) }}`)"
        );
    }
}

/// On a reorg that disconnects a withdrawal-bundle-event block, the
/// disconnect handler loads the seq idx from withdrawal_bundle_event_blocks but
/// then DELETES that idx from deposit_blocks. If deposit_blocks has an entry at
/// that idx, an unrelated deposit checkpoint is destroyed while the stale
/// withdrawal checkpoint is left in place.
#[cfg(test)]
mod bug_reorg_wrong_db_deletion {
    use super::*;
    use crate::state::rollback::RollBack;
    use crate::types::{M6id, WithdrawalBundleEvent, WithdrawalBundleStatus};
    use crate::types::proto::mainchain::{BlockInfo, BlockEvent, TwoWayPegData};
    use hashlink::LinkedHashMap;

    #[test]
    fn disconnect_deletes_wrong_db_corrupting_deposit_checkpoint() {
        let env = poc_fresh_env();
        let state = State::new(&env).unwrap();

        let block_height = 10u32;
        let seq_idx = 0u32;

        use bitcoin::hashes::Hash as _;
        // The mainchain block being disconnected.
        let event_block_hash = bitcoin::BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x7c; 32]),
        );
        // An unrelated deposit checkpoint that happens to share seq idx 0.
        let unrelated_deposit_hash = bitcoin::BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0xDD; 32]),
        );

        // A Submitted, Unknown withdrawal bundle so the bundle-disconnect is a
        // near no-op that just removes the withdrawal_bundles row.
        let m6id = M6id(bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0x6c; 32]),
        ));

        {
            let mut rwtxn = env.write_txn().unwrap();
            state.height.put(&mut rwtxn, &(), &block_height).unwrap();

            // withdrawal_bundle_event_blocks[0] = (event_block_hash, height-1)
            state
                .withdrawal_bundle_event_blocks
                .put(
                    &mut rwtxn,
                    &seq_idx,
                    &(event_block_hash, block_height - 1),
                )
                .unwrap();

            // deposit_blocks[0] = unrelated checkpoint (the victim)
            state
                .deposit_blocks
                .put(
                    &mut rwtxn,
                    &seq_idx,
                    &(unrelated_deposit_hash, block_height - 1),
                )
                .unwrap();

            // withdrawal_bundles[m6id] = (Unknown, [Submitted@height])
            state
                .withdrawal_bundles
                .put(
                    &mut rwtxn,
                    &m6id,
                    &(
                        WithdrawalBundleInfo::Unknown,
                        RollBack::new(
                            WithdrawalBundleStatus::Submitted,
                            block_height,
                        ),
                    ),
                )
                .unwrap();
            rwtxn.commit().unwrap();
        }

        // Build TwoWayPegData with a single block carrying the Submitted event.
        let mut block_info = LinkedHashMap::new();
        block_info.insert(
            event_block_hash,
            BlockInfo {
                bmm_commitment: None,
                events: vec![BlockEvent::WithdrawalBundle(
                    WithdrawalBundleEvent {
                        m6id,
                        status: WithdrawalBundleStatus::Submitted,
                    },
                )],
            },
        );
        let twpd = TwoWayPegData { block_info };

        let mut rwtxn = env.write_txn().unwrap();
        super::disconnect(&state, &mut rwtxn, &twpd).unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        // BUG: the unrelated deposit checkpoint was deleted...
        let deposit_entry =
            state.deposit_blocks.try_get(&rotxn, &seq_idx).unwrap();
        assert!(
            deposit_entry.is_none(),
            "the unrelated deposit_blocks[0] checkpoint should have been wrongly deleted"
        );
        // ...while the stale withdrawal-event checkpoint was left in place.
        let wd_entry = state
            .withdrawal_bundle_event_blocks
            .try_get(&rotxn, &seq_idx)
            .unwrap();
        assert!(
            wd_entry.is_some(),
            "the withdrawal_bundle_event_blocks[0] checkpoint should have been left stale"
        );
        println!(
            "proven: disconnecting a withdrawal-bundle-event block deleted the unrelated deposit_blocks[0] checkpoint and left the stale withdrawal_bundle_event_blocks[0] in place (wrong DB targeted)"
        );
    }
}
