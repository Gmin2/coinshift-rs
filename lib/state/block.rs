//! Connect and disconnect blocks

use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use sneed::{RoTxn, RwTxn, db::error::Error as DbError};

use crate::{
    authorization::Authorization,
    state::{Error, PrevalidatedBlock, State, error, swap},
    types::{
        AccumulatorDiff, AmountOverflowError, Body, FilledTransaction,
        GetAddress as _, GetValue as _, Header, InPoint, MerkleRoot, OutPoint,
        OutPointKey, PointedOutput, SpentOutput, Swap, SwapId, SwapState,
        SwapTxId, TxData, Verify as _,
    },
};

/// Prevalidate a block: compute and verify all read-only checks and
/// prepare data needed for fast connection.
pub fn prevalidate(
    state: &State,
    rotxn: &RoTxn,
    header: &Header,
    body: &Body,
) -> Result<PrevalidatedBlock, Error> {
    let tip_hash = state.try_get_tip(rotxn)?;
    if header.prev_side_hash != tip_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    };
    let next_height = state.try_get_height(rotxn)?.map_or(0, |h| h + 1);
    if body.authorizations.len() > State::body_sigops_limit(next_height) {
        return Err(Error::TooManySigops);
    }
    let body_size =
        borsh::object_length(&body).map_err(Error::BorshSerialize)?;
    if body_size > State::body_size_limit(next_height) {
        return Err(Error::BodyTooLarge);
    }

    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rotxn, &())
        .map_err(DbError::from)?
        .unwrap_or_default();

    // gather and verify transactions
    let mut total_inputs: usize = 0;
    let mut total_outputs: usize = 0;
    for tx in &body.transactions {
        total_inputs += tx.inputs.len();
        total_outputs += tx.outputs.len();
    }
    let mut all_input_keys: Vec<OutPointKey> = Vec::with_capacity(total_inputs);
    // Accumulator diff from txs. The bool value is true for insertions, false
    // for deletions.
    let mut accumulator_diff_txs =
        Vec::with_capacity(total_inputs + total_outputs);
    let mut filled_transactions: Vec<FilledTransaction> =
        Vec::with_capacity(body.transactions.len());
    let mut total_fees = bitcoin::Amount::ZERO;
    for transaction in &body.transactions {
        let txid = transaction.txid();
        let mut spent_utxos = Vec::with_capacity(transaction.inputs.len());
        let mut spent_utxo_hashes =
            Vec::<BitcoinNodeHash>::with_capacity(transaction.inputs.len());
        for (outpoint, utxo_hash) in &transaction.inputs {
            let key = OutPointKey::from(outpoint);
            let spent_output =
                state.utxos.try_get(rotxn, &key)?.ok_or(Error::NoUtxo {
                    outpoint: *outpoint,
                })?;
            all_input_keys.push(OutPointKey::from(outpoint));
            spent_utxos.push(spent_output);
            spent_utxo_hashes.push(utxo_hash.into());
            accumulator_diff_txs.push((false, utxo_hash.into()));
        }
        for (vout, output) in transaction.outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let pointed_output = PointedOutput {
                outpoint,
                output: output.clone(),
            };
            accumulator_diff_txs.push((true, (&pointed_output).into()));
        }
        if !accumulator.verify(&transaction.proof, &spent_utxo_hashes)? {
            return Err(Error::UtreexoProofFailed { txid });
        }
        let filled_tx = FilledTransaction {
            spent_utxos,
            transaction: transaction.clone(),
        };
        swap::validate_block_transaction(
            state,
            rotxn,
            transaction,
            &filled_tx,
        )?;
        total_fees = total_fees
            .checked_add(state.validate_filled_transaction(&filled_tx)?)
            .ok_or(AmountOverflowError)?;
        filled_transactions.push(filled_tx);
    }
    let computed_merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_transactions.as_slice(),
    )?;
    if computed_merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: computed_merkle_root,
        };
        return Err(err);
    }
    {
        use rayon::prelude::ParallelSliceMut;
        all_input_keys.par_sort_unstable();
        if all_input_keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::UtxoDoubleSpent);
        }
    }
    let mut coinbase_value = bitcoin::Amount::ZERO;
    let mut accumulator_diff = AccumulatorDiff::with_capacity(
        body.coinbase.len() + accumulator_diff_txs.len(),
    );
    for (vout, output) in body.coinbase.iter().enumerate() {
        coinbase_value = coinbase_value
            .checked_add(output.get_value())
            .ok_or(AmountOverflowError)?;
        let outpoint = OutPoint::Coinbase {
            merkle_root: computed_merkle_root,
            vout: vout as u32,
        };
        let pointed_output = PointedOutput {
            outpoint,
            output: output.clone(),
        };
        accumulator_diff.insert((&pointed_output).into());
    }
    for (insert, utxo_hash) in accumulator_diff_txs {
        if insert {
            accumulator_diff.insert(utxo_hash);
        } else {
            accumulator_diff.remove(utxo_hash);
        }
    }
    if coinbase_value > total_fees {
        return Err(Error::NotEnoughFees);
    }
    // For SwapClaim transactions, SwapPending inputs are owned by the swap
    // creator but spent by the claimer (who may be a different wallet).
    // Skip the address-matching check for those specific inputs — swap
    // validation already ensures legitimacy.
    let mut auth_offset = 0usize;
    let mut swap_claim_pending = std::collections::HashSet::<usize>::new();
    for filled_tx in &filled_transactions {
        if matches!(filled_tx.transaction.data, TxData::SwapClaim { .. }) {
            for (i, utxo) in filled_tx.spent_utxos.iter().enumerate() {
                if utxo.content.is_swap_pending() {
                    swap_claim_pending.insert(auth_offset + i);
                }
            }
        }
        auth_offset += filled_tx.spent_utxos.len();
    }
    let spent_utxos = filled_transactions
        .iter()
        .flat_map(|t| t.spent_utxos.iter());
    for (idx, (authorization, spent_utxo)) in
        body.authorizations.iter().zip(spent_utxos).enumerate()
    {
        if swap_claim_pending.contains(&idx) {
            continue;
        }
        if authorization.get_address() != spent_utxo.address {
            return Err(Error::WrongPubKeyForAddress);
        }
    }
    if Authorization::verify_body(body).is_err() {
        return Err(Error::Authorization);
    }
    // Check root consistency without committing to DB
    let () = accumulator.apply_diff(accumulator_diff.clone())?;
    let roots: Vec<BitcoinNodeHash> = accumulator.get_roots();
    if roots != header.roots {
        return Err(Error::UtreexoRootsMismatch);
    }

    Ok(PrevalidatedBlock {
        filled_transactions,
        computed_merkle_root,
        total_fees,
        coinbase_value,
        next_height,
        accumulator_diff,
    })
}

/// Connect a block using the provided prevalidated data.
pub fn connect_prevalidated(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
    pre: PrevalidatedBlock,
) -> Result<crate::types::MerkleRoot, Error> {
    let tip_hash = state.try_get_tip(rwtxn)?;
    if tip_hash != header.prev_side_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    }
    if pre.computed_merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: pre.computed_merkle_root,
            computed: header.merkle_root,
        };
        return Err(err);
    }

    // Apply UTXO set changes
    for (vout, output) in body.coinbase.iter().enumerate() {
        let outpoint = OutPoint::Coinbase {
            merkle_root: pre.computed_merkle_root,
            vout: vout as u32,
        };
        state
            .utxos
            .put(rwtxn, &OutPointKey::from(&outpoint), output)
            .map_err(DbError::from)?;
    }

    for filled in &pre.filled_transactions {
        let txid = filled.transaction.txid();
        for (vin, (outpoint, _)) in filled.transaction.inputs.iter().enumerate()
        {
            let spent_output = state
                .utxos
                .try_get(rwtxn, &OutPointKey::from(outpoint))
                .map_err(DbError::from)?
                .ok_or(Error::NoUtxo {
                    outpoint: *outpoint,
                })?;
            state
                .utxos
                .delete(rwtxn, &OutPointKey::from(outpoint))
                .map_err(DbError::from)?;
            let spent_output = SpentOutput {
                output: spent_output,
                inpoint: InPoint::Regular {
                    txid,
                    vin: vin as u32,
                },
            };
            state
                .stxos
                .put(rwtxn, &OutPointKey::from(outpoint), &spent_output)
                .map_err(DbError::from)?;
        }
        for (vout, output) in filled.transaction.outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            state
                .utxos
                .put(rwtxn, &OutPointKey::from(&outpoint), output)
                .map_err(DbError::from)?;
        }

        // Process swap transactions
        match &filled.transaction.data {
            TxData::SwapCreate {
                swap_id,
                parent_chain,
                l1_txid_bytes,
                required_confirmations,
                l2_recipient,
                l2_amount,
                l1_recipient_address,
                l1_amount,
            } => {
                let swap_id = SwapId(*swap_id);
                let current_height = pre.next_height;

                // Reconstruct L1 txid
                let l1_txid = SwapTxId::from_bytes(l1_txid_bytes);

                // Check if swap already exists (might be from mempool or previous block)
                // If it exists but is corrupted, delete it first to avoid issues
                match state.get_swap(rwtxn, &swap_id) {
                    Ok(Some(ref existing)) => {
                        tracing::warn!(
                            swap_id = %swap_id,
                            existing_state = ?existing.state,
                            "Swap already exists in database, will overwrite during block connection"
                        );
                    }
                    Ok(None) => {
                        // Swap doesn't exist, that's fine
                    }
                    Err(_) => {
                        // Swap exists but is corrupted - delete it first
                        tracing::warn!(
                            swap_id = %swap_id,
                            "Existing swap is corrupted, deleting before saving new one"
                        );
                        // Try to delete the corrupted swap
                        drop(state.swaps.delete(rwtxn, &swap_id));
                    }
                }

                // L2 creator = first input's address (only they may cancel/delete)
                let l2_creator_address =
                    filled.spent_utxos.first().map(|o| o.address);

                // Reconstruct swap object
                let swap = Swap::new(
                    swap_id,
                    crate::types::SwapDirection::L2ToL1,
                    *parent_chain,
                    l1_txid,
                    Some(*required_confirmations),
                    *l2_recipient, // Now optional
                    bitcoin::Amount::from_sat(*l2_amount),
                    l1_recipient_address.clone(),
                    bitcoin::Amount::from_sat(*l1_amount),
                    current_height,
                    Some(
                        current_height
                            + parent_chain.default_swap_expiration_blocks(),
                    ),
                    l2_creator_address,
                );

                // Verify swap ID matches
                if swap.id.0 != swap_id.0 {
                    return Err(Error::InvalidTransaction(
                        "Swap ID mismatch in SwapCreate".to_owned(),
                    ));
                }

                tracing::debug!(
                    swap_id = %swap_id,
                    l2_recipient = ?swap.l2_recipient,
                    l2_amount = %swap.l2_amount,
                    l1_amount = ?swap.l1_amount,
                    state = ?swap.state,
                    "Reconstructed swap from SwapCreate transaction, about to save"
                );

                // Lock outputs for L2 → L1 swaps
                // Only lock outputs with SwapPending content, not change outputs
                for (vout, output) in
                    filled.transaction.outputs.iter().enumerate()
                {
                    // Only lock SwapPending outputs, not regular Value outputs (change)
                    if matches!(
                        output.content,
                        crate::types::OutputContent::SwapPending { .. }
                    ) {
                        let outpoint = OutPoint::Regular {
                            txid,
                            vout: vout as u32,
                        };
                        state
                            .lock_output_to_swap(rwtxn, &outpoint, &swap_id)?;
                    }
                }

                // Save swap - this is where corruption might happen
                tracing::debug!(
                    swap_id = %swap_id,
                    "About to save swap during block connection"
                );
                state.save_swap(rwtxn, &swap)?;
                tracing::debug!(
                    swap_id = %swap_id,
                    "Swap saved during block connection"
                );
            }
            TxData::SwapClaim {
                swap_id,
                l2_claimer_address,
                ..
            } => {
                let swap_id = SwapId(*swap_id);

                // Get swap
                let mut swap = state
                    .get_swap(rwtxn, &swap_id)?
                    .ok_or_else(|| Error::SwapNotFound { swap_id })?;

                // If this node hasn't yet observed the L1 fill (swap
                // state set by local, non-deterministic L1 monitoring),
                // trust the block and advance the swap to ReadyToClaim.
                // The miner who produced the block already validated the
                // L1 side before including this SwapClaim.
                if !matches!(swap.state, SwapState::ReadyToClaim) {
                    tracing::warn!(
                        %swap_id,
                        state = ?swap.state,
                        "SwapClaim in block but local swap not ReadyToClaim; \
                         advancing state to match block"
                    );
                    swap.state = SwapState::ReadyToClaim;
                    state.save_swap(rwtxn, &swap)?;
                }

                // For open swaps, verify claimer address is provided
                if swap.l2_recipient.is_none() && l2_claimer_address.is_none() {
                    return Err(Error::InvalidTransaction(
                        "Open swap claim requires l2_claimer_address"
                            .to_string(),
                    ));
                }

                // Unlock outputs
                for (outpoint, _) in &filled.transaction.inputs {
                    if state.is_output_locked_to_swap(rwtxn, outpoint)?
                        == Some(swap_id)
                    {
                        state.unlock_output_from_swap(rwtxn, outpoint)?;
                    }
                }

                // Mark swap as completed
                swap.mark_completed();
                state.save_swap(rwtxn, &swap)?;
            }
            TxData::Regular => {}
        }
    }

    // Update tip/height
    let block_hash = header.hash();
    state
        .tip
        .put(rwtxn, &(), &block_hash)
        .map_err(DbError::from)?;
    state
        .height
        .put(rwtxn, &(), &pre.next_height)
        .map_err(DbError::from)?;

    // Apply accumulator diff
    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rwtxn, &())
        .map_err(DbError::from)?
        .unwrap_or_default();
    let () = accumulator.apply_diff(pre.accumulator_diff)?;
    state
        .utreexo_accumulator
        .put(rwtxn, &(), &accumulator)
        .map_err(DbError::from)?;

    Ok(pre.computed_merkle_root)
}

pub fn validate(
    state: &State,
    rotxn: &RoTxn,
    header: &Header,
    body: &Body,
) -> Result<(bitcoin::Amount, MerkleRoot), Error> {
    let tip_hash = state.try_get_tip(rotxn)?;
    if header.prev_side_hash != tip_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    };
    let height = state.try_get_height(rotxn)?.map_or(0, |height| height + 1);
    if body.authorizations.len() > State::body_sigops_limit(height) {
        return Err(Error::TooManySigops);
    }
    let body_size =
        borsh::object_length(&body).map_err(Error::BorshSerialize)?;
    if body_size > State::body_size_limit(height) {
        return Err(Error::BodyTooLarge);
    }
    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rotxn, &())
        .map_err(DbError::from)?
        .unwrap_or_default();
    let filled_transactions: Vec<_> = body
        .transactions
        .iter()
        .map(|t| state.fill_transaction(rotxn, t))
        .collect::<Result<_, _>>()?;
    let merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_transactions.as_slice(),
    )?;
    if merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: merkle_root,
        };
        return Err(err);
    }
    let mut accumulator_diff = AccumulatorDiff::default();
    let mut coinbase_value = bitcoin::Amount::ZERO;
    for (vout, output) in body.coinbase.iter().enumerate() {
        coinbase_value = coinbase_value
            .checked_add(output.get_value())
            .ok_or(AmountOverflowError)?;
        let outpoint = OutPoint::Coinbase {
            merkle_root,
            vout: vout as u32,
        };
        let pointed_output = PointedOutput {
            outpoint,
            output: output.clone(),
        };
        accumulator_diff.insert((&pointed_output).into());
    }
    let mut total_fees = bitcoin::Amount::ZERO;
    // Gather all input keys to check double-spends via sort-and-scan
    let total_inputs = body.inputs_len();
    let mut all_input_keys = Vec::with_capacity(total_inputs);
    for filled_transaction in &filled_transactions {
        let txid = filled_transaction.transaction.txid();
        swap::validate_block_transaction(
            state,
            rotxn,
            &filled_transaction.transaction,
            filled_transaction,
        )?;
        // hashes of spent utxos, used to verify the utreexo proof
        let mut spent_utxo_hashes = Vec::<BitcoinNodeHash>::with_capacity(
            filled_transaction.transaction.inputs.len(),
        );
        for (outpoint, utxo_hash) in &filled_transaction.transaction.inputs {
            all_input_keys.push(OutPointKey::from(outpoint));
            spent_utxo_hashes.push(utxo_hash.into());
            accumulator_diff.remove(utxo_hash.into());
        }
        for (vout, output) in
            filled_transaction.transaction.outputs.iter().enumerate()
        {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let pointed_output = PointedOutput {
                outpoint,
                output: output.clone(),
            };
            accumulator_diff.insert((&pointed_output).into());
        }
        total_fees = total_fees
            .checked_add(state.validate_filled_transaction(filled_transaction)?)
            .ok_or(AmountOverflowError)?;
        // verify utreexo proof
        if !accumulator
            .verify(&filled_transaction.transaction.proof, &spent_utxo_hashes)?
        {
            return Err(Error::UtreexoProofFailed { txid });
        }
    }
    // Sort and check for duplicate outpoints (double-spend detection)
    {
        use rayon::prelude::ParallelSliceMut;
        all_input_keys.par_sort_unstable();
        if all_input_keys.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::UtxoDoubleSpent);
        }
    }
    if coinbase_value > total_fees {
        return Err(Error::NotEnoughFees);
    }
    // Same SwapClaim + SwapPending skip as in prevalidate.
    let mut auth_offset = 0usize;
    let mut swap_claim_pending = std::collections::HashSet::<usize>::new();
    for filled_tx in &filled_transactions {
        if matches!(filled_tx.transaction.data, TxData::SwapClaim { .. }) {
            for (i, utxo) in filled_tx.spent_utxos.iter().enumerate() {
                if utxo.content.is_swap_pending() {
                    swap_claim_pending.insert(auth_offset + i);
                }
            }
        }
        auth_offset += filled_tx.spent_utxos.len();
    }
    let spent_utxos = filled_transactions
        .iter()
        .flat_map(|t| t.spent_utxos.iter());
    for (idx, (authorization, spent_utxo)) in
        body.authorizations.iter().zip(spent_utxos).enumerate()
    {
        if swap_claim_pending.contains(&idx) {
            continue;
        }
        if authorization.get_address() != spent_utxo.address {
            return Err(Error::WrongPubKeyForAddress);
        }
    }
    if Authorization::verify_body(body).is_err() {
        return Err(Error::Authorization);
    }
    // Check root consistency without committing to DB
    let () = accumulator.apply_diff(accumulator_diff)?;
    let roots: Vec<BitcoinNodeHash> = accumulator.get_roots();
    if roots != header.roots {
        return Err(Error::UtreexoRootsMismatch);
    }
    Ok((total_fees, merkle_root))
}

pub fn connect(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
) -> Result<MerkleRoot, Error> {
    let tip_hash = state.try_get_tip(rwtxn)?;
    if tip_hash != header.prev_side_hash {
        let err = error::InvalidHeader::PrevSideHash {
            expected: tip_hash,
            received: header.prev_side_hash,
        };
        return Err(Error::InvalidHeader(err));
    }
    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rwtxn, &())?
        .unwrap_or_default();
    let mut accumulator_diff = AccumulatorDiff::default();
    for (vout, output) in body.coinbase.iter().enumerate() {
        let outpoint = OutPoint::Coinbase {
            merkle_root: header.merkle_root,
            vout: vout as u32,
        };
        let pointed_output = PointedOutput {
            outpoint,
            output: output.clone(),
        };
        accumulator_diff.insert((&pointed_output).into());
        let key = OutPointKey::from(&outpoint);
        state.utxos.put(rwtxn, &key, output)?;
    }
    let mut filled_txs: Vec<FilledTransaction> =
        Vec::with_capacity(body.transactions.len());
    for transaction in &body.transactions {
        let mut spent_utxos = Vec::with_capacity(transaction.inputs.len());
        let txid = transaction.txid();
        for (vin, (outpoint, utxo_hash)) in
            transaction.inputs.iter().enumerate()
        {
            let key = OutPointKey::from(outpoint);
            let spent_output =
                state.utxos.try_get(rwtxn, &key)?.ok_or(Error::NoUtxo {
                    outpoint: *outpoint,
                })?;

            accumulator_diff.remove(utxo_hash.into());
            let key = OutPointKey::from(outpoint);
            state.utxos.delete(rwtxn, &key)?;
            let spent_output = SpentOutput {
                output: spent_output,
                inpoint: InPoint::Regular {
                    txid,
                    vin: vin as u32,
                },
            };
            state
                .stxos
                .put(rwtxn, &OutPointKey::from(outpoint), &spent_output)
                .map_err(DbError::from)?;
            spent_utxos.push(spent_output.output);
        }
        for (vout, output) in transaction.outputs.iter().enumerate() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let pointed_output = PointedOutput {
                outpoint,
                output: output.clone(),
            };
            accumulator_diff.insert((&pointed_output).into());
            let key = OutPointKey::from(&outpoint);
            state.utxos.put(rwtxn, &key, output)?;
        }
        let filled_tx = FilledTransaction {
            spent_utxos,
            transaction: transaction.clone(),
        };
        filled_txs.push(filled_tx);
    }
    let merkle_root = Body::compute_merkle_root(
        body.coinbase.as_slice(),
        filled_txs.as_slice(),
    )?;
    if merkle_root != header.merkle_root {
        let err = Error::InvalidBody {
            expected: header.merkle_root,
            computed: merkle_root,
        };
        return Err(err);
    }
    let block_hash = header.hash();
    let height = state.try_get_height(rwtxn)?.map_or(0, |height| height + 1);
    state.tip.put(rwtxn, &(), &block_hash)?;
    state.height.put(rwtxn, &(), &height)?;
    let () = accumulator.apply_diff(accumulator_diff)?;
    state.utreexo_accumulator.put(rwtxn, &(), &accumulator)?;
    Ok(merkle_root)
}

pub fn disconnect_tip(
    state: &State,
    rwtxn: &mut RwTxn,
    header: &Header,
    body: &Body,
) -> Result<(), Error> {
    let tip_hash = state
        .tip
        .try_get(rwtxn, &())
        .map_err(DbError::from)?
        .ok_or(Error::NoTip)?;
    if tip_hash != header.hash() {
        let err = error::InvalidHeader::BlockHash {
            expected: tip_hash,
            computed: header.hash(),
        };
        return Err(Error::InvalidHeader(err));
    }
    let mut accumulator = state
        .utreexo_accumulator
        .try_get(rwtxn, &())
        .map_err(DbError::from)?
        .unwrap_or_default();
    tracing::debug!("Got acc");
    let mut accumulator_diff = AccumulatorDiff::default();
    // revert txs, last-to-first
    body.transactions.iter().rev().try_for_each(|tx| {
        let txid = tx.txid();

        // Rollback swap transactions
        match &tx.data {
            TxData::SwapCreate { swap_id, .. } => {
                let swap_id = SwapId(*swap_id);

                // Unlock outputs for L2 → L1 swaps
                // Only unlock SwapPending outputs that were locked
                for (vout, output) in tx.outputs.iter().enumerate().rev() {
                    if matches!(
                        output.content,
                        crate::types::OutputContent::SwapPending { .. }
                    ) {
                        let outpoint = OutPoint::Regular {
                            txid,
                            vout: vout as u32,
                        };
                        if state.is_output_locked_to_swap(rwtxn, &outpoint)?
                            == Some(swap_id)
                        {
                            state.unlock_output_from_swap(rwtxn, &outpoint)?;
                        }
                    }
                }

                // Delete swap (rollback: no creator check)
                state.delete_swap_unchecked(rwtxn, &swap_id)?;
            }
            TxData::SwapClaim { swap_id, .. } => {
                let swap_id = SwapId(*swap_id);

                // Get swap
                let mut swap = state
                    .get_swap(rwtxn, &swap_id)?
                    .ok_or_else(|| Error::SwapNotFound { swap_id })?;

                // Re-lock outputs
                for (outpoint, _) in tx.inputs.iter().rev() {
                    if state
                        .is_output_locked_to_swap(rwtxn, outpoint)?
                        .is_none()
                    {
                        state.lock_output_to_swap(rwtxn, outpoint, &swap_id)?;
                    }
                }

                // Revert swap state
                if matches!(swap.state, SwapState::Completed) {
                    swap.state = SwapState::ReadyToClaim;
                    state.save_swap(rwtxn, &swap)?;
                }
            }
            TxData::Regular => {}
        }

        // delete UTXOs, last-to-first
        tx.outputs.iter().enumerate().rev().try_for_each(
            |(vout, output)| {
                let outpoint = OutPoint::Regular {
                    txid,
                    vout: vout as u32,
                };
                let pointed_output = PointedOutput {
                    outpoint,
                    output: output.clone(),
                };
                accumulator_diff.remove((&pointed_output).into());
                let key = OutPointKey::from(&outpoint);
                if state.utxos.delete(rwtxn, &key).map_err(DbError::from)? {
                    Ok(())
                } else {
                    Err(Error::NoUtxo { outpoint })
                }
            },
        )?;
        // unspend STXOs, last-to-first
        tx.inputs
            .iter()
            .rev()
            .try_for_each(|(outpoint, utxo_hash)| {
                let key = OutPointKey::from(outpoint);
                if let Some(spent_output) = state.stxos.try_get(rwtxn, &key)? {
                    accumulator_diff.insert(utxo_hash.into());
                    state.stxos.delete(rwtxn, &key)?;
                    state.utxos.put(rwtxn, &key, &spent_output.output)?;
                    Ok(())
                } else {
                    Err(Error::NoStxo {
                        outpoint: *outpoint,
                    })
                }
            })
    })?;
    // delete coinbase UTXOs, last-to-first
    body.coinbase
        .iter()
        .enumerate()
        .rev()
        .try_for_each(|(vout, output)| {
            let outpoint = OutPoint::Coinbase {
                merkle_root: header.merkle_root,
                vout: vout as u32,
            };
            let pointed_output = PointedOutput {
                outpoint,
                output: output.clone(),
            };
            accumulator_diff.remove((&pointed_output).into());
            let key = OutPointKey::from(&outpoint);
            if state.utxos.delete(rwtxn, &key).map_err(DbError::from)? {
                Ok(())
            } else {
                Err(Error::NoUtxo { outpoint })
            }
        })?;
    let height = state
        .try_get_height(rwtxn)?
        .expect("Height should not be None");
    match (header.prev_side_hash, height) {
        (None, 0) => {
            state.tip.delete(rwtxn, &()).map_err(DbError::from)?;
            state.height.delete(rwtxn, &()).map_err(DbError::from)?;
        }
        (None, _) | (_, 0) => return Err(Error::NoTip),
        (Some(prev_side_hash), height) => {
            state
                .tip
                .put(rwtxn, &(), &prev_side_hash)
                .map_err(DbError::from)?;
            state
                .height
                .put(rwtxn, &(), &(height - 1))
                .map_err(DbError::from)?;
        }
    }
    let () = accumulator.apply_diff(accumulator_diff)?;
    state
        .utreexo_accumulator
        .put(rwtxn, &(), &accumulator)
        .map_err(DbError::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use sneed::Env;

    use super::*;
    use crate::{
        authorization::{SigningKey, authorize, get_address},
        types::{
            Accumulator, Address, Output, OutputContent, ParentChainType,
            SwapDirection, SwapTxId, Transaction, Txid, hash,
        },
    };

    fn sat(value: u64) -> bitcoin::Amount {
        bitcoin::Amount::from_sat(value)
    }

    fn test_state() -> (temp_dir::TempDir, Env, State) {
        let dir = temp_dir::TempDir::new().unwrap();
        let mut opts = heed::EnvOpenOptions::new();
        opts.map_size(10 * 1024 * 1024).max_dbs(State::NUM_DBS);
        let env = unsafe { Env::open(&opts, dir.path()) }.unwrap();
        let state = State::new(&env).unwrap();
        (dir, env, state)
    }

    fn seed_utxo_set(env: &Env, state: &State, utxos: &[PointedOutput]) {
        let mut accumulator = Accumulator::default();
        let mut accumulator_diff = AccumulatorDiff::default();
        let mut rwtxn = env.write_txn().unwrap();
        for pointed_output in utxos {
            state
                .utxos
                .put(
                    &mut rwtxn,
                    &OutPointKey::from(&pointed_output.outpoint),
                    &pointed_output.output,
                )
                .unwrap();
            accumulator_diff.insert(pointed_output.into());
        }
        accumulator.apply_diff(accumulator_diff).unwrap();
        state
            .utreexo_accumulator
            .put(&mut rwtxn, &(), &accumulator)
            .unwrap();
        rwtxn.commit().unwrap();
    }

    #[test]
    fn apply_block_accepts_outpoint_hash_mismatch_and_corrupts_accumulator() {
        let (_dir, env, state) = test_state();
        let signing_key_a = SigningKey::from_bytes(&[1u8; 32]);
        let address_a = get_address(&signing_key_a.verifying_key());

        let outpoint_a = OutPoint::Regular {
            txid: Txid([1u8; 32]),
            vout: 0,
        };
        let output_a = Output {
            address: address_a,
            content: OutputContent::Value(sat(10_000)),
        };
        let pointed_a = PointedOutput {
            outpoint: outpoint_a,
            output: output_a.clone(),
        };

        let outpoint_b = OutPoint::Regular {
            txid: Txid([2u8; 32]),
            vout: 0,
        };
        let output_b = Output {
            address: Address([2u8; 20]),
            content: OutputContent::Value(sat(20_000)),
        };
        let pointed_b = PointedOutput {
            outpoint: outpoint_b,
            output: output_b.clone(),
        };
        seed_utxo_set(&env, &state, &[pointed_a.clone(), pointed_b.clone()]);

        let rotxn = env.read_txn().unwrap();
        let proof_for_b = state
            .get_utreexo_proof(&rotxn, std::iter::once(&pointed_b))
            .unwrap();
        let utxo_hash_b = hash(&pointed_b);
        drop(rotxn);

        let transaction = Transaction {
            inputs: vec![(outpoint_a, utxo_hash_b)],
            proof: proof_for_b,
            outputs: vec![Output {
                address: address_a,
                content: OutputContent::Value(sat(9_000)),
            }],
            data: TxData::Regular,
        };
        let authorized_transaction =
            authorize(&[(address_a, &signing_key_a)], transaction).unwrap();
        let body = Body::new(vec![authorized_transaction], vec![]);

        let filled_transaction = FilledTransaction {
            transaction: body.transactions[0].clone(),
            spent_utxos: vec![output_a.clone()],
        };
        let rotxn = env.read_txn().unwrap();
        let mut header_accumulator = state.get_accumulator(&rotxn).unwrap();
        let merkle_root = Body::modify_memforest(
            &body.coinbase,
            &[filled_transaction],
            &mut header_accumulator.0,
        )
        .unwrap();
        let header = Header {
            merkle_root,
            prev_side_hash: None,
            prev_main_hash: bitcoin::BlockHash::all_zeros(),
            roots: header_accumulator.get_roots(),
        };
        drop(rotxn);

        let mut rwtxn = env.write_txn().unwrap();
        state.apply_block(&mut rwtxn, &header, &body).unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        assert!(
            state
                .utxos
                .try_get(&rotxn, &OutPointKey::from(&outpoint_a))
                .unwrap()
                .is_none(),
            "the DB spent outpoint A"
        );
        assert_eq!(
            state
                .utxos
                .try_get(&rotxn, &OutPointKey::from(&outpoint_b))
                .unwrap(),
            Some(output_b),
            "the DB still exposes outpoint B as unspent"
        );

        let accumulator = state.get_accumulator(&rotxn).unwrap();
        assert!(
            accumulator
                .prove(&[BitcoinNodeHash::from(&pointed_a)])
                .is_ok(),
            "outpoint A remains in the accumulator"
        );
        assert!(
            accumulator
                .prove(&[BitcoinNodeHash::from(&pointed_b)])
                .is_err(),
            "outpoint B was removed from the accumulator"
        );
    }

    #[test]
    fn mempool_validation_accepts_too_few_authorizations_but_block_validation_rejects()
     {
        let (_dir, env, state) = test_state();
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let address = get_address(&signing_key.verifying_key());

        let outpoint_a = OutPoint::Regular {
            txid: Txid([3u8; 32]),
            vout: 0,
        };
        let output_a = Output {
            address,
            content: OutputContent::Value(sat(10_000)),
        };
        let pointed_a = PointedOutput {
            outpoint: outpoint_a,
            output: output_a,
        };
        let outpoint_b = OutPoint::Regular {
            txid: Txid([4u8; 32]),
            vout: 0,
        };
        let output_b = Output {
            address,
            content: OutputContent::Value(sat(10_000)),
        };
        let pointed_b = PointedOutput {
            outpoint: outpoint_b,
            output: output_b,
        };
        seed_utxo_set(&env, &state, &[pointed_a.clone(), pointed_b.clone()]);

        let rotxn = env.read_txn().unwrap();
        let proof = state
            .get_utreexo_proof(&rotxn, [&pointed_a, &pointed_b])
            .unwrap();
        drop(rotxn);

        let transaction = Transaction {
            inputs: vec![
                (outpoint_a, hash(&pointed_a)),
                (outpoint_b, hash(&pointed_b)),
            ],
            proof,
            outputs: vec![Output {
                address,
                content: OutputContent::Value(sat(19_000)),
            }],
            data: TxData::Regular,
        };
        let authorized_transaction =
            authorize(&[(address, &signing_key)], transaction).unwrap();

        assert_eq!(authorized_transaction.transaction.inputs.len(), 2);
        assert_eq!(authorized_transaction.authorizations.len(), 1);

        let rotxn = env.read_txn().unwrap();
        assert!(
            state
                .validate_transaction(&rotxn, &authorized_transaction)
                .is_ok(),
            "transaction-level validation accepts one signature for two inputs"
        );
        drop(rotxn);

        let body = Body::new(vec![authorized_transaction], vec![]);
        assert!(
            Authorization::verify_body(&body).is_err(),
            "block-level authorization validation rejects the same transaction"
        );
    }

    #[test]
    fn swap_claim_can_spend_unlocked_swap_pending_input_without_owner_signature()
     {
        let (_dir, env, state) = test_state();
        let attacker_key = SigningKey::from_bytes(&[5u8; 32]);
        let attacker_address = get_address(&attacker_key.verifying_key());
        let victim_address = Address([6u8; 20]);
        let swap_id = SwapId([7u8; 32]);

        let locked_outpoint = OutPoint::Regular {
            txid: Txid([8u8; 32]),
            vout: 0,
        };
        let locked_output = Output {
            address: attacker_address,
            content: OutputContent::SwapPending {
                value: sat(10_000),
                swap_id: swap_id.0,
            },
        };
        let locked_pointed = PointedOutput {
            outpoint: locked_outpoint,
            output: locked_output.clone(),
        };

        let victim_outpoint = OutPoint::Regular {
            txid: Txid([9u8; 32]),
            vout: 0,
        };
        let victim_output = Output {
            address: victim_address,
            content: OutputContent::SwapPending {
                value: sat(10_000),
                swap_id: [9u8; 32],
            },
        };
        let victim_pointed = PointedOutput {
            outpoint: victim_outpoint,
            output: victim_output.clone(),
        };

        seed_utxo_set(
            &env,
            &state,
            &[locked_pointed.clone(), victim_pointed.clone()],
        );
        let mut rwtxn = env.write_txn().unwrap();
        let mut swap = Swap::new(
            swap_id,
            SwapDirection::L2ToL1,
            ParentChainType::Regtest,
            SwapTxId::from_bytes(&[1u8; 32]),
            Some(1),
            Some(attacker_address),
            sat(5_000),
            "bcrt1qattacker".to_owned(),
            sat(5_000),
            0,
            Some(50),
            Some(attacker_address),
        );
        swap.state = SwapState::ReadyToClaim;
        state.save_swap(&mut rwtxn, &swap).unwrap();
        state
            .lock_output_to_swap(&mut rwtxn, &locked_outpoint, &swap_id)
            .unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        let proof = state
            .get_utreexo_proof(&rotxn, [&locked_pointed, &victim_pointed])
            .unwrap();
        drop(rotxn);

        let transaction = Transaction {
            inputs: vec![
                (locked_outpoint, hash(&locked_pointed)),
                (victim_outpoint, hash(&victim_pointed)),
            ],
            proof,
            outputs: vec![Output {
                address: attacker_address,
                content: OutputContent::Value(sat(19_000)),
            }],
            data: TxData::SwapClaim {
                swap_id: swap_id.0,
                l2_claimer_address: None,
                proof_data: None,
            },
        };
        let authorized_transaction = authorize(
            &[
                (attacker_address, &attacker_key),
                (attacker_address, &attacker_key),
            ],
            transaction,
        )
        .unwrap();
        let body = Body::new(vec![authorized_transaction], vec![]);

        let filled_transaction = FilledTransaction {
            transaction: body.transactions[0].clone(),
            spent_utxos: vec![locked_output, victim_output.clone()],
        };
        let rotxn = env.read_txn().unwrap();
        let mut header_accumulator = state.get_accumulator(&rotxn).unwrap();
        let merkle_root = Body::modify_memforest(
            &body.coinbase,
            &[filled_transaction],
            &mut header_accumulator.0,
        )
        .unwrap();
        let header = Header {
            merkle_root,
            prev_side_hash: None,
            prev_main_hash: bitcoin::BlockHash::all_zeros(),
            roots: header_accumulator.get_roots(),
        };
        drop(rotxn);

        let mut rwtxn = env.write_txn().unwrap();
        state.apply_block(&mut rwtxn, &header, &body).unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        assert!(
            state
                .utxos
                .try_get(&rotxn, &OutPointKey::from(&victim_outpoint))
                .unwrap()
                .is_none(),
            "victim's unlocked SwapPending output was spent"
        );
        assert_eq!(
            state
                .stxos
                .try_get(&rotxn, &OutPointKey::from(&victim_outpoint))
                .unwrap()
                .unwrap()
                .output,
            victim_output
        );
    }

    #[test]
    fn swap_claim_completes_pending_swap_without_ready_to_claim_state() {
        let (_dir, env, state) = test_state();
        let creator_key = SigningKey::from_bytes(&[13u8; 32]);
        let creator_address = get_address(&creator_key.verifying_key());
        let recipient_key = SigningKey::from_bytes(&[14u8; 32]);
        let recipient_address = get_address(&recipient_key.verifying_key());
        let swap_id = SwapId([15u8; 32]);

        let locked_outpoint = OutPoint::Regular {
            txid: Txid([16u8; 32]),
            vout: 0,
        };
        let locked_output = Output {
            address: creator_address,
            content: OutputContent::SwapPending {
                value: sat(10_000),
                swap_id: swap_id.0,
            },
        };
        let locked_pointed = PointedOutput {
            outpoint: locked_outpoint,
            output: locked_output.clone(),
        };
        seed_utxo_set(&env, &state, std::slice::from_ref(&locked_pointed));

        let mut rwtxn = env.write_txn().unwrap();
        let swap = Swap::new(
            swap_id,
            SwapDirection::L2ToL1,
            ParentChainType::Regtest,
            SwapTxId::from_bytes(&[1u8; 32]),
            Some(1),
            Some(recipient_address),
            sat(10_000),
            "bcrt1ql1recipient".to_owned(),
            sat(5_000),
            0,
            Some(50),
            Some(creator_address),
        );
        assert!(matches!(swap.state, SwapState::Pending));
        state.save_swap(&mut rwtxn, &swap).unwrap();
        state
            .lock_output_to_swap(&mut rwtxn, &locked_outpoint, &swap_id)
            .unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        let proof = state
            .get_utreexo_proof(&rotxn, std::iter::once(&locked_pointed))
            .unwrap();
        drop(rotxn);

        let transaction = Transaction {
            inputs: vec![(locked_outpoint, hash(&locked_pointed))],
            proof,
            outputs: vec![Output {
                address: recipient_address,
                content: OutputContent::Value(sat(10_000)),
            }],
            data: TxData::SwapClaim {
                swap_id: swap_id.0,
                l2_claimer_address: None,
                proof_data: None,
            },
        };
        let authorized_transaction =
            authorize(&[(recipient_address, &recipient_key)], transaction)
                .unwrap();
        let body = Body::new(vec![authorized_transaction], vec![]);

        let filled_transaction = FilledTransaction {
            transaction: body.transactions[0].clone(),
            spent_utxos: vec![locked_output],
        };
        let rotxn = env.read_txn().unwrap();
        let mut header_accumulator = state.get_accumulator(&rotxn).unwrap();
        let merkle_root = Body::modify_memforest(
            &body.coinbase,
            &[filled_transaction],
            &mut header_accumulator.0,
        )
        .unwrap();
        let header = Header {
            merkle_root,
            prev_side_hash: None,
            prev_main_hash: bitcoin::BlockHash::all_zeros(),
            roots: header_accumulator.get_roots(),
        };
        drop(rotxn);

        let mut rwtxn = env.write_txn().unwrap();
        state.apply_block(&mut rwtxn, &header, &body).unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        assert!(
            state
                .utxos
                .try_get(&rotxn, &OutPointKey::from(&locked_outpoint))
                .unwrap()
                .is_none(),
            "locked swap output was spent"
        );
        let completed = state.get_swap(&rotxn, &swap_id).unwrap().unwrap();
        assert!(
            matches!(completed.state, SwapState::Completed),
            "pending swap was advanced and completed by the block"
        );
    }

    #[test]
    fn swap_create_accepts_arbitrary_l1_txid_and_populates_uniqueness_index() {
        let (_dir, env, state) = test_state();
        let creator_key = SigningKey::from_bytes(&[10u8; 32]);
        let creator_address = get_address(&creator_key.verifying_key());
        let l2_recipient = Address([11u8; 20]);
        let parent_chain = ParentChainType::Regtest;
        let l1_recipient_address = "bcrt1qrecipient".to_owned();
        let l1_amount = sat(5_000);
        let l2_amount = sat(10_000);
        let poisoned_l1_txid = [42u8; 32];
        let swap_id = SwapId::from_l2_to_l1(
            &l1_recipient_address,
            l1_amount,
            &creator_address,
            Some(&l2_recipient),
        );

        let funding_outpoint = OutPoint::Regular {
            txid: Txid([12u8; 32]),
            vout: 0,
        };
        let funding_output = Output {
            address: creator_address,
            content: OutputContent::Value(sat(11_000)),
        };
        let funding_pointed = PointedOutput {
            outpoint: funding_outpoint,
            output: funding_output.clone(),
        };
        seed_utxo_set(&env, &state, &[funding_pointed.clone()]);

        let rotxn = env.read_txn().unwrap();
        let proof = state
            .get_utreexo_proof(&rotxn, std::iter::once(&funding_pointed))
            .unwrap();
        drop(rotxn);

        let transaction = Transaction {
            inputs: vec![(funding_outpoint, hash(&funding_pointed))],
            proof,
            outputs: vec![Output {
                address: l2_recipient,
                content: OutputContent::SwapPending {
                    value: l2_amount,
                    swap_id: swap_id.0,
                },
            }],
            data: TxData::SwapCreate {
                swap_id: swap_id.0,
                parent_chain,
                l1_txid_bytes: poisoned_l1_txid.to_vec(),
                required_confirmations: 1,
                l2_recipient: Some(l2_recipient),
                l2_amount: l2_amount.to_sat(),
                l1_recipient_address: l1_recipient_address.clone(),
                l1_amount: l1_amount.to_sat(),
            },
        };
        let authorized_transaction =
            authorize(&[(creator_address, &creator_key)], transaction).unwrap();
        let body = Body::new(vec![authorized_transaction], vec![]);

        let filled_transaction = FilledTransaction {
            transaction: body.transactions[0].clone(),
            spent_utxos: vec![funding_output],
        };
        let rotxn = env.read_txn().unwrap();
        let mut header_accumulator = state.get_accumulator(&rotxn).unwrap();
        let merkle_root = Body::modify_memforest(
            &body.coinbase,
            &[filled_transaction],
            &mut header_accumulator.0,
        )
        .unwrap();
        let header = Header {
            merkle_root,
            prev_side_hash: None,
            prev_main_hash: bitcoin::BlockHash::all_zeros(),
            roots: header_accumulator.get_roots(),
        };
        drop(rotxn);

        let mut rwtxn = env.write_txn().unwrap();
        state.apply_block(&mut rwtxn, &header, &body).unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        let indexed = state
            .get_swap_by_l1_txid(
                &rotxn,
                &parent_chain,
                &SwapTxId::from_bytes(&poisoned_l1_txid),
            )
            .unwrap()
            .expect("poisoned l1 txid should be indexed");
        assert_eq!(indexed.id, swap_id);
        assert_eq!(indexed.l1_txid, SwapTxId::from_bytes(&poisoned_l1_txid));
    }

    #[test]
    fn swap_create_can_advertise_l2_amount_without_locked_escrow_output() {
        let (_dir, env, state) = test_state();
        let creator_key = SigningKey::from_bytes(&[13u8; 32]);
        let creator_address = get_address(&creator_key.verifying_key());
        let l2_recipient = Address([14u8; 20]);
        let parent_chain = ParentChainType::Regtest;
        let l1_recipient_address = "bcrt1qrecipient-no-escrow".to_owned();
        let l1_amount = sat(5_000);
        let l2_amount = sat(10_000);
        let swap_id = SwapId::from_l2_to_l1(
            &l1_recipient_address,
            l1_amount,
            &creator_address,
            Some(&l2_recipient),
        );

        let funding_outpoint = OutPoint::Regular {
            txid: Txid([15u8; 32]),
            vout: 0,
        };
        let funding_output = Output {
            address: creator_address,
            content: OutputContent::Value(l2_amount),
        };
        let funding_pointed = PointedOutput {
            outpoint: funding_outpoint,
            output: funding_output.clone(),
        };
        seed_utxo_set(&env, &state, &[funding_pointed.clone()]);

        let rotxn = env.read_txn().unwrap();
        let proof = state
            .get_utreexo_proof(&rotxn, std::iter::once(&funding_pointed))
            .unwrap();
        drop(rotxn);

        let transaction = Transaction {
            inputs: vec![(funding_outpoint, hash(&funding_pointed))],
            proof,
            outputs: vec![Output {
                address: creator_address,
                content: OutputContent::Value(l2_amount),
            }],
            data: TxData::SwapCreate {
                swap_id: swap_id.0,
                parent_chain,
                l1_txid_bytes: [0u8; 32].to_vec(),
                required_confirmations: 1,
                l2_recipient: Some(l2_recipient),
                l2_amount: l2_amount.to_sat(),
                l1_recipient_address,
                l1_amount: l1_amount.to_sat(),
            },
        };
        let authorized_transaction =
            authorize(&[(creator_address, &creator_key)], transaction).unwrap();
        let body = Body::new(vec![authorized_transaction], vec![]);

        let filled_transaction = FilledTransaction {
            transaction: body.transactions[0].clone(),
            spent_utxos: vec![funding_output],
        };
        let rotxn = env.read_txn().unwrap();
        let mut header_accumulator = state.get_accumulator(&rotxn).unwrap();
        let merkle_root = Body::modify_memforest(
            &body.coinbase,
            &[filled_transaction],
            &mut header_accumulator.0,
        )
        .unwrap();
        let header = Header {
            merkle_root,
            prev_side_hash: None,
            prev_main_hash: bitcoin::BlockHash::all_zeros(),
            roots: header_accumulator.get_roots(),
        };
        drop(rotxn);

        let mut rwtxn = env.write_txn().unwrap();
        state.apply_block(&mut rwtxn, &header, &body).unwrap();
        rwtxn.commit().unwrap();

        let rotxn = env.read_txn().unwrap();
        let saved_swap = state.get_swap(&rotxn, &swap_id).unwrap().unwrap();
        assert_eq!(saved_swap.l2_amount, l2_amount);
        let output_outpoint = OutPoint::Regular {
            txid: body.transactions[0].txid(),
            vout: 0,
        };
        assert_eq!(
            state
                .is_output_locked_to_swap(&rotxn, &output_outpoint)
                .unwrap(),
            None,
            "SwapCreate was accepted but no output was escrow-locked to the swap"
        );
    }
}
