use ckicp_minter::crypto::*;
use ckicp_minter::memory::*;
use ckicp_minter::tecdsa::{ECDSAPublicKeyReply, ManagementCanister, SignWithECDSAReply};
use ckicp_minter::utils::*;

use candid::{CandidType, Nat};

use ic_cdk_macros::{init, post_upgrade, query, update};

use rustic::access_control::*;
use rustic::inter_canister::*;

use rustic::reentrancy_guard::*;
use rustic::types::*;
use rustic::utils::*;
use rustic_macros::modifiers;

use sha3::Keccak256;

use std::convert::From;
use std::str::FromStr;
use std::time::Duration;

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use evm_rpc_types::{
    Block, BlockTag, ConsensusStrategy, GetLogsArgs, GetLogsRpcConfig, Hex20, Hex32,
    HttpOutcallError, LogEntry, MultiRpcResult, RpcConfig, RpcError, RpcServices,
};

use icrc_ledger_types::icrc1;

type Amount = u64;
type MsgId = u128;

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ReturnError {
    GenericError,
    InputError,
    Unauthorized,
    Expired,
    InterCanisterCallError(String),
    TecdsaSignatureError(String),
    CryptoError,
    EventSeen,
    MemoryError,
    TransferError(String),
    EvmRpcError(RpcError),
    EvmRpcInconsistent(String),
    OutOfMemory,
    MaxResponseBytesExceeded,
    MaxResponseBytesNotEnoughForBlock(u64),
}

#[init]
pub fn init() {
    rustic::rustic_init();
}

#[post_upgrade]
pub fn post_upgrade() {
    rustic::rustic_post_upgrade(false, false, false);

    // post upgrade code for your canister
}

#[query]
#[modifiers("only_owner")]
pub fn get_config() -> CkicpConfig {
    get_ckicp_config()
}

fn get_ckicp_config() -> CkicpConfig {
    CKICP_CONFIG.with(|ckicp_config| {
        let ckicp_config = ckicp_config.borrow();
        ckicp_config.get().0.clone().unwrap()
    })
}

#[query]
pub fn get_ckicp_state() -> CkicpState {
    CKICP_STATE.with(|ckicp_state| {
        let ckicp_state = ckicp_state.borrow();
        ckicp_state.get().0.clone().unwrap_or_default()
    })
}

#[query]
pub fn get_nonce() -> u32 {
    let caller = ic_cdk::caller();
    let caller_subaccount = subaccount_from_principal(&caller);
    NONCE_MAP.with(|nonce_map| {
        let nonce_map = nonce_map.borrow();
        nonce_map.get(&caller_subaccount).unwrap_or(0)
    })
}

// The following defines log level.
#[derive(Copy, Clone, Debug)]
pub enum LogLevel {
    ERROR = 0,
    WARN = 1,
    INFO = 2,
    DEBUG = 3,
}

use LogLevel::*;

#[derive(Clone, CandidType, serde::Deserialize)]
pub struct LogView {
    from: Option<u64>,
    to: Option<u64>,
}

/// View debug logs in the given range (not including 'to').
/// If 'from' is missing, 0 is used.
/// If 'to' is missing, current length of all logs is used.
#[query]
#[modifiers("only_owner")]
pub async fn view_debug_log(view: LogView) -> Vec<String> {
    let debug_log_len = DEBUG_LOG.with(|log| log.borrow().len());
    let from = view.from.unwrap_or_default();
    let to = view.to.unwrap_or(debug_log_len).min(debug_log_len);
    let mut logs = Vec::new();
    DEBUG_LOG.with(|log| {
        let debug_log = log.borrow();
        for i in from..to {
            logs.push(debug_log.get(i).clone().unwrap_or_default())
        }
    });
    logs
}

/// Add a line of given log level to the debug log, only when
/// the given level is smaller than or equal to config.debug_log_level.
pub fn debug_log(level: LogLevel, line: String) -> Result<(), ReturnError> {
    let config = get_ckicp_config();
    if (level as u8) <= config.debug_log_level {
        DEBUG_LOG.with(|log| {
            log.borrow()
                .append(&format!(
                    "{} {:?} {}",
                    canister_time() / 1_000_000,
                    level,
                    line
                ))
                .map(|_| ())
                .map_err(|_| ReturnError::OutOfMemory)
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, CandidType, serde::Deserialize)]
pub struct SelfMintArgs {
    amount: u64,
    to: String,
    msgid: u128,
    expiry: u64,
    signature: String,
}

/// Nonce starts at 1 and is incremented for each call to mint_ckicp
/// MsgId is deterministically computed as xor_nibbles(keccak256(caller, nonce))
/// and does not need to be returned.
/// ~~ICP is transferred using ICRC-2 approved transfer~~
/// User needs to call `get_funding_subaccount` and transfer ICP to the returned subaccount of this canister first.
/// The amount of ICP transferred must be at least `amount + ICP tx fee`.
#[update]
pub async fn mint_ckicp(
    _from_subaccount: icrc1::account::Subaccount,
    amount: Amount,
    target_eth_wallet: String,
) -> Result<SelfMintArgs, ReturnError> {
    let _guard = ReentrancyGuard::new();
    let caller = canister_caller();
    let caller_subaccount = subaccount_from_principal(&caller);

    let nonce = NONCE_MAP.with(|nonce_map| {
        let mut nonce_map = nonce_map.borrow_mut();
        let nonce = nonce_map.get(&caller_subaccount).unwrap_or(0) + 1;
        nonce_map.insert(caller_subaccount, nonce);
        nonce
    });
    let msg_id = calc_msgid(&caller_subaccount, nonce);
    let config: CkicpConfig = get_ckicp_config();
    let now = canister_time();
    let expiry = now / 1_000_000_000 + config.expiry_seconds;

    fn update_status(msg_id: MsgId, amount: Amount, expiry: u64, state: MintState) {
        STATUS_MAP.with(|sm| {
            let mut sm = sm.borrow_mut();
            sm.insert(
                msg_id,
                MintStatus {
                    amount,
                    expiry,
                    state,
                },
            );
        });
    }

    update_status(msg_id, amount, expiry, MintState::Init);

    // ICRC-1 transfer
    let tx_args = icrc1::transfer::TransferArg {
        from_subaccount: Some(caller_subaccount),
        to: icrc1::account::Account {
            owner: canister_id(),
            subaccount: None,
        },
        fee: None,
        created_at_time: Some(ic_cdk::api::time()),
        memo: Some(icrc1::transfer::Memo::from(msg_id.to_be_bytes().to_vec())),
        amount: Nat::from(amount),
    };
    let tx_result: Result<Nat, icrc1::transfer::TransferError> = canister_call(
        config.ledger_canister_id,
        "icrc1_transfer",
        tx_args,
        candid::encode_one,
        |r| candid::decode_one(r),
    )
    .await
    .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;

    match tx_result {
        Ok(_) => {
            update_status(msg_id, amount, expiry, MintState::FundReceived);
        }
        Err(err) => return Err(ReturnError::TransferError(format!("{:?}", err))),
    }

    // ICRC-2 transfer -> not yet available on ICP ledger
    // When ICRC-2 becomes available, uncomment the following block (and handle icrc-1 tx failure differently)

    // if icrc1_tx_failed {
    //     let tx_args = icrc2::transfer_from::TransferFromArgs {
    //         spender_subaccount: None,
    //         from: icrc1::account::Account {
    //             owner: caller,
    //             subaccount: Some(from_subaccount),
    //         },
    //         to: icrc1::account::Account {
    //             owner: canister_id(),
    //             subaccount: None,
    //         },
    //         amount: Nat::from(amount),
    //         fee: None,
    //         memo: Some(icrc1::transfer::Memo::from(msg_id.to_be_bytes().to_vec())),
    //         created_at_time: Some(now),
    //     };
    //     let tx_result: Result<Nat, icrc2::transfer_from::TransferFromError> = canister_call(
    //         config.ledger_canister_id,
    //         "icrc2_transfer_from",
    //         tx_args,
    //         candid::encode_one,
    //         |r| candid::decode_one(r),
    //     )
    //     .await
    //     .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;

    //     match tx_result {
    //         Ok(_) => {
    //             update_status(msg_id, amount, expiry, MintState::FundReceived);
    //         }
    //         Err(err) => return Err(ReturnError::TransferError(format!("{:?}", err))),
    //     }
    // }

    // Generate tECDSA signature
    // payload is (amount, to, msgId, expiry, chainId, ckicp_eth_address), 32 bytes each
    let amount_to_transfer = amount;
    let ckicp_eth_address = hex_decode_0x(&config.ckicp_eth_erc20_address).unwrap();

    let mut payload_to_sign: [u8; 192] = [0; 192];
    payload_to_sign[24..32].copy_from_slice(&amount_to_transfer.to_be_bytes());
    payload_to_sign[44..64].copy_from_slice(&hex_decode_0x_fixed_length(&target_eth_wallet, 20));
    payload_to_sign[80..96].copy_from_slice(&msg_id.to_be_bytes());
    payload_to_sign[120..128].copy_from_slice(&expiry.to_be_bytes());
    payload_to_sign[152..160].copy_from_slice(&config.target_chain_ids[0].to_be_bytes());
    payload_to_sign[172..192].copy_from_slice(&ckicp_eth_address);

    use sha3::Digest;
    let mut hasher = Keccak256::new();
    hasher.update(payload_to_sign);
    let hashed = hasher.finalize();
    let digest = hashed.to_vec();

    let signature: Vec<u8> = {
        let (res,): (SignWithECDSAReply,) =
            ManagementCanister::sign(&config.ecdsa_key_name, digest)
                .await
                .map_err(|err| ReturnError::TecdsaSignatureError(err.1))?;
        res.signature
    };

    // Calculate `v`
    let sec1_public_key = CKICP_STATE.with(|ckicp_state| {
        let ckicp_state = ckicp_state.borrow();
        let ckicp_state = ckicp_state.get().0.clone().unwrap();
        ckicp_state.tecdsa_pubkey
    });
    let public_key = VerifyingKey::from_sec1_bytes(&sec1_public_key).unwrap();

    let recid = RecoveryId::trial_recovery_from_prehash(
        &public_key,
        &hashed,
        &Signature::from_slice(signature.as_slice()).unwrap(),
    )
    .unwrap();

    let v = recid.is_y_odd() as u8 + 27;

    // Add signature to map for future queries
    SIGNATURE_MAP.with(|sm| {
        let mut sm = sm.borrow_mut();
        sm.insert(msg_id, EcdsaSignature::from_signature_v(&signature, v));
    });

    update_status(msg_id, amount, expiry, MintState::Signed);

    // Return tECDSA signature
    Ok(SelfMintArgs {
        amount: amount_to_transfer,
        to: target_eth_wallet,
        msgid: msg_id,
        expiry,
        signature: EcdsaSignature::from_signature_v(&signature, v).to_string(),
    })
}

async fn eth_block_number(block_tag: BlockTag, cycles: u128) -> Result<u64, ReturnError> {
    let config: CkicpConfig = get_ckicp_config();
    let rpc_config = RpcConfig {
        response_consensus: Some(ConsensusStrategy::Threshold {
            min: 2,
            total: Some(3),
        }),
        ..RpcConfig::default()
    };
    let result: Result<MultiRpcResult<Block>, _> = canister_call_with_payment(
        config.eth_rpc_canister_id,
        "eth_getBlockByNumber",
        (RpcServices::EthMainnet(None), Some(rpc_config), block_tag),
        candid::encode_args,
        |r| candid::decode_one(r),
        cycles,
    )
    .await;
    match result {
        Ok(MultiRpcResult::Consistent(result)) => result
            .map(|block| block.number.try_into().unwrap_or(0u64))
            .map_err(ReturnError::EvmRpcError),
        Ok(MultiRpcResult::Inconsistent(results)) => {
            Err(ReturnError::EvmRpcInconsistent(format!("{:?}", results)))
        }
        Err((err_code, err_msg)) => {
            let err = format!("{{code: {:?}, message: {}}}", err_code, err_msg);
            debug_log(DEBUG, format!("Received error {}", err))?;
            Err(ReturnError::InterCanisterCallError(err))
        }
    }
}

async fn eth_get_logs(
    from_block: BlockTag,
    to_block: BlockTag,
    cycles: u128,
) -> Result<Vec<LogEntry>, ReturnError> {
    let config: CkicpConfig = get_ckicp_config();
    let rpc_config = GetLogsRpcConfig {
        response_consensus: Some(ConsensusStrategy::Threshold {
            min: 2,
            total: Some(3),
        }),
        ..GetLogsRpcConfig::default()
    };
    let address = Hex20::from_str(&config.ckicp_eth_erc20_address).unwrap();
    let topics = config
        .ckicp_getlogs_topics
        .iter()
        .map(|s| Hex32::from_str(s).unwrap())
        .collect::<Vec<_>>();

    let args = GetLogsArgs {
        addresses: vec![address],
        from_block: Some(from_block),
        to_block: Some(to_block),
        topics: Some(vec![topics]),
    };
    let result: Result<MultiRpcResult<Vec<LogEntry>>, _> = canister_call_with_payment(
        config.eth_rpc_canister_id,
        "eth_getLogs",
        (RpcServices::EthMainnet(None), Some(rpc_config), args),
        candid::encode_args,
        |r| candid::decode_one(r),
        cycles,
    )
    .await;
    match result {
        Ok(MultiRpcResult::Consistent(result)) => result.map_err(ReturnError::EvmRpcError),
        Ok(MultiRpcResult::Inconsistent(results)) => {
            Err(ReturnError::EvmRpcInconsistent(format!("{:?}", results)))
        }
        Err((err_code, err_msg)) => {
            let err = format!("{{code: {:?}, message: {}}}", err_code, err_msg);
            debug_log(DEBUG, format!("Received error {}", err))?;
            Err(ReturnError::InterCanisterCallError(err))
        }
    }
}

/// Look up ethereum event log of the given block for Burn events.
/// Process those that have not yet been processed.
///
/// This is can only be called by owner and only meant for debugging purposes.
#[update]
#[modifiers("only_owner")]
pub async fn process_block(block_height: u64) -> Result<(), ReturnError> {
    let config = get_config();
    let logs = eth_get_logs(
        BlockTag::Number(block_height.into()),
        BlockTag::Number(block_height.into()),
        config.cycle_cost_of_eth_getlogs,
    )
    .await?;
    process_logs(logs).await
}

/// Given some event logs, process burn events in them.
async fn process_logs(entries: Vec<LogEntry>) -> Result<(), ReturnError> {
    debug_log(DEBUG, format!("Processing {} log entries", entries.len()))?;
    for entry in entries {
        let event_id = EventId::from_entry(&entry).unwrap();
        match parse_burn_event(&entry) {
            Ok(burn) => {
                if let Err(err) = release_icp(burn.clone(), event_id).await {
                    debug_log(
                        DEBUG,
                        format!(
                            "Error {:?} in releasing ICP {} of event {:?}",
                            err, burn, event_id
                        ),
                    )?;
                } else {
                    debug_log(
                        DEBUG,
                        format!("Processed transfer {} of event {:?}", burn, event_id),
                    )?;
                }
            }
            Err(err) => {
                // parsing error? unknown event type? They should be investigated!
                debug_log(
                    WARN,
                    format!(
                        "Skip processing event {:?} due to error {:?}",
                        event_id, err,
                    ),
                )?;
            }
        }
    }

    Ok(())
}

/// Sync event logs of the ckICP ERC-20 contract via RPC.
/// This is meant to be called from a timer.
pub async fn sync_event_logs() -> Result<(), ReturnError> {
    let _guard = ReentrancyGuard::new();
    // get log events from block with the given block_hash
    // NOTE: if log exceeds pre-allocated space, we need manual intervention.
    let config: CkicpConfig = get_ckicp_config();
    let mut state: CkicpState = get_ckicp_state();
    let last_block = BlockTag::Number((state.last_block + 1).into());
    let next_block = state
        .next_block
        .take()
        .map(|x| BlockTag::Number(x.into()))
        .unwrap_or(BlockTag::Safe);
    match eth_get_logs(
        last_block.clone(),
        next_block.clone(),
        config.cycle_cost_of_eth_getlogs,
    )
    .await
    {
        Err(ReturnError::EvmRpcError(RpcError::HttpOutcallError(HttpOutcallError::IcError {
            code: _,
            message,
        }))) if message.contains("size limit") || message.contains("length limit") => {
            debug_log(
                WARN,
                format!(
                    "RPC result exceeds buffer size limit, trying to halve range [{:?}, {:?})",
                    last_block, next_block,
                ),
            )?;
            let next = match &next_block {
                BlockTag::Number(next) => u64::try_from(next.clone()).unwrap(),
                _ => {
                    let block_number =
                        eth_block_number(BlockTag::Safe, config.cycle_cost_of_eth_blocknumber)
                            .await?;
                    debug_log(
                        INFO,
                        format!("Received latest block number {:?}", block_number),
                    )?;
                    block_number
                }
            };
            let last_block = (next - state.last_block) / 2 + state.last_block;
            if last_block == state.last_block + 1 {
                return Err(ReturnError::MaxResponseBytesNotEnoughForBlock(last_block));
            }

            CKICP_STATE.with(|ckicp_state| {
                let mut ckicp_state = ckicp_state.borrow_mut();
                let mut state = ckicp_state.get().0.clone();
                if let Some(s) = state.as_mut() {
                    s.next_block = Some(last_block);
                };
                ckicp_state.set(Cbor(state)).unwrap();
            });
            Err(ReturnError::MaxResponseBytesExceeded)
        }
        Err(err) => Err(err)?,
        Ok(logs) => {
            // Find the highest block number from log, remember it in state so
            // that next time we fetch from this number onwards.
            let last_block = last_block_number_from_event_logs(&logs);
            // process_logs(logs).await?;
            CKICP_STATE.with(|ckicp_state| {
                let mut ckicp_state = ckicp_state.borrow_mut();
                let mut state = ckicp_state.get().0.clone();
                if let Some(s) = state.as_mut() {
                    if let Some(last_block) = s.next_block.take() {
                        s.last_block = last_block;
                    } else if let Some(last_block) = last_block {
                        s.last_block = last_block;
                    }
                }
                ckicp_state.set(Cbor(state)).unwrap();
            });
            Ok(())
        }
    }
}

/// The event_id needs to uniquely identify each burn event on Ethereum.
/// This allows the ETH State Sync canister to be stateless.
pub async fn release_icp(event: BurnEvent, event_id: EventId) -> Result<(), ReturnError> {
    let config: CkicpConfig = get_ckicp_config();

    // FIXME: should differentiate between event_seen and event_processed.
    // This is because the actual transfer could fail, which would leave us
    // with event_seen but fund not released. In such case, we should have
    // an option to re-try the transfer.
    let event_seen = EVENT_ID_MAP.with(|event_id_map| {
        let mut event_id_map = event_id_map.borrow_mut();
        if event_id_map.contains_key(&event_id.into()) {
            true
        } else {
            event_id_map.insert(event_id.into(), 1);
            false
        }
    });

    if event_seen {
        debug_log(
            DEBUG,
            format!("Event {:?} was seen. Skip releasing ICP", event_id),
        )?;
        return Err(ReturnError::EventSeen);
    }

    match event {
        BurnEvent::BurnToIcp(account, amount) => {
            if amount <= config.ckicp_fee {
                return Err(ReturnError::TransferError(format!(
                    "Amount must be greater than fee {}",
                    config.ckicp_fee
                )));
            }
            let amount = Nat::from(amount - config.ckicp_fee);
            let tx_args = icrc1::transfer::TransferArg {
                from_subaccount: None,
                to: account,
                amount,
                fee: None,
                memo: None,
                created_at_time: None,
            };
            debug_log(DEBUG, format!("Calling icrc1_transfer {:?}", tx_args))?;
            let tx_result: Result<Nat, icrc1::transfer::TransferError> = canister_call(
                config.ledger_canister_id,
                "icrc1_transfer",
                tx_args,
                candid::encode_one,
                |r| candid::decode_one(r),
            )
            .await
            .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;
            match tx_result {
                Ok(_) => Ok(()),
                Err(err) => Err(ReturnError::TransferError(format!("{:?}", err))),
            }
        }
        BurnEvent::BurnToIcpAccountId(account_id, amount) => {
            if amount <= config.ckicp_fee {
                return Err(ReturnError::TransferError(format!(
                    "Amount must be greater than fee {}",
                    config.ckicp_fee
                )));
            }
            let amount = ic_ledger_types::Tokens::from_e8s(amount - config.ckicp_fee);
            let tx_args = ic_ledger_types::TransferArgs {
                from_subaccount: None,
                to: account_id,
                amount,
                fee: ic_ledger_types::Tokens::from_e8s(config.ckicp_fee),
                memo: ic_ledger_types::Memo(0),
                created_at_time: None,
            };
            debug_log(DEBUG, format!("Calling transfer {:?}", tx_args))?;
            let tx_result: Result<u64, ic_ledger_types::TransferError> = canister_call(
                config.ledger_canister_id,
                "transfer",
                tx_args,
                candid::encode_one,
                |r| candid::decode_one(r),
            )
            .await
            .map_err(|err| ReturnError::InterCanisterCallError(format!("{:?}", err)))?;
            match tx_result {
                Ok(_) => Ok(()),
                Err(err) => Err(ReturnError::TransferError(format!("{:?}", err))),
            }
        }
    }
}

#[query]
pub fn get_signature(msg_id: MsgId) -> Option<EcdsaSignature> {
    SIGNATURE_MAP.with(|sm| {
        let sm = sm.borrow();
        sm.get(&msg_id)
    })
}

// Call sync_event_logs(), and if it requires re-run, call it again.
// Also log errors returned as warning.
async fn periodic_task() {
    loop {
        match sync_event_logs().await {
            Err(ReturnError::MaxResponseBytesExceeded) => (), // re-run
            Err(ReturnError::MaxResponseBytesNotEnoughForBlock(block)) => {
                // NOTE: This error requires a manual fix. We'll stop the timer first.
                debug_log(
                    ERROR,
                    format!("Block {} returns events exceeding max buffer size. It requires manual intervention!", block),
                ).unwrap();
                TIMER_ID.with(|id| {
                    if let Some(timer_id) = *id.borrow() {
                        ic_cdk_timers::clear_timer(timer_id);
                    }
                });
            }
            Err(err) => {
                debug_log(WARN, format!("sync_event_logs returns error {:?}", err)).unwrap();
                break;
            }
            Ok(_) => break,
        }
    }
}
#[update]
#[modifiers("only_owner")]
pub async fn debug_get_block_number() -> Result<u64, ReturnError> {
    let config = get_config();
    eth_block_number(BlockTag::Safe, config.cycle_cost_of_eth_blocknumber).await
}

#[update]
#[modifiers("only_owner")]
pub async fn debug_get_logs(from: u64, to: u64) -> Result<Vec<String>, ReturnError> {
    let config = get_config();
    eth_get_logs(
        BlockTag::Number(from.into()),
        BlockTag::Number(to.into()),
        config.cycle_cost_of_eth_getlogs,
    )
    .await
    .map(|entries| {
        entries
            .into_iter()
            .map(|entry| format!("{:?}", entry))
            .collect::<Vec<_>>()
    })
}

/// Set the configuration. Must be called at least once after deployment.
/// It also starts syncing of event logs on a timer, based on the given
/// configuration parameter.
#[update]
#[modifiers("only_owner")]
pub fn set_ckicp_config(config: CkicpConfig) -> Result<(), ReturnError> {
    CKICP_CONFIG
        .with(|ckicp_config| {
            let mut ckicp_config = ckicp_config.borrow_mut();
            ckicp_config.set(Cbor(Some(config)))
        })
        .map(|_| ())
        .map_err(|_| ReturnError::MemoryError)?;

    TIMER_ID.with(|id| {
        if let Some(timer_id) = *id.borrow() {
            ic_cdk_timers::clear_timer(timer_id);
        }
        let timer_id = ic_cdk_timers::set_timer_interval(
            Duration::from_secs(get_ckicp_config().sync_interval_secs),
            || ic_cdk::spawn(periodic_task()),
        );
        *id.borrow_mut() = Some(timer_id);
    });
    Ok(())
}

// Update pub key and last_block stored in state.
#[update]
#[modifiers("only_owner")]
pub async fn update_ckicp_state() -> Result<(), ReturnError> {
    let config: CkicpConfig = get_ckicp_config();
    let mut state: CkicpState = get_ckicp_state();
    state.last_block = config.last_synced_block_number;

    // Update tecdsa signer key and calculate signer ETH address
    let (res,): (ECDSAPublicKeyReply,) =
        ManagementCanister::ecdsa_public_key(&config.ecdsa_key_name, canister_id())
            .await
            .map_err(|err| ReturnError::TecdsaSignatureError(err.1))?;
    state.tecdsa_pubkey = res.public_key.clone();

    state.tecdsa_signer_address =
        ethereum_address_from_public_key(&res.public_key).map_err(|_| ReturnError::CryptoError)?;

    CKICP_STATE
        .with(|ckicp_state| {
            let mut ckicp_state = ckicp_state.borrow_mut();
            ckicp_state.set(Cbor(Some(state)))
        })
        .map(|_| ())
        .map_err(|_| ReturnError::MemoryError)
}

#[query]
pub fn get_funding_subaccount() -> icrc1::account::Subaccount {
    let caller = ic_cdk::api::caller();
    subaccount_from_principal(&caller)
}

#[query]
pub fn get_funding_account() -> String {
    let caller = ic_cdk::api::caller();
    icrc1::account::Account {
        owner: ic_cdk::api::id(),
        subaccount: Some(subaccount_from_principal(&caller)),
    }
    .to_string()
}

#[query]
pub fn get_tecdsa_signer_address_hex() -> String {
    let state: CkicpState = get_ckicp_state();
    hex_encode(&state.tecdsa_signer_address)
}

fn main() {}

#[cfg(any(target_arch = "wasm32", test))]
ic_cdk::export_candid!();
