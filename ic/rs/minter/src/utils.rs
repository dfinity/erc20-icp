use candid::CandidType;
use candid::Principal;
use ic_ledger_types::AccountIdentifier;
use icrc_ledger_types::icrc1::account::{Account, Subaccount};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// Decode hex string regardless of whether it has 0x as a prefix.
// Note that strings without 0x prefix is also treated as hex.
pub fn hex_decode_0x(s: &str) -> Option<Vec<u8>> {
    let s = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };
    // the 'hex' library doesn't handle odd number of digits, but we do.
    if s.len() & 1 == 1 {
        let mut t = "0".to_string();
        t.push_str(s);
        hex::decode(t).ok()
    } else {
        hex::decode(s).ok()
    }
}

// Decode hex string as u64 number.
pub fn hex_decode_0x_u64(s: &str) -> Option<u64> {
    let x = hex_decode_0x(s)?;
    let mut bytes = [0; 8];
    let len = x.len().min(8);
    // Not an u64 if leading bytes have non-zeros.
    if !x[..(x.len() - len)].iter().all(|x| *x == 0) {
        return None;
    }
    bytes[(8 - len)..].copy_from_slice(&x[(x.len() - len)..]);
    Some(u64::from_be_bytes(bytes))
}

// Decode hex string ignoring invalid characters, to a fixed byte length.
// Short strings are pre-padded with 0s, long strings are tail truncated.
// Decode hex string regardless of whether it has 0x as a prefix.
// Note that strings without 0x prefix is also treated as hex.
pub fn hex_decode_0x_fixed_length(s: &str, length_bytes: usize) -> Vec<u8> {
    let s = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };
    let mut cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    cleaned.truncate(2 * length_bytes);
    let zeros_needed = 2 * length_bytes - cleaned.len();
    if zeros_needed > 0 {
        let zeros = "0".repeat(zeros_needed);
        cleaned.insert_str(0, &zeros);
    }
    let mut result = Vec::with_capacity(length_bytes);
    for i in (0..cleaned.len()).step_by(2) {
        let byte_str = &cleaned[i..i + 2];
        if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
            result.push(byte);
        }
    }
    result
}

// Encode bytes as hex string without 0x prefix.
pub fn hex_encode(data: &[u8]) -> String {
    const HEX_CHARS: [char; 16] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ];

    let mut result = String::with_capacity(data.len() * 2);
    for &byte in data {
        result.push(HEX_CHARS[(byte >> 4) as usize]);
        result.push(HEX_CHARS[(byte & 0x0F) as usize]);
    }
    result
}

// This function is copied from ic/rs/ethereum/cketh/minter/src/eth_logs/mod.rs
fn parse_principal_from_slice(slice: &[u8]) -> Result<Principal, String> {
    const ANONYMOUS_PRINCIPAL_BYTES: [u8; 1] = [4];

    if slice.is_empty() {
        return Err("slice too short".to_string());
    }
    if slice.len() > 32 {
        return Err(format!("Expected at most 32 bytes, got {}", slice.len()));
    }
    let num_bytes = slice[0] as usize;
    if num_bytes == 0 {
        return Err("management canister principal is not allowed".to_string());
    }
    if num_bytes > 29 {
        return Err(format!(
            "invalid number of bytes: expected a number in the range [1,29], got {num_bytes}",
        ));
    }
    if slice.len() < 1 + num_bytes {
        return Err("slice too short".to_string());
    }
    let (principal_bytes, trailing_zeroes) = slice[1..].split_at(num_bytes);
    if !trailing_zeroes
        .iter()
        .all(|trailing_zero| *trailing_zero == 0)
    {
        return Err("trailing non-zero bytes".to_string());
    }
    if principal_bytes == ANONYMOUS_PRINCIPAL_BYTES {
        return Err("anonymous principal is not allowed".to_string());
    }
    Principal::try_from_slice(principal_bytes).map_err(|err| err.to_string())
}

pub fn subaccount_from_principal(principal: &Principal) -> Subaccount {
    let mut subaccount = [0; 32];
    let principal = principal.as_slice();
    subaccount[0] = principal.len() as u8;
    subaccount[1..principal.len() + 1].copy_from_slice(principal);
    subaccount
}

// Note that this is not very safe (i.e. no error handling)
pub fn principal_from_subaccount(subaccount: &Subaccount) -> Principal {
    let len = subaccount[0] as usize;
    Principal::from_slice(&subaccount[1..1 + std::cmp::min(len, 29)])
}

pub fn calc_msgid(caller: &Subaccount, nonce: u32) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(caller);
    hasher.update(nonce.to_le_bytes());
    let hashed = hasher.finalize();
    // Return XOR of 128 bit chunks of the hashed principal
    let mut id = 0;
    for i in 0..2 {
        id ^= u128::from_le_bytes(hashed[i * 16..(i + 1) * 16].try_into().unwrap_or_default());
    }
    id
}

pub struct EventEntry {
    pub event_id: EventId,
    data: Vec<u8>,
    topics: Vec<Vec<u8>>,
}

#[derive(CandidType, candid::Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EventError {
    pub code: Option<u64>,
    pub message: String,
}

impl From<&'_ str> for EventError {
    fn from(msg: &'_ str) -> Self {
        EventError {
            code: None,
            message: msg.to_string(),
        }
    }
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EventError {{ code: {:?}, message: {} }}",
            self.code, self.message
        )
    }
}

pub fn last_block_number_from_event_logs(events: &serde_json::Value) -> Option<u64> {
    events
        .as_object()
        .and_then(|x| x.get("result"))
        .and_then(|x| x.as_array())
        .and_then(|x| x.last())
        .and_then(|x| x.as_object())
        .and_then(|x| x.get("blockNumber"))
        .and_then(|x| x.as_str())
        .and_then(hex_decode_0x_u64)
}

pub fn read_event_logs(events: &serde_json::Value) -> Result<Vec<EventEntry>, EventError> {
    if let Some(error) = events
        .as_object()
        .and_then(|x| x.get("error"))
        .and_then(|x| x.as_object())
    {
        Err(EventError {
            code: error.get("code").and_then(|x| x.as_u64()),
            message: error
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
        })
    } else if let Some(results) = events
        .as_object()
        .and_then(|x| x.get("result"))
        .and_then(|x| x.as_array())
    {
        let mut entries = Vec::new();
        for r in results {
            let block_number = r
                .as_object()
                .and_then(|x| x.get("blockNumber"))
                .and_then(|x| x.as_str())
                .and_then(hex_decode_0x)
                .map(|x| {
                    let mut bytes = [0; 8];
                    let len = x.len().min(8);
                    bytes[(8 - len)..].copy_from_slice(&x[(x.len() - len)..]);
                    u64::from_be_bytes(bytes)
                });
            let log_index = r
                .as_object()
                .and_then(|x| x.get("logIndex"))
                .and_then(|x| x.as_str())
                .and_then(hex_decode_0x)
                .map(|x| {
                    let mut bytes = [0; 8];
                    let len = x.len().min(8);
                    bytes[(8 - len)..].copy_from_slice(&x[(x.len() - len)..]);
                    u64::from_be_bytes(bytes)
                });
            let data = r
                .as_object()
                .and_then(|x| x.get("data"))
                .and_then(|x| x.as_str())
                .and_then(hex_decode_0x);
            let topics = r
                .as_object()
                .and_then(|x| x.get("topics"))
                .and_then(|x| x.as_array())
                .map(|x| {
                    x.iter()
                        .filter_map(|x| x.as_str())
                        .filter_map(hex_decode_0x)
                        .collect()
                });
            match (block_number, log_index, data, topics) {
                (Some(block_number), Some(log_index), Some(data), Some(topics)) => {
                    entries.push(EventEntry {
                        event_id: EventId {
                            block_number,
                            log_index,
                        },
                        data,
                        topics,
                    })
                }
                (None, _, _, _) => {
                    return Err("No valid 'result.block_number' found in JSON".into())
                }
                (_, None, _, _) => {
                    return Err("No 'result.log_index' found in JSON".into());
                }
                (_, _, None, _) => return Err("No valid 'result.data' found in JSON".into()),
                (_, _, _, None) => {
                    return Err("No 'result.topics' found in JSON".into());
                }
            }
        }
        Ok(entries)
    } else {
        Err("No 'result' found in JSON".into())
    }
}

pub fn parse_transfer(entry: &EventEntry) -> Result<ethabi::Log, String> {
    use ethabi::*;

    let params = vec![
        EventParam {
            name: "from".to_string(),
            kind: ParamType::Address,
            indexed: true,
        },
        EventParam {
            name: "to".to_string(),
            kind: ParamType::Address,
            indexed: true,
        },
        EventParam {
            name: "tokens".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        },
    ];
    let transfer = Event {
        name: "Transfer".to_string(),
        inputs: params,
        anonymous: false,
    };

    let topics = entry
        .topics
        .iter()
        .map(|topic| Hash::from_slice(topic))
        .collect();
    let rawlog = RawLog {
        topics,
        data: entry.data.to_vec(),
    };

    transfer.parse_log(rawlog).map_err(|err| format!("{}", err))
}

pub fn parse_burn_to_icp(entry: &EventEntry) -> Result<ethabi::Log, String> {
    use ethabi::*;

    let params = vec![
        EventParam {
            name: "amount".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        },
        EventParam {
            name: "principal".to_string(),
            kind: ParamType::FixedBytes(32),
            indexed: true,
        },
        EventParam {
            name: "subaccount".to_string(),
            kind: ParamType::FixedBytes(32),
            indexed: true,
        },
    ];
    let burn_to_icp = Event {
        name: "BurnToIcp".to_string(),
        inputs: params,
        anonymous: false,
    };

    let topics = entry
        .topics
        .iter()
        .map(|topic| Hash::from_slice(topic))
        .collect();
    let rawlog = RawLog {
        topics,
        data: entry.data.to_vec(),
    };
    burn_to_icp
        .parse_log(rawlog)
        .map_err(|err| format!("{}", err))
}

pub fn parse_burn_to_icp_account_id(entry: &EventEntry) -> Result<ethabi::Log, String> {
    use ethabi::*;

    let params = vec![
        EventParam {
            name: "amount".to_string(),
            kind: ParamType::Uint(256),
            indexed: false,
        },
        EventParam {
            name: "accountId".to_string(),
            kind: ParamType::FixedBytes(32),
            indexed: true,
        },
    ];
    let burn_to_icp_account_id = Event {
        name: "BurnToIcpAccountId".to_string(),
        inputs: params,
        anonymous: false,
    };

    let topics = entry
        .topics
        .iter()
        .map(|topic| Hash::from_slice(topic))
        .collect();
    let rawlog = RawLog {
        topics,
        data: entry.data.to_vec(),
    };
    burn_to_icp_account_id
        .parse_log(rawlog)
        .map_err(|err| format!("{}", err))
}

pub fn log_to_map(log: ethabi::Log) -> BTreeMap<String, ethabi::Token> {
    log.params.into_iter().map(|p| (p.name, p.value)).collect()
}

type Amount = u64;

#[derive(Clone, CandidType, serde::Serialize, serde::Deserialize, Debug)]
pub enum BurnEvent {
    BurnToIcp(Account, Amount),
    BurnToIcpAccountId(AccountIdentifier, Amount),
}

impl std::fmt::Display for BurnEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use BurnEvent::*;
        match self {
            BurnToIcp(account, amount) => {
                write!(
                    f,
                    "BurnToIcp(Account {{ principal: {}, subaccount: {}}}, {})",
                    account.owner,
                    account
                        .subaccount
                        .map(hex::encode)
                        .unwrap_or_else(|| "None".to_string()),
                    amount
                )
            }
            BurnToIcpAccountId(account_id, amount) => {
                write!(
                    f,
                    "BurnToIcpAccountId({}, {})",
                    hex::encode(account_id),
                    amount
                )
            }
        }
    }
}

#[derive(Copy, Clone, CandidType, serde::Serialize, serde::Deserialize, Debug)]
pub struct EventId {
    block_number: u64,
    log_index: u64,
}

impl From<EventId> for u128 {
    fn from(x: EventId) -> Self {
        (u128::from(x.block_number) << 64) + u128::from(x.log_index)
    }
}

pub fn parse_burn_event(entry: &EventEntry) -> Result<BurnEvent, String> {
    if let Ok(burn) = parse_burn_to_icp(entry).map(log_to_map) {
        let amount = burn
            .get("amount")
            .ok_or_else(|| "amount is not found".to_string())
            .and_then(|x| {
                x.clone()
                    .into_uint()
                    .ok_or_else(|| "amount is not uint256".to_string())
            })
            .and_then(|x| u64::try_from(x).map_err(|err| err.to_string()))?;
        let principal = burn
            .get("principal")
            .ok_or_else(|| "principal is not found".to_string())
            .and_then(|x| {
                x.clone()
                    .into_fixed_bytes()
                    .ok_or_else(|| "principal is not fixed bytes".to_string())
            })
            .and_then(|x| parse_principal_from_slice(&x))?;
        let mut subaccount: [u8; 32] = [0; 32];
        burn.get("subaccount")
            .ok_or_else(|| "subaccount is not found".to_string())
            .and_then(|x| {
                x.clone()
                    .into_fixed_bytes()
                    .ok_or_else(|| "subaccount is not fixed bytes".to_string())
            })
            .and_then(|x| {
                if x.len() == 32 {
                    subaccount.copy_from_slice(&x);
                    Ok(())
                } else {
                    Err("subaccount is not 32 bytes".to_string())
                }
            })?;
        let subaccount = if subaccount == [0; 32] {
            None
        } else {
            Some(subaccount)
        };
        Ok(BurnEvent::BurnToIcp(
            Account {
                owner: principal,
                subaccount,
            },
            amount,
        ))
    } else if let Ok(burn) = parse_burn_to_icp_account_id(entry).map(log_to_map) {
        let amount = burn
            .get("amount")
            .ok_or_else(|| "amount is not found".to_string())
            .and_then(|x| {
                x.clone()
                    .into_uint()
                    .ok_or_else(|| "amount is not uint256".to_string())
            })
            .and_then(|x| u64::try_from(x).map_err(|err| err.to_string()))?;
        let account_id = burn
            .get("accountId")
            .ok_or_else(|| "accountId is not found".to_string())
            .and_then(|x| {
                x.clone()
                    .into_fixed_bytes()
                    .ok_or_else(|| "accountId is not fixed bytes".to_string())
            })
            .and_then(|x| {
                AccountIdentifier::from_slice(x.as_slice()).map_err(|err| err.to_string())
            })?;
        Ok(BurnEvent::BurnToIcpAccountId(account_id, amount))
    } else {
        Err("Expect either BurnToIcp or BurnToIcpAccountId event".to_string())
    }
}

// In the following, we register a custom getrandom implementation because
// otherwise getrandom (which is a dependency of k256) fails to compile.
// This is necessary because getrandom by default fails to compile for the
// wasm32-unknown-unknown target (which is required for deploying a canister).
// Our custom implementation always fails, which is sufficient here because
// we only use the k256 crate for verifying secp256k1 signatures, and such
// signature verification does not require any randomness.
getrandom::register_custom_getrandom!(always_fail);
pub fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[test]
fn test_parse_burn_to_icp() {
    let value = serde_json::json!({"id":null,"jsonrpc":"2.0","result":[{"address":"0x8c283b98edeb405816fd1d321005df4d3aa956ba","blockHash":"0x8900bc3dbd462e7a9f76bfac3199729943e677d7d44bd50556b27f935a705fc7","blockNumber":"0x93fd3b","data":"0x000000000000000000000000000000000000000000000000016345785d8a0000","logIndex":"0x32","removed":false,"topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","0x0000000000000000000000002c91e73a358e6f0aff4b9200c8bad0d4739a70dd","0x0000000000000000000000000000000000000000000000000000000000000000"],"transactionHash":"0xcea897ee46a9fbe6ce6f2945b172ebc224d2871f70b35de35600be9d71a05dd1","transactionIndex":"0x1e"},{"address":"0x8c283b98edeb405816fd1d321005df4d3aa956ba","blockHash":"0x8900bc3dbd462e7a9f76bfac3199729943e677d7d44bd50556b27f935a705fc7","blockNumber":"0x93fd3b","data":"0x0000000000000000000000000000000000000000000000000000000000989680","logIndex":"0x33","removed":false,"topics":["0x7fe818d2b919ac5cc197458482fab0d4285d783795541be06864b0baa6ac2f5c","0x1d9e7d426db28fa46d013ad4c9955074e3946ab25203eece542b098f1c020000","0x0000000000000000000000000000000000000000000000000000000000000000"],"transactionHash":"0xcea897ee46a9fbe6ce6f2945b172ebc224d2871f70b35de35600be9d71a05dd1","transactionIndex":"0x1e"},{"address":"0x8c283b98edeb405816fd1d321005df4d3aa956ba","blockHash":"0xc502ea9bc3955ff179de881dce2ede89fcc4068adc4e197f138ea4c49c6efb2a","blockNumber":"0x944078","data":"0x0000000000000000000000000000000000000000000000000000000000989680","logIndex":"0x93","removed":false,"topics":["0xa6a16062bb41b9bcfb300790709ad9b778bcb5cdcf87dfa633ab3adfd8a7ab59","0x9bf916c86e344b8a0aaac73271ae0612e8212d0bd59e30db38281982f46d3d2b"],"transactionHash":"0x335791840b4d8b2edfb6018e7e1dc62ba1d81cd0fa46785ccc672e7c491e365d","transactionIndex":"0x57"}]});
    // test highest block number
    assert_eq!(last_block_number_from_event_logs(&value), Some(0x944078));

    let mut data_and_topics = read_event_logs(&value).unwrap();
    assert_eq!(data_and_topics.len(), 3);
    // Check BurnToIcpAccountId
    let entry = data_and_topics.pop().unwrap();
    let m = log_to_map(parse_burn_to_icp_account_id(&entry).unwrap());
    assert!(m
        .get("amount")
        .cloned()
        .and_then(|x| x.into_uint())
        .is_some());
    assert!(m
        .get("accountId")
        .cloned()
        .and_then(|x| x.into_fixed_bytes())
        .is_some());
    let burn = parse_burn_event(&entry).unwrap();
    assert!(matches!(burn, BurnEvent::BurnToIcpAccountId(_, _)));
    // Check BurnToIcp
    let entry = data_and_topics.pop().unwrap();
    let m = log_to_map(parse_burn_to_icp(&entry).unwrap());
    assert!(m
        .get("amount")
        .cloned()
        .and_then(|x| x.into_uint())
        .is_some());
    assert!(m
        .get("principal")
        .cloned()
        .and_then(|x| x.into_fixed_bytes())
        .is_some());
    assert!(m
        .get("subaccount")
        .cloned()
        .and_then(|x| x.into_fixed_bytes())
        .is_some());
    let burn = parse_burn_event(&entry).unwrap();
    assert!(matches!(burn, BurnEvent::BurnToIcp(_, _)));
    // Check Transfer
    let entry = data_and_topics.pop().unwrap();
    let m = log_to_map(parse_transfer(&entry).unwrap());
    assert!(m
        .get("from")
        .cloned()
        .and_then(|x| x.into_address())
        .is_some());
    assert!(m
        .get("to")
        .cloned()
        .and_then(|x| x.into_address())
        .is_some());
    assert!(m
        .get("tokens")
        .cloned()
        .and_then(|x| x.into_uint())
        .is_some());
}

#[test]
fn test_hex_decode_0x() {
    assert_eq!(hex_decode_0x("0xabcd"), Some(vec![0xab, 0xcd]));
    assert_eq!(hex_decode_0x("abcd"), Some(vec![0xab, 0xcd]));
    assert_eq!(hex_decode_0x("0x123"), Some(vec![0x1, 0x23]));
    assert_eq!(hex_decode_0x("123"), Some(vec![0x1, 0x23]));
    assert_eq!(hex_decode_0x("123@"), None);
    assert_eq!(hex_decode_0x(" 123"), None);
    assert_eq!(hex_decode_0x("0x 123"), None);
    assert_eq!(hex_decode_0x(""), Some(vec![]));
    assert_eq!(hex_decode_0x("0x"), Some(vec![]));
    assert_eq!(hex_decode_0x(" "), None);
}

#[test]
fn test_hex_decode_0x_u64() {
    assert_eq!(hex_decode_0x_u64("0xabcd"), Some(0xabcd));
    assert_eq!(hex_decode_0x_u64("abcd"), Some(0xabcd));
    assert_eq!(hex_decode_0x_u64("0x123"), Some(0x123));
    assert_eq!(hex_decode_0x_u64("123"), Some(0x123));
    assert_eq!(hex_decode_0x_u64("123@"), None);
    assert_eq!(hex_decode_0x_u64(" 123"), None);
    assert_eq!(hex_decode_0x_u64("0x 123"), None);
    assert_eq!(hex_decode_0x_u64(""), Some(0));
    assert_eq!(hex_decode_0x_u64("0x"), Some(0));
    assert_eq!(hex_decode_0x_u64(" "), None);
    assert_eq!(
        hex_decode_0x_u64("0xdeadbeef12345678"),
        Some(0xdeadbeef12345678)
    );
    assert_eq!(
        hex_decode_0x_u64("0x0deadbeef12345678"),
        Some(0xdeadbeef12345678)
    );
    assert_eq!(hex_decode_0x_u64("0x1deadbeef12345678"), None);
}
