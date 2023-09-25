use candid::CandidType;
use candid::Principal;
use ic_cdk::api::call::{call_with_payment, CallResult};
use ic_cdk::call;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

#[derive(CandidType, Serialize, Debug)]
pub struct PublicKeyReply {
    pub public_key: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub enum EcdsaCurve {
    #[serde(rename = "secp256k1")]
    Secp256k1,
}

#[derive(CandidType, Serialize, Debug, Clone)]
pub struct EcdsaKeyId {
    pub curve: EcdsaCurve,
    pub name: String,
}

#[derive(CandidType, Serialize, Debug)]
pub struct ECDSAPublicKey {
    pub canister_id: Option<Principal>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct ECDSAPublicKeyReply {
    pub public_key: Vec<u8>,
    pub chain_code: Vec<u8>,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignWithECDSAReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
struct SignWithECDSA {
    pub message_hash: Vec<u8>,
    pub derivation_path: Vec<Vec<u8>>,
    pub key_id: EcdsaKeyId,
}

#[derive(CandidType, Serialize, Debug)]
pub struct SignatureReply {
    pub signature: Vec<u8>,
}

#[derive(CandidType, Serialize, Debug)]
pub struct ManagementCanister {}

lazy_static! {
    pub static ref MGMT_ID: Principal = Principal::from_text("aaaaa-aa").unwrap();
}

impl ManagementCanister {
    pub async fn raw_rand() -> CallResult<(Vec<u8>,)> {
        call(*MGMT_ID, "raw_rand", ()).await
    }

    pub async fn ecdsa_public_key(
        key_name: &str,
        canister_id: Principal,
    ) -> CallResult<(ECDSAPublicKeyReply,)> {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name.to_string(),
            // name: "dfx_test_key".to_string(),
        };

        let request = ECDSAPublicKey {
            canister_id: Some(canister_id),
            derivation_path: vec![],
            key_id: key_id.clone(),
        };
        // ic_cdk::println!("request {:?}", request);
        call(*MGMT_ID, "ecdsa_public_key", (request,)).await
    }

    pub async fn sign(key_name: &str, message: Vec<u8>) -> CallResult<(SignWithECDSAReply,)> {
        let key_id = EcdsaKeyId {
            curve: EcdsaCurve::Secp256k1,
            name: key_name.to_string(),
        };

        let request = SignWithECDSA {
            message_hash: message.clone(),
            derivation_path: vec![],
            key_id,
        };
        call_with_payment(*MGMT_ID, "sign_with_ecdsa", (request,), 25_000_000_000).await
    }
}
