NETWORK=${NETWORK:-local}
OPTS="--network=$NETWORK"

case "$NETWORK" in
  ic) ECDSA_KEY_NAME=${ECDSA_KEY_NAME:-key_1};;
  local) ECDSA_KEY_NAME=${ECDSA_KEY_NAME:-dfx_test_key};;
esac

for i in `seq 3 -1 0` ; do echo -ne "\rAbout to run with $OPTS, CTRL-C now if it is not what your want.. ($i) " ; sleep 1 ; done
echo
echo Calling set_icp_config...

EVM_RPC_CANISTER_ID=$(dfx canister $OPTS id evm_rpc)
ICP_LEDGER_CANISTER_ID=$(dfx canister $OPTS id ledger)
dfx canister $OPTS call minter set_ckicp_config "(record {
  expiry_seconds = 18000: nat64;
  max_response_bytes = 4000: nat64;
  target_chain_ids = vec {5}: vec nat64;
  ckicp_eth_erc20_address = \"0x054b8f99d15cc5b35a42a926635977d62692f25b\";
  eth_rpc_service_url = \"\";
  eth_rpc_canister_id = principal \"$EVM_RPC_CANISTER_ID\";
  ledger_canister_id = principal \"$ICP_LEDGER_CANISTER_ID\";
  ckicp_getlogs_topics = vec { \"0xa6a16062bb41b9bcfb300790709ad9b778bcb5cdcf87dfa633ab3adfd8a7ab59\"; \"0x7fe818d2b919ac5cc197458482fab0d4285d783795541be06864b0baa6ac2f5c\" } : vec text;
  ckicp_fee = 10000 : nat64;
  last_synced_block_number = 9_721_763 : nat64;
  sync_interval_secs = 180 : nat64;
  cycle_cost_of_eth_getlogs = 5_000_000_000: nat;
  cycle_cost_of_eth_blocknumber = 5_000_000_000: nat;
  debug_log_level = 3;
  ecdsa_key_name = \"$ECDSA_KEY_NAME\";
})"
echo Calling update_ckicp_state...
dfx canister $OPTS call minter update_ckicp_state
