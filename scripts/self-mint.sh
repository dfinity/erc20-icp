#!/usr/bin/env bash
#
# This script lets you mint ICP ERC20 tokens, and requires these 
# tools in order to work properly: dfx, seth, idl2json, jq.
for NAME in dfx seth idl2json jq; do
  TOOL=$(which "$NAME")
  test -z "$TOOL" && echo "Need $NAME in PATH" && exit 1
done

# The following environment variables must be set:
#
# ETH_RPC_URL   RPC provider's URL
#
# ETH_FROM      The address to sign & send ETH transactions.
#               seth must be configured with its private key first.
#
# MINTER_ADDR   The token's ERC20 contract address
test -z "$ETH_RPC_URL" && echo "Must set ETH_RPC_URL" && exit 1
test -z "$ETH_FROM" && echo "Must set ETH_FROM" && exit 1

MINTER_ADDR=${MINTER_ADDR:-0x054B8f99D15cC5B35a42a926635977d62692F25b}
MINTER_CANISTER_ID=${MINTER_CANISTER_ID:-gyfmy-eqaaa-aaaar-qabza-cai}
MINTER_DID_FILE=${MINTER_DID_FILE:-minter.did}
NETWORK=${NETWORK:-ic}
IDENTITY=${IDENTITY:-default}
FEE=10000
MINTING_TMP=minting.tmp
MINTING_LOG=minting.log
MINTING_TXS=minting.txs
NUM_BLOCKS_PER_EPOCH=32

touch "$MINTING_LOG"
touch "$MINTING_TXS"

USAGE="USAGE: $0 <eth address> <e8s>"
ETH_ADDRESS="$1"
AMOUNT="$2"

[[ ! -s "$MINTER_DID_FILE" ]] && echo "Candid file not found: $MINTER_DID_FILE" && exit 1

# When we have a pending JSON transaction, but minting failed to get txid.
# In this case we should try again.
if [[ -s "$MINTING_TMP" ]]; then
    TX_JSON=$(tail -n1 $MINTING_TMP)
else
    TX_JSON=$(tail -n1 $MINTING_LOG)
    TX_HASH=$(tail -n1 $MINTING_TXS)
    if [[ -n "$TX_HASH" && -n "$TX_JSON" ]]; then
        echo "0. Checking previous TX $TX_HASH"
        while true; do
            BLOCK=$(seth receipt --async "$TX_HASH" blockNumber 2>&1)
            if [[ "$BLOCK" =~ "not found" ]]; then
                echo "   ERROR: transaction $TX_HASH is not found! Need to resend!"
                break
            elif [[ ! "$BLOCK" =~ ^[0-9]+$ ]]; then
                # other kind of error, e.g. network connection broke?
                echo "   ERROR: $BLOCK"
                echo "   Try again in 10 seconds"
                sleep 10
                continue
            fi
            LATEST=$(seth block-number)
            CONFIRMATION=$((LATEST - BLOCK))
            echo "   $CONFIRMATION confirmations"
            if [[ "$CONFIRMATION" -gt "$NUM_BLOCKS_PER_EPOCH" ]]; then
                TX_JSON=
                TX_HASH=
                break
            fi
            sleep 30
        done
    fi
fi

# If TX_JSON is empty, we process program arguments
if [[ -z "$TX_JSON" ]]; then
    [[ -z "$ETH_ADDRESS" || -z "$AMOUNT" ]] && echo "$USAGE" && exit 1

    [[ ! "$AMOUNT" =~ ^[0-9]+$ ]] && echo "Invalid amount: $AMOUNT" && exit 1

    BALANCE=$(seth balance "$ETH_ADDRESS" 2>&1)
    [[ ! "$BALANCE" =~ ^[0-9]+$ ]] && echo "Invalid ETH address: $ETH_ADDRESS" && exit 1

    echo "1. Finding out your principal of identity $IDENTITY"
    PRINCIPAL=$(dfx identity --identity="$IDENTITY" get-principal 2>/dev/null)
    echo "   $PRINCIPAL"

    echo "2. Finding out funding account"
    TARGET_ACCOUNT=$(dfx canister --identity="$IDENTITY" --network="$NETWORK" call "$MINTER_CANISTER_ID" --candid "$MINTER_DID_FILE" get_funding_account 2>/dev/null | idl2json | jq -r)
    #echo "   $TARGET_ACCOUNT"
    SUBACCOUNT=$(echo "$TARGET_ACCOUNT" | sed -e 's/^.*\.//')
    ACCOUNT=$(dfx ledger --network="$NETWORK" account-id --of-canister "$MINTER_CANISTER_ID" --subaccount "$SUBACCOUNT" 2>/dev/null)
    [[ -z "$ACCOUNT" ]] && echo "ERROR: failed to compute account id" && exit 1

    echo "3. Please send $((AMOUNT + FEE)) e8s to $ACCOUNT"
    # echo dfx ledger --network="$NETWORK" balance "$ACCOUNT"
    while true; do
        BALANCE=$(dfx ledger --network="$NETWORK" balance "$ACCOUNT" 2>/dev/null)
        echo -n "   Current balance = $BALANCE"
        BALANCE=$(echo "$BALANCE" | sed -e 's/ ICP//' -e 's/[.]//' -e 's/^0*//')
        [[ -z "$BALANCE" ]] && BALANCE=0
        [[ "$BALANCE" -ge $((AMOUNT + FEE)) ]] && echo -e "\n   All received!" && break
        echo -en "... needs remainder $((AMOUNT + FEE - BALANCE)) e8s\r"
        sleep 5
    done

    echo "4. Calling Minter canister"
    TX_JSON=$(dfx canister --network="$NETWORK" --identity="$IDENTITY" call "$MINTER_CANISTER_ID" --candid="$MINTER_DID_FILE" mint_ckicp "(vec {0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;0;}, $AMOUNT, \"$ETH_ADDRESS\")" | idl2json)
    echo "$TX_JSON" >>"$MINTING_TMP"
fi

MSGID=$(echo "$TX_JSON" | jq -r .Ok.msgid | sed -e 's/_//g')
SIGNATURE=$(echo "$TX_JSON" | jq -r .Ok.signature)
EXPIRY=$(echo "$TX_JSON" | jq -r .Ok.expiry)
TO=$(echo "$TX_JSON" | jq -r .Ok.to | sed -e 's/^0x//')
echo "MSGID=$MSGID"
echo "SIGNATURE=$SIGNATURE"
echo "EXPIRY=$EXPIRY"
echo "TO=$TO"
[[ -z "$MSGID" || -z "$SIGNATURE" || -z "$EXPIRY" || -z "$TO" ]] && echo "ERROR: cannot get msgid. Abort!" && exit 1

echo "5. Creating ETH transaction"
NONCE=$(seth nonce "$ETH_FROM")
TX=$(seth --nonce "$NONCE" -S/dev/null mktx "$MINTER_ADDR" 'selfMint(uint256,address,uint256,uint64,bytes)' "$AMOUNT" "0x$TO" "$MSGID" "$EXPIRY" "0x$SIGNATURE")
echo '   Created'

echo "6. Estimating transaction gas cost"
ETH_GAS=$(seth estimate "$MINTER_ADDR" 'selfMint(uint256,address,uint256,uint64,bytes)' "$AMOUNT" "0x$TO" "$MSGID" "$EXPIRY" "0x$SIGNATURE")
if [[ "$ETH_GAS" =~ ^[0-9][0-9]*$ ]]; then
    export ETH_GAS
    echo 7. Sending the transaction with "$ETH_GAS" gas
    TXID=$(seth publish "$TX")

    if [[ -n "$TXID" ]]; then
        echo "   Created transaction $TXID"
        rm -f "$MINTING_TMP"
        echo "$TX_JSON" | jq -c >>"$MINTING_LOG"
        echo "$TXID" >>"$MINTING_TXS"
    else
        echo "ERROR: failed to create transaction! You can try running this again."
    fi
else
    echo ERROR: failed to estimate gas cost
fi
