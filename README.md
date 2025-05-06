# Flashbots MEV-REPL CLI Tool

This command-line tool provides an interactive REPL-style interface for testing and demonstrating various Flashbots
MEV-Share workflows.  
It is intended as a reference implementation and experimentation tool for developers exploring MEV flows such as hint
decoding, backrunning, and private transaction submission

## Supported Commands

### [send-private-tx](https://github.com/flashbots/mevrepl/blob/04e7d7a43df6a4bc33f08f75525ccb5cf3eb1a90/cmd/mevrepl/main.go#L171)

Sends a test private transaction using
the [Flashbots Protect RPC endpoint](https://docs.flashbots.net/flashbots-protect/overview).  
Demonstrates how to submit transactions privately to avoid frontrunning and failed tx.

### Available `tx-types` flags:

`weth-wrap` - sends deposit on `WETH` contract

`fake-tx` - sends fake tx which does not pass simulation using `CheckAndSend` contract with the fake calldata.

`eip7702-tx` - illustrates Pectra update test workflow. The command does in 3 steps:

- construct and send `SetCode` transaction
- get tx_receipt and verify that auth was set correctly
- use EOA account to execute tx batchcall using `BatchCallAndSponsor` contract.

`eth-amount` - sets value for tx. By default sets to 1 wei.

### [hints-stream](https://github.com/flashbots/mevrepl/blob/04e7d7a43df6a4bc33f08f75525ccb5cf3eb1a90/cmd/mevrepl/main.go#L411)

Connects to the MEV-Share Server-Sent Events (SSE) stream and listens for real-time hint messages.  
Useful for observing and debugging MEV-Share hint flows.

### [backrun](https://github.com/flashbots/mevrepl/blob/04e7d7a43df6a4bc33f08f75525ccb5cf3eb1a90/cmd/mevrepl/main.go#L438)

Illustrates a basic MEV backrun flow:

1. Sends a private transaction
2. Listens to the hint stream
3. Sends a backrun transaction when a matching `hintHash` is detected

### [tx-status](https://github.com/flashbots/mevrepl/blob/04e7d7a43df6a4bc33f08f75525ccb5cf3eb1a90/cmd/mevrepl/main.go#L380)

This command calls Flashbots Protect Transaction Status API and logs info txStatus.

For details, see: https://docs.flashbots.net/flashbots-protect/additional-documentation/status-api

## 📁 Structure

- `mev/client.go`: Implements a Flashbots client with methods for:
    - `SendBundle`
    - `SimulateBundle`
    - `SendPrivateTx`
    - `GetTxStatus`

- `mev/stream.go`: Implements the `HintsStream`

- `cmd/mevrepl/main.go` includes reference implementations for `backrun`, `hints-stream`and `send-private-tx` flows

## Helper Contracts

| Contract            | Mainnet                                                                                                                 | Sepolia                                                                                                                         |
|---------------------|-------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| WETH                | [`0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`](https://etherscan.io/address/0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2) | [`0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14`](https://sepolia.etherscan.io/address/0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14) |
| CheckAndSend        | [`0xC4595E3966e0Ce6E3c46854647611940A09448d3`](https://etherscan.io/address/0xC4595E3966e0Ce6E3c46854647611940A09448d3) | [`0xB0D90094d296DA87485C623a7f42d245A74036a0`](https://sepolia.etherscan.io/address/0xB0D90094d296DA87485C623a7f42d245A74036a0) |
| BatchCallAndSponsor | [`0x775c8D470CC8d4530b8F233322480649f4FAb758`](https://etherscan.io/address/0x775c8D470CC8d4530b8F233322480649f4FAb758) | [`0x33ACD5b112a17c863beb2f37f785bAEf8a8f8369`](https://sepolia.etherscan.io/address/0x33ACD5b112a17c863beb2f37f785bAEf8a8f8369) |

> **Note:** The following contracts, except WETH, are for testing purposes only. These contracts are not intended for
> production use.

## 🚀 Getting Started

```bash
export FLASHBOTS_ETH_PRIVATE_KEY=$1; export FLASHBOTS_ETH_PRIVATE_KEY_2=$2
NETWORK={mainnet/sepolia} go run main.go <command>
```

### Examples

```bash
NETWORK=sepolia go run main.go backrun --eth-amount 200000000000000000 
```

```bash
NETWORK=mainnet go run main.go hints-stream
```

### HintsStream

The example shows init subscription on MEV-Share hints stream. `SubscriptionOpts` is available to customize ping and
retry timeouts, and max retries to establish connection.

```go
ch := make(chan mev.Hint)
stream, err := mev.SubscribeHints(context.Background(), "https://mev-share.flashbots.net", ch, nil)
if err != nil {
    panic(err)
}

go func () {
    <-time.After(time.Second * 5)
    close(ch)
}()

for hint := range ch {
    fmt.Println("Parsed hint", hint)
}

if err := stream.Error(); err!=nil {
    panic("error returned from stream connection: "+err.Error())
}
```

### Please note: This project is a WIP and not intended for production use.
