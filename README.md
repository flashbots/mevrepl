# Flashbots MEV-REPL CLI Tool

This command-line tool provides an interactive REPL-style interface for testing and demonstrating various Flashbots
MEV-Share workflows.  
It is intended as a reference implementation and experimentation tool for developers exploring MEV flows such as hint
decoding, backrunning, and private transaction submission

## Supported Commands

### `send-private-tx`

Sends a test private transaction using
the [Flashbots Protect RPC endpoint](https://docs.flashbots.net/flashbots-protect/overview).  
Demonstrates how to submit transactions privately to avoid frontrunning and failed tx.

### `hints-stream`

Connects to the MEV-Share Server-Sent Events (SSE) stream and listens for real-time hint messages.  
Useful for observing and debugging MEV-Share hint flows.

### `backrun`

Illustrates a basic MEV backrun flow:

1. Sends a private transaction
2. Listens to the hint stream
3. Sends a backrun transaction when a matching `hintHash` is detected

### Optional flags to customize `send-private-tx`

```
--eth-amount   set value for tx. By default sets to 1 wei.
--tx-type      available types: weth-wrap, builder-tip. By default weth-wrap
```

## 📁 Structure

- `mev/client.go`: Implements a Flashbots client with methods for:
    - `SendBundle`
    - `SimulateBundle`
    - `SendPrivateTx`
    - `GetTxStatus`

- `mev/stream.go`: Implements the `HintsStream`

- `cmd/mevrepl/main.go` includes reference implementations for `backrun`, `hints-stream`and `send-private-tx` flows

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

###  HintsStream
The example shows init subscription on MEV-Share hints stream. `SubscriptionOpts` is available to customize ping and retry timeouts, and max retries to establish connection.
```go
ch := make(chan mev.Hint)
stream, err := mev.SubscribeHints(context.Background(), "https://mev-share.flashbots.net", ch, nil)
if err != nil {
    panic(err)
}

go func() {
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
