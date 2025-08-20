package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/mevrepl/ports"
	"github.com/flashbots/mevrepl/protect"
	"github.com/urfave/cli/v2"
)

var (
	txFlags = []cli.Flag{
		&cli.StringFlag{
			Name:    "eth-amount",
			Aliases: []string{"a"},
		},
		&cli.StringFlag{
			Name:    "tx-type",
			Aliases: []string{"tt"},
			Usage: "--tt weth-wrap. " +
				"--tt builder-tip. " +
				"--tt fake-tx (send failed tx -> send bundle matching failed tx (Test case))" +
				"--tt eip7702-tx (send eip7702 tx)",
		},
	}

	txStatusFlags = []cli.Flag{
		&cli.StringFlag{
			Name: "tx-hash",
		},
	}
)

func main() {
	logLevel := slog.LevelInfo
	if ll := os.Getenv("LOG_LEVEL"); ll != "" {
		if ll == "DEBUG" {
			logLevel = slog.LevelDebug
		}
	}

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	privKey1 := os.Getenv("FLASHBOTS_ETH_PRIVATE_KEY")
	if privKey1 == "" {
		panic("FLASHBOTS_ETH_PRIVATE_KEY must be provided")
	}

	alice, err := crypto.HexToECDSA(privKey1)
	if err != nil {
		panic(fmt.Errorf("failed to parse secp256k1 private key error %w", err))
	}

	var (
		priorityFee *big.Int

		network      = os.Getenv("NETWORK")
		publicRPCURL = os.Getenv("PUBLIC_RPC")

		builderAddr          common.Address
		wethAddr             common.Address
		checkAndSendContract common.Address

		// pectra
		batchcallAndSponsorContract common.Address
	)

	switch network {
	case "", protect.SepoliaNetwork:
		network = protect.SepoliaNetwork
		priorityFee = big.NewInt(1e5)
		if publicRPCURL == "" {
			publicRPCURL = "https://ethereum-sepolia-rpc.publicnode.com"
		}

		builderAddr = common.HexToAddress("0x13cb6ae34a13a0977f4d7101ebc24b87bb23f0d5")
		wethAddr = common.HexToAddress("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14")
		checkAndSendContract = common.HexToAddress("0xB0D90094d296DA87485C623a7f42d245A74036a0")

		batchcallAndSponsorContract = common.HexToAddress("0x33ACD5b112a17c863beb2f37f785bAEf8a8f8369")
	case protect.Mainnet:
		if publicRPCURL == "" {
			publicRPCURL = "https://eth.llamarpc.com"
		}
		priorityFee = big.NewInt(2e9)

		builderAddr = common.HexToAddress("0xdadB0d80178819F2319190D340ce9A924f783711")
		wethAddr = common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")
		checkAndSendContract = common.HexToAddress("0xC4595E3966e0Ce6E3c46854647611940A09448d3")

		batchcallAndSponsorContract = common.HexToAddress("0x775c8D470CC8d4530b8F233322480649f4FAb758")
	default:
		panic("unsupported network")
	}

	ethClient, err := ethclient.Dial(publicRPCURL)
	if err != nil {
		panic(fmt.Errorf("failed to init public RPC client error %w", err))
	}

	internalTestingRPCOpts := "fast?originId=fb-test"
	mevClient, err := protect.ConstructClient(alice, network, &protect.ClientOpts{
		RPCOpts: internalTestingRPCOpts,
	})
	if err != nil {
		panic(fmt.Errorf("failed to construct mev client error %w", err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGQUIT, syscall.SIGTERM)
	defer cancel()

	handler := &ports.Handler{
		MEVClient:                   mevClient,
		EthClient:                   ethClient,
		Alice:                       alice,
		Network:                     network,
		BuilderAddr:                 builderAddr,
		WETHAddr:                    wethAddr,
		CheckAndSendContract:        checkAndSendContract,
		BatchCallAndSponsorContract: batchcallAndSponsorContract,
		DefaultPriorityFee:          priorityFee,
	}

	app := &cli.App{
		Name:        "mevrepl",
		Description: "Command line based repl test toolkit",
	}

	// This command sends a test private transaction using the Flashbots Protect RPC endpoint.
	//
	// Flashbots Protect allows users to submit transactions privately, bypassing the public mempool.
	// This helps protect against frontrunning, sandwich attacks, and other forms of MEV exploitation.
	//
	// Transactions sent through this endpoint are only included if they succeed (i.e., no reverts),
	// ensuring that failed transactions do not appear on-chain.
	//
	// This command uses a test transaction for illustrative purposes only. It is intended
	// as a minimal example to demonstrate how to interact with the Protect RPC.
	//
	// For details, see: https://docs.flashbots.net/flashbots-protect/overview
	sendPrivateTxCmd := &cli.Command{
		Name:        "send-private-tx",
		Aliases:     []string{"stx"},
		Description: "send private test tx on flashbots rpc endpoint",
		Flags:       txFlags,
		Action:      handler.SendPrivateTx(ctx),
	}
	// This command is for the test goals. Sends fake tx which must fail
	sendFakeTxCmd := &cli.Command{
		Name:        "send-fake-tx",
		Aliases:     []string{"sft"},
		Description: "send fake tx which must fail on flashbots rpc endpoint",
		Flags:       txFlags,
		Action:      handler.SendFakeTx(ctx),
	}
	sendPrivateRelayTxCmd := &cli.Command{
		Name:        "send-private-relay-tx",
		Aliases:     []string{"sprt"},
		Description: "send private tx to relay",
		Flags:       txFlags,
		Action:      handler.SendPrivateRelayTx(ctx),
	}

	ethCallBundleCmd := &cli.Command{
		Name:        "eth-call-bundle",
		Aliases:     []string{"ecb"},
		Description: "simulate eth bundle",
		Flags:       txFlags,
		Action:      handler.CallEthBundle(ctx),
	}

	ethSendBundleCmd := &cli.Command{
		Name:        "eth-send-bundle",
		Aliases:     []string{"esb"},
		Description: "send eth bundle",
		Flags:       txFlags,
		Action:      handler.SendEthBundle(ctx),
	}

	ethCancelBundleCmd := &cli.Command{
		Name:        "eth-cancel-bundle",
		Aliases:     []string{"ecanb"},
		Description: "cancel eth bundle",
		Flags:       txFlags,
		Action:      handler.CancelEthBundle(ctx),
	}

	cancelRelayTxCmd := &cli.Command{
		Name:        "cancel-relay-tx",
		Aliases:     []string{"crt"},
		Description: "cancel private tx on relay",
		Flags:       txFlags,
		Action:      handler.CancelRelayTx(ctx),
	}

	// This command calls Flashbots Protect Transaction Status API and logs info txStatus
	//
	// For details, see: https://docs.flashbots.net/flashbots-protect/additional-documentation/status-api
	txStatusCmd := &cli.Command{
		Name:        "tx-status",
		Aliases:     []string{"ts"},
		Description: "query check tx status on Flashbots Protect endpoint",
		Flags:       txStatusFlags,
		Action:      handler.TxStatus(ctx),
	}

	// Flashbots provides a Server-Sent Events (SSE) stream to access MEV-Share events.
	//
	// This command connects to the MEV-Share SSE stream and listens for hint events.
	// The target hintHash is a keccak256 hash of the original transaction hash.
	// For more information, see:
	// https://docs.flashbots.net/flashbots-mev-share/searchers/event-stream#understanding-double-hash
	//
	// This tool allows searchers to subscribe to real-time MEV opportunities
	// by decoding and handling hint messages streamed from the Flashbots network.
	hintsStreamCmd := &cli.Command{
		Name:        "hints-stream",
		Aliases:     []string{"hs"},
		Description: "listen distributed MevShare events via SSE. Info log hints only",
		Action:      handler.HintsStream(ctx),
	}

	// This command demonstrates a simple MEV backrun flow using the Flashbots MEV-Share network.
	//
	// The example flow includes the following steps:
	// 1. Send a private transaction to the network.
	// 2. Subscribe to the MEV-Share SSE stream and listen for incoming hints.
	// 3. When a received hintHash matches the original transaction, send a backrun transaction.
	//
	// This tool serves as a minimal working example for understanding and testing
	// basic backrun logic.
	backrunFlags := []cli.Flag{&cli.BoolFlag{
		Name:    "use-relay",
		Aliases: []string{"ur"},
	}}
	backrunFlags = append(backrunFlags, txFlags...)
	backrunCmd := &cli.Command{
		Name:        "backrun",
		Aliases:     []string{"br"},
		Description: "backrun tx based on the MevShare events",
		Flags:       backrunFlags,
		Action:      handler.Backrun(ctx),
	}

	app.Commands = append(app.Commands, sendPrivateTxCmd, sendFakeTxCmd, txStatusCmd, hintsStreamCmd, backrunCmd, sendPrivateRelayTxCmd, ethCallBundleCmd, ethSendBundleCmd, cancelRelayTxCmd, ethCancelBundleCmd)

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
