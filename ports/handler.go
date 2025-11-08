package ports

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/flashbots/mevrepl/mevutil"
	"github.com/flashbots/mevrepl/protect"
	"github.com/holiman/uint256"
	"github.com/urfave/cli/v2"
)

var (
	ErrHintNotFound          = errors.New("hint hash not found")
	ErrUnsupportedTestTxType = errors.New("unsupported tx-type")
)

// Flashbots tx statuses
const (
	Included = "INCLUDED"
	Pending  = "PENDING"
	Failed   = "FAILED"
)

type TestTxType string

const (
	WethWrap   TestTxType = "weth-wrap"
	BuilderTip TestTxType = "builder-tip"
	FakeTx     TestTxType = "fake-tx"
	EIP7702Tx  TestTxType = "eip7702-tx"
	RawBatchTx TestTxType = "raw-batch-tx"
)

type Handler struct {
	Alice                       *ecdsa.PrivateKey
	Network                     string
	EthClient                   *ethclient.Client
	MEVClient                   *protect.Client
	WETHAddr                    common.Address
	BuilderAddr                 common.Address
	CheckAndSendContract        common.Address
	BatchCallAndSponsorContract common.Address
	DefaultPriorityFee          *big.Int
}

func (h *Handler) SendPrivateTx(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		if txTypeStr == RawBatchTx {
			return h.sendRawBatchTx(ctx)
		}

		if txTypeStr == EIP7702Tx {
			return h.pectraWorkflow(ctx, ethAmount, h.DefaultPriorityFee)
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		_, err = h.sendPrivateTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("faield to execute send-private-tx error %w", err)
		}

		txStatus, err := h.getFlashbotsTxReceipt(ctx, tx.Hash())
		if err != nil {
			return err
		}

		slog.Info("Received tx status", "tx", tx, "status", txStatus.Status)

		return nil
	}
}

func (h *Handler) Backrun(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		rawKeyY := os.Getenv("FLASHBOTS_ETH_PRIVATE_KEY_2")
		if rawKeyY == "" {
			return errors.New("FLASHBOTS_ETH_PRIVATE_KEY_2 must be provided")
		}

		ethAmountStr := cCtx.String("eth-amount")
		useRelay := cCtx.Bool("use-relay")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		// 60 seconds should be enough to catch the target hint as we're listening immediately after private tx was sent
		listenCtx, stop := context.WithTimeout(ctx, time.Second*60)
		defer stop()

		ch := make(chan protect.Hint, 100)
		hintsStream, err := protect.SubscribeHints(listenCtx, h.MEVClient.FlashbotsMEVShareURL, ch, nil)
		if err != nil {
			return err
		}
		go func() {
			<-listenCtx.Done()
			<-time.After(time.Second * 1)
			close(ch)
		}()

		currBlock, err := h.EthClient.HeaderByNumber(listenCtx, nil)
		if err != nil {
			return err
		}

		now := uint64(time.Now().Unix())
		blockTime := currBlock.Time
		if blockTime > now {
			panic("invalid block timestamp")
		}
		diff := now - blockTime

		// if diff between time now and current block onchain is more than 5 sec
		// we should wait till the next block to increase chances that the backrun will be landed
		slog.Info("Computing block_diff duration", "block", currBlock.Number.Uint64(), "curr_block_diff_dur", diff)
		if diff >= 5 {
			slog.Warn("Wait till the next block")
			for {
				nextBlock, err := h.EthClient.HeaderByNumber(ctx, big.NewInt(int64(currBlock.Number.Uint64()+1)))
				if err != nil {
					<-time.After(time.Second * 1)
					continue
				}
				currBlock = nextBlock
				slog.Info("Next block recevied", "next_block", currBlock.Number.Uint64())
				break
			}
		}

		var tx *types.Transaction
		if txTypeStr == FakeTx {
			tx, err = h.sendFakeTx(ctx, nil, h.DefaultPriorityFee)
		} else {
			tx, err = h.ethTransfer(ctx, big.NewInt(1), h.DefaultPriorityFee, nil, toAddr, nil)
			if err != nil {
				return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
			}

			if useRelay {
				tx, err = h.sendPrivateRawRelayTx(ctx, tx)
			} else {
				tx, err = h.sendPrivateTx(ctx, tx)
			}
		}
		if err != nil {
			return fmt.Errorf("faield to send tx error %w", err)
		}

		privKey2, err := crypto.HexToECDSA(rawKeyY)
		if err != nil {
			return fmt.Errorf("failed to parse secp256k1 private key error %w", err)
		}

		matchHash, err := mevutil.DoubleTxHash(tx.Hash())
		if err != nil {
			return err
		}

		for hint := range ch {
			if matchHash == hint.Hash {
				hintRaw, err := json.Marshal(hint)
				if err != nil {
					return err
				}
				slog.Any("hint:", string(hintRaw))

				bundleResp, err := h.SendBackrun(ctx, matchHash, h.DefaultPriorityFee, ethAmount, privKey2)
				if err != nil {
					return fmt.Errorf("failed to send backrun error %w", err)
				}

				slog.Info("Backrun sent", "bundle", bundleResp.BundleHash.String())

				for range time.NewTicker(time.Second * 2).C {
					txStatus, err := h.MEVClient.GetTxStatus(ctx, tx.Hash())
					if err != nil {
						slog.Warn("Failed to get tx status", "erorr", err)
						continue
					}

					slog.Info("Received tx status", "tx", tx.Hash(), "status", txStatus.Status)
					if txStatus.Status == Included || txStatus.Status == Failed {
						break
					}
				}

				return hintsStream.Error()
			}
		}

		return ErrHintNotFound

	}
}

func (h *Handler) HintsStream(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ch := make(chan protect.Hint)
		hintsStream, err := protect.SubscribeHints(context.Background(), h.MEVClient.FlashbotsMEVShareURL, ch, nil)
		if err != nil {
			return err
		}
		for hint := range ch {
			slog.Info("Parsed hint", "hint", hint)
		}

		return hintsStream.Error()
	}
}

func (h *Handler) TxStatus(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		txHash := cCtx.String("tx-hash")
		if txHash == "" {
			return errors.New("txHash expected")
		}

		txStatus, err := h.MEVClient.GetTxStatus(ctx, common.HexToHash(txHash))
		if err != nil {
			return err
		}

		slog.Info("Received tx status", "status", txStatus)

		return nil
	}
}

func (h *Handler) CancelRelayTx(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		_, err = h.sendPrivateRawRelayTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("faield to execute eth-call-bundle error %w", err)
		}

		slog.Info("Sent private transaction before cancelation", "hash", tx.Hash())

		err = h.MEVClient.CancelPrivateRelayTx(ctx, tx.Hash())
		if err != nil {
			return err
		}

		return nil
	}
}

func (h *Handler) CancelRpcTx(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		senderAddr := crypto.PubkeyToAddress(h.Alice.PublicKey)
		nonce, err := h.MEVClient.FlashbotsRPC.PendingNonceAt(ctx, senderAddr)
		if err != nil {
			return fmt.Errorf("failed to get pending nonce: %w", err)
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, &nonce)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		_, err = h.sendPrivateTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("failed to send private tx error %w", err)
		}

		slog.Info("Sent private transaction before cancellation", "hash", tx.Hash(), "nonce", nonce)

		// protect-rpc detects self-transfer (to == sender && data <= 2 bytes) and cancels original tx with same nonce
		cancelTx, err := h.ethTransfer(ctx, big.NewInt(1), h.DefaultPriorityFee, nil, senderAddr, &nonce)
		if err != nil {
			return fmt.Errorf("failed to construct cancellation tx error %w", err)
		}

		_, err = h.sendPrivateTx(ctx, cancelTx)
		if err != nil {
			return fmt.Errorf("failed to send cancellation tx error %w", err)
		}

		slog.Info("Sent cancellation transaction (self-transfer)", "hash", cancelTx.Hash(), "nonce", nonce)

		txStatus, err := h.getFlashbotsTxReceipt(ctx, tx.Hash())
		if err != nil {
			slog.Warn("Failed to get tx status", "error", err)
		} else {
			slog.Info("Final tx status", "originalTx", tx.Hash(), "status", txStatus.Status)
		}

		return nil
	}
}

func (h *Handler) sendPrivateRawRelayTx(ctx context.Context, tx *types.Transaction, builders ...string) (*types.Transaction, error) {
	resp, err := h.MEVClient.SendPrivateRawRelayTx(ctx, tx, builders...)
	if err != nil {
		return nil, err
	}

	slog.Info("Private tx send", "tx_hash", resp.String())
	return tx, nil
}

func (h *Handler) CancelEthBundle(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		currBlock, err := h.EthClient.HeaderByNumber(ctx, nil)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		rawTx, err := tx.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal tx %w", err)
		}

		bn := new(big.Int).Add(currBlock.Number, big.NewInt(1))

		replacementID := "4728baec-6d41-41d5-8e2c-697797b2344f"
		args := []*protect.SendBundleArgs{
			{
				Txs:             []string{hexutil.Encode(rawTx)},
				BlockNumber:     "0x" + bn.Text(16),
				ReplacementUuid: replacementID,
			},
		}

		err = h.sendEthBundle(ctx, args[0])
		if err != nil {
			return fmt.Errorf("faield to execute eth-call-bundle error %w", err)
		}

		err = h.MEVClient.CancelEthBundle(ctx, protect.CancelETHBundleArgs{ReplacementUuid: replacementID})
		if err != nil {
			return err
		}

		return nil
	}
}

func (h *Handler) SendEthBundle(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {

		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		currBlock, err := h.EthClient.HeaderByNumber(ctx, nil)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		rawTx, err := tx.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal tx %w", err)
		}

		bn := new(big.Int).Add(currBlock.Number, big.NewInt(1))
		args := []*protect.SendBundleArgs{
			{
				Txs:         []string{hexutil.Encode(rawTx)},
				BlockNumber: "0x" + bn.Text(16),
				// ReplacementUuid: "4728baec-6d41-41d5-8e2c",
				// Builders:        []string{"titan"},
			},
		}

		err = h.sendEthBundle(ctx, args[0])
		if err != nil {
			return fmt.Errorf("faield to execute eth-call-bundle error %w", err)
		}

		return nil
	}
}

func (h *Handler) sendEthBundle(ctx context.Context, args *protect.SendBundleArgs) error {
	resp, err := h.MEVClient.SendEthBundle(ctx, args)
	if err != nil {
		return err
	}

	slog.Info("eth_bundle response", "resp", resp)

	return nil

}

func (h *Handler) CallEthBundle(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		currBlock, err := h.EthClient.HeaderByNumber(ctx, nil)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		rawTx, err := tx.MarshalBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal tx %w", err)
		}

		args := &protect.CallBundleArgs{
			Txs:              []string{hexutil.Encode(rawTx)},
			BlockNumber:      "0x" + currBlock.Number.Text(16),
			StateBlockNumber: "0x" + currBlock.Number.Text(16),
			Timestamp:        nil,
		}

		return h.MEVClient.CallEthBundle(ctx, args)
	}
}

func (h *Handler) SendPrivateRelayTx(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		ethAmountStr := cCtx.String("eth-amount")
		txTypeStr := TestTxType(cCtx.String("tx-type"))
		toAddr, err := h.parseToAddr(txTypeStr)
		if err != nil {
			return err
		}

		ethAmount, err := h.getEthValue(ethAmountStr)
		if err != nil {
			return err
		}

		tx, err := h.ethTransfer(ctx, ethAmount, h.DefaultPriorityFee, nil, toAddr, nil)
		if err != nil {
			return fmt.Errorf("failed to construct ethTransfer tx error %w", err)
		}

		resp, err := h.sendPrivateRelayTx(ctx, tx)
		if err != nil {
			return fmt.Errorf("faield to execute send-private-tx error %w", err)
		}
		slog.Info("Resposne:", "resp", resp.String())

		return nil
	}
}

func (h *Handler) sendPrivateRelayTx(ctx context.Context, tx *types.Transaction) (hexutil.Bytes, error) {
	resp, err := h.MEVClient.SendPrivateRelayTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	slog.Info("Private tx send", "tx_hash", tx.Hash().String())
	return resp, nil
}

func (h *Handler) SendFakeTx(ctx context.Context) func(*cli.Context) error {
	return func(cCtx *cli.Context) error {
		tx, err := h.sendFakeTx(ctx, nil, h.DefaultPriorityFee)
		if err != nil {
			return fmt.Errorf("faield to execute send-private-tx error %w", err)
		}

		slog.Info("Send fake tx which must fail", "tx_hash", tx.Hash())

		return nil
	}
}

func (h *Handler) sendFakeTx(ctx context.Context, sender *ecdsa.PrivateKey, priorityFee *big.Int) (*types.Transaction, error) {
	if sender == nil {
		sender = h.Alice
	}
	currBlock, err := h.MEVClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	// builds fake call data which staticcalls always fail
	fakeCalldata, err := h.checkAndSendMultiCallData([]common.Address{h.WETHAddr}, [][]byte{{0xFF}}, [][]byte{{0xAF}})
	if err != nil {
		return nil, err
	}

	senderAddr := crypto.PubkeyToAddress(sender.PublicKey)
	nonce, err := h.EthClient.PendingNonceAt(ctx, senderAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	signer := types.LatestSignerForChainID(h.MEVClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(110))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 80_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   h.MEVClient.ChainID,
		Nonce:     nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &h.CheckAndSendContract,
		Value:     nil,
		Data:      fakeCalldata,
	})

	fakeTx, err := types.SignTx(tx, signer, sender)
	if err != nil {
		return nil, err
	}

	if err := h.MEVClient.SendPrivateTx(ctx, fakeTx); err != nil {
		return nil, err
	}

	return fakeTx, nil
}

func (h *Handler) sendPrivateTx(ctx context.Context, tx *types.Transaction) (*types.Transaction, error) {
	if err := h.MEVClient.SendPrivateTx(ctx, tx); err != nil {
		return nil, err
	}

	slog.Info("Private tx send", "tx_hash", tx.Hash().String())
	return tx, nil
}

func (h *Handler) checkAndSendMultiCallData(addrs []common.Address, payloads [][]byte, results [][]byte) ([]byte, error) {
	checkAndSendABI, err := abi.JSON(strings.NewReader(mevutil.FlashbotsCheckAndSendABI))
	if err != nil {
		return nil, err
	}

	calldata, err := checkAndSendABI.Pack("checkBytesAndSendMulti", addrs, payloads, results)
	if err != nil {
		return nil, fmt.Errorf("failed to pack checkBytesAndSend calldata error %w", err)
	}

	return calldata, nil
}

func (h *Handler) SendBackrun(ctx context.Context, originalTx common.Hash, priorityFee *big.Int, payableAmount *big.Int, sender *ecdsa.PrivateKey) (*protect.SendMevBundleResponse, error) {
	currBlock, err := h.MEVClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	if payableAmount == nil {
		if h.Network == protect.SepoliaNetwork {
			payableAmount = big.NewInt(5e16)
		} else {
			payableAmount = big.NewInt(2e15)
		}
	}

	calldata, err := h.checkAndSendMultiCallData([]common.Address{}, [][]byte{}, [][]byte{})
	if err != nil {
		return nil, err
	}

	senderAddr := crypto.PubkeyToAddress(sender.PublicKey)
	nonce, err := h.EthClient.PendingNonceAt(ctx, senderAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	signer := types.LatestSignerForChainID(h.MEVClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(110))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 80_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}
	baseFeeFuture.Add(baseFeeFuture, gasTipCap)

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   h.MEVClient.ChainID,
		Nonce:     nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &h.CheckAndSendContract,
		Value:     payableAmount,
		Data:      calldata,
	})
	backrunTx, err := types.SignTx(tx, signer, sender)
	if err != nil {
		return nil, err
	}

	bundle, err := h.MEVClient.CreateMEVBundle(originalTx, currBlock.NumberU64(), nil, backrunTx)
	if err != nil {
		return nil, fmt.Errorf("failed to bundle tx error %w", err)
	}

	resp, err := h.MEVClient.SendMEVBundle(ctx, bundle)
	if err != nil {
		return nil, err
	}

	slog.Info("Send backrun tx", "backrun_tx_hash", backrunTx.Hash())

	return resp, nil
}

func (h *Handler) getFlashbotsTxReceipt(ctx context.Context, tx common.Hash) (protect.TxStatus, error) {
	// check flashbots status endpoint
	for range time.NewTicker(time.Second * 2).C {
		txStatus, err := h.MEVClient.GetTxStatus(ctx, tx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return protect.TxStatus{}, err
			}
			slog.Warn("Failed to get tx status", "erorr", err)
			continue
		}

		if txStatus.Status == Pending {
			continue
		}

		if txStatus.Status == Included || txStatus.Status == Failed {
			return txStatus, nil
		}

		return protect.TxStatus{}, errors.New("tx dropped")
	}

	return protect.TxStatus{}, errors.New("failed to get tx receipt")
}

func (h *Handler) sendRawBatchTx(ctx context.Context) error {
	addr := crypto.PubkeyToAddress(h.Alice.PublicKey)

	nonceAt, err := h.EthClient.PendingNonceAt(ctx, addr)
	if err != nil {
		return err
	}

	tx1, err := h.delegateTxWithEIP7702(ctx, nil, h.DefaultPriorityFee, &nonceAt)
	if err != nil {
		return err
	}

	nonceAt += 2
	tx2, err := h.delegateTxWithEIP7702(ctx, nil, h.DefaultPriorityFee, &nonceAt)
	if err != nil {
		return err
	}

	if err := h.MEVClient.SendPrivateTx(ctx, tx1); err != nil {
		return err
	}

	if err := h.MEVClient.SendPrivateTx(ctx, tx2); err != nil {
		return err
	}

	slog.Info("Sent tx", "hash", tx1.Hash())
	slog.Info("Sent tx", "hash", tx2.Hash())

	return nil
}

// pectraWorkflow

// Pectra update test workflow using batch call transactions
//
// 1. construct and send SetCode transaction
// 2. get tx_receipt and verify that auth set correctly
// 3. use EOA account to execute tx batchcall
func (h *Handler) pectraWorkflow(ctx context.Context, ethAmount, priorityFee *big.Int) error {

	tx, err := h.delegateTxWithEIP7702(ctx, nil, h.DefaultPriorityFee, nil)
	if err != nil {
		return fmt.Errorf("failed to construct eip7702 tx error %w", err)
	}

	listenCtx, stopListen := context.WithTimeout(ctx, time.Second*60)
	defer stopListen()
	hintsC := make(chan protect.Hint, 100)
	_, err = protect.SubscribeHints(listenCtx, h.MEVClient.FlashbotsMEVShareURL, hintsC, nil)
	if err != nil {
		return err
	}

	go func() {
		<-listenCtx.Done()
		<-time.After(time.Second * 1)
		close(hintsC)
	}()

	slog.Info("Sent eip7702-tx", "tx_hash", tx.Hash())

	if err := h.MEVClient.SendPrivateTx(ctx, tx); err != nil {
		return err
	}

	matchHash, err := mevutil.DoubleTxHash(tx.Hash())
	if err != nil {
		return err
	}

	rawKeyY := os.Getenv("FLASHBOTS_ETH_PRIVATE_KEY_2")
	if rawKeyY == "" {
		return errors.New("FLASHBOTS_ETH_PRIVATE_KEY_2 must be provided")
	}

	privKey2, err := crypto.HexToECDSA(rawKeyY)
	if err != nil {
		return fmt.Errorf("failed to parse secp256k1 private key error %w", err)
	}

	var found bool
	for hint := range hintsC {
		if hint.Hash == matchHash {
			bundleResp, err := h.SendBackrun(ctx, matchHash, priorityFee, ethAmount, privKey2)
			if err != nil {
				return fmt.Errorf("failed to send backrun error %w", err)
			}

			slog.Info("Sent Bundle", "bundle_hash", bundleResp.BundleHash)
			stopListen()
			found = true
			break
		}
	}

	if !found {
		return errors.New("failed to send backrun")
	}

	txStatus, err := h.getFlashbotsTxReceipt(ctx, tx.Hash())
	if err != nil {
		return err
	}

	slog.Info("Received tx status", "tx", tx.Hash(), "status", txStatus.Status)

	slog.Info("Start verify auth_list")
	// verify auth
VerifyLoop:
	for {
		<-time.After(time.Second * 2)
		onchainTx, pending, err := h.MEVClient.FlashbotsRPC.TransactionByHash(ctx, tx.Hash())
		if err != nil {
			if errors.Is(err, ethereum.NotFound) {
				continue
			}
			return err
		}

		if pending {
			continue
		}

		for _, auth := range onchainTx.SetCodeAuthorizations() {
			code, err := h.EthClient.CodeAt(ctx, crypto.PubkeyToAddress(h.Alice.PublicKey), nil)
			if err != nil {
				return err
			}
			delegation := types.AddressToDelegation(auth.Address)
			if string(code) != string(delegation) {
				return fmt.Errorf("code is not equal expected delegation")
			}
			break VerifyLoop
		}
	}

	batchCallABI, err := abi.JSON(strings.NewReader(mevutil.BatchCallAndSponsorABI))
	if err != nil {
		return err
	}

	calldata, err := batchCallABI.Pack("execute", []Call{
		{
			To:    h.WETHAddr,
			Value: big.NewInt(1),
			Data:  nil,
		},
		{
			To:    h.BuilderAddr,
			Value: big.NewInt(1),
			Data:  nil,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to pack batchcall error %w", err)
	}

	currBlock, err := h.EthClient.BlockByNumber(ctx, nil)
	if err != nil {
		return err
	}

	senderAddr := crypto.PubkeyToAddress(h.Alice.PublicKey)
	nonce, err := h.EthClient.PendingNonceAt(ctx, senderAddr)
	if err != nil {
		return err
	}

	signer := types.LatestSignerForChainID(h.MEVClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(150))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 180_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}

	rawTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   h.MEVClient.ChainID,
		Nonce:     nonce,
		GasTipCap: gasTipCap,
		GasFeeCap: baseFeeFuture,
		Gas:       uint64(gasLimit),
		To:        &senderAddr,
		Value:     nil,
		Data:      calldata,
	})

	stx, err := types.SignTx(rawTx, signer, h.Alice)
	if err != nil {
		return err
	}

	if err := h.MEVClient.SendPrivateTx(ctx, stx); err != nil {
		return err
	}

	slog.Info("Sent batchcall-tx", "tx_hash", stx.Hash())
	return nil

}

func (h *Handler) getEthValue(value string) (*big.Int, error) {
	ethAmount := new(big.Int).SetUint64(1)
	if value != "" {
		if _, ok := ethAmount.SetString(value, 10); !ok {
			return nil, fmt.Errorf("failed to parse ethAmount from string base: 10 value: %v", value)
		}
	}

	return ethAmount, nil
}

func (h *Handler) parseToAddr(txType TestTxType) (common.Address, error) {
	switch txType {
	case WethWrap, FakeTx, "":
		return h.WETHAddr, nil
	case BuilderTip:
		return h.BuilderAddr, nil
	case EIP7702Tx, RawBatchTx:
		return common.Address{}, nil

	default:
		return common.Address{}, ErrUnsupportedTestTxType
	}
}

func (h *Handler) ethTransfer(ctx context.Context, value *big.Int, priorityFee *big.Int, sender *ecdsa.PrivateKey, to common.Address, nonce *uint64) (*types.Transaction, error) {
	key := h.Alice
	if sender != nil {
		key = sender
	}

	currBlock, err := h.MEVClient.FlashbotsRPC.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get block error %w", err)
	}

	address := crypto.PubkeyToAddress(key.PublicKey)
	if nonce == nil {
		nonceAt, err := h.MEVClient.FlashbotsRPC.PendingNonceAt(ctx, address)
		if err != nil {
			return nil, fmt.Errorf("failed to get pending nonce: %w", err)
		}
		nonce = &nonceAt
	}

	signer := types.LatestSignerForChainID(h.MEVClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(150))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))

	gasLimit := 50_000
	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}
	baseFeeFuture.Add(baseFeeFuture, gasTipCap)

	log.Println("baseFee:", baseFeeFuture.String(), "priorityFee:", gasTipCap.String())

	return types.SignTx(types.NewTx(&types.DynamicFeeTx{
		ChainID:   h.MEVClient.ChainID,
		Nonce:     *nonce,
		GasFeeCap: baseFeeFuture,
		GasTipCap: gasTipCap,
		Gas:       uint64(gasLimit),
		To:        &to,
		Value:     value,
	}), signer, key)
}

type Call struct {
	To    common.Address `json:"to"`
	Value *big.Int       `json:"value"`
	Data  []byte         `json:"data"`
}

func (h *Handler) delegateTxWithEIP7702(ctx context.Context, sender *ecdsa.PrivateKey, priorityFee *big.Int, nonce *uint64) (*types.Transaction, error) {
	if sender == nil {
		sender = h.Alice
	}

	currBlock, err := h.EthClient.BlockByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}

	senderAddr := crypto.PubkeyToAddress(sender.PublicKey)
	if nonce == nil {
		nonceAt, err := h.EthClient.PendingNonceAt(ctx, senderAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce error %w", err)
		}
		nonce = &nonceAt
	}

	// generate signature for specific contract implementation
	auth, err := types.SignSetCode(sender, types.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(h.MEVClient.ChainID),
		Address: h.BatchCallAndSponsorContract,

		Nonce: *nonce + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign auth error %w", err)
	}

	signer := types.LatestSignerForChainID(h.MEVClient.ChainID)
	gasPrice := currBlock.BaseFee()
	baseFeeFuture := new(big.Int).Mul(gasPrice, big.NewInt(150))
	baseFeeFuture = new(big.Int).Div(baseFeeFuture, big.NewInt(100))
	gasLimit := 180_000

	var gasTipCap *big.Int
	if priorityFee != nil {
		gasTipCap = priorityFee
	} else {
		gasTipCap = big.NewInt(1e5)
	}

	rawTx := types.NewTx(&types.SetCodeTx{
		ChainID:   uint256.MustFromBig(h.MEVClient.ChainID),
		Nonce:     *nonce,
		GasTipCap: uint256.MustFromBig(gasTipCap),
		GasFeeCap: uint256.MustFromBig(baseFeeFuture),
		Gas:       uint64(gasLimit),
		To:        senderAddr,
		Value:     nil,
		Data:      []byte("hello!"),
		AuthList:  []types.SetCodeAuthorization{auth},
	})

	return types.SignTx(rawTx, signer, sender)
}
