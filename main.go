package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/flashbots/mevrepl/application"
)

func main() {
	rawKey := os.Getenv("BASE_KEY")
	key, err := crypto.HexToECDSA(rawKey)
	if err != nil {
		log.Fatal("Base key", err)
	}
	rawKey2 := os.Getenv("SECOND_KEY")
	key2, err := crypto.HexToECDSA(rawKey2)
	if err != nil {
		log.Fatal(err)
	}
	_ = key2
	address1 := crypto.PubkeyToAddress(key.PublicKey)
	fmt.Println("first address", address1)
	//mc, err := application.ConstructMevClient(key, "mainnet", "fast")
	mc, err := application.ConstructMevClient(key, "sepolia", "fast?hint=full")
	if err != nil {
		log.Fatal("Failed to counstruct mev client", err)
	}
	tx, err := mc.CreateWrapETH(big.NewInt(4), nil, nil)
	if err != nil {
		log.Fatal("Failed to create wrap ETH tx: ", err)
	}
	err = mc.SendPrivateTx(context.Background(), tx)
	if err != nil {
		log.Fatal("Failed to send private tx: ", err)
	}

	fmt.Println("tx sent", tx.Hash().Hex())

	/*
		{"level":"info","ts":"2025-04-09T18:36:00.611Z","msg":"Simulated bundle error","service":"node","module":"sbundle_processor","bundle":"0x46bd9f588dc67692c1ebec2b2f12a2093225a712b5c94a734a204c79809fed9d","targetBlock":8085733,"message":"Invalid params","code":-32602,"data":"data did not match any variant of untagged enum BundleItem at line 1 column 1008"}
	*/

	// Wait for the transaction to be processed
	time.Sleep(500 * time.Millisecond)
	resp, err := mc.SendBackrun(context.Background(), tx, key2)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("bundle hash", resp.BundleHash.Hex())
}
