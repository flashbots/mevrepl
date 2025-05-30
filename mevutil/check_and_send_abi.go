package mevutil

// FlashbotsCheckAndSendABI is abi for FlashbotsCheckAndSend.sol
//
// Deployed contract:
// https://etherscan.io/address/0xc4595e3966e0ce6e3c46854647611940a09448d3#code
var FlashbotsCheckAndSendABI = `[{"inputs":[{"internalType":"address","name":"_target","type":"address"},{"internalType":"bytes","name":"_payload","type":"bytes"},{"internalType":"bytes32","name":"_resultMatch","type":"bytes32"}],"name":"check32BytesAndSend","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address[]","name":"_targets","type":"address[]"},{"internalType":"bytes[]","name":"_payloads","type":"bytes[]"},{"internalType":"bytes32[]","name":"_resultMatches","type":"bytes32[]"}],"name":"check32BytesAndSendMulti","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"_target","type":"address"},{"internalType":"bytes","name":"_payload","type":"bytes"},{"internalType":"bytes","name":"_resultMatch","type":"bytes"}],"name":"checkBytesAndSend","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address[]","name":"_targets","type":"address[]"},{"internalType":"bytes[]","name":"_payloads","type":"bytes[]"},{"internalType":"bytes[]","name":"_resultMatches","type":"bytes[]"}],"name":"checkBytesAndSendMulti","outputs":[],"stateMutability":"payable","type":"function"}]`
